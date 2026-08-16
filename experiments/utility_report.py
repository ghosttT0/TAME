"""Utility decomposition: separate contamination delta from model capability.

Reports, per state mode and defense, on clean (no payload) and attacked sets:
  ACC_w4   - trigger window verdict accuracy (malicious judged malicious, benign judged benign)
  ACC_win  - all-window verdict accuracy
  MTR/BMR  - per-window miss / false-alarm
Then:
  clean_gain        = ACC(S1..S4) - ACC(S0)          on clean data (state helps?)
  attacked_delta    = ACC(S1..S4) - ACC(S0)          on attacked data (state helps/hurts)
  contamination_delta = attacked_delta - clean_gain   # pollution-specific penalty
  gate_utility_loss = ACC_gated - ACC_ungated        on CLEAN data (side effect of defense)
"""
from __future__ import annotations

import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")

MODES = ("S0", "S1", "S2", "S3", "S4")
DEFENSES = ("none", "G1", "G2", "G3", "G4", "learned")


def load(p: str) -> list[dict]:
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def acc_w4(rows: list[dict]) -> float:
    if not rows:
        return float("nan")
    ok = sum(1 for r in rows if r["w4_verdict"] == r["w4_expected"])
    return ok / len(rows)


def acc_all(rows: list[dict]) -> float:
    n = ok = 0
    for r in rows:
        for i in (1, 2, 3, 4):
            n += 1
            ok += int(r[f"w{i}_verdict"] == r[f"w{i}_expected"])
    return ok / n if n else float("nan")


def mtr_bmr(rows: list[dict]) -> tuple[float, float]:
    ben = mal = fn = fp = 0
    for r in rows:
        for i in (1, 2, 3, 4):
            if r[f"w{i}_expected"] == "malicious":
                mal += 1
                fn += int(r[f"w{i}_verdict"] != "malicious")
            else:
                ben += 1
                fp += int(r[f"w{i}_verdict"] != "benign")
    return (fn / mal if mal else float("nan")), (fp / ben if ben else float("nan"))


def report(rows_by: dict, label: str) -> dict:
    out = {"label": label}
    for m in MODES:
        rs = rows_by.get(m, [])
        out[m] = {"n": len(rs), "ACC_w4": acc_w4(rs), "ACC_all": acc_all(rs),
                  "MTR": mtr_bmr(rs)[0], "BMR": mtr_bmr(rs)[1]}
    return out


def main() -> None:
    syn_clean = load(os.path.join(RES, "clean_syn_none_items.jsonl"))
    syn_att = load(os.path.join(RES, "items.jsonl"))
    real_clean = load(os.path.join(RES, "clean_real_items.jsonl"))
    real_att = load(os.path.join(RES, "real_none_items.jsonl"))

    def group(rows, key="mode"):
        g: dict[str, list] = {}
        for r in rows:
            g.setdefault(r.get(key), []).append(r)
        return g

    blocks = [
        ("synthetic", group(syn_clean), group(syn_att)),
        ("real", group(real_clean), group(real_att)),
    ]
    out = {}
    for name, clean_g, att_g in blocks:
        out[name] = {"clean": report(clean_g, name), "attacked": report(att_g, name)}
        c, a = out[name]["clean"], out[name]["attacked"]
        rows = []
        for m in MODES:
            c_acc, a_acc = c[m]["ACC_w4"], a[m]["ACC_w4"]
            rows.append((m, c_acc, a_acc,
                         a_acc - c_acc,
                         c[m]["MTR"], a[m]["MTR"], c[m]["BMR"], a[m]["BMR"]))
        print(f"\n== {name}: per-mode utility (ACC_w4) ==")
        print(f"{'mode':<4} {'clean':>7} {'attacked':>8} {'delta(att-clean)':>15} "
              f"{'MTR clean/att':>16} {'BMR clean/att':>16}")
        for m, c_acc, a_acc, d, mtr_c, mtr_a, bmr_c, bmr_a in rows:
            print(f"{m:<4} {c_acc:>7.3f} {a_acc:>8.3f} {d:>15.3f} "
                  f"{mtr_c:.2f}/{mtr_a:.2f}       {bmr_c:.2f}/{bmr_a:.2f}")
        # state-induced deltas
        c_s0, a_s0 = c["S0"]["ACC_w4"], a["S0"]["ACC_w4"]
        print("\nstate-induced delta vs S0:")
        for m in ("S1", "S2", "S3", "S4"):
            clean_gain = c[m]["ACC_w4"] - c_s0
            att_delta = a[m]["ACC_w4"] - a_s0
            print(f"  {m}: clean_gain={clean_gain:+.3f}  attacked_delta={att_delta:+.3f}  "
                  f"contamination_penalty={att_delta - clean_gain:+.3f}")
        out[name]["deltas"] = {m: {"clean_gain": c[m]["ACC_w4"] - c_s0,
                                   "attacked_delta": a[m]["ACC_w4"] - a_s0}
                               for m in ("S1", "S2", "S3", "S4")}
    # gate utility loss on clean data (side effects)
    print("\n== gate side effects on CLEAN synthetic data (ACC_w4) ==")
    g1_clean = load(os.path.join(RES, "clean_syn_g1_items.jsonl"))
    g3_clean = load(os.path.join(RES, "clean_syn_g3_items.jsonl"))
    g4_clean = load(os.path.join(RES, "clean_syn_g4_items.jsonl"))
    for label, frows in (("G1", g1_clean), ("G3", g3_clean), ("G4", g4_clean)):
        if not frows:
            print(f"  {label}: not run")
            continue
        gg = group(frows)
        losses = {}
        for m in ("S1", "S2", "S3", "S4"):
            clean_acc = out["synthetic"]["clean"][m]["ACC_w4"]
            gated_acc = report(gg, "")[m]["ACC_w4"]
            losses[m] = gated_acc - clean_acc
        print(f"  {label}: utility_loss(S1..S4)=",
              {m: f"{v:+.3f}" for m, v in losses.items()})
        out.setdefault("gate_side_effects", {})[label] = losses

    with open(os.path.join(RES, "utility_decomposition.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2, default=str)
    print("\nwritten results/utility_decomposition.json")


if __name__ == "__main__":
    main()