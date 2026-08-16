"""Final consolidated report across the frozen benchmark artifacts."""
from __future__ import annotations

import json
import os
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")
OUT = os.path.join(RES, "FINAL_REPORT.md")


def load(p: str) -> list[dict]:
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def dasr(rows, mode=None):
    rs = [r for r in rows if mode is None or r["mode"] == mode]
    return sum(r["DASR"] for r in rs) / len(rs) if rs else float("nan")


def acc4(rows, mode=None):
    rs = [r for r in rows if mode is None or r["mode"] == mode]
    return (sum(r["w4_verdict"] == r["w4_expected"] for r in rs) / len(rs)) if rs else float("nan")


def main():
    syn_none = load(os.path.join(RES, "items.jsonl"))
    syn_clean = load(os.path.join(RES, "clean_syn_none_items.jsonl"))
    syn_g3 = load(os.path.join(RES, "method_g3_items.jsonl"))
    tame_syn = load(os.path.join(RES, "guard_syn_final_items.jsonl"))
    tame_syn_clean = load(os.path.join(RES, "guard_syn_clean_final_items.jsonl"))
    real_none = load(os.path.join(RES, "real8_none_items.jsonl"))
    real_g3 = load(os.path.join(RES, "real8_g3_items.jsonl"))
    tame_real = load(os.path.join(RES, "guard_real8_items.jsonl"))
    real_clean = load(os.path.join(RES, "real_clean_mixed_s13_items.jsonl"))
    tame_real_clean = load(os.path.join(RES, "guard_real_clean_final_items.jsonl"))
    ioc_syn = load(os.path.join(RES, "ioc_syn_none_items.jsonl"))
    ioc_real = load(os.path.join(RES, "ioc_real_none_items.jsonl"))

    L = []
    A = L.append
    A("# Final Report")
    A("")
    A("## 1. Final benchmark framing")
    A("")
    A("The artifact is no longer a single-round prompt-injection benchmark. It is a"
      " **stateful contamination evaluation framework** with: multi-window delayed"
      " triggering, multiple state carriers, real logs, mechanism labels, and"
      " defense-aware evaluation.")
    A("")

    A("## 2. Main security table (verdict task)")
    A("")
    A("| Dataset | Mode | none DASR | G3 DASR | TAME DASR |")
    A("|---|---:|---:|---:|---:|")
    for label, base, g3, tame in (("synthetic", syn_none, syn_g3, tame_syn),
                                  ("real-104", real_none, real_g3, tame_real)):
        for m in ("S1", "S3"):
            A(f"| {label} | {m} | {pct(dasr(base, m))} | {pct(dasr(g3, m))} | {pct(dasr(tame, m))} |")
    A("")

    A("## 3. Clean utility final table")
    A("")
    A("| Dataset | Mode | baseline ACC_w4 | TAME ACC_w4 | delta |")
    A("|---|---:|---:|---:|---:|")
    for label, base, tame in (("synthetic", syn_clean, tame_syn_clean),
                              ("real", real_clean, tame_real_clean)):
        for m in ("S1", "S3"):
            b = acc4(base, m)
            t = acc4(tame, m)
            A(f"| {label} | {m} | {pct(b)} | {pct(t)} | {t-b:+.3f} |")
    A("")

    A("## 4. Payload breakdown")
    A("")
    A("| payload_kind | count | S1 DASR(real-104 none) |")
    A("|---|---:|---:|")
    by_kind = defaultdict(lambda: [0, 0])
    for r in real_none:
        if r["mode"] != "S1":
            continue
        by_kind[r.get("payload_kind", "?")][0] += 1
        by_kind[r.get("payload_kind", "?")][1] += r["DASR"]
    for k in sorted(by_kind):
        n, s = by_kind[k]
        A(f"| {k} | {n} | {pct(s/n)} |")
    A("")
    A("| payload_trust | count | S1 DASR(real-104 none) |")
    A("|---|---:|---:|")
    by_trust = defaultdict(lambda: [0, 0])
    for r in real_none:
        if r["mode"] != "S1":
            continue
        by_trust[r.get("payload_trust", "?")][0] += 1
        by_trust[r.get("payload_trust", "?")][1] += r["DASR"]
    for k in sorted(by_trust):
        n, s = by_trust[k]
        A(f"| {k} | {n} | {pct(s/n)} |")
    A("")

    A("## 5. Task split")
    A("")
    A("| Task | Dataset | Mode | none DASR |")
    A("|---|---|---:|---:|")
    for dataset, rows in (("synthetic", syn_none), ("synthetic-IOC", ioc_syn), ("real-IOC", ioc_real)):
        for m in ("S1", "S3"):
            A(f"| {'IOC' if 'IOC' in dataset else 'verdict'} | {dataset} | {m} | {pct(dasr(rows, m))} |")
    A("")

    A("## 6. Trigger distance")
    A("")
    A("Current frozen benchmark fixes `trigger_distance=3` (W1->W4). The field is now"
      " explicit in every row. The next expansion should add distance-1 / distance-2"
      " variants rather than overloading the main benchmark with synthetic-only numbers.")
    A("")

    A("## 7. Final scripts")
    A("")
    A("- `experiments/frozen_benchmark.sh`: regenerate final TAME tables")
    A("- `experiments/run_tame_ablations.sh`: regenerate TAME ablations")
    A("- `experiments/stats_ci.py`: bootstrap CI + paired sign test")
    A("- `results/FROZEN_BENCHMARK.md`: frozen result inventory")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
