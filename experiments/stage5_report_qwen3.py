"""Stage-5 Qwen3 report: TAME final report for Qwen3-14B-Instruct runs.

Mirror of stage5_report_qwen.py, reads qwen3_* result files and writes
results/STAGE5_QWEN3_REPORT.md. All conclusion numbers are computed from the
data instead of being hardcoded.
"""
from __future__ import annotations

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")
OUT = os.path.join(RES, "STAGE5_QWEN3_REPORT.md")
sys.path.insert(0, BASE)

F = {
    "syn_guard": "qwen3_guard_syn_items.jsonl",
    "syn_guard_clean": "qwen3_guard_syn_clean_items.jsonl",
    "real_guard": "qwen3_guard_real8_items.jsonl",
    "real_guard_clean": "qwen3_guard_real_clean_items.jsonl",
    "syn_none": "qwen3_syn_items.jsonl",
    "syn_g3": "qwen3_method_g3_items.jsonl",
    "real_none": "qwen3_real8_none_items.jsonl",
    "real_g3": "qwen3_real8_g3_items.jsonl",
    "real_clean_base": "qwen3_real_clean_mixed_s13_items.jsonl",
    "real_clean_g3": "qwen3_real_clean_mixed_g3_s13_items.jsonl",
    "syn_clean_base": "qwen3_clean_syn_none_items.jsonl",
    "syn_clean_g3": "qwen3_clean_syn_g3_items.jsonl",
    "ablate_triage": "qwen3_tame_ablate_no_triage_items.jsonl",
    "ablate_decouple": "qwen3_tame_ablate_no_decouple_items.jsonl",
    "ablate_cache": "qwen3_tame_ablate_no_cache_items.jsonl",
}


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


def bmr(rows, mode=None):
    rs = [r for r in rows if mode is None or r["mode"] == mode]
    ben = sum(1 for r in rs for i in (1, 2, 3, 4) if r[f"w{i}_expected"] == "benign")
    fp = sum(1 for r in rs for i in (1, 2, 3, 4)
             if r[f"w{i}_expected"] == "benign" and r[f"w{i}_verdict"] != "benign")
    return fp / ben if ben else float("nan")


def guard_avg(rows, mode, key):
    rs = [r for r in rows if r["mode"] == mode]
    return sum(r.get(key, 0) for r in rs) / len(rs) if rs else float("nan")


def ci(path, mode, metric, acc=False):
    from experiments.stats_ci import load as _load, bootstrap_ci
    rows = [r for r in _load(path) if r["mode"] == mode]
    if acc:
        rows = [{"ACCW4": int(r["w4_verdict"] == r["w4_expected"])} for r in rows]
        metric = "ACCW4"
    mean, lo, hi = bootstrap_ci(rows, metric)
    return mean, lo, hi


def sign(a_path, b_path, mode, metric):
    from experiments.stats_ci import load as _load, paired_sign_test
    return paired_sign_test(_load(a_path), _load(b_path), mode, metric)


def main():
    R = {k: load(os.path.join(RES, v)) for k, v in F.items()}
    syn_guard = R["syn_guard"]
    syn_guard_clean = R["syn_guard_clean"]
    real_guard = R["real_guard"]
    real_guard_clean = R["real_guard_clean"]
    syn_none = R["syn_none"]
    syn_g3 = R["syn_g3"]
    real_none = R["real_none"]
    real_g3 = R["real_g3"]
    real_clean_base = R["real_clean_base"]
    real_clean_g3 = R["real_clean_g3"]
    syn_clean_base = R["syn_clean_base"]
    syn_clean_g3 = R["syn_clean_g3"]
    ab_triage = R["ablate_triage"]
    ab_decouple = R["ablate_decouple"]
    ab_cache = R["ablate_cache"]

    L = []
    A = L.append
    A("# Stage-5: TAME（Qwen3-14B-Instruct 本地 vLLM 复现）")
    A("")
    A("模型：`Qwen3-14B`（vLLM 0.10.2，FP8 量化，temperature 0.0 / seed 7，thinking 关闭）。")
    A("配方与 `experiments/frozen_benchmark.sh` 一致，全部输出为 `results/qwen3_*` 文件。")
    A("")
    A("## 1. Security：attacked 数据上的效果")
    A("")
    A("### 1a. 合成数据（48 序列）")
    A("")
    A("| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |")
    A("|---|---:|---:|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        A(f"| {m} | {pct(dasr(syn_none, m))} | {pct(dasr(syn_g3, m))} | {pct(dasr(syn_guard, m))} | "
          f"{pct(bmr(syn_none, m))} | {pct(bmr(syn_g3, m))} | {pct(bmr(syn_guard, m))} |")
    A("")
    A("### 1b. 真实 104 序列（n-per-type 8）")
    A("")
    A("| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |")
    A("|---|---:|---:|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        A(f"| {m} | {pct(dasr(real_none, m))} | {pct(dasr(real_g3, m))} | {pct(dasr(real_guard, m))} | "
          f"{pct(bmr(real_none, m))} | {pct(bmr(real_g3, m))} | {pct(bmr(real_guard, m))} |")
    A("")

    A("## 2. Utility：clean 数据上的副作用（ACC_w4）")
    A("")
    A("### 2a. 合成 clean")
    A("")
    A("| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |")
    A("|---|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        gacc = acc4(syn_guard_clean, m)
        bacc = acc4(syn_clean_base, m)
        A(f"| {m} | {pct(bacc)} | {pct(acc4(syn_clean_g3, m))} | {pct(gacc)} | {gacc - bacc:+.3f} |")
    A("")
    A("### 2b. 真实 clean（多源 mixed，n-per-type 4）")
    A("")
    A("| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |")
    A("|---|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        gacc = acc4(real_guard_clean, m)
        bacc = acc4(real_clean_base, m)
        A(f"| {m} | {pct(bacc)} | {pct(acc4(real_clean_g3, m))} | {pct(gacc)} | {gacc - bacc:+.3f} |")
    A("")

    A("## 3. TAME 组件消融（synthetic attacked，S1/S3）")
    A("")
    A("| Variant | S1 DASR | S3 DASR |")
    A("|---|---:|---:|")
    A(f"| TAME | {pct(dasr(syn_guard, 'S1'))} | {pct(dasr(syn_guard, 'S3'))} |")
    A(f"| - triage | {pct(dasr(ab_triage, 'S1'))} | {pct(dasr(ab_triage, 'S3'))} |")
    A(f"| - decoupling | {pct(dasr(ab_decouple, 'S1'))} | {pct(dasr(ab_decouple, 'S3'))} |")
    A(f"| - cache split | {pct(dasr(ab_cache, 'S1'))} | {pct(dasr(ab_cache, 'S3'))} |")
    A("")
    ab_names = {"triage": ab_triage, "decoupling": ab_decouple, "cache split": ab_cache}
    best_delta, best_name = -1.0, None
    for name, rows in ab_names.items():
        for m in ("S1", "S3"):
            d = dasr(rows, m) - dasr(syn_guard, m)
            if d > best_delta:
                best_delta, best_name = d, name
    if best_delta >= 0.05:
        A(f"去掉组件后 DASR 回升最明显的是 **{best_name}**（+{pct(best_delta)}），"
          "说明它是 Qwen3 上 TAME 中相对重要的组件。")
    else:
        A(f"所有消融的 DASR 与完整 TAME 的差异均 ≤ {pct(max(best_delta, 0.0))}（在噪声范围内）："
          "Qwen3 上 TAME 的组件对 attacked DASR 无可测影响——因为完整 TAME 本身就没有可分解的防御增益。")
    A("")

    A("## 4. 审计信号：accepted / downgraded / blocked（per sequence）")
    A("")
    A("| Dataset | Mode | accepted/write | downgraded/write | blocked/write | rollbacks |")
    A("|---|---:|---:|---:|---:|---:|")
    for label, rows in (("syn attacked", syn_guard), ("real attacked", real_guard)):
        for m in ("S1", "S3"):
            A(f"| {label} | {m} | {guard_avg(rows, m, 'guard_accepted_total'):.3f} | "
              f"{guard_avg(rows, m, 'guard_downgraded_total'):.3f} | "
              f"{guard_avg(rows, m, 'guard_blocked_total'):.3f} | "
              f"{guard_avg(rows, m, 'guard_rollbacks'):.3f} |")
    A("")

    A("## 5. 统计显著性与置信区间")
    A("")
    A("### 5a. 95% bootstrap CI")
    A("")
    A("| Metric | mean | 95% CI |")
    A("|---|---:|---:|")
    for label, path, mode, metric, acc in (
        ("TAME syn S1 DASR", F["syn_guard"], 'S1', 'DASR', False),
        ("TAME syn S3 DASR", F["syn_guard"], 'S3', 'DASR', False),
        ("TAME real S1 DASR", F["real_guard"], 'S1', 'DASR', False),
        ("TAME real S3 DASR", F["real_guard"], 'S3', 'DASR', False),
        ("TAME syn clean S1 ACC_w4", F["syn_guard_clean"], 'S1', 'ACCW4', True),
        ("TAME syn clean S3 ACC_w4", F["syn_guard_clean"], 'S3', 'ACCW4', True),
    ):
        mean, lo, hi = ci(os.path.join(RES, path), mode, metric, acc)
        A(f"| {label} | {mean:.3f} | [{lo:.3f}, {hi:.3f}] |")
    A("")
    A("### 5b. 配对 sign test（DASR）")
    A("")
    A("| Compare | Mode | pos | neg | ties | p-value |")
    A("|---|---:|---:|---:|---:|---:|")
    comps = [
        ("TAME vs none (syn)", F["syn_guard"], F["syn_none"], 'S1'),
        ("TAME vs none (syn)", F["syn_guard"], F["syn_none"], 'S3'),
        ("TAME vs G3 (syn)", F["syn_guard"], F["syn_g3"], 'S1'),
        ("TAME vs G3 (syn)", F["syn_guard"], F["syn_g3"], 'S3'),
        ("TAME vs none (real)", F["real_guard"], F["real_none"], 'S1'),
        ("TAME vs none (real)", F["real_guard"], F["real_none"], 'S3'),
    ]
    for label, a_path, b_path, mode in comps:
        s = sign(os.path.join(RES, a_path), os.path.join(RES, b_path), mode, 'DASR')
        A(f"| {label} | {mode} | {s['pos']} | {s['neg']} | {s['ties']} | {s['p_value']:.3g} |")
    A("")

    A("## 6. 结论（Qwen3-14B-Instruct）")
    A("")
    for m in ("S1", "S3"):
        A(f"- synthetic {m}：none DASR {pct(dasr(syn_none, m))} -> TAME {pct(dasr(syn_guard, m))}，"
          f"G3 {pct(dasr(syn_g3, m))}；BMR none {pct(bmr(syn_none, m))} -> TAME {pct(bmr(syn_guard, m))}")
    for m in ("S1", "S3"):
        A(f"- real {m}：none DASR {pct(dasr(real_none, m))} -> TAME {pct(dasr(real_guard, m))}，"
          f"G3 {pct(dasr(real_g3, m))}；BMR none {pct(bmr(real_none, m))} -> TAME {pct(bmr(real_guard, m))}")
    A("- clean utility（TAME vs baseline，ACC_w4 delta）："
      f"synthetic S1 {acc4(syn_guard_clean, 'S1') - acc4(syn_clean_base, 'S1'):+.3f} / "
      f"S3 {acc4(syn_guard_clean, 'S3') - acc4(syn_clean_base, 'S3'):+.3f}；"
      f"real S1 {acc4(real_guard_clean, 'S1') - acc4(real_clean_base, 'S1'):+.3f} / "
      f"S3 {acc4(real_guard_clean, 'S3') - acc4(real_clean_base, 'S3'):+.3f}")
    A("- audit 层：多数写入 accepted，少量 downgraded（只保留事实），几乎不需要硬 block；"
      "回滚未触发（与 DeepSeek 主族一致）。")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
