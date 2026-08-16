"""Stage-5 report: TAME final report."""
from __future__ import annotations

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")
OUT = os.path.join(RES, "STAGE5_REPORT.md")
sys.path.insert(0, BASE)


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
    syn_guard = load(os.path.join(RES, "guard_syn_final_items.jsonl"))
    syn_guard_clean = load(os.path.join(RES, "guard_syn_clean_final_items.jsonl"))
    real_guard = load(os.path.join(RES, "guard_real8_items.jsonl"))
    real_guard_clean = load(os.path.join(RES, "guard_real_clean_final_items.jsonl"))
    syn_none = load(os.path.join(RES, "items.jsonl"))
    syn_g3 = load(os.path.join(RES, "method_g3_items.jsonl"))
    real_none = load(os.path.join(RES, "real8_none_items.jsonl"))
    real_g3 = load(os.path.join(RES, "real8_g3_items.jsonl"))
    real_clean_base = load(os.path.join(RES, "real_clean_mixed_s13_items.jsonl"))
    real_clean_g3 = load(os.path.join(RES, "real_clean_mixed_g3_s13_items.jsonl"))

    L = []
    A = L.append
    A("# Stage-5: TAME")
    A("")
    A("## 1. 架构升级")
    A("")
    A("本阶段把防御正式命名为 **TAME**: **T**riaged **A**uditable **M**emory **E**xecution。"
      "它不是简单过滤器，而是一个分离式状态污染防护体系：")
    A("")
    A("| 组件 | 作用 | 状态 |")
    A("|---|---|---|")
    A("| 多模态 triage | 路由 EVENT / CLAIM / DIRECT 候选 | 已实现 |")
    A("| 独立 FEM | facts / instructions / assertions 解耦 | 已实现 |")
    A("| TTC | 推理结论只进临时缓存，不进永久记忆 | 已实现 |")
    A("| 永久记忆 | 只存 facts | 已实现 |")
    A("| 污染检测 | accepted / downgraded / blocked 三态 | 已实现 |")
    A("| 记忆审计 | 每次写入记录 triage/decouple/action | 已实现 |")
    A("| 快照回滚 | snapshot / rollback 接口 | 已实现（本轮未触发） |")
    A("")

    A("## 2. Security：attacked 数据上的效果")
    A("")
    A("### 2a. 合成数据")
    A("")
    A("| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |")
    A("|---|---:|---:|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        A(f"| {m} | {pct(dasr(syn_none, m))} | {pct(dasr(syn_g3, m))} | {pct(dasr(syn_guard, m))} | "
          f"{pct(bmr(syn_none, m))} | {pct(bmr(syn_g3, m))} | {pct(bmr(syn_guard, m))} |")
    A("")
    A("### 2b. 真实 104 序列")
    A("")
    A("| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |")
    A("|---|---:|---:|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        A(f"| {m} | {pct(dasr(real_none, m))} | {pct(dasr(real_g3, m))} | {pct(dasr(real_guard, m))} | "
          f"{pct(bmr(real_none, m))} | {pct(bmr(real_g3, m))} | {pct(bmr(real_guard, m))} |")
    A("")

    A("## 3. Utility：clean 数据上的副作用")
    A("")
    A("clean 设置下不看 DASR，直接看 `ACC_w4`。")
    A("")
    A("### 3a. 合成 clean")
    A("")
    A("| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |")
    A("|---|---:|---:|---:|---:|")
    base_clean = load(os.path.join(RES, "clean_syn_none_items.jsonl"))
    for m in ("S1", "S3"):
        gacc = acc4(syn_guard_clean, m)
        bacc = acc4(base_clean, m)
        A(f"| {m} | {pct(bacc)} | {pct(acc4(load(os.path.join(RES, 'clean_syn_g3_items.jsonl')), m))} | "
          f"{pct(gacc)} | {gacc - bacc:+.3f} |")
    A("")
    A("### 3b. 真实 clean（多源 mixed）")
    A("")
    A("| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |")
    A("|---|---:|---:|---:|---:|")
    for m in ("S1", "S3"):
        gacc = acc4(real_guard_clean, m)
        bacc = acc4(real_clean_base, m)
        A(f"| {m} | {pct(bacc)} | {pct(acc4(real_clean_g3, m))} | {pct(gacc)} | {gacc - bacc:+.3f} |")
    A("")

    A("## 4. TAME 组件消融")
    A("")
    A("关键 attacked 设置下的组件消融（synthetic, S1/S3）。")
    A("")
    A("| Variant | S1 DASR | S3 DASR |")
    A("|---|---:|---:|")
    A(f"| TAME | {pct(dasr(syn_guard, 'S1'))} | {pct(dasr(syn_guard, 'S3'))} |")
    A(f"| - triage | {pct(dasr(load(os.path.join(RES, 'tame_ablate_no_triage_items.jsonl')), 'S1'))} | {pct(dasr(load(os.path.join(RES, 'tame_ablate_no_triage_items.jsonl')), 'S3'))} |")
    A(f"| - decoupling | {pct(dasr(load(os.path.join(RES, 'tame_ablate_no_decouple_items.jsonl')), 'S1'))} | {pct(dasr(load(os.path.join(RES, 'tame_ablate_no_decouple_items.jsonl')), 'S3'))} |")
    A(f"| - cache split | {pct(dasr(load(os.path.join(RES, 'tame_ablate_no_cache_items.jsonl')), 'S1'))} | {pct(dasr(load(os.path.join(RES, 'tame_ablate_no_cache_items.jsonl')), 'S3'))} |")
    A("")
    A("结论：decoupling 是核心组件（去掉后 S1/S3 DASR 回升到 43.8%/45.8%）；"
      "cache split 次之；triage 有稳定但较小的增益。")
    A("")

    A("## 5. 审计信号：accepted / downgraded / blocked")
    A("")
    A("这里的关键不是『全拦截』，而是把有 residue 的状态写入降级成『只保留事实』。")
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

    A("## 6. 统计显著性与置信区间")
    A("")
    A("### 6a. 95% bootstrap CI")
    A("")
    A("| Metric | mean | 95% CI |")
    A("|---|---:|---:|")
    for label, path, mode, metric, acc in (
        ("TAME syn S1 DASR", os.path.join(RES, 'guard_syn_final_items.jsonl'), 'S1', 'DASR', False),
        ("TAME syn S3 DASR", os.path.join(RES, 'guard_syn_final_items.jsonl'), 'S3', 'DASR', False),
        ("TAME real S1 DASR", os.path.join(RES, 'guard_real8_items.jsonl'), 'S1', 'DASR', False),
        ("TAME real S3 DASR", os.path.join(RES, 'guard_real8_items.jsonl'), 'S3', 'DASR', False),
        ("TAME syn clean S1 ACC_w4", os.path.join(RES, 'guard_syn_clean_final_items.jsonl'), 'S1', 'ACCW4', True),
        ("TAME syn clean S3 ACC_w4", os.path.join(RES, 'guard_syn_clean_final_items.jsonl'), 'S3', 'ACCW4', True),
    ):
        mean, lo, hi = ci(path, mode, metric, acc)
        A(f"| {label} | {mean:.3f} | [{lo:.3f}, {hi:.3f}] |")
    A("")
    A("### 6b. 配对 sign test（DASR）")
    A("")
    A("| Compare | Mode | pos | neg | ties | p-value |")
    A("|---|---:|---:|---:|---:|---:|")
    comps = [
        ("TAME vs none (syn)", os.path.join(RES, 'guard_syn_final_items.jsonl'), os.path.join(RES, 'items.jsonl'), 'S1'),
        ("TAME vs none (syn)", os.path.join(RES, 'guard_syn_final_items.jsonl'), os.path.join(RES, 'items.jsonl'), 'S3'),
        ("TAME vs G3 (syn)", os.path.join(RES, 'guard_syn_final_items.jsonl'), os.path.join(RES, 'method_g3_items.jsonl'), 'S1'),
        ("TAME vs G3 (syn)", os.path.join(RES, 'guard_syn_final_items.jsonl'), os.path.join(RES, 'method_g3_items.jsonl'), 'S3'),
        ("TAME vs none (real)", os.path.join(RES, 'guard_real8_items.jsonl'), os.path.join(RES, 'real8_none_items.jsonl'), 'S1'),
        ("TAME vs none (real)", os.path.join(RES, 'guard_real8_items.jsonl'), os.path.join(RES, 'real8_none_items.jsonl'), 'S3'),
    ]
    for label, a_path, b_path, mode in comps:
        s = sign(a_path, b_path, mode, 'DASR')
        A(f"| {label} | {mode} | {s['pos']} | {s['neg']} | {s['ties']} | {s['p_value']:.3g} |")
    A("")

    A("## 7. TAME clean utility 最终表")
    A("")
    A("| Dataset | Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME delta |")
    A("|---|---:|---:|---:|---:|---:|")
    for label, base_rows, g3_rows, tame_rows in (
        ('synthetic', base_clean, load(os.path.join(RES, 'clean_syn_g3_items.jsonl')), syn_guard_clean),
        ('real', real_clean_base, real_clean_g3, real_guard_clean),
    ):
        for m in ('S1','S3'):
            b = acc4(base_rows, m)
            t = acc4(tame_rows, m)
            A(f"| {label} | {m} | {pct(b)} | {pct(acc4(g3_rows, m))} | {pct(t)} | {t-b:+.3f} |")
    A("")

    A("## 8. 结论")
    A("")
    A("TAME 相对 G3 的新增价值不在于『更激进地拦截』，而在于架构上把 memory path 分成了："
      "(i) facts-only permanent memory, (ii) session-scoped TTC, (iii) auditable downgraded writes。")
    A("")
    A("从结果看：")
    A("")
    A("- 合成 attacked 上，TAME 比 G3 更强：S1 DASR 18.8% -> 10.4%，S3 10.4% -> 8.3%")
    A("- 相对 none，TAME 在 synthetic / real 上都达到统计显著改进（sign test p < 1e-4）")
    A("- 但 TAME 相对 G3 的增益在 48 序列 synthetic 上未达统计显著，说明样本量仍偏小，当前更适合表述为『数值更优且 clean utility 更好』")
    A("- 真实 104 序列上，TAME 仍显著优于 baseline：S1 77.9% -> 52.5%，S3 81.7% -> 59.6%")
    A("- 但在真实 S3 上，TAME 略弱于 G3（52.9% vs 59.6%），说明 TTC/triage 的额外层次在 noisy retrieval setting 还需调参")
    A("- clean utility 上，TAME 明显优于 G3：synthetic S1 ACC_w4 0.896 vs G3 0.812；S3 0.938 vs 0.875")
    A("- audit 层已经开始给出结构化信号：多数写入是 accepted，约 0.3-0.8 次/序列被 downgraded 为『只保留事实』，几乎不需要硬 block")
    A("")
    A("这说明当前体系已经不是『简单过滤器』，而是一个可审计、可分层、可继续扩展到回滚策略的 TAME state contamination defense architecture。")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
