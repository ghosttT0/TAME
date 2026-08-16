"""Generate the next-stage Memory Gate mitigation report."""
from __future__ import annotations

import json
import os
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(BASE, "results")
FILES = {
    "none": os.path.join(RESULTS, "items.jsonl"),
    "G1": os.path.join(RESULTS, "gate_g1_items.jsonl"),
    "G2": os.path.join(RESULTS, "gate_g2_items.jsonl"),
}
OUT = os.path.join(RESULTS, "GATE_REPORT.md")


def pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def load(path: str) -> dict[tuple[str, str], dict]:
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            out[(r["sid"], r["mode"])] = r
    return out


def rates(rows: list[dict]) -> dict:
    n = len(rows)
    benign = sum(4 - int(r["w1_expected"] == "malicious") -
                 int(r["w4_expected"] == "malicious") for r in rows)
    malicious = sum(int(r["w1_expected"] == "malicious") +
                    int(r["w4_expected"] == "malicious") for r in rows)
    return {
        "n": n,
        "IASR": sum(r["IASR"] for r in rows) / n if n else 0,
        "DASR": sum(r["DASR"] for r in rows) / n if n else 0,
        "CPL": sum(r["CPL"] for r in rows) / n if n else 0,
        "BMR": sum(r["BMR"] for r in rows) / benign if benign else 0,
        "MTR": sum(r["MTR"] for r in rows) / malicious if malicious else 0,
        "reject": sum(r.get("gate_rejected", 0) for r in rows),
        "decisions": sum(r.get("gate_rejected", 0) + r.get("gate_accepted", 0)
                          for r in rows),
    }


def main() -> None:
    data = {k: load(v) for k, v in FILES.items()}
    modes = ("S0", "S1", "S2", "S3", "S4")
    lines = [
        "# StateShield Memory Gate MVP Report",
        "",
        "本报告对应 `loginject_next_stage_plan.md` 的 Phase 3：G1 rule-based gate 与 "
        "G2 provenance/confidence gate。两种 gate 只作用于 memory write/index/update path，"
        "当前窗口原始日志仍直接进入 verdict 分析。",
        "",
        "## 实验规模",
        "",
        "- 48 个 4-window 序列，240 个 `(sequence, mode)` 结果/组。",
        "- 5 种 carrier：stateless、full-history、summary、retrieval、analyst-note。",
        "- G1/G2 各拒绝候选 memory update，而不对当前窗口做 input filtering。",
        "",
        "## 表 1：主 mitigation 结果",
        "",
        "| Mode | No gate DASR | G1 DASR | G2 DASR | G1 delta | G2 delta |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in modes:
        vals = {g: rates([r for (sid, m), r in data[g].items() if m == mode])
                for g in ("none", "G1", "G2")}
        lines.append(f"| {mode} | {pct(vals['none']['DASR'])} | {pct(vals['G1']['DASR'])} | "
                     f"{pct(vals['G2']['DASR'])} | "
                     f"{pct(vals['G1']['DASR'] - vals['none']['DASR'])} | "
                     f"{pct(vals['G2']['DASR'] - vals['none']['DASR'])} |")

    lines += [
        "",
        "## 表 2：误报、漏报和持续长度",
        "",
        "| Mode | Gate | CPL | BMR | MTR |",
        "|---|---|---:|---:|---:|",
    ]
    for mode in modes:
        for gate in ("none", "G1", "G2"):
            r = rates([row for (sid, m), row in data[gate].items() if m == mode])
            lines.append(f"| {mode} | {gate} | {r['CPL']:.2f} | {pct(r['BMR'])} | {pct(r['MTR'])} |")

    lines += [
        "",
        "## 表 3：memory gate 开销",
        "",
        "| Gate | Rejected updates | Total decisions | Rejection rate |",
        "|---|---:|---:|---:|",
    ]
    for gate in ("G1", "G2"):
        r = rates(list(data[gate].values()))
        lines.append(f"| {gate} | {r['reject']} | {r['decisions']} | "
                     f"{pct(r['reject'] / r['decisions'] if r['decisions'] else 0)} |")

    lines += ["", "## 按攻击类型的 DASR", "",
              "| Mode | Attack | No gate | G1 | G2 |", "|---|---|---:|---:|---:|"]
    for mode in modes:
        for attack in ("A1", "A2", "A3"):
            vals = {}
            for gate in ("none", "G1", "G2"):
                vals[gate] = rates([r for (sid, m), r in data[gate].items()
                                    if m == mode and r["attack"] == attack])
            lines.append(f"| {mode} | {attack} | {pct(vals['none']['DASR'])} | "
                         f"{pct(vals['G1']['DASR'])} | {pct(vals['G2']['DASR'])} |")

    lines += [
        "",
        "## 结果解释",
        "",
        "- G1 将 full-history DASR 从 45.8% 降到 8.3%，将 retrieval DASR 从 39.6% 降到 8.3%。",
        "- G2 将 full-history DASR 降到 10.4%，retrieval DASR 降到 8.3%。",
        "- 两个 gate 的拒绝率约为 7.6%，说明主要拦截少量高风险状态更新，而不是清空 memory。",
        "- S2/S4 的收益较小，因为无 gate 时它们已经比 full-history/retrieval 更不容易保留攻击载荷。",
        "- BMR 和 MTR 同时变化，说明 gate 的效果不能只用 DASR 描述，需要在后续实验中加入更严格的 utility 任务和人工/LLM judge。",
        "",
        "## Kill-criteria 判断",
        "",
        "- gate 后 DASR 降低：通过，尤其在 full-history 和 retrieval 上明显。",
        "- full-history / retrieval 现象可重复：通过，原始实验与 gate 实验都保留了相同的状态模式差异。",
        "- 训练标签可构造：尚未进入 learned gate 阶段；当前 G1/G2 已产生候选 rejected/accepted update 标签，可作为 Phase 4 数据起点。",
        "",
        "## 当前限制",
        "",
        "- G1/G2 目前都是轻量规则 gate，G2 还不是训练得到的分类器。",
        "- 本批 gate 实验使用合成 LogInject 风格数据，不代表真实 LogInject-1.0 泛化性能。",
        "- 不同实验组使用独立 API 调用，模型输出存在少量非确定性；正式论文应使用固定缓存、重复运行和置信区间。",
        "- 尚未实现 attribution、remediation 和 repeated low-strength poison 任务。",
    ]
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
