"""Compute FINAL_REPORT-style summary numbers for Qwen3-14B from qwen3_* files.

Reads the same files as stage5_report_qwen3.py and prints:
  - Section-8 style rows: none/TAME DASR + BMR per dataset/mode
  - Section-9 style rows: clean miss floor, Delta, TAME recovery
Run after qwen3_frozen_benchmark.sh completes.
"""
from __future__ import annotations

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")
sys.path.insert(0, BASE)

F = {
    "syn_guard": "qwen3_guard_syn_items.jsonl",
    "real_guard": "qwen3_guard_real8_items.jsonl",
    "syn_none": "qwen3_syn_items.jsonl",
    "real_none": "qwen3_real8_none_items.jsonl",
    "real_clean_base": "qwen3_real_clean_mixed_s13_items.jsonl",
    "syn_clean_base": "qwen3_clean_syn_none_items.jsonl",
}


def load(p: str) -> list[dict]:
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def dasr(rows, mode):
    rs = [r for r in rows if r["mode"] == mode]
    return sum(r["DASR"] for r in rs) / len(rs) if rs else float("nan")


def bmr(rows, mode):
    rs = [r for r in rows if r["mode"] == mode]
    ben = sum(1 for r in rs for i in (1, 2, 3, 4) if r[f"w{i}_expected"] == "benign")
    fp = sum(1 for r in rs for i in (1, 2, 3, 4)
             if r[f"w{i}_expected"] == "benign" and r[f"w{i}_verdict"] != "benign")
    return fp / ben if ben else float("nan")


def clean_miss_floor(rows, mode):
    """Fraction of W4 windows with expected=malicious judged non-malicious on clean slices."""
    rs = [r for r in rows if r["mode"] == mode]
    tot = sum(1 for r in rs if r["w4_expected"] == "malicious")
    miss = sum(1 for r in rs
               if r["w4_expected"] == "malicious" and r["w4_verdict"] != "malicious")
    return miss / tot if tot else float("nan")


def pct(x):
    return f"{x * 100:.1f}%"


def main():
    R = {k: load(os.path.join(RES, v)) for k, v in F.items()}
    print("== Section-8 style rows (none/TAME DASR + BMR) ==")
    print(f"| Model | Dataset | Mode | none DASR | TAME DASR | none BMR | TAME BMR |")
    for ds, none, tame in (("synthetic", "syn_none", "syn_guard"),
                           ("real-104", "real_none", "real_guard")):
        for m in ("S1", "S3"):
            print(f"| Qwen3-14B (local vLLM, thinking off) | {ds} | {m} | "
                  f"{pct(dasr(R[none], m))} | {pct(dasr(R[tame], m))} | "
                  f"{pct(bmr(R[none], m))} | {pct(bmr(R[tame], m))} |")
    print()
    print("== Section-9 style rows (clean miss floor / Delta / recovery) ==")
    print(f"| Model | Dataset | Mode | clean miss floor | none DASR | TAME DASR | "
          f"Delta (attributable) | TAME recovery |")
    for ds, none, tame, clean in (("synthetic", "syn_none", "syn_guard", "syn_clean_base"),
                                  ("real", "real_none", "real_guard", "real_clean_base")):
        for m in ("S1", "S3"):
            floor = clean_miss_floor(R[clean], m)
            nd = dasr(R[none], m)
            td = dasr(R[tame], m)
            print(f"| Qwen3-14B | {ds} | {m} | {pct(floor)} | {pct(nd)} | {pct(td)} | "
                  f"{nd - floor:+.1%} | {nd - td:+.1%} |")


if __name__ == "__main__":
    main()
