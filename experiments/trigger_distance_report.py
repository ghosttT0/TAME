"""Trigger-distance analysis report."""
from __future__ import annotations

import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")
OUT = os.path.join(RES, "TRIGGER_DISTANCE_REPORT.md")


def load(p: str) -> list[dict]:
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def dasr(rows, mode):
    rs = [r for r in rows if r["mode"] == mode]
    return sum(r["DASR"] for r in rs) / len(rs) if rs else float("nan")


def main():
    L = []
    A = L.append
    A("# Trigger Distance Report")
    A("")
    A("Trigger remains fixed at W4. Payload is planted in W1/W2/W3, corresponding to"
      " trigger distances 3/2/1 respectively.")
    A("")
    A("## Synthetic")
    A("")
    A("| distance | inject_window | S1 none | S1 TAME | S3 none | S3 TAME |")
    A("|---|---:|---:|---:|---:|---:|")
    for w in (1, 2, 3):
        none = load(os.path.join(RES, f"distance_syn_w{w}_none.jsonl"))
        tame = load(os.path.join(RES, f"distance_syn_w{w}_tame.jsonl"))
        dist = 4 - w
        A(f"| {dist} | W{w} | {pct(dasr(none, 'S1'))} | {pct(dasr(tame, 'S1'))} | {pct(dasr(none, 'S3'))} | {pct(dasr(tame, 'S3'))} |")
    A("")
    A("Interpretation: if DASR rises with larger distance, the benchmark is measuring"
      " persistent state pollution rather than immediate prompt-following only. If TAME's"
      " gap widens at larger distance, that supports the claim that facts-only memory is"
      " especially useful against long-range contamination.")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
