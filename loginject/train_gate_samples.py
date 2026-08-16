"""Collect per-line gate training samples (text, G1 label) from harness runs."""
from __future__ import annotations

import json
import os

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loginject.memory_gate import MemoryGate
from loginject.real_dataset import build_real_dataset
from loginject.dataset import build_dataset
from loginject.harness import Harness

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "results")
OUT = os.path.join(RESULTS, "gate_training.jsonl")


def main(n_real_per: int = 4):
    gate = MemoryGate("G1")
    rows = 0
    with open(OUT, "w", encoding="utf-8") as f:
        for source, seqs in (("synthetic", build_dataset(12)),
                             ("real", build_real_dataset(n_real_per))):
            for s in seqs:
                # Use a no-LLM gate-only pass: label each line of every window.
                for w in s.windows:
                    for line in w.lines:
                        d = gate.decide(line.text, "log")
                        f.write(json.dumps({
                            "sid": s.sid, "mode": "labelgen", "window": w.idx,
                            "text": line.text, "label": int(not d.accepted),
                            "source": source,
                        }, ensure_ascii=False) + "\n")
                        rows += 1
    print(f"wrote {rows} samples to {OUT}")


if __name__ == "__main__":
    main()