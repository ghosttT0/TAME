"""Stage-3 adversarial variants: paraphrase / indirect / low-key / retr-friendly.

Runs the strongest state carriers (S1 full-history, S3 retrieval) under
none / G1 / G3 with n_per_type sequences per attack-polarity combo.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from experiments.run_all import main as run_main

VARIANTS = ("paraphrase", "indirect", "low-key", "retrfriendly")
MODES = ("S1", "S3")
GATES = ("none", "G1", "G3")
N = 6


def run_variant(variant: str):
    for gate in GATES:
        out = os.path.join("results", f"var_{variant}_{gate}.jsonl")
        print(f"[variant] {variant} gate={gate}", flush=True)
        method = "G3" if gate == "G3" else "none"
        run_main(N, workers=5, gate="none" if gate in ("none", "G3") else "G1",
                 output=out, modes=list(MODES), variant=variant, method=method)


if __name__ == "__main__":
    for v in VARIANTS:
        run_variant(v)
    print("all variants done")