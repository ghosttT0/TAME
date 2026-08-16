"""Simple bootstrap CIs + paired significance tests for benchmark results."""
from __future__ import annotations

import json
import math
import os
import random
from statistics import mean


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def group_by_sid(rows: list[dict], mode: str) -> dict[str, dict]:
    return {r["sid"]: r for r in rows if r["mode"] == mode}


def metric(r: dict, name: str) -> float:
    return float(r[name])


def bootstrap_ci(rows: list[dict], metric_name: str, iters: int = 2000, seed: int = 7) -> tuple[float, float, float]:
    rng = random.Random(seed)
    vals = [metric(r, metric_name) for r in rows]
    n = len(vals)
    boots = []
    for _ in range(iters):
        sample = [vals[rng.randrange(n)] for _ in range(n)]
        boots.append(sum(sample) / n)
    boots.sort()
    lo = boots[int(0.025 * len(boots))]
    hi = boots[int(0.975 * len(boots))]
    return (sum(vals) / n, lo, hi)


def paired_sign_test(rows_a: list[dict], rows_b: list[dict], mode: str, metric_name: str) -> dict:
    a = group_by_sid(rows_a, mode)
    b = group_by_sid(rows_b, mode)
    sids = sorted(set(a) & set(b))
    pos = neg = ties = 0
    for sid in sids:
        da = metric(a[sid], metric_name)
        db = metric(b[sid], metric_name)
        if da < db:
            pos += 1
        elif da > db:
            neg += 1
        else:
            ties += 1
    n = pos + neg
    # two-sided sign test p-value by exact binomial tail
    def comb(n, k):
        from math import comb as _c
        return _c(n, k)
    p = 0.0
    if n:
        tail = min(pos, neg)
        for k in range(0, tail + 1):
            p += comb(n, k) * (0.5 ** n)
        p *= 2
        p = min(1.0, p)
    return {"pos": pos, "neg": neg, "ties": ties, "p_value": p}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("file_a")
    p.add_argument("file_b")
    p.add_argument("--mode", default="S1")
    p.add_argument("--metric", default="DASR")
    a = p.parse_args()
    rows_a = load(a.file_a)
    rows_b = load(a.file_b)
    print(paired_sign_test(rows_a, rows_b, a.mode, a.metric))
