"""Learned memory gate: distills the rule-based G1 decisions into a lightweight
classifier that can generalize across log formats (synthetic -> real audit logs).

Supervision: G1 rule verdicts per candidate state item (log line or summary text).
Features: char n-gram TF-IDF + hand-crafted signal features.
Model: L1-regularized logistic regression (train 60% / test 40% by sequence id).
"""
from __future__ import annotations

import json
import os
import re

import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.pipeline import make_pipeline

from .memory_gate import RISK_RE

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(BASE, "results")

MANUAL_FEATURES = (
    "answer", "benign", "malicious", "ignore", "instructions", "confirmed",
    "clean", "approved", "verified", "incident", "simulation", "note",
    "noreply", "priority", "urgent", "system", "override", "quarantine",
    "future", "again", "header", "end of", "begin", "://", "warning",
    "error", "audit", "authentication", "login", "password",
)

META_WORDS = ("you", "ignore", "answer", "do not", "please", "must",
              "never", "always", "confirm", "instruct", "your task")


def features(text: str) -> list[float]:
    t = text.lower()
    out = []
    for w in MANUAL_FEATURES:
        out.append(float(w in t))
    out.append(float(len(text)))
    out.append(float(sum(1 for w in META_WORDS if w in t)))
    hits = RISK_RE.findall(t)
    out.append(float(len(hits)))
    return out


class LearnedGate:
    """Trained on (text, label) pairs from G1; exposes decide() like MemoryGate."""

    def __init__(self, model_path: str | None = None):
        self.pipeline = make_pipeline(
            TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                            max_features=20000, sublinear_tf=True),
            LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced"),
        )
        self.manual = None  # optional manual-feature model (kept simple: pipeline only)
        self.accepted = 0
        self.rejected = 0
        if model_path and os.path.exists(model_path):
            self.load(model_path)

    def fit(self, texts: list[str], labels: list[int]):
        self.pipeline.fit(texts, labels)
        return self

    def predict(self, texts: list[str]) -> list[int]:
        return list(self.pipeline.predict(texts))

    def predict_proba(self, texts: list[str]) -> list[float]:
        return [float(p) for p in self.pipeline.predict_proba(texts)[:, 1]]

    def decide(self, text: str, source: str = "log") -> object:
        from .memory_gate import GateDecision
        if not text:
            self.accepted += 1
            return GateDecision(True, text, 1.0, "empty")
        p = self.predict_proba([text])[0]
        if p >= 0.5:
            self.rejected += 1
            return GateDecision(False, "", p, f"learned p(reject)={p:.2f}")
        self.accepted += 1
        return GateDecision(True, text, 1 - p, f"learned p(reject)={p:.2f}")

    def filter_lines(self, text: str, source: str = "log") -> tuple[str, list[dict]]:
        decisions = []
        kept = []
        for line in text.splitlines():
            if not line.strip():
                continue
            d = self.decide(line, source)
            decisions.append({"accepted": d.accepted, "confidence": d.confidence,
                              "reason": d.reason, "source": source})
            if d.accepted:
                kept.append(line)
        return "\n".join(kept), decisions

    def filter_state(self, text: str, source: str) -> tuple[str, list[dict]]:
        if source == "log":
            return self.filter_lines(text, source)
        d = self.decide(text, source)
        record = [{"accepted": d.accepted, "confidence": d.confidence,
                   "reason": d.reason, "source": source}]
        return (text if d.accepted else ""), record

    def stats(self) -> dict:
        total = self.accepted + self.rejected
        return {"name": "learned", "accepted": self.accepted, "rejected": self.rejected,
                "rejection_rate": self.rejected / total if total else 0.0}

    def save(self, path: str):
        import joblib
        joblib.dump(self.pipeline, path)

    def load(self, path: str):
        import joblib
        self.pipeline = joblib.load(path)
        self.accepted = self.rejected = 0


def collect_g1_labels() -> tuple[list[str], list[int], list[dict]]:
    """Collect (text, G1 label) pairs from completed G1 run: per-line decisions were
    logged in gate_g1_items.jsonl (wN_gate_decisions)."""
    path = os.path.join(RESULTS, "gate_g1_items.jsonl")
    texts: list[str] = []
    labels: list[int] = []
    meta: list[dict] = []
    import gzip
    if not os.path.exists(path):
        return texts, labels, meta
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            for i in (1, 2, 3, 4):
                dec = r.get(f"w{i}_gate_decisions") or []
                for d in dec:
                    # we only stored decisions, recover text? -> store text in run_all
                    pass
    return texts, labels, meta


class DatasetWriter:
    """Helper to persist gate training samples from harness runs."""

    @staticmethod
    def append(path: str, sid: str, mode: str, window: int,
               text: str, label: int, source: str):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "sid": sid, "mode": mode, "window": window,
                "text": text, "label": label, "source": source,
            }, ensure_ascii=False) + "\n")


def default_train_test_split(items: list[dict], frac: float = 0.6):
    """Stratify by sequence id prefix so no overlap leaks across sequences."""
    import random
    rng = random.Random(42)
    sids = sorted({it["sid"] for it in items})
    rng.shuffle(sids)
    k = max(1, int(len(sids) * frac))
    train_sids = set(sids[:k])
    train = [it for it in items if it["sid"] in train_sids]
    test = [it for it in items if it["sid"] not in train_sids]
    return train, test


def evaluate_gate(gate: "LearnedGate", texts_test: list[str],
                  labels_test: list[int]) -> dict:
    pred = gate.predict(texts_test)
    return {
        "n": len(texts_test),
        "precision": precision_score(labels_test, pred, zero_division=0),
        "recall": recall_score(labels_test, pred, zero_division=0),
        "f1": f1_score(labels_test, pred, zero_division=0),
        "reject_rate": float(np.mean(pred)),
    }


def main():
    from .real_dataset import collect as collect_real  # noqa
    from .memory_gate import MemoryGate
    import random

    path = os.path.join(RESULTS, "gate_training.jsonl")
    if not os.path.exists(path):
        print("training data not found; run train_gate_samples first")
        return
    items = [json.loads(l) for l in open(path, encoding="utf-8")]
    texts = [it["text"] for it in items]
    labels = [int(it["label"]) for it in items]
    train, test = default_train_test_split(items)
    g = LearnedGate().fit([t["text"] for t in train], [int(t["label"]) for t in train])
    scores = evaluate_gate(g, [t["text"] for t in test], [int(t["label"]) for t in test])
    print("learned gate (distilled from G1):", scores)
    return g


if __name__ == "__main__":
    main()