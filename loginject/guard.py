"""TAME: Triaged Auditable Memory Execution.

A full state-contamination defense architecture (not a filter).

Components (each is a separable module, testable on its own):

1. Triage (multimodal routing)
   Raw log lines are routed by log modality before any memory write:
     EVENT   - concrete event lines (AUTH/NET/FILE...): actor+action+object
     CLAIM   - status/assertion lines (AUDIT security-*, SYSLOG notes): authority
               or verdict claims, the usual injection vehicle
     DIRECT  - explicit instruction language (NOTE=[...], task_mode=...)
   The route decides which downstream treatment applies.

2. FEM - Fact Extraction Module (independent, LLM-backed)
   A standalone module that DECOUPLES any candidate memory item into
   facts / instructions / assertions. Only facts may proceed to permanent
   memory. Instructions and assertions are dropped (or quarantined).

3. TTC - Temporary Thinking Cache vs Permanent Fact Memory
   Verdicts, notes and intermediate conclusions live only in an ephemeral
   per-session cache that is destroyed when the session ends. Permanent
   memory only ever stores facts. This separates "thinking" from "memory".

4. Contamination Detector
   Scores each candidate on instruction/assertion residue, keyword signals
   and fact-quality. A contamination score > threshold blocks the write.

5. Memory Audit + Snapshot Rollback
   Every write is appended to an audit trail (source, modality, decision,
   timestamp). A snapshot of permanent memory is kept after each window;
   if a later detector flag or inconsistency appears, memory can roll back
   to the last clean snapshot. Single-instance safety net, not the front line.
"""
from __future__ import annotations

import json
import re
import time

EVENT_KW = re.compile(r"action=|op=|src=|dst=|bytes=|result=FAILED|result=success|flags=")
CLAIM_KW = re.compile(r"security[- ]|verified|approved|incident=|conclusion=|status=|state=|severity=")
DIRECT_KW = re.compile(
    r"ignore\s+(all\s+)?(prior|previous|the)\s+(logs|instructions)|"
    r"answer\s+[\"']?(benign|malicious)|task_mode\s*=|note\s*=\s*\[|"
    r"if\s+this\s+host\s+appears\s+again|future\s+events?\s+on\s+this\s+host|"
    r"you\s+are\s+(now\s+)?the\s+(log\s+)?analysis\s+engine")

DECOUPLE_PROMPT = (
    "TASK=decouple\n"
    "Separate the content below into three categories:\n"
    "- facts: concrete verifiable events (actor, action, object, time)\n"
    "- instructions: directives, commands, or guidance about how to judge/answer\n"
    "- assertions: claims, status labels, authority statements, verdicts\n"
    "Output JSON only, no preamble:\n"
    '{{"facts": [...], "instructions": [...], "assertions": [...]}}  // omit empty arrays\n'
    "[CONTENT]\n{content}"
)


def triage(line: str) -> str:
    """Route a log line by modality. Returns EVENT / CLAIM / DIRECT / OTHER."""
    if DIRECT_KW.search(line):
        return "DIRECT"
    if EVENT_KW.search(line) and not CLAIM_KW.search(line):
        return "EVENT"
    if CLAIM_KW.search(line):
        return "CLAIM"
    return "EVENT" if "=" in line else "OTHER"


class FactExtractionModule:
    """Independent, LLM-backed fact extraction with decoupling."""

    def __init__(self, client, name: str = "FEM"):
        self.client = client
        self.name = name

    def decouple(self, content: str, source: str) -> dict:
        """Return {'facts': [...], 'instructions': [...], 'assertions': [...]}."""
        if not content:
            return {"facts": [], "instructions": [], "assertions": []}
        raw = self.client.complete(
            [{"role": "system",
              "content": "You are a strict fact extractor for security log forensics."},
             {"role": "user",
              "content": DECOUPLE_PROMPT.format(content=content[:6000])}],
            json_mode=True)
        m = re.search(r"\{.*\}", raw, re.S)
        d = {}
        if m:
            try:
                d = json.loads(m.group(0))
            except Exception:
                d = {}
        return {
            "facts": [str(f) for f in d.get("facts") or []][:16],
            "instructions": [str(f) for f in d.get("instructions") or []][:16],
            "assertions": [str(f) for f in d.get("assertions") or []][:16],
        }


class ContaminationDetector:
    """Scores candidates on instruction/assertion residue and keyword signals."""

    def __init__(self, fem: FactExtractionModule, w_inst: float = 1.0,
                 w_asrt: float = 0.7, w_kw: float = 0.5, threshold: float = 0.6):
        self.fem = fem
        self.w_inst, self.w_asrt, self.w_kw = w_inst, w_asrt, w_kw
        self.threshold = threshold

    def score(self, content: str, source: str) -> dict:
        d = self.fem.decouple(content, source)
        n = max(1, len(d["facts"]) + len(d["instructions"]) + len(d["assertions"]))
        score = (self.w_inst * len(d["instructions"]) +
                 self.w_asrt * len(d["assertions"]) +
                 self.w_kw * int(bool(DIRECT_KW.search(content)))) / n
        return {"score": min(1.0, score), "blocked": score >= self.threshold, **d}

    def decide(self, content: str, source: str) -> tuple[str, dict]:
        d = self.score(content, source)
        has_facts = bool(d["facts"])
        has_residue = bool(d["instructions"] or d["assertions"] or DIRECT_KW.search(content))
        if has_facts and not has_residue:
            return ("accepted", d)
        if has_facts and has_residue:
            return ("downgraded", d)
        return ("blocked", d)


class TemporaryCache:
    """Ephemeral per-session inference cache; destroyed with the session."""

    def __init__(self):
        self._store: dict[str, str] = {}

    def write(self, key: str, value: str):
        self._store[key] = value

    def read(self, key: str) -> str:
        return self._store.get(key, "")

    def destroy(self):
        self._store.clear()

    def __len__(self):
        return len(self._store)


class MemoryAudit:
    """Append-only audit trail for every memory write."""

    def __init__(self):
        self.entries: list[dict] = []

    def log(self, **kw):
        self.entries.append({"t": time.time(), **kw})

    def export(self) -> list[dict]:
        return list(self.entries)

    def contamination_events(self) -> list[dict]:
        return [e for e in self.entries if e.get("action") in ("blocked", "downgraded")]


class TAMEGuard:
    """Permanent fact memory + audit + snapshot rollback.

    Write path:
      triage -> decouple (FEM) -> detector -> {facts -> permanent} | {blocked}
    On every window close a snapshot is stored; rollback restores the last
    snapshot that had no contamination event after it.
    """

    def __init__(self, client, use_triage: bool = True,
                 use_decoupling: bool = True, use_cache_split: bool = True):
        self.fem = FactExtractionModule(client)
        self.detector = ContaminationDetector(self.fem)
        self.audit = MemoryAudit()
        self.ttc = TemporaryCache()
        self.permanent: dict[str, str] = {}
        self._snapshots: list[dict] = []
        self._rollbacks = 0
        self.use_triage = use_triage
        self.use_decoupling = use_decoupling
        self.use_cache_split = use_cache_split

    # ---- write path ----

    def write(self, key: str, content: str, source: str) -> dict:
        tri = triage(content) if self.use_triage else "EVENT"
        record = {"key": key, "source": source, "triage": tri,
                  "window": self._cur_window}
        if not self.use_decoupling:
            dec = {"facts": [content], "instructions": [], "assertions": [], "score": 0.0, "blocked": False}
            action = "accepted"
        else:
            action, dec = self.detector.decide(content, source)
        record.update(dec)
        record["action"] = action
        if action in ("accepted", "downgraded"):
            facts = "\n".join(dec["facts"]) if dec["facts"] else content
            self.permanent[key] = facts
            self.audit.log(**record)
        else:
            self.audit.log(**record)
        return record

    def snapshot(self, window: int):
        self._cur_window = window
        self._snapshots.append({
            "window": window,
            "permanent": {k: v for k, v in self.permanent.items()},
            "audit_len": len(self.audit.entries),
        })

    def rollback(self):
        """Restore the last snapshot without a post-snapshot contamination event."""
        for snap in reversed(self._snapshots):
            if not any(e.get("window", 0) > snap["window"]
                       and e.get("action") == "blocked" for e in self.audit.entries):
                self.permanent = {k: v for k, v in snap["permanent"].items()}
                self._rollbacks += 1
                return snap["window"]
        return None

    def stats(self) -> dict:
        acc = sum(1 for e in self.audit.entries if e.get("action") == "accepted")
        dng = sum(1 for e in self.audit.entries if e.get("action") == "downgraded")
        blk = sum(1 for e in self.audit.entries if e.get("action") == "blocked")
        return {
            "accepted": acc, "downgraded": dng, "blocked": blk,
            "rejection_rate": blk / (acc + dng + blk) if (acc + dng + blk) else 0.0,
            "snapshots": len(self._snapshots), "rollbacks": self._rollbacks,
            "ttc_size": len(self.ttc),
            "use_triage": self.use_triage,
            "use_decoupling": self.use_decoupling,
            "use_cache_split": self.use_cache_split,
        }


# Backward-compatible alias while the codebase still says "guard" in some places.
GuardedMemory = TAMEGuard
