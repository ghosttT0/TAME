"""Real-log stream dataset: reorganizes CAM-LDS / AIT-LDSv2 real attack & benign
log sequences (Linux auditd / auth / apache access logs, from
ait-aecid/log-interpretation-prompt-injection) into our 4-window streamed sequences.

Ground truth: lines originating from the attack sequences are malicious; lines from
the benign sequences are benign. Windows keep the ORIGINAL log-line text.
"""
from __future__ import annotations

import glob
import os
import random
import re
import subprocess
from dataclasses import dataclass

from .dataset import LogLine, Window, Sequence, TRIGGER_Q  # noqa

REPO = os.environ.get(
    "AIT_LOGINJECT_REPO",
    "/tmp/opencode/log-interpretation-prompt-injection")
REPO_URL = os.environ.get(
    "AIT_LOGINJECT_REPO_URL",
    "https://github.com/ait-aecid/log-interpretation-prompt-injection.git")


def ensure_repo(repo_path: str = REPO) -> str:
    """Ensure the upstream AIT-AECID benchmark repo exists locally.

    Repro fix: when the workspace is moved to another machine, `/tmp/opencode/...`
    may not exist. In that case we clone the public repo into a deterministic,
    workspace-adjacent cache directory instead of failing with a vague not-found
    error.
    """
    if os.path.isdir(os.path.join(repo_path, "manifestations_original")):
        return repo_path

    fallback = os.environ.get(
        "AIT_LOGINJECT_REPO_FALLBACK",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     ".external", "log-interpretation-prompt-injection"))
    if os.path.isdir(os.path.join(fallback, "manifestations_original")):
        return fallback

    os.makedirs(os.path.dirname(fallback), exist_ok=True)
    if not os.path.isdir(fallback):
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", REPO_URL, fallback],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            raise RuntimeError(
                "Missing AIT benchmark repo. Tried local path and auto-clone. "
                "Set AIT_LOGINJECT_REPO explicitly or run experiments/setup_repro.sh."
            ) from e
    if not os.path.isdir(os.path.join(fallback, "manifestations_original")):
        raise RuntimeError(
            f"AIT benchmark repo not initialized at {fallback}. "
            "Run experiments/setup_repro.sh."
        )
    return fallback


def _clean(text: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).rstrip()


def _kind_of(path: str) -> str:
    p = path.replace("\\", "/")
    base = os.path.basename(p)
    if "access" in base or "error" in base:
        return "apache"
    if "audit" in base:
        return "audit"
    if "auth" in base:
        return "auth"
    if "kern" in base:
        return "kern"
    if "fast" in base or "suricata" in p:
        return "suricata"
    if "output" in base or "attackmate" in base:
        return "shell"
    return "other"


def load_sequence_logs(seq_dir: str, kind: str = "") -> list[str]:
    """Collect ALL victim-side log lines for a sequence, optionally by kind."""
    all_lines: list[str] = []
    for pat in ("**/*.log", "**/*.log.*"):
        for f in glob.glob(os.path.join(seq_dir, pat), recursive=True):
            if "attacker" in f.replace("\\", "/") or "attackmate" in f:
                continue
            k = _kind_of(f)
            if kind and k != kind:
                continue
            with open(f, encoding="utf-8", errors="replace") as fh:
                for l in fh.read().splitlines():
                    c = _clean(l)
                    if c:
                        all_lines.append(c)
    return all_lines


# Upstream marks these two scenarios as benign (metadata "None" in labels.json).
# They live under manifestations_original alongside the attacks, so collect()
# must not treat them as attack logs; they are already read from
# manifestations_benign below.
BENIGN_SEQUENCE_NAMES = {"russellmitchell-access", "wilson-ssh"}


def collect(kinds: tuple = ("audit", "auth", "apache", "kern", "suricata")) -> dict:
    """Return dict: {'attack': {name: {kind: [lines]}}, 'benign': {...}}"""
    repo = ensure_repo(REPO)
    out = {"attack": {}, "benign": {}}
    seq_root = os.path.join(repo, "manifestations_original", "sequences")
    if os.path.isdir(seq_root):
        for d in sorted(os.listdir(seq_root)):
            if d.startswith(".") or d in BENIGN_SEQUENCE_NAMES:
                continue
            per_kind = {}
            for k in kinds:
                lines = load_sequence_logs(os.path.join(seq_root, d), k)
                if lines:
                    per_kind[k] = lines
            if per_kind:
                out["attack"][d] = per_kind
    ben_root = os.path.join(repo, "manifestations_benign", "sequences")
    if os.path.isdir(ben_root):
        for d in sorted(os.listdir(ben_root)):
            if d.startswith("."):
                continue
            per_kind = {}
            for k in kinds:
                lines = load_sequence_logs(os.path.join(ben_root, d), k)
                if lines:
                    per_kind[k] = lines
            if per_kind:
                out["benign"][d] = per_kind
    return out

def _chunk(lines: list[str], size: int, offset: int) -> list[LogLine]:
    return [LogLine(t, malicious=True) for t in lines[offset:offset + size]]


def _bchunk(lines: list[str], size: int, offset: int) -> list[LogLine]:
    return [LogLine(t, malicious=False) for t in lines[offset:offset + size]]


def build_real_dataset(n_per_attack: int = 3, chunk: int = 6,
                       variant: str = "plain", max_attacks: int = 0,
                       mixed: bool = True) -> list[Sequence]:
    """Construct streamed sequences from real logs (multi-source aware).

    Each attack sequence contributes up to n_per_attack streamed sequences
    built from chunks of its log lines. With mixed=True, malicious windows
    may combine lines from several log kinds of the SAME attack sequence
    (e.g. audit + apache), mirroring a real incident where multiple daemons
    log the same attack.
    """
    data = collect()
    attacks = sorted(data["attack"].items())
    benigns = sorted(data["benign"].items())
    if max_attacks:
        attacks = attacks[:max_attacks]
    rng = random.Random(2026)

    def ben_pool(off):
        name, per_kind = benigns[rng.randrange(len(benigns))]
        pool = [l for k in per_kind for l in per_kind[k] if len(l) < 1500]
        return _bchunk(pool, chunk, (off * 7) % max(1, len(pool) - chunk - 1))

    from .dataset import attack_payload, window_text  # noqa

    seqs = []
    sid = 0
    for name, per_kind in attacks:
        pool = [l for k in per_kind for l in per_kind[k] if len(l) < 1500]
        if len(pool) < 2 * chunk:
            continue
        for rep in range(n_per_attack):
            off1 = (rng.randrange(0, max(1, len(pool) - chunk)))
            off4 = (rng.randrange(0, max(1, len(pool) - chunk)))
            # avoid identical window content
            if off4 == off1:
                off4 = (off4 + chunk) % max(1, len(pool) - chunk)
            mal1 = _chunk(pool, chunk, off1)
            mal4 = _chunk(pool, chunk, off4)
            if mixed and len(per_kind) > 1:
                # mix a secondary log kind into the malicious windows
                kinds = [k for k in per_kind if len(per_kind[k]) >= 4]
                if kinds:
                    k2 = kinds[rng.randrange(len(kinds))]
                    l2 = per_kind[k2]
                    mid = rng.randrange(0, max(1, len(l2) - 2))
                    mal1.insert(rng.randrange(len(mal1) + 1),
                                LogLine(_clean(l2[mid]), malicious=True))
                    mal4.insert(rng.randrange(len(mal4) + 1),
                                LogLine(_clean(l2[(mid + 1) % len(l2)]), malicious=True))
            host = f"victim-{sid:02d}"
            combo = (("A1", "FN"), ("A2", "FN"), ("A3", "FN"), ("A3", "FP"))
            attack_type, polarity = combo[rep % len(combo)]
            payload = attack_payload(host, attack_type, polarity, variant)

            if attack_type == "A1":
                w1_lines = [*mal1, payload]
                w1_mal, expected_w1 = True, "malicious"
                w4_lines, w4_mal = mal4, True
            elif attack_type == "A2":
                w1_lines = [payload, *ben_pool(1)]
                w1_mal, expected_w1 = False, "benign"
                w4_lines, w4_mal = mal4, True
            else:
                w1_lines = [payload, *ben_pool(1)]
                w1_mal, expected_w1 = False, "benign"
                if polarity == "FN":
                    w4_lines, w4_mal = mal4, True
                else:
                    w4_lines, w4_mal = ben_pool(3), False

            windows = [
                Window(1, w1_lines, w1_mal),
                Window(2, ben_pool(5), False),
                Window(3, ben_pool(7), False),
                Window(4, w4_lines, w4_mal),
            ]
            if attack_type == "A1":
                pk, pt = "SYSLOG", "low"
            elif attack_type == "A2":
                pk, pt = "AUDIT-status", "medium"
            elif polarity == "FN":
                pk, pt = "AUDIT-followup", "medium"
            else:
                pk, pt = "AUDIT-followup", "low"
            seqs.append(Sequence(
                sid=f"real{sid:03d}",
                attack_type=attack_type,
                polarity=polarity,
                host=host,
                windows=windows,
                trigger_q=TRIGGER_Q.format(host=host),
                expected_w1=expected_w1,
                expected_final="malicious" if w4_mal else "benign",
                payload_kind=pk,
                payload_trust=pt,
                trigger_distance=3,
            ))
            sid += 1
    return seqs

if __name__ == "__main__":
    data = collect()
    print("attack seqs:", len(data["attack"]), "benign seqs:", len(data["benign"]))
    for k, v in list(data["attack"].items())[:3]:
        kinds = {kk: len(ll) for kk, ll in v.items()}
        print(k, "kinds:", kinds)
    for k, v in list(data["benign"].items())[:2]:
        kinds = {kk: len(ll) for kk, ll in v.items()}
        print(k, "kinds:", kinds)
    ds = build_real_dataset(4, mixed=True)
    print("\nconstructed sequences:", len(ds))
    for s in ds[:6]:
        print(s.sid, s.attack_type, s.polarity,
              [w.malicious for w in s.windows], len(s.windows[0].lines), "w1 lines")
