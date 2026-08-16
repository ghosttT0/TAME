"""Full pipeline orchestration: build dataset, run all (mode, seq) jobs with
concurrency, incremental on-disk results, resumable. Usage: python3 -m experiments.run_all"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loginject.dataset import build_dataset
from loginject.harness import Harness
from loginject.llm import LLMClient, MockClient
from loginject.eval import eval_sequence

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ROOT, "..", "results")
ITEMS = os.path.join(RESULTS, "items.jsonl")
CACHE = os.path.join(RESULTS, "llm_cache.json")

MODES = ["S0", "S1", "S2", "S3", "S4"]


def job_key(sid: str, mode: str, gate: str = "none", method: str = "none") -> str:
    return f"{sid}|{mode}|{gate}|{method}"


def load_done(items_path: str) -> set:
    done = set()
    if os.path.exists(items_path):
        for line in open(items_path, encoding="utf-8"):
            try:
                d = json.loads(line)
                done.add(job_key(d["sid"], d["mode"], d.get("gate", "none"),
                                 d.get("method", "none")))
            except Exception:
                pass
    return done


def load_state(items_path: str) -> tuple[set, set]:
    """Return (done_clean, done_unknown): split finished jobs by whether any
    window verdict is 'unknown' (parse/timeout failure)."""
    clean, unknown = set(), set()
    if os.path.exists(items_path):
        for line in open(items_path, encoding="utf-8"):
            try:
                d = json.loads(line)
                key = job_key(d["sid"], d["mode"], d.get("gate", "none"),
                              d.get("method", "none"))
                if any(d.get(f"w{i}_verdict") == "unknown" for i in (1, 2, 3, 4)):
                    unknown.add(key)
                else:
                    clean.add(key)
            except Exception:
                pass
    return clean, unknown


def dedup(items_path: str):
    """Keep the last written row per job_key (new result wins over stale unknown)."""
    if not os.path.exists(items_path):
        return
    order, last = [], {}
    with open(items_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                key = job_key(d["sid"], d["mode"], d.get("gate", "none"),
                              d.get("method", "none"))
            except Exception:
                continue
            if key not in last:
                order.append(key)
            last[key] = line
    with open(items_path, "w", encoding="utf-8") as f:
        for key in order:
            f.write(last[key] + "\n")


def append(item: dict, items_path: str):
    with open(items_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def main(n_per_type: int = 12, mock: bool = False, workers: int = 4,
         retr_topk: int = 3, summary_len: str = "64-token", gate: str = "none",
         output: str = ITEMS, dataset: str = "synthetic", modes: list[str] | None = None,
         gate_model: str | None = None, variant: str = "plain", clean: bool = False,
         method: str = "none", task: str = "verdict", guard: bool = False,
         tame_triage: bool = True, tame_decoupling: bool = True,
         tame_cache_split: bool = True, inject_window: int = 1,
         reasoning_effort: str | None = None, redo_unknown: bool = False):
    os.makedirs(RESULTS, exist_ok=True)
    if dataset == "real":
        from loginject.real_dataset import build_real_dataset as _brd
        from loginject.dataset import clean_sequence
        ds = _brd(n_per_type, variant=variant)
    else:
        from loginject.dataset import build_dataset, build_distance_dataset, clean_sequence
        if inject_window == 1:
            ds = build_dataset(n_per_type, variant=variant, task=task)
        else:
            ds = build_distance_dataset(n_per_type, variant=variant, task=task,
                                        inject_window=inject_window)
    if clean:
        ds = [clean_sequence(s) for s in ds]
    print(f"[dataset] {len(ds)} sequences ({dataset} variant={variant} clean={clean} task={task} inject_window={inject_window})")
    client = MockClient() if mock else LLMClient(cache_path=CACHE, use_cache=True,
                                                 reasoning_effort=reasoning_effort)
    mode_list = modes or MODES
    if redo_unknown:
        done, _ = load_state(output)  # only clean jobs are considered done
    else:
        done = load_done(output)
    jobs = [(s, m) for s in ds for m in mode_list
            if job_key(s.sid, m, gate, method) not in done]
    print(f"[jobs] {len(jobs)} remaining (of {len(ds) * len(mode_list)})")
    t0 = time.time()
    lock = threading.Lock()

    def work(item):
        s, m = item
        h = Harness(m, client, summary_len=summary_len, retr_topk=retr_topk,
                    gate=gate, gate_model=gate_model, method=method, guard=guard,
                    tame_triage=tame_triage, tame_decoupling=tame_decoupling,
                    tame_cache_split=tame_cache_split)
        run = h.run(s)
        row = eval_sequence(run)
        with lock:
            append(row, output)
        print(f"  {s.sid} {m} verdicts=" +
              ",".join(str(row[f"w{i}_verdict"]) for i in (1, 2, 3, 4)), flush=True)
        return row

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(work, j) for j in jobs]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                print(f"[error] {e}", flush=True)

    print(f"[done] {time.time() - t0:.1f}s; LLM stats: "
          f"{client.stats()['calls']} calls, {client.stats()['total_tokens']} tokens")
    if redo_unknown:
        dedup(output)
        print("[redo-unknown] deduped output (last write per job wins)")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--n-per-type", type=int, default=12)
    p.add_argument("--mock", action="store_true")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--retr-topk", type=int, default=3)
    p.add_argument("--summary-len", default="64-token")
    p.add_argument("--gate", choices=("none", "G1", "G2", "learned"), default="none")
    p.add_argument("--output", default=ITEMS)
    p.add_argument("--dataset", choices=("synthetic", "real"), default="synthetic")
    p.add_argument("--modes", default=None)
    p.add_argument("--gate-model", default=None)
    p.add_argument("--variant", choices=("plain", "paraphrase", "indirect",
                                         "low-key", "retrfriendly"), default="plain")
    p.add_argument("--clean", action="store_true")
    p.add_argument("--method", choices=("none", "G3", "G4"), default="none")
    p.add_argument("--task", choices=("verdict", "ioc"), default="verdict")
    p.add_argument("--guard", action="store_true")
    p.add_argument("--no-tame-triage", action="store_true")
    p.add_argument("--no-tame-decoupling", action="store_true")
    p.add_argument("--no-tame-cache-split", action="store_true")
    p.add_argument("--inject-window", type=int, choices=(1, 2, 3), default=1)
    p.add_argument("--reasoning-effort", default=None,
                   help="optional reasoning_effort for reasoning-capable models "
                        "(e.g. low/medium/high for grok)")
    p.add_argument("--redo-unknown", action="store_true",
                   help="re-run only jobs whose window verdicts contain 'unknown', "
                        "then dedup (last write wins)")
    a = p.parse_args()
    modes = a.modes.split(",") if a.modes else None
    main(a.n_per_type, mock=a.mock, workers=a.workers, retr_topk=a.retr_topk,
         summary_len=a.summary_len, gate=a.gate, output=a.output, dataset=a.dataset,
         modes=modes, gate_model=a.gate_model, variant=a.variant, clean=a.clean,
         method=a.method, task=a.task, guard=a.guard,
         tame_triage=not a.no_tame_triage,
         tame_decoupling=not a.no_tame_decoupling,
         tame_cache_split=not a.no_tame_cache_split,
         inject_window=a.inject_window,
         reasoning_effort=a.reasoning_effort,
         redo_unknown=a.redo_unknown)
