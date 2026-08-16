#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

set -a
. /root/.diffagent_api.env
set +a

python3 experiments/run_all.py --guard --modes S1,S3 --output results/guard_syn_final_items.jsonl
python3 experiments/run_all.py --guard --clean --modes S1,S3 --output results/guard_syn_clean_final_items.jsonl
python3 experiments/run_all.py --dataset real --guard --n-per-type 8 --modes S1,S3 --output results/guard_real8_items.jsonl
python3 experiments/run_all.py --dataset real --guard --clean --n-per-type 4 --modes S1,S3 --output results/guard_real_clean_final_items.jsonl

python3 experiments/run_all.py --guard --no-tame-triage --modes S1,S3 --output results/tame_ablate_no_triage_items.jsonl
python3 experiments/run_all.py --guard --no-tame-decoupling --modes S1,S3 --output results/tame_ablate_no_decouple_items.jsonl
python3 experiments/run_all.py --guard --no-tame-cache-split --modes S1,S3 --output results/tame_ablate_no_cache_items.jsonl

python3 experiments/stage5_report.py

echo "TAME ablations complete. Report: results/STAGE5_REPORT.md"
