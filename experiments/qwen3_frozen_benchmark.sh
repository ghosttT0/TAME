#!/usr/bin/env bash
# Qwen3-14B-Instruct frozen TAME benchmark (mirror of qwen_frozen_benchmark.sh,
# served model: Qwen3-14B via local vLLM, all outputs written to results/qwen3_*
# so the canonical DeepSeek/Qwen2.5 files are untouched).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export DEEPSEEK_BASE_URL=http://127.0.0.1:8000/v1
export DEEPSEEK_MODEL=Qwen3-14B
export DEEPSEEK_API_KEY=EMPTY
unset DEEPSEEK_REASONING_EFFORT OMP_NUM_THREADS NVIDIA_VISIBLE_DEVICES

LOG=results/qwen3_frozen_run.log
: > "$LOG"

step() { echo ""; echo "===== $* ====="; echo "===== $* =====" >> "$LOG"; }

# --- attacked slices -------------------------------------------------------
step "syn none attacked S1,S3"
python3 experiments/run_all.py --modes S1,S3 --output results/qwen3_syn_items.jsonl 2>&1 | tee -a "$LOG"
step "syn G3 attacked S1,S3"
python3 experiments/run_all.py --method G3 --modes S1,S3 --output results/qwen3_method_g3_items.jsonl 2>&1 | tee -a "$LOG"
step "syn TAME attacked S1,S3"
python3 experiments/run_all.py --guard --modes S1,S3 --output results/qwen3_guard_syn_items.jsonl 2>&1 | tee -a "$LOG"
step "real n8 none attacked S1,S3"
python3 experiments/run_all.py --dataset real --n-per-type 8 --modes S1,S3 --output results/qwen3_real8_none_items.jsonl 2>&1 | tee -a "$LOG"
step "real n8 G3 attacked S1,S3"
python3 experiments/run_all.py --dataset real --method G3 --n-per-type 8 --modes S1,S3 --output results/qwen3_real8_g3_items.jsonl 2>&1 | tee -a "$LOG"
step "real n8 TAME attacked S1,S3"
python3 experiments/run_all.py --dataset real --guard --n-per-type 8 --modes S1,S3 --output results/qwen3_guard_real8_items.jsonl 2>&1 | tee -a "$LOG"

# --- clean utility slices --------------------------------------------------
step "syn clean baseline S1,S3"
python3 experiments/run_all.py --clean --modes S1,S3 --output results/qwen3_clean_syn_none_items.jsonl 2>&1 | tee -a "$LOG"
step "syn clean G3 S1,S3"
python3 experiments/run_all.py --clean --method G3 --modes S1,S3 --output results/qwen3_clean_syn_g3_items.jsonl 2>&1 | tee -a "$LOG"
step "syn clean TAME S1,S3"
python3 experiments/run_all.py --guard --clean --modes S1,S3 --output results/qwen3_guard_syn_clean_items.jsonl 2>&1 | tee -a "$LOG"
step "real n4 clean baseline S1,S3"
python3 experiments/run_all.py --dataset real --clean --n-per-type 4 --modes S1,S3 --output results/qwen3_real_clean_mixed_s13_items.jsonl 2>&1 | tee -a "$LOG"
step "real n4 clean G3 S1,S3"
python3 experiments/run_all.py --dataset real --method G3 --clean --n-per-type 4 --modes S1,S3 --output results/qwen3_real_clean_mixed_g3_s13_items.jsonl 2>&1 | tee -a "$LOG"
step "real n4 clean TAME S1,S3"
python3 experiments/run_all.py --dataset real --guard --clean --n-per-type 4 --modes S1,S3 --output results/qwen3_guard_real_clean_items.jsonl 2>&1 | tee -a "$LOG"

# --- TAME ablations --------------------------------------------------------
step "TAME ablation -triage S1,S3"
python3 experiments/run_all.py --guard --no-tame-triage --modes S1,S3 --output results/qwen3_tame_ablate_no_triage_items.jsonl 2>&1 | tee -a "$LOG"
step "TAME ablation -decoupling S1,S3"
python3 experiments/run_all.py --guard --no-tame-decoupling --modes S1,S3 --output results/qwen3_tame_ablate_no_decouple_items.jsonl 2>&1 | tee -a "$LOG"
step "TAME ablation -cache-split S1,S3"
python3 experiments/run_all.py --guard --no-tame-cache-split --modes S1,S3 --output results/qwen3_tame_ablate_no_cache_items.jsonl 2>&1 | tee -a "$LOG"

# --- report ----------------------------------------------------------------
step "generate STAGE5_QWEN3_REPORT.md"
python3 experiments/stage5_report_qwen3.py 2>&1 | tee -a "$LOG"

echo "===== QWEN3 FROZEN BENCHMARK DONE ====="
