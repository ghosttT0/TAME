# Frozen Benchmark

This directory contains the frozen result set used for the final benchmark narrative.

## Core result files

- `items.jsonl`: synthetic attacked baseline
- `clean_syn_none_items.jsonl`: synthetic clean baseline
- `method_g3_items.jsonl`: synthetic G3 facts-only defense
- `real8_none_items.jsonl`: scaled real attacked baseline (104 sequences)
- `real8_g3_items.jsonl`: scaled real G3 defense
- `guard_syn_final_items.jsonl`: synthetic TAME attacked
- `guard_syn_clean_final_items.jsonl`: synthetic TAME clean
- `guard_real8_items.jsonl`: real TAME attacked (104 sequences)
- `guard_real_clean_final_items.jsonl`: real TAME clean

## TAME ablations

- `tame_ablate_no_triage_items.jsonl`
- `tame_ablate_no_decouple_items.jsonl`
- `tame_ablate_no_cache_items.jsonl`

## Reports

- `STAGE3_REPORT.md`
- `STAGE4_REPORT.md`
- `STAGE5_REPORT.md`
- `FINAL_REPORT.md`

## Additional model slices

- `v4pro_syn_none_cleanrun_items.jsonl`
- `v4pro_syn_tame_cleanrun_items.jsonl`
- `v4pro_real_none_cleanrun_items.jsonl`
- `v4pro_real_tame_cleanrun_items.jsonl`
- `claude5_syn_none_items.jsonl`
- `claude5_syn_tame_items.jsonl`
- `claude5_real_none_items.jsonl`
- `claude5_real_tame_items.jsonl`
- `glm52_syn_none_items.jsonl`
- `glm52_syn_tame_items.jsonl`
- `glm52_real_none_items.jsonl`
- `glm52_real_tame_items.jsonl`
- `gpt54_syn_none_items.jsonl`
- `gpt54_syn_tame_items.jsonl`
- `gpt54_real_none_items.jsonl`
- `gpt54_real_tame_items.jsonl`

## Reproduction

Run:

```bash
bash experiments/setup_repro.sh
bash experiments/frozen_benchmark.sh
```

to regenerate the final TAME tables and report.

`setup_repro.sh` does two important things:

- validates DeepSeek API env vars from `/root/.diffagent_api.env`
- auto-fetches the upstream AIT-AECID real-log repo into `.external/` if it is missing
