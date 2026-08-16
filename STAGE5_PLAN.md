# Stage-5 Plan: Full State-Contamination Defense Architecture

## Goal

Upgrade from a write-time filter to a complete state-protection architecture:

- multimodal triage
- independent fact extraction module (FEM)
- fact / instruction decoupling
- temporary thinking cache (TTC) separated from permanent memory
- contamination detection
- memory audit trail
- snapshot rollback

## Architecture

1. `loginject/guard.py`
   - `triage()` routes candidate memory by modality: `EVENT`, `CLAIM`, `DIRECT`
   - `FactExtractionModule.decouple()` returns `facts[]`, `instructions[]`, `assertions[]`
   - `ContaminationDetector` blocks writes with high instruction/assertion residue
   - `TemporaryCache` stores ephemeral conclusions only
   - `GuardedMemory` stores permanent facts only, plus audit and snapshots

2. `loginject/harness.py`
   - new `guard=True` path routes all state writes through the architecture
   - verdict conclusions are written only to TTC
   - state carriers receive permanent facts only

3. `loginject/eval.py`
   - records guard metrics: per-window blocked writes, total blocked writes, rollbacks

## Experiments To Run Now

### Core attacked runs

- synthetic, `S1,S3`, `guard=True`
- real 104-sequence scale-up, `S1,S3`, `guard=True`

### Clean utility runs

- synthetic clean, `S1,S3`, `guard=True`
- real clean, `S1,S3`, `guard=True`

### Variant robustness

- low-key / paraphrase / indirect / retrfriendly, `S1,S3`, `guard=True`

## Key questions

1. Does the architecture preserve the G3 security gains on attacked data?
2. Does TTC separation reduce clean utility loss versus simple filtering?
3. Does audit show that blocked writes correspond to instruction/assertion residue?
4. Do low-key variants still bypass keyword gates but get neutralized by fact-only writes?

## Deliverables

- `results/guard_*_items.jsonl`
- `results/guard_real_*_items.jsonl`
- `results/STAGE5_REPORT.md`
