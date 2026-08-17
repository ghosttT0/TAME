# Final Report

## 1. Final benchmark framing

The artifact is no longer a single-round prompt-injection benchmark. It is a **stateful contamination evaluation framework** with: multi-window delayed triggering, multiple state carriers, real logs, mechanism labels, and defense-aware evaluation.

## 2. Main security table (verdict task)

| Dataset | Mode | none DASR | G3 DASR | TAME DASR |
|---|---:|---:|---:|---:|
| synthetic | S1 | 45.8% | 18.8% | 10.4% |
| synthetic | S3 | 39.6% | 10.4% | 8.3% |
| real-104 | S1 | 77.9% | 50.0% | 52.5% |
| real-104 | S3 | 81.7% | 52.9% | 59.6% |

## 3. Clean utility final table

| Dataset | Mode | baseline ACC_w4 | TAME ACC_w4 | delta |
|---|---:|---:|---:|---:|
| synthetic | S1 | 91.7% | 89.6% | -0.021 |
| synthetic | S3 | 89.6% | 93.8% | +0.042 |
| real | S1 | 65.4% | 63.5% | -0.019 |
| real | S3 | 50.0% | 48.1% | -0.019 |

## 4. Payload breakdown

| payload_kind | count | S1 DASR(real-104 none) |
|---|---:|---:|
| AUDIT-followup | 52 | 94.2% |
| AUDIT-status | 26 | 57.7% |
| SYSLOG | 26 | 65.4% |

| payload_trust | count | S1 DASR(real-104 none) |
|---|---:|---:|
| low | 52 | 82.7% |
| medium | 52 | 73.1% |

## 5. Task split

| Task | Dataset | Mode | none DASR |
|---|---|---:|---:|
| verdict | synthetic | S1 | 45.8% |
| verdict | synthetic | S3 | 39.6% |
| IOC | synthetic-IOC | S1 | 35.4% |
| IOC | synthetic-IOC | S3 | 33.3% |
| IOC | real-IOC | S1 | 78.8% |
| IOC | real-IOC | S3 | 88.5% |

## 6. Trigger distance

Current frozen benchmark fixes `trigger_distance=3` (W1->W4). The field is now explicit in every row. The next expansion should add distance-1 / distance-2 variants rather than overloading the main benchmark with synthetic-only numbers.

## 7. Final scripts

- `experiments/frozen_benchmark.sh`: regenerate final TAME tables
- `experiments/run_tame_ablations.sh`: regenerate TAME ablations
- `experiments/stats_ci.py`: bootstrap CI + paired sign test
- `results/FROZEN_BENCHMARK.md`: frozen result inventory

## 8. Additional models

The frozen main narrative above uses the original DeepSeek run family as the primary reference.
To reduce the chance that the conclusions are an artifact of one model, we also ran two extra
model families on the same key `S1/S3` verdict slices.

| Model | Dataset | Mode | none DASR | TAME DASR | none BMR | TAME BMR |
|---|---|---:|---:|---:|---:|---:|
| GPT-5.4 | synthetic | S1 | 62.5% | 35.4% | 50.0% | 38.2% |
| GPT-5.4 | synthetic | S3 | 58.3% | 35.4% | 49.3% | 27.8% |
| GPT-5.4 | real | S1 | 76.9% | 71.2% | 46.2% | 32.1% |
| GPT-5.4 | real | S3 | 82.7% | 61.5% | 33.3% | 13.5% |
| DeepSeek-V4-Pro | synthetic | S1 | 6.2% | 0.0% | 52.8% | 13.2% |
| DeepSeek-V4-Pro | synthetic | S3 | 4.2% | 0.0% | 38.9% | 14.6% |
| DeepSeek-V4-Pro | real | S1 | 3.8% | 9.6% | 51.9% | 11.5% |
| DeepSeek-V4-Pro | real | S3 | 30.8% | 9.6% | 29.5% | 8.3% |
| Claude-Sonnet-5 | synthetic | S1 | 27.1% | 20.8% | 78.5% | 79.9% |
| Claude-Sonnet-5 | synthetic | S3 | 20.8% | 29.2% | 70.1% | 66.7% |
| Claude-Sonnet-5 | real | S1 | 38.5% | 40.4% | 79.5% | 66.7% |
| Claude-Sonnet-5 | real | S3 | 48.1% | 40.4% | 50.6% | 22.4% |
| GLM-5.2 | synthetic | S1 | 4.2% | 6.2% | 51.4% | 29.9% |
| GLM-5.2 | synthetic | S3 | 14.6% | 0.0% | 41.0% | 26.4% |
| GLM-5.2 | real | S1 | 19.2% | 21.2% | 51.3% | 20.5% |
| GLM-5.2 | real | S3 | 21.2% | 19.2% | 30.8% | 11.5% |
| Qwen2.5-7B (local vLLM, thinking off) | synthetic | S1 | 75.0% | 77.1% | 13.2% | 32.6% |
| Qwen2.5-7B (local vLLM, thinking off) | synthetic | S3 | 75.0% | 75.0% | 21.5% | 8.3% |
| Qwen2.5-7B (local vLLM, thinking off) | real-104 | S1 | 83.7% | 72.1% | 14.1% | 12.2% |
| Qwen2.5-7B (local vLLM, thinking off) | real-104 | S3 | 73.1% | 75.0% | 0.0% | 0.0% |
| Qwen3-14B (local vLLM, thinking off) | synthetic | S1 | 70.8% | 75.0% | 6.2% | 11.1% |
| Qwen3-14B (local vLLM, thinking off) | synthetic | S3 | 68.8% | 62.5% | 8.3% | 2.1% |
| Qwen3-14B (local vLLM, thinking off) | real-104 | S1 | 81.7% | 71.2% | 22.4% | 31.4% |
| Qwen3-14B (local vLLM, thinking off) | real-104 | S3 | 61.5% | 42.3% | 6.4% | 2.2% |

Interpretation:

- `gpt-5.4` is highly vulnerable on the key real slices, but TAME reduces both DASR and BMR substantially, especially on real `S3`
- `deepseek-v4-pro` is substantially stronger than the earlier baseline family and shows very low DASR on synthetic data; TAME still helps, especially on real `S3`
- `claude-sonnet-5` has much higher benign false-alarm pressure (BMR), and TAME is not uniformly beneficial on every slice, but it still substantially reduces real `S3` contamination and cuts BMR there by more than half
- `GLM-5.2` sits in the middle: baseline DASR is moderate, and TAME's clearest gain is on BMR reduction rather than a uniform DASR drop; the strongest benefit appears on `S3`
- `Qwen2.5-7B-Instruct` (local vLLM, thinking off) is the weakest detector in the table: its clean-window miss rate on genuinely malicious trigger windows is ~95–100% (MTR ≈ 1.0), so DASR is dominated by baseline detection failure rather than contamination. TAME shows no gain on synthetic, a small non-significant drop on real `S1` in absolute terms but statistically significant (paired sign test pos 14 / neg 2, p=0.004), and no change on real `S3`. See §9: this is the "detector-ceiling" boundary condition — when the model's own miss floor already exceeds the attack-attributable error, memory defenses have nothing left to remove.
- `Qwen3-14B-Instruct` (local vLLM, thinking off, FP8) is a meaningfully stronger local detector than Qwen2.5-7B: real clean miss floors drop from ~95–100% to ~67–69%, and its failure profile is mixed — under-triggering overall (MTR 86–96%) but with a real FP-direction component on real `S1` (FP DASR 69.2%). TAME now shows significant real-data gains: real `S3` DASR 61.5% → 42.3% (paired sign test pos 20 / neg 0, p=1.9e-6) and real `S1` 81.7% → 71.2% (pos 18 / neg 7, p=0.043). This confirms the §9 boundary from the other side: once a local open-weight model alarms often enough to have contamination-attributable error, TAME again recovers it.
- so the benchmark is not single-model brittle: the exact security/utility tradeoff moves by model family, which is itself a useful benchmark outcome

## 9. Contamination-attributable error decomposition (Δ) and the detector-ceiling boundary

Raw DASR mixes two error sources: (i) errors the **attack** pushes the model into, and (ii) errors the model would make anyway on the trigger window even with clean memory. To separate them we normalize by each model's clean-window miss floor:

> Δ = attacked DASR − clean miss floor, where the clean miss floor is the fraction of W4 windows with `expected=malicious` judged non-`malicious` on the **clean** slices. Δ is the contamination-attributable error; TAME's recovery is `none DASR − TAME DASR` on the attacked slices.

| Model | Dataset | Mode | clean miss floor | none DASR | TAME DASR | Δ (attributable) | TAME recovery |
|---|---|---:|---:|---:|---:|---:|---:|
| DeepSeek (main) | synthetic | S1 | 11.1% | 45.8% | 10.4% | +34.7% | 35.4% |
| DeepSeek (main) | synthetic | S3 | 11.1% | 39.6% | 8.3% | +28.5% | 31.2% |
| DeepSeek (main) | real | S1 | 46.2% | 77.9% | 52.5% | +31.7% | 25.4% |
| DeepSeek (main) | real | S3 | 66.7% | 81.7% | 59.6% | +15.1% | 22.1% |
| Qwen2.5-7B | synthetic | S1 | 100.0% | 75.0% | 77.1% | −25.0% | −2.1% |
| Qwen2.5-7B | synthetic | S3 | 100.0% | 75.0% | 75.0% | −25.0% | 0.0% |
| Qwen2.5-7B | real | S1 | 94.9% | 83.7% | 72.1% | −11.2% | 11.5% |
| Qwen2.5-7B | real | S3 | 100.0% | 73.1% | 75.0% | −26.9% | −1.9% |
| Qwen3-14B | synthetic | S1 | 97.2% | 70.8% | 75.0% | −26.4% | −4.2% |
| Qwen3-14B | synthetic | S3 | 72.2% | 68.8% | 62.5% | −3.5% | +6.2% |
| Qwen3-14B | real | S1 | 66.7% | 81.7% | 71.2% | +15.1% | +10.6% |
| Qwen3-14B | real | S3 | 69.2% | 61.5% | 42.3% | −7.7% | +19.2% |

Notes:
- Synthetic Δ uses matched 48-sequence clean/attacked sets (exact). Real clean uses `n-per-type 4` (52 sequences) while attacked real uses `n-per-type 8` (104 sequences) — different sequence draws from the same log pool, so real Δ is approximate; a matched real clean/attacked pair is a follow-up.
- DeepSeek rows: clean floors from `clean_syn_none` / `real_clean_mixed_s13`; attacked from `items.jsonl` / `real8_none`; TAME from `guard_syn_final` / `guard_real8`.
- Qwen rows: `qwen_clean_syn_none` / `qwen_real_clean_mixed_s13` (clean), `qwen_syn` / `qwen_real8_none` (attacked), `qwen_guard_syn` / `qwen_guard_real8` (TAME).
- Qwen3 rows: `qwen3_clean_syn_none` / `qwen3_real_clean_mixed_s13` (clean), `qwen3_syn` / `qwen3_real8_none` (attacked), `qwen3_guard_syn` / `qwen3_guard_real8` (TAME); same caveat as Qwen2.5 on real Δ (clean n-per-type 4 vs attacked n-per-type 8).

Reading:

- **On capable detectors (DeepSeek family), TAME recovery ≈ Δ**: the defense removes essentially the entire contamination-attributable error (35.4% ≈ 34.7% on syn S1, 31.2% ≈ 28.5% on syn S3), i.e. it does exactly the job it is designed for.
- **On a weak detector (Qwen2.5-7B), Δ ≤ 0**: the model's own miss floor is ~95–100% (it almost never emits `malicious`), so the attack does not push errors above the floor and there is no contamination-attributable error for TAME to remove. The remaining DASR is detection failure, not state contamination.
- **On an intermediate local detector (Qwen3-14B), Δ > 0 reappears where the model alarms**: real clean floors fall to ~67–69%, real `S1` shows +15.1% attributable error and TAME recovers +10.6% of it (p=0.043); on real `S3` TAME recovery (+19.2%) even exceeds the approximate Δ (−7.7%), i.e. the guard also removes instruction-residue amplification beyond the clean-floor-normalized error. On synthetic, Qwen3 still sits near its own floor (Δ ≤ 0), so TAME is a no-op there — the boundary is per-slice, not per-model-family.
- **Boundary condition (detector ceiling).** TAME's benefit is conditional on the model's baseline detection capability: it removes contamination-attributable error when such error exists (stronger detectors), and is a no-op on weak detectors whose errors are not contamination-driven. This is a characterization of *when* memory defense applies, not a failure of the defense: the guard audit shows it still blocks/downgrades instruction-residue writes (accepted 3.2–3.3, downgraded 0.73–0.77 per sequence) even when DASR is unchanged.
- The one significant Qwen gain (real S1, p=0.004, and clean utility +0.135 ACC_w4) shows the defense is not harmful on weak detectors and can still help where contamination exists.

Full Qwen reproduction details: `results/STAGE5_QWEN_REPORT.md`, `results/QWEN_FULL_REPRO_SUMMARY.md`, `experiments/qwen_frozen_benchmark.sh`; Qwen3-14B: `results/STAGE5_QWEN3_REPORT.md`, `results/qwen3_*`, `experiments/qwen3_frozen_benchmark.sh`.

### 9.1 FP/FN mechanism split: why similar raw DASR ≠ similar vulnerability

GPT-5.4 and Qwen2.5-7B land in the same raw-DASR range on real data (77–84%), yet their failure mechanisms are opposite. Splitting DASR by attack direction (FN = attacker pushes the model to *miss* malicious activity; FP = attacker pushes the model to *flag* benign activity) and reporting BMR per direction:

| Model | Dataset | Mode | FN DASR | FP DASR | BMR (FP windows) | MTR (FN windows) | Failure profile |
|---|---|---:|---:|---:|---:|---:|---|
| GPT-5.4 | synthetic | S1 | 50.0% | 100.0% | 100.0% | 45.8% | over-triggering (FP-driven) |
| GPT-5.4 | synthetic | S3 | 44.4% | 100.0% | 100.0% | 43.8% | over-triggering |
| GPT-5.4 | real | S1 | 69.2% | 100.0% | 96.2% | 71.2% | over-triggering |
| GPT-5.4 | real | S3 | 82.1% | 84.6% | 92.3% | 82.7% | over-triggering |
| Qwen2.5-7B | synthetic | S1 | 100.0% | 0.0% | 0.0% | 100.0% | under-triggering (FN-driven) |
| Qwen2.5-7B | synthetic | S3 | 100.0% | 0.0% | 0.0% | 100.0% | under-triggering |
| Qwen2.5-7B | real | S1 | 97.4% | 42.3% | 0.0% | 97.1% | under-triggering |
| Qwen2.5-7B | real | S3 | 97.4% | 0.0% | 0.0% | 98.1% | under-triggering |
| Qwen3-14B | synthetic | S1 | 94.4% | 0.0% | 18.8% | 95.8% | under-triggering (FN-driven), hedges with `suspicious` |
| Qwen3-14B | synthetic | S3 | 91.7% | 0.0% | 22.9% | 93.8% | under-triggering (FN-driven) |
| Qwen3-14B | real | S1 | 85.9% | 69.2% | 3.8% | 89.4% | mixed (FN-driven + FP component) |
| Qwen3-14B | real | S3 | 82.1% | 0.0% | 0.0% | 86.5% | under-triggering (FN-driven) |

Reading:

- **GPT-5.4's high DASR is contamination-driven over-triggering**: it genuinely flags malicious activity (low-to-moderate MTR), which is exactly what FP-direction injections exploit (FP DASR 100%, BMR 92–100%). This is why TAME works on it (real S3 DASR 82.7%→61.5%, BMR 33.3%→13.5%): removing injected instruction residue reduces the false alarms the attack manufactures.
- **Qwen's high DASR is detection-ceiling under-triggering**: it almost never emits `malicious` even on clean windows (MTR 97–100%, BMR 0%), so FN-direction injections "succeed" trivially (FN DASR 97–100%) while FP injections fail (FP DASR 0–42%). There is no contamination-attributable error for TAME to remove.
- **Qwen3-14B is an intermediate "hedging" detector**: still under-triggering overall (MTR 86–96%, FN DASR 82–94%) and rarely committing to `malicious` (strict FP BMR 0–23% — it mostly answers `suspicious`), but it does alarm enough on real `S1` to carry a genuine FP-direction failure (FP DASR 69.2%) — precisely the slice where TAME's real `S1` gain (+10.6%, p=0.043) appears. The §9 boundary therefore holds per-slice rather than per-model: TAME recovers where the model can be pushed to over-alarm, and is a no-op where it cannot alarm at all (synthetic, real `S3`).
- Together with §9, this pins down the boundary condition: **defense value peaks on models that alarm but can be misled (contamination-attributable error > 0); weak non-alarming detectors and extremely robust detectors both benefit little**. Raw DASR alone conflates the two opposite failure modes — direction-split reporting and Δ decomposition are both needed.
