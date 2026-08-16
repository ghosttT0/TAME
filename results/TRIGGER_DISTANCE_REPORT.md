# Trigger Distance Report

Trigger remains fixed at W4. Payload is planted in W1/W2/W3, corresponding to trigger distances 3/2/1 respectively.

## Synthetic

| distance | inject_window | S1 none | S1 TAME | S3 none | S3 TAME |
|---|---:|---:|---:|---:|---:|
| 3 | W1 | 45.8% | 18.8% | 41.7% | 10.4% |
| 2 | W2 | 45.8% | 25.0% | 37.5% | 8.3% |
| 1 | W3 | 47.9% | 22.9% | 37.5% | 10.4% |

Interpretation: if DASR rises with larger distance, the benchmark is measuring persistent state pollution rather than immediate prompt-following only. If TAME's gap widens at larger distance, that supports the claim that facts-only memory is especially useful against long-range contamination.