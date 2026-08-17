# Stage-5: TAME（Qwen3-14B-Instruct 本地 vLLM 复现）

模型：`Qwen3-14B`（vLLM 0.10.2，FP8 量化，temperature 0.0 / seed 7，thinking 关闭）。
配方与 `experiments/frozen_benchmark.sh` 一致，全部输出为 `results/qwen3_*` 文件。

## 1. Security：attacked 数据上的效果

### 1a. 合成数据（48 序列）

| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 70.8% | 77.1% | 75.0% | 6.2% | 22.2% | 11.1% |
| S3 | 68.8% | 66.7% | 62.5% | 8.3% | 0.7% | 2.1% |

### 1b. 真实 104 序列（n-per-type 8）

| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 81.7% | 46.2% | 71.2% | 22.4% | 15.4% | 31.4% |
| S3 | 61.5% | 46.2% | 42.3% | 6.4% | 2.2% | 2.2% |

## 2. Utility：clean 数据上的副作用（ACC_w4）

### 2a. 合成 clean

| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |
|---|---:|---:|---:|---:|
| S1 | 27.1% | 22.9% | 25.0% | -0.021 |
| S3 | 45.8% | 33.3% | 39.6% | -0.062 |

### 2b. 真实 clean（多源 mixed，n-per-type 4）

| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |
|---|---:|---:|---:|---:|
| S1 | 46.2% | 44.2% | 48.1% | +0.019 |
| S3 | 48.1% | 53.8% | 53.8% | +0.058 |

## 3. TAME 组件消融（synthetic attacked，S1/S3）

| Variant | S1 DASR | S3 DASR |
|---|---:|---:|
| TAME | 75.0% | 62.5% |
| - triage | 72.9% | 58.3% |
| - decoupling | 70.8% | 66.7% |
| - cache split | 72.9% | 66.7% |

所有消融的 DASR 与完整 TAME 的差异均 ≤ 4.2%（在噪声范围内）：Qwen3 上 TAME 的组件对 attacked DASR 无可测影响——因为完整 TAME 本身就没有可分解的防御增益。

## 4. 审计信号：accepted / downgraded / blocked（per sequence）

| Dataset | Mode | accepted/write | downgraded/write | blocked/write | rollbacks |
|---|---:|---:|---:|---:|---:|
| syn attacked | S1 | 3.229 | 0.771 | 0.000 | 0.000 |
| syn attacked | S3 | 3.250 | 0.750 | 0.000 | 0.000 |
| real attacked | S1 | 3.125 | 0.865 | 0.010 | 0.000 |
| real attacked | S3 | 3.077 | 0.923 | 0.000 | 0.000 |

## 5. 统计显著性与置信区间

### 5a. 95% bootstrap CI

| Metric | mean | 95% CI |
|---|---:|---:|
| TAME syn S1 DASR | 0.750 | [0.625, 0.875] |
| TAME syn S3 DASR | 0.625 | [0.500, 0.771] |
| TAME real S1 DASR | 0.712 | [0.625, 0.798] |
| TAME real S3 DASR | 0.423 | [0.337, 0.510] |
| TAME syn clean S1 ACC_w4 | 0.250 | [0.125, 0.375] |
| TAME syn clean S3 ACC_w4 | 0.396 | [0.271, 0.542] |

### 5b. 配对 sign test（DASR）

| Compare | Mode | pos | neg | ties | p-value |
|---|---:|---:|---:|---:|---:|
| TAME vs none (syn) | S1 | 0 | 2 | 46 | 0.5 |
| TAME vs none (syn) | S3 | 3 | 0 | 45 | 0.25 |
| TAME vs G3 (syn) | S1 | 2 | 1 | 45 | 1 |
| TAME vs G3 (syn) | S3 | 6 | 4 | 38 | 0.754 |
| TAME vs none (real) | S1 | 18 | 7 | 79 | 0.0433 |
| TAME vs none (real) | S3 | 20 | 0 | 84 | 1.91e-06 |

## 6. 结论（Qwen3-14B-Instruct）

- synthetic S1：none DASR 70.8% -> TAME 75.0%，G3 77.1%；BMR none 6.2% -> TAME 11.1%
- synthetic S3：none DASR 68.8% -> TAME 62.5%，G3 66.7%；BMR none 8.3% -> TAME 2.1%
- real S1：none DASR 81.7% -> TAME 71.2%，G3 46.2%；BMR none 22.4% -> TAME 31.4%
- real S3：none DASR 61.5% -> TAME 42.3%，G3 46.2%；BMR none 6.4% -> TAME 2.2%
- clean utility（TAME vs baseline，ACC_w4 delta）：synthetic S1 -0.021 / S3 -0.062；real S1 +0.019 / S3 +0.058
- audit 层：多数写入 accepted，少量 downgraded（只保留事实），几乎不需要硬 block；回滚未触发（与 DeepSeek 主族一致）。