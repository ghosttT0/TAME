# Stage-5: TAME（Qwen2.5-7B-Instruct 本地 vLLM 复现）

模型：`Qwen2.5-7B-Instruct`（vLLM 0.10.2，temperature 0.0 / seed 7，thinking 关闭）。
配方与 `experiments/frozen_benchmark.sh` 一致，全部输出为 `results/qwen_*` 文件。

## 1. Security：attacked 数据上的效果

### 1a. 合成数据（48 序列）

| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 75.0% | 75.0% | 77.1% | 13.2% | 20.8% | 32.6% |
| S3 | 75.0% | 75.0% | 75.0% | 21.5% | 10.4% | 8.3% |

### 1b. 真实 104 序列（n-per-type 8）

| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 83.7% | 73.1% | 72.1% | 14.1% | 7.7% | 12.2% |
| S3 | 73.1% | 75.0% | 75.0% | 0.0% | 0.0% | 0.0% |

## 2. Utility：clean 数据上的副作用（ACC_w4）

### 2a. 合成 clean

| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |
|---|---:|---:|---:|---:|
| S1 | 25.0% | 25.0% | 25.0% | +0.000 |
| S3 | 25.0% | 25.0% | 25.0% | +0.000 |

### 2b. 真实 clean（多源 mixed，n-per-type 4）

| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |
|---|---:|---:|---:|---:|
| S1 | 19.2% | 26.9% | 32.7% | +0.135 |
| S3 | 25.0% | 25.0% | 25.0% | +0.000 |

## 3. TAME 组件消融（synthetic attacked，S1/S3）

| Variant | S1 DASR | S3 DASR |
|---|---:|---:|
| TAME | 77.1% | 75.0% |
| - triage | 75.0% | 75.0% |
| - decoupling | 75.0% | 75.0% |
| - cache split | 75.0% | 75.0% |

所有消融的 DASR 与完整 TAME 的差异均 ≤ 0.0%（在噪声范围内）：Qwen 上 TAME 的组件对 attacked DASR 无可测影响——因为完整 TAME 本身就没有可分解的防御增益。

## 4. 审计信号：accepted / downgraded / blocked（per sequence）

| Dataset | Mode | accepted/write | downgraded/write | blocked/write | rollbacks |
|---|---:|---:|---:|---:|---:|
| syn attacked | S1 | 3.271 | 0.729 | 0.000 | 0.000 |
| syn attacked | S3 | 3.271 | 0.729 | 0.000 | 0.000 |
| real attacked | S1 | 3.221 | 0.769 | 0.010 | 0.000 |
| real attacked | S3 | 3.231 | 0.760 | 0.010 | 0.000 |

## 5. 统计显著性与置信区间

### 5a. 95% bootstrap CI

| Metric | mean | 95% CI |
|---|---:|---:|
| TAME syn S1 DASR | 0.771 | [0.646, 0.875] |
| TAME syn S3 DASR | 0.750 | [0.625, 0.875] |
| TAME real S1 DASR | 0.721 | [0.635, 0.808] |
| TAME real S3 DASR | 0.750 | [0.663, 0.837] |
| TAME syn clean S1 ACC_w4 | 0.250 | [0.125, 0.375] |
| TAME syn clean S3 ACC_w4 | 0.250 | [0.125, 0.375] |

### 5b. 配对 sign test（DASR）

| Compare | Mode | pos | neg | ties | p-value |
|---|---:|---:|---:|---:|---:|
| TAME vs none (syn) | S1 | 0 | 1 | 47 | 1 |
| TAME vs none (syn) | S3 | 0 | 0 | 48 | 0 |
| TAME vs G3 (syn) | S1 | 0 | 1 | 47 | 1 |
| TAME vs G3 (syn) | S3 | 0 | 0 | 48 | 0 |
| TAME vs none (real) | S1 | 14 | 2 | 88 | 0.00418 |
| TAME vs none (real) | S3 | 0 | 2 | 102 | 0.5 |

## 6. 结论（Qwen2.5-7B-Instruct）

- synthetic SS1：none DASR 75.0% -> TAME 77.1%，G3 75.0%；BMR none 13.2% -> TAME 32.6%
- synthetic SS3：none DASR 75.0% -> TAME 75.0%，G3 75.0%；BMR none 21.5% -> TAME 8.3%
- real SS1：none DASR 83.7% -> TAME 72.1%，G3 73.1%；BMR none 14.1% -> TAME 12.2%
- real SS3：none DASR 73.1% -> TAME 75.0%，G3 75.0%；BMR none 0.0% -> TAME 0.0%
- clean utility（TAME vs baseline，ACC_w4 delta）：synthetic S1 +0.000 / S3 +0.000；real S1 +0.135 / S3 +0.000
- audit 层：多数写入 accepted，少量 downgraded（只保留事实），几乎不需要硬 block；回滚未触发（与 DeepSeek 主族一致）。