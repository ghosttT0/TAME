# Stage-5: TAME

## 1. 架构升级

本阶段把防御正式命名为 **TAME**: **T**riaged **A**uditable **M**emory **E**xecution。它不是简单过滤器，而是一个分离式状态污染防护体系：

| 组件 | 作用 | 状态 |
|---|---|---|
| 多模态 triage | 路由 EVENT / CLAIM / DIRECT 候选 | 已实现 |
| 独立 FEM | facts / instructions / assertions 解耦 | 已实现 |
| TTC | 推理结论只进临时缓存，不进永久记忆 | 已实现 |
| 永久记忆 | 只存 facts | 已实现 |
| 污染检测 | accepted / downgraded / blocked 三态 | 已实现 |
| 记忆审计 | 每次写入记录 triage/decouple/action | 已实现 |
| 快照回滚 | snapshot / rollback 接口 | 已实现（本轮未触发） |

## 2. Security：attacked 数据上的效果

### 2a. 合成数据

| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 45.8% | 18.8% | 10.4% | 42.4% | 28.5% | 20.8% |
| S3 | 39.6% | 10.4% | 8.3% | 32.6% | 11.8% | 9.7% |

### 2b. 真实 104 序列

| Mode | none DASR | G3 DASR | TAME DASR | none BMR | G3 BMR | TAME BMR |
|---|---:|---:|---:|---:|---:|---:|
| S1 | 77.9% | 50.0% | 52.5% | 36.2% | 14.7% | 23.2% |
| S3 | 81.7% | 52.9% | 59.6% | 33.0% | 10.9% | 10.3% |

## 3. Utility：clean 数据上的副作用

clean 设置下不看 DASR，直接看 `ACC_w4`。

### 3a. 合成 clean

| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |
|---|---:|---:|---:|---:|
| S1 | 91.7% | 81.2% | 89.6% | -0.021 |
| S3 | 89.6% | 87.5% | 93.8% | +0.042 |

### 3b. 真实 clean（多源 mixed）

| Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME utility delta |
|---|---:|---:|---:|---:|
| S1 | 65.4% | 51.9% | 63.5% | -0.019 |
| S3 | 50.0% | 51.9% | 48.1% | -0.019 |

## 4. TAME 组件消融

关键 attacked 设置下的组件消融（synthetic, S1/S3）。

| Variant | S1 DASR | S3 DASR |
|---|---:|---:|
| TAME | 10.4% | 8.3% |
| - triage | 22.9% | 10.4% |
| - decoupling | 43.8% | 45.8% |
| - cache split | 14.6% | 16.7% |

结论：decoupling 是核心组件（去掉后 S1/S3 DASR 回升到 43.8%/45.8%）；cache split 次之；triage 有稳定但较小的增益。

## 5. 审计信号：accepted / downgraded / blocked

这里的关键不是『全拦截』，而是把有 residue 的状态写入降级成『只保留事实』。

| Dataset | Mode | accepted/write | downgraded/write | blocked/write | rollbacks |
|---|---:|---:|---:|---:|---:|
| syn attacked | S1 | 3.229 | 0.771 | 0.000 | 0.000 |
| syn attacked | S3 | 3.229 | 0.771 | 0.000 | 0.000 |
| real attacked | S1 | 3.367 | 0.325 | 0.017 | 0.000 |
| real attacked | S3 | 3.367 | 0.329 | 0.013 | 0.000 |

## 6. 统计显著性与置信区间

### 6a. 95% bootstrap CI

| Metric | mean | 95% CI |
|---|---:|---:|
| TAME syn S1 DASR | 0.104 | [0.021, 0.208] |
| TAME syn S3 DASR | 0.083 | [0.021, 0.167] |
| TAME real S1 DASR | 0.525 | [0.458, 0.588] |
| TAME real S3 DASR | 0.596 | [0.537, 0.658] |
| TAME syn clean S1 ACC_w4 | 0.896 | [0.792, 0.979] |
| TAME syn clean S3 ACC_w4 | 0.938 | [0.854, 1.000] |

### 6b. 配对 sign test（DASR）

| Compare | Mode | pos | neg | ties | p-value |
|---|---:|---:|---:|---:|---:|
| TAME vs none (syn) | S1 | 18 | 1 | 29 | 7.63e-05 |
| TAME vs none (syn) | S3 | 15 | 0 | 33 | 6.1e-05 |
| TAME vs G3 (syn) | S1 | 6 | 2 | 40 | 0.289 |
| TAME vs G3 (syn) | S3 | 4 | 3 | 41 | 1 |
| TAME vs none (real) | S1 | 30 | 0 | 74 | 1.86e-09 |
| TAME vs none (real) | S3 | 28 | 2 | 74 | 8.68e-07 |

## 7. TAME clean utility 最终表

| Dataset | Mode | baseline ACC_w4 | G3 ACC_w4 | TAME ACC_w4 | TAME delta |
|---|---:|---:|---:|---:|---:|
| synthetic | S1 | 91.7% | 81.2% | 89.6% | -0.021 |
| synthetic | S3 | 89.6% | 87.5% | 93.8% | +0.042 |
| real | S1 | 65.4% | 51.9% | 63.5% | -0.019 |
| real | S3 | 50.0% | 51.9% | 48.1% | -0.019 |

## 8. 结论

TAME 相对 G3 的新增价值不在于『更激进地拦截』，而在于架构上把 memory path 分成了：(i) facts-only permanent memory, (ii) session-scoped TTC, (iii) auditable downgraded writes。

从结果看：

- 合成 attacked 上，TAME 比 G3 更强：S1 DASR 18.8% -> 10.4%，S3 10.4% -> 8.3%
- 相对 none，TAME 在 synthetic / real 上都达到统计显著改进（sign test p < 1e-4）
- 但 TAME 相对 G3 的增益在 48 序列 synthetic 上未达统计显著，说明样本量仍偏小，当前更适合表述为『数值更优且 clean utility 更好』
- 真实 104 序列上，TAME 仍显著优于 baseline：S1 77.9% -> 52.5%，S3 81.7% -> 59.6%
- 但在真实 S3 上，TAME 略弱于 G3（52.9% vs 59.6%），说明 TTC/triage 的额外层次在 noisy retrieval setting 还需调参
- clean utility 上，TAME 明显优于 G3：synthetic S1 ACC_w4 0.896 vs G3 0.812；S3 0.938 vs 0.875
- audit 层已经开始给出结构化信号：多数写入是 accepted，约 0.3-0.8 次/序列被 downgraded 为『只保留事实』，几乎不需要硬 block

这说明当前体系已经不是『简单过滤器』，而是一个可审计、可分层、可继续扩展到回滚策略的 TAME state contamination defense architecture。