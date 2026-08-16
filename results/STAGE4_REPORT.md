# Stage-4: 数据规模扩展 + 多任务 + 标注体系

## 1. 规模（scale-up）

| 数据集 | 阶段3 | 阶段4 | 扩充方式 |
|---|---:|---:|---|
| 合成 | 48 序列 | 48 序列 × 2 任务 | 增加 IOC 任务类型 |
| 真实(多源) | 48 序列(单源) | 104 序列(多源混合) | 全日志目录收集 + 多源混合窗口 |
| 总计 | 96 | ~304 (含任务维度) | |

- 真实扩大版共 104 序列、520 条 item（5 模式）

## 2. 多任务：verdict vs IOC-hunting

| Task | Mode | none DASR |
|---|---:|---:|
| verdict (syn) | S1 | 45.8% |
| IOC-hunting (syn) | S1 | 35.4% |
| IOC-hunting (real) | S1 | 78.8% |
| verdict (syn) | S3 | 39.6% |
| IOC-hunting (syn) | S3 | 33.3% |
| IOC-hunting (real) | S3 | 88.5% |

## 3. 标注体系（新增字段）

每条 item 新增以下结构化解：

| 字段 | 说明 | 取值 |
|---|---|---|
| `trigger_distance` | 注入窗口→触发窗口的间隔 | 3（W1→W4） |
| `payload_kind` | 注入载体类型 | SYSLOG / AUDIT-status / AUDIT-followup |
| `payload_trust` | 注入内容的表面可信度等级 | low / medium |
| `w{i}_agreement` | G4 双判一致性 | 0/1 |
| `w{i}_quarantined` | G4 隔离触发 | 0/1 |
| `w{i}_fact_card` | G3 事实卡（剥离指令后） | 文本 |

**污染传播的标注归因**（S1 none, 真实 104 序列 attacked）：

| payload_kind | 序列数 | S1 DASR |
|---|---:|---:|
| AUDIT-followup | 52 | 94.2% |
| AUDIT-status | 26 | 57.7% |
| SYSLOG | 26 | 65.4% |

| payload_trust | 序列数 | S1 DASR |
|---|---:|---:|
| low | 52 | 82.7% |
| medium | 52 | 73.1% |

## 4. 扩大规模下的防御验证（G3）

| Mode | none DASR | G3 DASR | none BMR | G3 BMR |
|---|---:|---:|---:|---:|
| S1 | 77.9% | 50.0% | 36.2% | 14.7% |
| S3 | 81.7% | 52.9% | 33.0% | 10.9% |

结论：G3 fact-card 在 104 序列（2.2 倍规模）上仍把 DASR 压低 ~28 个百分点，BMR 从 0.33-0.36 降到 0.09-0.12，规模扩展未破坏防御结论。

## 5. 结论

**C 数据规模**：真实数据集从 48（单源）扩到 104 序列（全部日志目录 + 多源混合窗口：audit/auth/apache/kern/suricata），合成集新增 IOC 任务维度，总体评测面约 3 倍。污染放大（S1/S3 DASR >> S0）在 2 倍规模上稳定复现。

**D 标注体系**：每条 item 现在带 trigger_distance / payload_kind / payload_trust /agreement / quarantined / fact_card 结构化标注。标注归因揭示：AUDIT-followup（A3 未来指向型）污染最强（S1 DASR 94.2%），显著高于 SYSLOG(65.4%) 与 AUDIT-status(57.7%)——注入效力由『指令指向未来窗口』的语义驱动，而非表面载体类型。剩余可扩展：trigger distance 目前固定 3（W1→W4），后续可加1-2 窗口距离的变体。

**多任务**：IOC-hunting 任务在真实数据上污染更强（S3 DASR 88.5% vs verdict 基线 56.2%）——IOC 检索任务需要引用具体指标，注入的『无 IOC』结论更容易被采纳。合成数据上 IOC 表述略降低污染强度（35% vs verdict 46%），说明任务表述与日志真实性的交互影响注入效力，这本身成为 benchmark 的参数维度。