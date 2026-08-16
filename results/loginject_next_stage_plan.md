# LogInject / StateShield 下阶段推进计划

日期：2026 年 8 月 11 日（星期二）

## 1. 目标

下阶段目标是不再把工作停留在 benchmark 扩展，而是收敛到：

> **stateful contamination in LLM-based security log analysis + contamination-aware memory gate mitigation**

也就是：

- 前半部分证明问题存在；
- 后半部分提出一个 memory gate 模块去缓解问题。

---

## 2. Phase 1：定题与止损点

### 目标
确认这个方向是否值得继续投入。

### 主要任务
- 把题目正式收敛为：
  - `stateful contamination in LLM-based log analysis`
  - `contamination-aware memory gate mitigation`
- 明确三个核心 claim：
  1. stateful contamination 确实存在；
  2. 污染主要通过 memory / update path 传播；
  3. memory gate 可以显著降低 delayed attack success。
- 设置 kill criteria：
  - gate 后 DASR 降不下来；
  - full-history / retrieval 现象不稳定；
  - 训练标签构造不出来。

### 产出物
- 题目与方法命名初稿；
- 成功/失败判据；
- 固定版问题描述。

---

## 3. Phase 2：把 MVP 升级成问题定义

### 目标
把当前的现象报告升级成论文级问题定义。

### 主要任务
- 写清楚 threat model；
- 形式化定义：
  - contamination；
  - delayed trigger；
  - contamination carrier；
  - harmful memory update；
  - benign-only trigger。
- 基于 `E:\NDSS\REPORT.md` 整理：
  - 问题存在性证据；
  - 为什么 retrieval / full-history 更危险；
  - 为什么这不是普通单轮 prompt injection。

### 产出物
- Threat model 小节；
- Problem definition 小节；
- 现象归因草稿。

---

## 4. Phase 3：实现最小版 Memory Gate

### 目标
验证“修 memory update path”是不是正确方向。

### 先做两个轻量版本

#### G1：Rule-based gate
- 拦截明显指令性语言；
- 拦截元语言/非日志语气；
- 拦截 `answer benign`、`host is clean`、`ignore previous logs` 一类模式；
- 只允许低风险事实摘要写入 memory。

#### G2：Confidence / Provenance gate
- 给候选 summary / note / retrieval chunk 打可信度；
- 只允许“事实一致且低风险”的内容写入状态；
- 对高风险内容执行降权、延迟写入或标记为 `untrusted`。

### 评估重点
- DASR；
- BMR；
- MTR；
- utility loss；
- latency / cost。

### 产出物
- 两个轻量 gate baseline；
- 初步 mitigation 结果表。

---

## 5. Phase 4：实现可学习的 Memory Gate

### 目标
形成真正的方法贡献，而不只是规则修补。

### 主要任务
- 构造训练样本：
  - clean history vs poisoned history；
  - 标出哪些 memory update 会导致后续 delayed error。
- 训练一个小 gate / classifier，预测：
  - 该不该写入；
  - 是否降权；
  - 是否标记 `untrusted`。
- 保持主模型不变，只训练轻模块。

### 产出物
- Learned memory gate 原型；
- 训练数据构造管线；
- 与规则版 gate 的对比结果。

---

## 6. Phase 5：补完整实验矩阵

### 目标
把 MVP 扩展成论文级实验。

### 实验维度

#### 状态模式
- stateless；
- full-history；
- summary-memory；
- retrieval-memory；
- analyst-note。

#### 攻击模式
- immediate；
- latent；
- staged；
- repeated low-strength poison。

#### 任务类型
- threat detection；
- attribution；
- remediation recommendation。

### 核心表格
- 问题存在性；
- 不同 carrier 的污染强度；
- gate 总效果；
- 消融实验；
- utility / cost 开销。

### 产出物
- 主实验结果表；
- 消融实验表；
- attack mode / carrier 分析表。

---

## 7. Phase 6：补 defense story

### 目标
避免论文看起来只是“一个小过滤器”。

### 主要任务
- 对比 input filter 为什么不够；
- 强调真正需要保护的是：
  - summary write path；
  - retrieval indexing path；
  - note update path。
- 说明 memory gate 与 provenance tagging 的系统意义。

### 产出物
- Defense motivation 小节；
- Design rationale 小节；
- 与原始 LogInject defense 的关系说明。

---

## 8. Phase 7：写作与收束

### 目标
从实验原型转向论文主体。

### 优先写作顺序
1. Introduction；
2. Threat Model；
3. Problem Definition；
4. Method；
5. Main Results。

### 后续补写
- Related Work；
- Discussion；
- Limitations；
- Ethics / deployment considerations。

### 产出物
- 论文大纲；
- 引言初稿；
- 方法与实验章节骨架。

---

## 9. 当前最优先的三件事

1. 把 memory gate 方案正式纳入课题主线；
2. 完成 rule-based / provenance gate feasibility；
3. 确认 gate 后 DASR 是否能显著下降。

---

## 10. 阶段判断

如果下阶段实验表明：

- memory gate 可以显著降低 delayed contamination；
- utility 损失可控；
- retrieval / history 的放大机制可重复出现；

那么这个方向就可以从“现象扩展”升级为：

> **一个关于 stateful contamination 的新问题 + 一个 contamination-aware memory defense 机制**

如果这些条件都不满足，则应尽快止损，不再继续沿 LogInject 线推进。
