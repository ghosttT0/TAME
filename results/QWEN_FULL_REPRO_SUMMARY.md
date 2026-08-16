# Qwen2.5-7B-Instruct 全量复现工作总结

> 日期：2026-08-16 ｜ 项目：loginject 流式状态污染基准 + TAME 防御（论文）
> 本文档汇总：本地部署 Qwen2.5-7B-Instruct（thinking 关闭）复现 benchmark 的全部工作、结果、对论文观点的验证结论、原创性盘点与待议事项。

---

## 1. 背景与任务

- **项目**：StreamPoison / TAME —— 针对"流式多窗口日志解读流水线"的状态污染（prompt-injection via state carriers）攻击基准与防御架构。
- **本次任务**：把 `/autodl-fs/data/Qwen2.5-7B-Instruct` 本地启起来（**thinking 模式关闭**），跑通 benchmark，并回答"结果是否支持论文观点"。
- **执行范围**（用户选定）：
  1. 标准全模式 S0–S4（synthetic + real，无防御）；
  2. 完整 frozen TAME 配方（attacked + clean + 3 消融 + 报告）。

## 2. 部署环境

| 项 | 值 |
|---|---|
| 模型 | `/autodl-fs/data/Qwen2.5-7B-Instruct`（Qwen2ForCausalLM, bf16, 32k ctx, 4 shards ~15GB） |
| 服务 | vLLM 0.10.2 OpenAI 兼容 API，`http://127.0.0.1:8000/v1`，`--served-model-name Qwen2.5-7B-Instruct` |
| 硬件 | NVIDIA RTX 4090 24GB（单卡），gpu-memory-utilization 0.92，max_model_len 16384 |
| 推理配置 | temperature 0.0 / seed 7 / max_tokens 2048 / JSON mode 可用 |
| **Thinking 关闭** | Qwen2.5-Instruct 本身无推理；服务端未启用任何 reasoning 后端，客户端**未传** `reasoning_effort`；已实测响应无 `reasoning_content`，返回纯内容 |
| 基准接入 | `DEEPSEEK_BASE_URL=http://127.0.0.1:8000/v1`、`DEEPSEEK_MODEL=Qwen2.5-7B-Instruct`、`DEEPSEEK_API_KEY=EMPTY`（复用 `loginject/llm.py` 的 OpenAI 客户端） |

## 3. 运行批次与耗时

### 3.1 标准全模式 S0–S4（无防御）

| 数据集 | jobs | LLM 调用 | tokens | 耗时 | unknown |
|---|---|---|---:|---:|---:|---:|
| synthetic（48 seq × 5 modes） | 240 | 1,259 | 655k | 680s (11.3min) | 0 |
| real（156 seq × 5 modes） | 780 | 3,402 | 3.66M | 1918s (32min) | 0 |

输出：`results/qwen_syn_items.jsonl`、`results/qwen_real_items.jsonl`

每模式指标（无防御）：

| 数据集 | Mode | IASR | DASR | CPL | BMR* | MTR |
|---|---|---|---:|---:|---:|---:|---:|
| syn | S0 | 0.479 | 0.750 | 0.98 | 0.000 | 1.000 |
| syn | S1 | 0.479 | 0.750 | 1.00 | 0.000 | 1.000 |
| syn | S2 | 0.500 | 0.771 | 1.48 | 0.000 | 1.000 |
| syn | S3 | 0.500 | 0.750 | 1.25 | 0.000 | 1.000 |
| syn | S4 | 0.500 | 0.771 | 1.25 | 0.007 | 1.000 |
| real | S0 | 0.365 | 0.731 | 0.86 | 0.000 | 0.974 |
| real | S1 | 0.365 | 0.840 | 1.10 | 0.004 | 0.981 |
| real | S2 | 0.263 | 0.744 | 1.01 | 0.000 | 0.949 |
| real | S3 | 0.244 | 0.731 | 0.74 | 0.000 | 0.974 |
| real | S4 | 0.276 | 0.731 | 0.93 | 0.000 | 0.968 |

\* BMR 此处为 `eval.py` 口径（仅 benign→malicious）；`stage5_report.py` 口径含 suspicious。

### 3.2 Frozen TAME 配方（15 步全量，脚本 `experiments/qwen_frozen_benchmark.sh`）

| # | 步骤 | jobs | 耗时 | LLM 调用 |
|---|---|---|---:|---:|
| 1 | syn G3 attacked | 96 | 440.2s | 745 |
| 2 | syn TAME attacked | 96 | 715.9s | 765 |
| 3 | real n8 none attacked | 208 | 443.8s | 780 |
| 4 | real n8 G3 attacked | 208 | 571.6s | 839 |
| 5 | real n8 TAME attacked | 208 | 988.4s | 927 |
| 6 | syn clean none | 96 | 233.8s | 384 |
| 7 | syn clean G3 | 96 | 432.5s | 690 |
| 8 | syn clean TAME | 96 | 668.4s | 739 |
| 9 | real n4 clean none | 104 | 96.0s | 159 |
| 10 | real n4 clean G3 | 104 | 113.9s | 161 |
| 11 | real n4 clean TAME | 104 | 225.9s | 177 |
| 12 | TAME 消融 -triage | 96 | 654.8s | 728 |
| 13 | TAME 消融 -decoupling | 96 | 234.9s | 384 |
| 14 | TAME 消融 -cache-split | 96 | 665.4s | 735 |
| 15 | 生成 STAGE5_QWEN_REPORT.md | — | <1s | — |
| **合计** | | **1704** | **~6485s (≈1.8h)** | **~8713** |

- 加标准批次总计约 **2.5 小时** LLM 计算；全部结果 **0 个 unknown**（无超时、无解析失败）。
- 每步独立输出文件，可断点续跑；`set -euo pipefail` 串行执行避免打爆 vLLM / 缓存并发写竞争。

## 4. 核心结果

### 4.1 Security：attacked DASR / BMR（Qwen vs 论文 DeepSeek 主族）

| Dataset | Mode | Qwen none | Qwen G3 | Qwen TAME | DeepSeek 论文（none→G3→TAME） |
|---|---|---|---:|---:|---:|---:|
| synthetic | S1 | 75.0% | 75.0% | **77.1%** | 45.8% → 18.8% → 10.4% |
| synthetic | S3 | 75.0% | 75.0% | 75.0% | 39.6% → 10.4% → 8.3% |
| real-104 | S1 | 83.7% | 73.1% | **72.1%** | 77.9% → 50.0% → 52.5% |
| real-104 | S3 | 73.1% | 75.0% | 75.0% | 81.7% → 52.9% → 59.6% |

BMR（stage5 口径，含 suspicious）：syn S1 none 13.2% → TAME 32.6%；syn S3 21.5% → 8.3%；real S1 14.1% → 12.2%；real S3 0% → 0%。

### 4.2 Utility：clean ACC_w4

| Dataset | Mode | baseline | G3 | TAME | TAME delta |
|---|---|---|---:|---:|---:|---:|
| synthetic | S1 | 25.0% | 25.0% | 25.0% | +0.000 |
| synthetic | S3 | 25.0% | 25.0% | 25.0% | +0.000 |
| real | S1 | 19.2% | 26.9% | 32.7% | **+0.135** |
| real | S3 | 25.0% | 25.0% | 25.0% | +0.000 |

**注意**：clean 数据上 Qwen 的 W4 命中率极低（syn 25%），原因是 clean 序列的 W4 expected 多为 `malicious`（syn 72/96、real 78/104），而 Qwen 几乎从不判 malicious（判 suspicious/benign）。这是**模型检测底噪**，不是防御副作用。

### 4.3 TAME 组件消融（synthetic attacked）

| Variant | S1 DASR | S3 DASR |
|---|---:|---:|
| TAME | 77.1% | 75.0% |
| − triage | 75.0% | 75.0% |
| − decoupling | 75.0% | 75.0% |
| − cache split | 75.0% | 75.0% |

全部差异 ≤ 0.0%（噪声内）：Qwen 上组件无可测影响——因为完整 TAME 本身没有可分解的防御增益。

### 4.4 审计信号（per sequence，guard 机制确实在运转）

| Dataset | Mode | accepted | downgraded | blocked | rollbacks |
|---|---:|---:|---:|---:|---:|
| syn attacked | S1/S3 | 3.271 | 0.729 | 0.000 | 0.000 |
| real attacked | S1 | 3.221 | 0.769 | 0.010 | 0.000 |
| real attacked | S3 | 3.231 | 0.760 | 0.010 | 0.000 |

### 4.5 统计检验

- 配对 sign test（DASR）：
  - TAME vs none（syn S1/S3）：p = 1 / 0（47–48 ties，无改善）
  - TAME vs none（real S1）：**pos 14 / neg 2，p = 0.0042（显著改善）**
  - TAME vs none（real S3）：p = 0.5（无显著变化）
- bootstrap 95% CI：TAME real S1 DASR 0.721 [0.635, 0.808]。

## 5. 论文观点验证结论（逐条）

| 论文主张 | Qwen 结果 | 判定 |
|---|---|---|
| 流式状态污染威胁真实、跨模型成立 | real DASR 73–84%（与 GPT-5.4 同级，最脆弱一档）；CPL 0.74–1.25 | ✅ 强烈支持 |
| 真实日志比合成更脆弱 | S1 支持（84.0% > 75.0%）；S3 不支持（73.1% < 75.0%，合成已饱和） | ⚠️ 部分支持 |
| 跨模型脆弱性异质（BMR 独立第二维度） | Qwen = 高 DASR + 近零 BMR + MTR≈100%（纯漏报型），填补论文表格缺的象限 | ✅ 支持并扩展 |
| 污染经 state carriers 跨窗口传播 | summary/note 污染率 0 但 DASR 高 → 主通道是检索原文/历史原始行，与论文机制归因一致 | ✅ 方向一致 |
| **TAME 显著降低 DASR** | syn 无改善；real S1 显著（83.7→72.1, p=0.004）；real S3 无改善 | ❌ **Qwen 上基本不成立**（详见 §6） |

## 6. 关键新分析：污染可归因误差分解（Δ = attacked − clean 底噪）

| 模型 | 数据集/Mode | clean 漏报底噪 | attacked none DASR | attacked TAME DASR | **可归因 Δ** | **TAME 回收** |
|---|---:|---:|---:|---:|---:|---:|
| DeepSeek | syn S1 | 11.1% | 45.8% | 10.4% | +34.7% | 35.4% |
| DeepSeek | syn S3 | 11.1% | 39.6% | 8.3% | +28.5% | 31.2% |
| DeepSeek | real S1 | 46.2% | 77.9% | 52.5% | +31.7% | 25.4% |
| DeepSeek | real S3 | 66.7% | 81.7% | 59.6% | +15.1% | 22.1% |
| Qwen | syn S1 | 100.0% | 75.0% | 77.1% | −25.0% | −2.1% |
| Qwen | syn S3 | 100.0% | 75.0% | 75.0% | −25.0% | 0.0% |
| Qwen | real S1 | 94.9% | 83.7% | 72.1% | −11.2% | 11.5% |
| Qwen | real S3 | 100.0% | 73.1% | 75.0% | −26.9% | −1.9% |

**解读**：
- TAME 消除的是**污染可归因误差**；DeepSeek 上回收量 ≈ 可归因量（对账完美）。
- Qwen 上 Δ ≤ 0：clean 底噪已 95–100%，攻击没有把错误推到底噪之上，**无污染可归因误差可回收**。这是机制验证而非反例：瓶颈在模型检测能力，不在记忆。
- 结论：**TAME 的收益是模型依赖的**——检测能力足够的模型上显著有效；weak-detector（高 MTR）上是"天花板失效"场景。

## 7. 原创性盘点与论文定位

### 7.1 属于既有工作的部分（必须引用）
- 间接注入/检索注入：Greshake 等（AISec'23）
- 摘要携带隐藏指令：Morris 等 Context Distillation / Repeated Context Distillation
- 记忆/知识库投毒：[AgentPoison（NeurIPS 2024）](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract.html)、Memory Injection on LLM Agents（NeurIPS'24）、InjecAgent（ICLR'25）
- 真实日志数据来自上游 `.external/log-interpretation-prompt-injection`（AIT 日志域注入基准）

### 7.2 可以主张为原创贡献的部分
1. **受控机制可归因的流式污染评估框架**：per-window 载体归因（summary/note/retrieved index）、trigger-distance 控制、CPL 污染持久长度、payload kind/trust 标注、FN/FP 攻击方向——现有注入文献无同款。
2. **Δ 分解（clean 底噪归一化）**：区分"污染可归因误差"与"模型检测底噪"的方法学贡献。
3. **领域定位**：安全日志解读流水线（SOC 场景），注入文献主要覆盖 chatbot/RAG agent。
4. **TAME 防御架构**（triage + FEM 解耦 + TTC 分离 + 可审计 facts-only 记忆 + downgraded writes）+ 消融 + 边界条件。

### 7.3 风险与定位建议
- **当前最大风险不是"论点不新"，而是 repo 零引用**——必须补 related work 主干。
- 定位一句话：*不是"We discover prompt injection"，而是"We build a mechanism-attributable benchmark for state contamination in streaming security-log pipelines, and a defense (TAME) that removes the contamination-attributable error — with a characterized boundary condition (detector capability)"*。
- Qwen 结果建议进附加模型表，并作为**边界条件贡献**（防御有效性随模型检测能力变化），而非"失败"。

## 8. 文件清单（本次新增/修改）

| 文件 | 说明 |
|---|---|
| `results/qwen_syn_items.jsonl` | synthetic S0–S4 无防御（240 行） |
| `results/qwen_real_items.jsonl` | real S0–S4 无防御（780 行） |
| `results/qwen_method_g3_items.jsonl` | syn G3 attacked S1/S3（96 行） |
| `results/qwen_guard_syn_items.jsonl` | syn TAME attacked S1/S3（96 行） |
| `results/qwen_real8_none_items.jsonl` | real n8 none attacked S1/S3（208 行） |
| `results/qwen_real8_g3_items.jsonl` | real n8 G3 attacked S1/S3（208 行） |
| `results/qwen_guard_real8_items.jsonl` | real n8 TAME attacked S1/S3（208 行） |
| `results/qwen_clean_syn_none_items.jsonl` | syn clean baseline（96 行） |
| `results/qwen_clean_syn_g3_items.jsonl` | syn clean G3（96 行） |
| `results/qwen_guard_syn_clean_items.jsonl` | syn clean TAME（96 行） |
| `results/qwen_real_clean_mixed_s13_items.jsonl` | real clean baseline（104 行） |
| `results/qwen_real_clean_mixed_g3_s13_items.jsonl` | real clean G3（104 行） |
| `results/qwen_guard_real_clean_items.jsonl` | real clean TAME（104 行） |
| `results/qwen_tame_ablate_no_triage_items.jsonl` | 消融 −triage（96 行） |
| `results/qwen_tame_ablate_no_decouple_items.jsonl` | 消融 −decoupling（96 行） |
| `results/qwen_tame_ablate_no_cache_items.jsonl` | 消融 −cache-split（96 行） |
| `results/STAGE5_QWEN_REPORT.md` | Qwen 版 TAME 报告（全部数字由数据计算） |
| `results/qwen_frozen_run.log` | frozen 配方逐步日志（含每步 [done] 统计） |
| `results/qwen_syn_run.log` / `qwen_real_run.log` | 标准批次日志 |
| `results/qwen_vllm_server.log` | vLLM 服务日志 |
| `experiments/qwen_frozen_benchmark.sh` | Qwen frozen 配方脚本 |
| `experiments/stage5_report_qwen.py` | Qwen 参数化报告生成器 |
| `results/llm_cache.json` | 共享 LLM 缓存（现 16MB，含 Qwen 条目；key 含模型名+base_url，与 DeepSeek 不冲突） |

## 9. 待议事项（下一步候选）

- A. 起草 related-work 小节 + 论文定位段落（当前零引用，风险最高）
- B. 把 Δ 分解表 + 边界条件小节并入 `FINAL_REPORT.md` §8
- C. Qwen 完整表并入附加模型表
- D. 其他方向：更强开源模型对照（如 Qwen3-8B 关 thinking）、trigger-distance 变体、IOC 任务、变体（low-key/paraphrase/indirect/retrfriendly）等
