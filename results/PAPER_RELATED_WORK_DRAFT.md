# 论文素材草稿：定位段落 + Related Work（供审阅）

> 状态：**草稿**。英文段落可直接粘贴进论文；`[verify]` 标记处需核对原始出处后再定稿。
> 定位：本文不是"发现了 prompt injection"，而是 **"机制可归因的流式状态污染基准 + 可审计记忆防御（TAME）+ 边界条件刻画"**。

---

## 1. 引言定位段落（英文，可直接粘贴）

> **Abstract/Intro 定位（约 120 词）**
>
> Prompt injection is well known to compromise LLM-integrated applications through single-shot context. We study a more insidious failure mode in **streaming security-log interpretation pipelines**: an injection planted in one window persists through *state carriers* — summaries, analyst notes, and retrieval indices — and triggers a wrong verdict in a later window. We contribute (i) **a mechanism-attributable benchmark** that isolates contamination per carrier, controls trigger distance and attack direction, and separates *contamination-attributable error* from the model's own detection floor; (ii) **TAME**, a triaged, auditable, facts-only memory defense that removes exactly the contamination-attributable error on capable detectors (e.g. 34.7% → 35.4% recovery on synthetic S1 for the primary model family); and (iii) a **boundary condition**: on weak detectors whose clean-window miss floor already exceeds the attack-attributable error, memory defenses have nothing left to remove — a detector-ceiling regime we characterize empirically across model families.

## 2. Related Work（英文条目，中文注释）

### 2.1 注入攻击本体（已有，必须引用）
- **Indirect prompt injection** — Greshake et al., *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*, ACM AISec 2023. ［检索/工具/邮件内容里的隐藏指令。我们的攻击是其"状态化、多窗口延迟触发"特例。］
- **Context distillation** — Morris et al., *Context Distillation: Model Editing as a Stealthy Backdoor* (arXiv 2023)；*Repeated Context Distillation* (arXiv 2024). ［摘要/压缩文本可携带并传播隐藏指令——直接对应我们的 summary carrier 通道。］
- **Memory / knowledge-base poisoning** — Zhang et al., *AgentPoison: Red-Teaming LLM Agents via Poisoning Memory or Knowledge Bases*, NeurIPS 2024. ［[已核实](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract.html)；记忆/知识库后门投毒。］
- **Memory injection on agents** — Dong et al., *Memory Injection Attacks on LLM Agents via Query-Only Interaction (MINJA)*, NeurIPS 2024（arXiv:2503.03704）。［已核实；观察记录进 memory 后作为指令执行。］
- **Agent injection benchmark** — Zhan et al., *InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents*, ICLR 2025。［已核实（[OpenReview](https://openreview.net/pdf?id=2VmB01D9Ef)）；工具型 agent 的注入基准。］
- **Survey** — Liu et al., *Prompt Injection Attacks and Defenses in LLM-Integrated Applications* (arXiv 2023). ［攻击/防御分类法，可引作覆盖图。］

### 2.2 领域上游（数据来源，必须引用）
- **AIT log-domain injection benchmark** — "Adversarial Attacks against LLM-based System Log Interpretation"（本工作真实日志数据来源，`.external/log-interpretation-prompt-injection`）；底层数据集 **CAM-LDS**（[Zenodo 18861762](https://zenodo.org/records/18861762)）与 **AIT-LDSv2**（[Zenodo 19483937](https://zenodo.org/records/19483937)）。［仓库 README 只写 "We refer to our paper"，未给出论文标题——**需向上游作者索取论文引用**，待办。］

### 2.3 防御相关（对照引用）
- **输入过滤/输出护栏**：现有注入防御多为 prompt 层过滤或输出校验；TAME 的差异点在**记忆写入路径**（triage + FEM 解耦 + TTC 分离 + 可审计 downgrade），而非提示词层。
- **记忆卫生/审计**：[verify] 若引用 agent 记忆管理（如 MemGPT 的 memory hierarchy 概念），需说明 TAME 是安全导向的 facts-only 变体，且给出可审计信号。

## 3. 与已有工作的差异（我们的贡献点）

| 维度 | 已有工作 | 本文 |
|---|---|---|
| 攻击场景 | 单轮上下文注入；agent 工具链；RAG 知识库 | **流式多窗口 + 状态载体（summary/note/index）持久化 + 延迟触发** |
| 攻击测量 | 单一 ASR/成功率 | **per-carrier 归因 + trigger-distance 控制 + FN/FP 方向 + CPL 持久长度** |
| 评估口径 | 直接报攻击成功率 | **Δ = attacked − clean 底噪**：区分污染可归因误差与模型检测底噪 |
| 领域 | chatbot / RAG / 工具 agent | **安全日志解读流水线（SOC）**，真实日志 |
| 防御 | 提示词过滤、输入消毒 | **TAME**：记忆写入路径的三级处理 + 审计 + 降级写；并给出**适用边界（detector ceiling）** |

## 4. 中文要点备忘（写作时注意）

1. **别把攻击说成新发现**：引言一句 "prompt injection is well known; we study its stateful variant in a security domain" 即可，重心放基准/机制/防御/边界。
2. **Δ 分解是方法学卖点**：审稿人最可能问 "DASR 高是不是模型本身菜？"——Δ 表就是答案，主动写。
3. **Qwen 是边界条件贡献**：写成 "defense efficacy is conditional on detector capability"，并保留 real S1 的显著改善（p=0.004）与 clean utility +0.135 不受伤的证据。
4. **零引用是当前最大风险**：2.1/2.2 至少各引 2–3 篇；`[verify]` 项定稿前核对。
5. **数据来源必须致谢**：CAM-LDS / AIT-LDSv2（Zenodo）+ 上游仓库论文。

## 5. 待办
- [x] 核对 `[verify]` 条目（Memory Injection = Dong et al. NeurIPS'24 arXiv:2503.03704；InjecAgent = ICLR'25，均已核实）
- [ ] 补齐上游 AIT 论文引用（联系仓库/看其论文页）
- [ ] 决定是否补"中等强度开源模型"（如 Qwen3-8B thinking off）坐实边界曲线（约 1–1.5h）
- [ ] 把 §9 Δ 表并入论文主文（已入 `FINAL_REPORT.md` §9，改英文即可）
- [ ] §9.1 FP/FN 机制拆分表（GPT-5.4 over-triggering vs Qwen under-triggering）已入 `FINAL_REPORT.md`，并入论文时同步
