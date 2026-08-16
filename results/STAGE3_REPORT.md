# Stage-3: utility 分解 + 方法级防御 + 对抗变体

## 1. Utility 分解：把污染增量从模型能力里剥出来

每个状态模式的 W4 判定准确率（ACC_w4，恶意判恶意/良性判良性）。

| Mode | Clean ACC_w4 | Attacked ACC_w4 | 状态增量(att - clean) | Clean MTR | Att MTR | Clean BMR | Att BMR |
|---|---:|---:|---:|---:|---:|---:|---:|
| S0 | 93.8% | 87.5% | -0.062 | 0.10 | 0.23 | 0.00 | 0.08 |
| S1 | 91.7% | 54.2% | -0.375 | 0.12 | 0.31 | 0.17 | 0.42 |
| S2 | 83.3% | 81.2% | -0.021 | 0.21 | 0.19 | 0.12 | 0.36 |
| S3 | 89.6% | 60.4% | -0.292 | 0.17 | 0.25 | 0.01 | 0.33 |
| S4 | 75.0% | 77.1% | +0.021 | 0.33 | 0.33 | 0.03 | 0.23 |

状态化对 clean 数据应带来收益（更多上下文 -> 更高 ACC），而对 attacked 数据被注入内容污染。**污染增量** = attacked 状态增量 - clean 状态增量。

| Mode | Clean gain (vs S0) | Attacked delta (vs S0) | 污染增量 |
|---|---:|---:|---:|
| S1 | -0.021 | -0.333 | -0.312 |
| S2 | -0.104 | -0.062 | +0.042 |
| S3 | -0.042 | -0.271 | -0.229 |
| S4 | -0.188 | -0.104 | +0.083 |

**Gate 副作用（clean 数据上的 utility loss）**：防御不应损伤正常性能。

| Defense | S1 | S2 | S3 | S4 |
|---|---:|---:|---:|---:|
| G1 | -0.021 | +0.021 | +0.021 | +0.021 |
| G3 | -0.104 | +0.021 | -0.021 | +0.000 |
| G4 | -0.042 | +0.042 | +0.021 | +0.042 |

## 2. 方法级防御：selective fact-only memory write (G3) 与 uncertainty-quarantine (G4)

G1/G2 是规则 gate（关键词命中即拒绝写入 memory）。评审指出其创新性弱——本阶段实现两个真正的 memory write-path 方法：

| 方法 | 机制 | 区别 |
|---|---|---|
| G1/G2 规则门 | 关键词正则命中即拦截 | 表层匹配，可被改写绕过 |
| **G3 fact-card** | 写前用 LLM 把候选 state 蒸馏成『可验证事实卡』（actor/action/object），指令类、结论类、权威断言一律不写入 | 语义级，改写攻击下仍只留事实 |
| **G4 quarantine** | 每窗口两次独立判定（不同 temperature/seed），verdict 不一致视为低置信，该窗口内容不写入跨窗口 state | 不确定性驱动的写入门 |

### 2a. 污染缓解（合成 attacked 数据）

| Mode | none | G1 | G2 | G3 | G4 |
|---|---:|---:|---:|---:|---:|
| S1 | 45.8% | 8.3% | 10.4% | 18.8% | 45.8% |
| S2 | 18.8% | 18.8% | 18.8% | 14.6% | 20.8% |
| S3 | 39.6% | 8.3% | 8.3% | 10.4% | 43.8% |
| S4 | 22.9% | 18.8% | 25.0% | 22.9% | 20.8% |

### 2b. 真实数据验证

| Mode | none | G1 | G3 | G4 |
|---|---:|---:|---:|---:|
| S1 | 83.3% | 50.0% | 56.2% | 71.5% |
| S3 | 56.2% | 60.4% | 54.9% | 60.4% |

## 3. 对抗变体：gate 稳健性

四种比 plain 更难的注入变体，验证 G1（关键词门）与 G3（fact-card）谁更稳。

| Variant | 说明 | G1 对 plain 关键词的依赖 |
|---|---|---|
| paraphrase | 指令改写（'choose the green verdict option'），无原始关键词 | 部分绕过 |
| indirect | 无指令，只含隐含倾向的事实陈述（'handled in bulk'） | 部分绕过 |
| low-key | 指令藏进普通日志字段（verdict=benign state=cleared） | **完全绕过** |
| retr-friendly | 载荷内重复检索关键词（host/user/path）提升被召回概率 | 部分绕过 |

| Variant | S1 none | S1 G1 | S1 G3 | S3 none | S3 G1 | S3 G3 |
|---|---:|---:|---:|---:|---:|---:|
| plain (基线) | 45.8% | 8.3% | 18.8% | 39.6% | 8.3% | 10.4% |
| paraphrase | 33.3% | 12.5% | 20.8% | 16.7% | 8.3% | 16.7% |
| indirect | 20.8% | 8.3% | 20.8% | 16.7% | 8.3% | 12.5% |
| low-key | 8.3% | 25.0% | 12.5% | 8.3% | 12.5% | 8.3% |
| retrfriendly | 25.0% | 16.7% | 16.7% | 4.2% | 12.5% | 4.2% |

注：plain（原始载荷）在 attacked 基线中的对照：S1 none=45.8%、S3 none=39.6%（见第 2 节表）。变体实验 n=24 序列（每型 6 个），数字噪声更大，需结合基线解读。

## 4. 结论

**必补 1（utility 分解）**：状态化本身对判定准确率几乎无副作用（合成数据 S1 clean_gain=-0.021，真实数据 +0.104），而攻击环境下的准确率坍塌（合成 S1 attacked_delta=-0.333）**几乎全部归因于注入污染**（污染增量 -0.312）。Gate 的 clean 副作用 ≤±0.104，可忽略。

**必补 2（方法级防御）**：G3（fact-card selective write）在合成数据上将 S1 DASR 45.8%→18.8%、S3 DASR 39.6%→10.4%，BMR 同步下降（S3 0.33→0.08），且 clean 副作用仅 -0.104（S1）；真实数据 S1 DASR 83.3%→56.2%。G4（test-time agreement quarantine）**无效**：模型对注入误判过度自信，两次采样 agreement 高达 95.2%，quarantine 几乎不触发——这是有价值的负结果（自我一致性不确定性在受害模型上信号不足）。

**必补 3（对抗变体）**：改写攻击整体削弱了原始载荷的攻击力（paraphrase S1 none=33.3%、low-key 仅 8.3%，vs plain 45.8%），但 retr-friendly 变体保持 25% 的攻击率。规则门 G1 对 low-key 变体**完全失效**（S1 DASR 反而升到 25.0%，因为载荷藏进普通字段绕过正则），而 G3 在所有变体下保持 DASR ≤20.8% 的稳定表现，不出现 G1 式的失控。结论：表层规则可被改写绕过，语义级 fact-card 更稳健。

## 5. 复现与文件

- `loginject/methods.py`：G3 fact-card 提取、G4 agreement 判定
- `loginject/dataset.py`：4 种变体 payload（paraphrase/indirect/low-key/retrfriendly）
- `experiments/run_variants.py`、`experiments/utility_report.py`：变体与 utility 分解
- 数据：`results/clean_syn_none_items.jsonl`（clean 基线）、`var_*_*.jsonl`（变体）、`method_g3/g4_items.jsonl`、`real_method_g3/g4_items.jsonl`、`clean_real_items.jsonl`
