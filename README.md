# loginject_stream_experiments

受控的**流式状态污染（state contamination）评估框架 + TAME 防御**实验仓库。

针对"多窗口流式日志解读流水线"（SOC 场景）中，注入内容经状态载体（summary / analyst note / retrieval index）跨窗口持久化并在后续窗口触发错误判定的问题，提供：

- 机制可归因的基准（per-carrier 污染归因、trigger-distance 控制、FN/FP 攻击方向、CPL 污染持久长度、payload kind/trust 标注）
- 可审计记忆防御 **TAME**（Triage + FEM 解耦 + TTC 分离 + facts-only 永久记忆 + downgraded/blocked 写入 + 快照回滚接口）
- **Δ 分解**（attacked DASR − clean 漏报底噪 = 污染可归因误差）与 **FP/FN 机制拆分**（区分"注入放大的误报型"与"检测天花板漏报型"失败模式）

## 目录结构

```
loginject/          核心库：dataset / harness / guard(TAME) / methods(G3,G4) / eval / llm / real_dataset
experiments/        运行与报告脚本：run_all.py, frozen_benchmark.sh, stage5_report*.py, stats_ci.py ...
results/            冻结结果 + 报告（见下）
.external/          上游 AIT log 注入基准（自动拉取，不入库）
```

## 快速开始

```bash
# 1) 数据/依赖准备（需要 /root/.diffagent_api.env 提供 LLM API 配置）
bash experiments/setup_repro.sh

# 2) 跑 frozen TAME 基准（DeepSeek 主族）
bash experiments/frozen_benchmark.sh

# 3) 本地开源模型复现（Qwen2.5-7B-Instruct，vLLM，thinking 关）
bash experiments/qwen_frozen_benchmark.sh

# 3b) Qwen3-14B 复现（/root/autodl-tmp/Qwen3-14B，vLLM + FP8，thinking 关）
#     先启动服务：vllm serve /root/autodl-tmp/Qwen3-14B --host 0.0.0.0 --port 8000 \
#       --served-model-name Qwen3-14B --max-model-len 16384 --gpu-memory-utilization 0.92 \
#       --quantization fp8 --chat-template experiments/qwen3_no_thinking.jinja
bash experiments/qwen3_frozen_benchmark.sh
```

LLM 接入复用 `loginject/llm.py` 的 OpenAI 兼容客户端，通过环境变量切换端点：
`DEEPSEEK_BASE_URL` / `DEEPSEEK_MODEL` / `DEEPSEEK_API_KEY`，**不设置** `DEEPSEEK_REASONING_EFFORT`（thinking 关闭，避免破坏 JSON 输出）。

## 关键结果（见 results/ 各报告）

| 文件 | 内容 |
|---|---|
| `results/FINAL_REPORT.md` | 主表 + 附加模型表（6 家族）+ §9 Δ 分解 + §9.1 FP/FN 机制拆分 |
| `results/STAGE5_REPORT.md` | DeepSeek 主族 TAME 报告 |
| `results/STAGE5_QWEN_REPORT.md` | Qwen2.5-7B TAME 复现报告 |
| `results/STAGE5_QWEN3_REPORT.md` | Qwen3-14B TAME 复现报告（vLLM + FP8，thinking 关，`results/qwen3_*`） |
| `results/QWEN_FULL_REPRO_SUMMARY.md` | 本地 Qwen 全量复现工作总结 |
| `results/PAPER_RELATED_WORK_DRAFT.md` | 论文定位段落 + related work 草稿 |

核心结论：TAME 消除**污染可归因误差**（DeepSeek 主族回收量≈可归因量）；在检测能力弱的模型上（Qwen2.5-7B，clean 漏报底噪 ~100%）无可归因误差可回收——这是 **detector-ceiling 边界条件**，而非防御失效。

## 复现与统计

- `experiments/frozen_benchmark.sh`：frozen TAME 全量配方
- `experiments/qwen_frozen_benchmark.sh`：Qwen 版（输出 `results/qwen_*`）
- `experiments/stats_ci.py`：bootstrap CI + 配对 sign test
- 所有 run_all 输出为 jsonl，可断点续跑（`--redo-unknown` 重跑 unknown 行）

## 致谢/数据来源

真实日志数据来自上游 [log-interpretation-prompt-injection](https://github.com/)（CAM-LDS [Zenodo](https://zenodo.org/records/18861762)、AIT-LDSv2 [Zenodo](https://zenodo.org/records/19483937)），详见 `.external/` 内 README。
