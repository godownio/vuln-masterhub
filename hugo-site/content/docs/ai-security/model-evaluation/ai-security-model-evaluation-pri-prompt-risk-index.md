---
id: ai-security-model-evaluation-pri-prompt-risk-index
title: PRI（Prompt Risk Index）LLM 安全防护量化评估：五维评分 + 多裁判 + 策略前后对比
type: scenario
domain: ai-security
path: ai-security/model-evaluation
technique: pri-prompt-risk-index-evaluation
tags:
- ai-security
- llm
- evaluation
- prompt-injection
- jailbreak
- guardrail
- metrics
- pri
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:38:58+08:00'
  notes: 已对照全文与 6 张图核对：五维（输出合规/目标遵循/红队样本脆弱度/机密与系统提示词抵抗力/可用性损失）各 0-100 分加权、三档阈值、规则+语义+人工多裁判、均值/P95/方差与拒答/误拒/延迟指标、策略变更前后同基准对比、示例“脱敏后偏离率降 28%而误拒增 4%”均与原文一致。原文仅给框架和示例数字，无完整数据集/权重公式/实现，卡内 confidence=medium、severity=low 与局限说明恰当；frontmatter 无 sources/source_url，按原文实际标注。无受影响版本，未 set-versions。未验证点：无 PoC 可复跑。
url: /docs/ai-security/model-evaluation/ai-security-model-evaluation-pri-prompt-risk-index/
draft: false
kb_aliases:
- Prompt Risk Index
- PRI 评分
- LLM 防护效果量化
- 越狱防护度量
- 提示注入防护评估
---

## 一句话结论

PRI（Prompt Risk Index）是一套面向企业 LLM 应用的防护效果量化框架：把输出合规、目标遵循、红队样本脆弱度、机密/系统提示词抵抗力、严格防护下的可用性损失五个维度各打 0–100 分并加权成综合分，用同一基准集在每次策略变更前后重复评测，以均值/P95/方差和拒答率/误拒率等运营指标对比，回答“防护是否真的变好、代价是什么”。

## 原理

- 大模型护栏的效果很难用“感觉”比较：关键词规则、语义分类器、RAG 脱敏、工具权限等策略各自上线后，安全性和可用性会同时变化，缺少统一刻度就无法做取舍。
- PRI 把“安全效果”拆成可观测维度：
  1. 输出是否偏离合规与守则；
  2. 模型是否按既定目标行事；
  3. 面对标准化红队样本的脆弱程度（越狱/注入成功率）；
  4. 对机密信息和系统提示词的抵抗力；
  5. 在更严格保护下的可用性损失（误拒/拒答/延迟）。
- 每个维度 0–100 分，按业务权重加权得到综合分；阈值分为“安全 / 需要关注 / 需要整改”三档。分数本身不是目的，目的是在同一数据集上形成可对比的趋势曲线。
- 为避免单一裁判偏差，采用多裁判：
  - 规则裁判做结构化校验（格式、敏感串、策略命中）；
  - 语义裁判用小模型/专用分类器判断意图与主题；
  - 人工抽样做边界 case 标注与误判纠正。
- 评测需要固定抽样分布，并同时记录拒答率、误拒率、响应延迟等运营指标；每次策略/模型/检索/工具权限变化后自动触发，输出与上一版对比报告。
- 文章给出示例：检索文本做指令脱敏后，越狱相关偏离率降低 28%，误拒只增加 4%，用这种“收益/代价”数据推动产品接受安全策略。

## 触发条件

- 企业已部署 LLM 应用（客服、知识问答、代码助手、Agent），并配置了至少一层输入/输出防护或 RAG/工具权限策略。
- 需要比较不同防护策略、模型版本、检索配置或工具权限配置的安全效果与可用性代价。
- 有一批可复用的评测样本：去害化的红队语料、真实业务场景问题、边界 case。
- 有规则/分类器/人工中的至少两种裁判能力，能记录拒答、误拒、延迟等指标。

## 利用步骤

1. 建立固定基准集：红队样本（角色扮演、规则覆盖、间接注入、工具诱导等）+ 真实业务问题 + 边界 case；样本分布固定，版本化管理。
2. 定义五个维度及权重（按业务风险调整），并为每维度设定评分细则与 0–100 分映射。
3. 搭建多裁判流水线：规则校验 → 语义分类器 → 人工抽样复核；记录每个样本的判定、置信度与最终决策。
4. 跑基线 PRI：当前策略下的均值、P95、方差，以及拒答率、误拒率、响应延迟。
5. 变更策略（如 RAG 指令脱敏、Pre-Guard 规则、工具二次确认）后，用同一基准集重跑，生成前后对比曲线。
6. 按“安全收益 / 可用性代价”决定是否灰度、回滚或继续优化；把边界 case 回流到基准集，形成持续迭代。

## PoC

无 PoC；可用如下评分记录结构落地：

```json
{
  "policy_version": "guard-v2",
  "dataset": "bench-2025-09",
  "dimensions": {
    "output_compliance": 0,
    "goal_adherence": 0,
    "redteam_robustness": 0,
    "secret_system_prompt_resistance": 0,
    "usability_loss": 0
  },
  "weights": [0.25, 0.2, 0.25, 0.2, 0.1],
  "metrics": {"mean": 0, "p95": 0, "variance": 0,
              "refusal_rate": 0, "false_reject_rate": 0, "latency_ms": 0}
}
```

## 变体与关联

- **A/B 与灰度**：按用户/业务/场景分批上线策略，分别计算 PRI，确认无回退后再全量。
- **自动化流水线**：每次代码提交/模型更新触发离线评测，生成与历史版本的对比报告；样本泄漏会破坏评测有效性（参见 [[ai-security-model-evaluation-test-set-csv-leak-overfit-bypass]]）。
- **关联**：[[defense-hardening-ai-agent-scene-boundary-tool-permission]]（四层加固思路）、[[ai-security-prompt-injection-multilayer-defense-bypass]]（防护被绕过的具体手法，可作为红队样本来源）、[[ai-security-rag-security-chunk-boundary-trust-context-loss]]（RAG 防护维度）。
- **局限**：PRI 的权重和阈值需要按业务标定；文章只给出框架与示例数字，未提供完整数据集/公式，落地时需自行校准。

## 检测与防御

- **本卡性质**：属于 LLM 安全防护的度量与运营方法，不是攻击面本身。
- **防御价值**：用统一基准和趋势曲线避免“加规则就算安全”的错觉；量化误拒/延迟代价，防止过度防护损害业务。
- **注意事项**：评测集要脱敏、去害化并防泄漏；多裁判要定期校准；PRI 只反映基准集覆盖范围内的风险，不能替代真实红队与应急响应。
