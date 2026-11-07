---
id: ai-security-model-extraction-agent-tool-call-distillation
title: AI Agent 能力蒸馏：批量 API 查询复制工具调用与中间步骤
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: agent-tool-call-capability-distillation
tags:
- ai-security
- model-extraction
- agent
- distillation
- tool-calling
- behavior-cloning
- api-abuse
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T09:52:35+08:00'
  notes: 已通读全文（无图片）核对：Agent 蒸馏的 (query,response,tool_calls,intermediate_steps) 采集、5万查询/92%工具调用/85%任务完成数字、检测与防御逻辑均与原文一致；卡内已如实标注原文为综述/伪代码、无目标与数据集、PoC 不可运行、confidence low。未验证点：原文实验数字无法独立验证，未复跑；属能力蒸馏技术而非可直接复现漏洞。受影响版本不适用，未设置。
url: /docs/ai-security/model-extraction/ai-security-model-extraction-agent-tool-call-distillation/
draft: false
kb_aliases:
- Agent 蒸馏攻击
- 工具调用能力克隆
- 行为克隆窃取 Agent
- API 查询蒸馏
---

## 一句话结论

攻击者不用接触模型权重，只需通过目标 Agent 的 API 发起大量多样化查询，收集 `(query, response, tool_calls, intermediate_steps)` 对，再用监督学习/行为克隆训练学生 Agent，就能复制其工具调用与任务完成能力；原文引用实验称 5 万次查询可复制约 92% 的工具调用准确率、85% 的任务完成能力。

## 原理

- Agent 的 API 响应通常不只是最终答案，还包含工具选择、参数、工具返回、中间步骤等元数据；这些正是行为克隆所需的高质量标签。
- 模型蒸馏/模型提取的核心是“输入-输出对”监督：教师模型的输出分布/轨迹可以被学生模型拟合；查询覆盖越广、多样性越高，学生复制能力越强。
- 工具调用能力比纯文本生成更适合蒸馏，因为工具名、参数结构、调用顺序是离散、可枚举的标签；学生只需学会在相似上下文下选择相同工具和参数。
- 攻击从 API 日志看只是“大量正常查询”，没有明显 payload；检测需要分析查询模式、响应相似度、工具调用频率和查询多样性。
- 原文给出的实验数字（5 万查询、92%/85%）是综述引用，未给出目标模型、数据集与复现细节，因此本卡置信度标 low。

## 触发条件

- 目标 Agent 暴露可批量调用的 API，且响应包含最终答案；若还返回 `tool_calls`/`intermediate_steps`，蒸馏效果更好。
- 攻击者能生成覆盖目标工具/参数空间的多样化查询，且没有严格速率限制、配额或查询行为检测。
- 学生模型/Agent 可训练（本地或第三方），并能获得足够算力。
- 目标的使用条款/技术措施未禁止模型提取，或攻击者愿意绕过。

## 利用步骤

1. 枚举目标 Agent 的工具与能力：从 API 文档、错误消息、响应中的工具名/参数结构推断。
2. 构造多样化查询生成器：覆盖每个工具、参数范围、边界条件、多步任务和失败路径。
3. 批量调用目标 API，保存 `query`、`response`、`tool_calls`、`intermediate_steps`（若有）及时间戳。
4. 清洗/规范化数据：去掉敏感信息、统一工具名/参数格式，划分训练/验证集。
5. 用 SFT/行为克隆训练学生 Agent；损失可同时监督最终答案和工具调用序列。
6. 在留出集上评估工具调用准确率、任务完成率、参数匹配度；针对失败样本补充查询并迭代。
7. 部署学生 Agent，或仅提取特定高价值技能（如数据库查询、文件操作、邮件发送）。
8. 若目标隐藏了中间步骤，可只用最终答案做蒸馏；效果下降，但可通过更多查询和更强学生模型补偿。

## PoC

```python
# 结构性伪代码：原文为综述示意，未提供可运行目标/PoC
training_data = []
for q in query_generator.generate(num_queries=50000):
    r = target_agent.execute(q)
    training_data.append({
        'query': q,
        'response': r.final_answer,
        'tool_calls': r.metadata.get('tool_calls'),
        'intermediate_steps': r.metadata.get('steps'),
    })

student_agent.train(training_data)
similarity = evaluate(student_agent, target_agent, test_set)
print('tool_call_accuracy / task_success:', similarity)
```

```text
无完整可执行 PoC：需要目标 Agent API、查询生成器与学生模型；
原文只给出示意代码与引用实验数字，未提供目标/数据集/复现脚本。
```

## 变体与关联

- 变体：只蒸馏单一技能（如 SQL 生成、文件读取、邮件发送），减少查询量、提高针对性。
- 变体：主动学习/不确定性采样，优先查询学生最不确定的样本，提高查询效率。
- 变体：若 API 不返回工具调用元数据，可用最终答案 + 响应时间/错误模式做弱监督；或先通过提示注入诱导目标泄露工具 schema。
- 关联卡片：[[ai-security-model-extraction-encrypted-reasoning-replay-cot-theft]]（跨会话重放窃取思维链）、[[ai-security-agent-security-capability-closure-tool-memory-identity]]（Agent 能力闭包与工具/记忆/身份）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（权重水印提取）。
- 边界：强速率限制、查询多样性检测、响应水印、隐藏中间步骤、模型访问审批都会降低蒸馏效果；原文数字未独立验证。

## 检测与防御

- 检测：监控 API 日志中的高 volume、低多样性/高覆盖率查询、重复模板、异常工具调用频率；比较不同账号的查询分布与学生模型输出相似度。
- 防御：速率限制/配额、查询多样性异常检测、返回最小化（不返回 tool_calls/intermediate_steps）、输出水印/指纹、使用条款与访问审批、差分隐私/输出扰动。
- 加固：对高价值 Agent 只暴露必要工具与最小权限；对批量查询做账号级行为基线；对模型提取行为做法律/合同约束。
- 边界：蒸馏只能复制行为，不一定复制内部推理/知识；学生模型在分布外查询上可能显著退化。
