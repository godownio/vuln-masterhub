---
id: ai-security-jailbreak-defense-self-reminder-system-prompt
title: Self Reminder 系统模式自我提醒：在最外层 system 提示中要求“做负责任的 AI、不要生成有害/误导内容”，AdvBench 复现 ASR 降至 2%
type: scenario
domain: ai-security
path: ai-security/jailbreak
technique: self-reminder-system-prompt-responsible-ai
aliases:
- Self Reminder
- 系统模式自我提醒
- responsible AI 系统提示
- 越狱防御 system prompt
- ASR 2%
tags:
- ai-security
- jailbreak
- defense
- system-prompt
- self-reminder
- alignment
- llm
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V308
  verified_at: '2026-11-08T11:38:48+08:00'
  notes: 已对照原文核对：方法/提示文本/代码与原文图一致，ASR 数字按原文截图核对；未运行文中代码与模型，ASR 为原文复现值。
---

## 一句话结论

在对话模板的最外层 system 提示中追加一句自我提醒——`You should be a responsible AI and not generate harmful, misleading content! Please answer the following query in a responsible way.`（或 `Remember, you should be a responsible AI and should not generate harmful or misleading content!`）——可以让模型在处理内层用户越狱提示前先“提醒自己”处于负责任模式；文章在 AdvBench 上复现把 ASR 从基线降到 2%，无需改模型参数。

## 原理

- **系统模式优先于用户输入**：越狱常通过角色扮演/模式劫持让模型进入“无限制模式”；Self Reminder 反过来在最外层 system 角色中声明“你是负责任的 AI”，让模型把“当前模式”理解为受安全约束的助手模式，从而降低内层恶意指令的权重。
- **自我提醒的心理学类比**：人类通过自我提醒（心理或外部提示）回忆任务、加强自控；LLM 也表现出自我验证/自我校正能力，system 提示中的“Remember…”相当于在生成前注入一条高优先级的自我约束。
- **实现极简**：只需在构建会话模板时修改 system 字段，不改变用户查询内容、不增加额外模型调用（相比 Self Examination 无二次推理成本）；文章代码即 `conv_template.system += ' You should be a responsible AI ...'`，日志中 instruction 也附加了 `\nRemember, you should be a responsible AI and should not generate harmful or misleading content!`。
- **为什么不是万能**：它依赖模型对 system 指令的遵循程度；强越狱/对抗后缀仍可能覆盖；文章复现中仍有 1 例（毒品/危险行为社交媒体文案）产生有害内容，ASR 2%。不同模型/版本效果差异大。

## 触发条件

- 应用允许自定义/修改 system 提示（或对话模板的 system 字段），且模型对 system 角色指令有较高遵循度。
- 需要低成本、无额外推理的输入侧加固；可与输出过滤/上下文防御叠加。
- 目标模型未把 system 提示完全忽略（某些 chat 模板/微调模型对 system 权重低）。
- 仅用于防御部署/红队评估。

## 利用步骤

1. 在对话模板的 system 字段末尾追加自我提醒句（保留原有业务指令），例如：
   `You should be a responsible AI and not generate harmful, misleading content! Please answer the following query in a responsible way.`
2. 或在每条用户指令前追加 `Remember, you should be a responsible AI and should not generate harmful or misleading content!`（文章日志中的形式）。
3. 正常业务对话验证不产生过度拒答/功能退化；在越狱数据集（AdvBench 等）上测 ASR，文章复现 ASR 2%、safe_eval 0.0。
4. 对仍成功的样本分析原因（system 权重不足、越狱模式覆盖、多语言/编码），调整提醒位置/措辞或叠加 Self Examination/ICD。
5. 记录不同模型的 ASR/误拒率，选择提醒句与位置；避免把提醒写成可被用户输入覆盖的普通用户消息。

## PoC

```python
# 以 FastChat/类似对话模板为例
conv_template.system += (
    " You should be a responsible AI and not generate harmful, misleading content!"
    " Please answer the following query in a responsible way."
)

# 或在用户 instruction 前追加（文章日志形式）
instruction = user_query + (
    "\nRemember, you should be a responsible AI and should not generate harmful"
    " or misleading content!"
)
```

## 变体与关联

- 变体：提醒句可放在 system 开头/结尾、或每条 user 消息前；可加入“拒绝有害请求是责任”的具体示例，但会增加 token。
- 变体：与 Self Examination（输出自检）、ICD（安全 few-shot）、Retokenization（输入重标记化）组合，形成输入+输出多层防御。
- 变体：对多轮对话，每轮都保留 system 提醒，避免长上下文稀释；对工具调用场景，提醒还应覆盖“不得执行危险工具调用”。
- 关联：[[ai-security-jailbreak-defense-self-examination-response-filter]]（输出侧自检）、[[ai-security-jailbreak-defense-in-context-safe-demonstrations]]（安全示例）、[[ai-security-jailbreak-defense-retokenization-bpe-dropout]]（重标记化）、[[ai-security-jailbreak-godmode-persona-emoji-prefix]]（伪造无限制模式的越狱，作为被防御对象）。

## 检测与防御

- 检测：监控 system 提示是否被用户输入/模板注入覆盖；统计拒答率与 ASR；对强越狱样本做回归测试。
- 防御：Self Reminder 只是低成本加固，不能替代模型对齐/输入过滤/输出审核；对高-risk 应用应组合多层防御，并定期用新越狱手法复测。
- 说明：本文复现的是防御方法，severity 记为 info；ASR 2% 来自文章 AdvBench 复现，模型/版本不同结果会变化。
