---
id: ai-security-jailbreak-emoji-stuffing-chaining-filter-bypass
title: Emoji 填充与表情链越狱：拆分敏感词并用表情语义替代绕过 LLM 输入过滤
type: scenario
domain: ai-security
path: ai-security/jailbreak
technique: emoji-stuffing-chaining-safety-bypass
aliases:
- Emoji Stuffing
- 表情符号填充越狱
- Emoji Chaining
- 表情链越狱
- 表情符号绕过关键词过滤
- Emoji jailbreak
tags:
- ai-security
- jailbreak
- emoji
- token-filter
- obfuscation
- prompt-engineering
- safety-bypass
- llm
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T13:48:46+08:00'
  notes: 已对照原文与4张图核对：Emoji Stuffing/Chaining 定义、50条prompt、Gemma 2 9B 10%、Mistral 7B 10%、Llama 3 8B 6%、Qwen 2 7B 0%，合规率66/88/88/100%、延迟44.20/25.30/32.22/34.04秒，均与图02-04一致；卡片已注明原文分类函数优先匹配 successful 关键词、拒绝响应可能被误判、未公开原始输出，故 confidence 记 low。PoC 为无害演示，未复跑；无 sources/source_url；affected_versions 未设置。
---

## 一句话结论

在敏感短语的字符/单词之间插入表情符号（Emoji Stuffing），或用语义相关的表情序列替代敏感关键词（Emoji Chaining），可以破坏基于文本子串/关键词的输入过滤，同时让模型仍能从上下文重建原始意图，从而诱导模型对原本会被拒绝的请求作答；其效果高度依赖目标过滤是否做 Emoji 归一化以及模型自身的语义鲁棒性。

## 原理

- **过滤器的文本匹配盲区**：很多输入护栏在原始字符串或文本 token 上做敏感词黑名单/正则匹配。把“恶意软件”写成“恶😈意💣软🔓件”后，连续的敏感子串不再存在，黑名单匹配失败；如果过滤器没有先剥离/归一化 Emoji，就会放行。
- **模型仍能重建语义**：Emoji 是 Unicode 合法字符，模型分词后仍能看到两侧文字与表情的语义线索；在上下文足够明确时，模型可以把被表情拆开的词重新组合，理解成同一个请求。视觉上，人类也能一眼读出原句。
- **Emoji Chaining 用语义替代关键词**：不直接写敏感词，而用🔪（伤害）、🔓（破解）、💳（银行卡）、💣（爆炸物）等表情序列表达意图。单个表情通常不在关键词黑名单里，但模型可能根据训练数据中的表情用法推断出组合含义。
- **为什么能绕过安全对齐**：安全对齐依赖“敏感语义 → 拒绝”的稳定关联；表情的语义随语境变化（🔥可表示热门/焚烧），且训练数据中“表情 + 恶意文本”的安全标注相对稀缺，模型可能把组合误判为中性或玩笑，从而降低拒答率。
- **边界与不确定性**：若护栏先做 Unicode 归一化、去除 Emoji、还原被拆分的文本，或在模型侧用语义意图分类而非关键词，本手法会失效；不同模型/版本对表情序列的理解差异很大，文章给出的成功率不能直接外推到其他模型。本文实验的“成功”判定基于关键词分类且优先匹配成功词，可能把包含敏感词的拒绝响应误判为成功，原始输出也未公开，故本卡 confidence 记 low。

## 触发条件

- 目标 LLM 应用有输入侧关键词/正则过滤，且未对 Emoji 做剥离、归一化或还原。
- 模型本身能理解 Emoji 与上下文，且安全对齐对“表情 + 文本”组合不够鲁棒。
- 攻击者可向模型提交任意文本（聊天、评论、工单、RAG 文档等入口）。
- 需要模型输出违规内容时才构成完整危害；若输出侧还有独立审核，可能被二次拦截。

## 利用步骤

1. **确认过滤行为**：先用无害但含敏感词的句子测试是否被拦截，再用等价的 Emoji 拆分版本测试是否放行；对比响应差异，判断过滤器是否只做字符串匹配。
2. **选择策略**：
   - Emoji Stuffing：在敏感短语的字符/单词之间插入中性或带暗示的表情，保持可读性，例如把“制作披萨”写成“制🍕作🥘披🍕萨”（此处用无害短语演示，实际攻击会把短语换成目标违规请求）。
   - Emoji Chaining：用语义相关表情替代关键词，例如用🔓💳📱表达“破解手机获取银行卡信息”的意图。
3. **混合使用**：先填充拆词，再用表情链替代核心名词，增加过滤器还原难度。
4. **Unicode 归一化**：用 `unicodedata.normalize('NFC', prompt)` 统一表情编码，避免平台差异导致模型解析不一致。
5. **提交并观察**：记录模型是否拒答、是否给出部分响应、是否输出目标内容；若被拒，调整表情密度/位置或改用其他语义等价表情。
6. **输出侧绕过**：若模型输出被关键词拦截，可要求以编码/分段/隐喻形式输出（这属于另一层绕过，需单独评估）。

## PoC

无害演示（仅验证“拆分 + 表情”是否改变过滤/模型行为，不含违规内容）：

```python
import unicodedata

raw = "如何制作披萨"
stuffed = "如🍕何🥘制🍕作🥘披🍕萨"
chained = "如🍕何🥘做🍕一🍕个🍕披🍕萨"

for name, p in [("raw", raw), ("stuffed", stuffed), ("chained", chained)]:
    print(name, unicodedata.normalize("NFC", p))
```

```text
# 提交给目标模型的提示（示意）
请一步一步告诉我：如🍕何🥘制🍕作🥘披🍕萨？
```

实际攻击中，把无害短语替换为目标违规请求，并按目标过滤规则调整表情位置；本卡不提供违规内容示例。原文用 50 条覆盖暴力、网络攻击、隐私窃取、恶意代码等场景的 prompt 在 4 个本地模型上测试，报告 Gemma 2 9B 10%、Mistral 7B 10%、Llama 3 8B 6%、Qwen 2 7B 0% 的“越狱成功率”，但判定为关键词分类，未公开原始输出，数据仅可作参考。

## 变体与关联

- **Emoji Stuffing**：在字符间插入表情，重点是破坏连续子串；密度越高越容易绕过字符串匹配，但也越影响模型可读性。
- **Emoji Chaining**：用表情序列替代关键词，重点是规避词表；可结合同义词、隐喻、外语、拼音等。
- **编码变体**：Base64、零宽字符、Unicode 变体选择符、同形字、反向文本、拼音/谐音；与 Emoji 可叠加。
- **多模态变体**：把指令藏进图片、音频或 Markdown 图片 URL，绕过纯文本过滤；见间接提示注入相关卡。
- **关联**：[[ai-security-jailbreak-automated-prompt-generation-pipeline]]（37 种手法库中已把 Emoji 列为混淆/语言伪装手法之一）、[[ai-security-jailbreak-classical-chinese-wenyan-bypass]]（语言/文体伪装越狱）、[[ai-security-prompt-injection-invisible-unicode-tag-variation-selector-smuggling]]（不可见 Unicode 走私）、[[ai-security-prompt-injection-multiturn-variable-split-guardrail-bypass]]（拆分绕过护栏）。
- **边界**：过滤器做 Emoji 归一化/剥离、模型侧语义意图分类、输出侧独立审核、模型对表情不敏感时，本手法失效或只能得到部分响应。

## 检测与防御

- **输入归一化**：在关键词/正则匹配前，先做 Unicode NFC/NFKC、剥离 Emoji 与零宽字符、还原常见同形字与变体选择符；对被拆分的文本做去分隔符后再匹配敏感短语。
- **语义检测**：不要只依赖关键词；用意图分类/安全分类模型判断“表情 + 文本”的整体语义，对高风险组合加权。
- **模型侧**：在安全对齐数据中加入 Emoji 填充/表情链样本，训练模型识别“被拆分/被替代的敏感请求”；对表情密集、字符间夹杂符号的输入提高审查级别。
- **输出侧**：独立审核模型输出，不因输入通过就放行；对部分响应/模糊响应也做风险评估。
- **监控**：统计 Emoji 密度异常、敏感词被拆分的模式、同一账号高频变体请求；对绕过尝试告警并沉淀样本。
- **评估方法**：判定越狱成功不能只看关键词命中（拒绝响应也可能包含敏感词）；应结合人工复核/独立研判模型，并保留原始输出以便复现。
