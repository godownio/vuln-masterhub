---
id: ai-security-prompt-injection-guardrail-input-truncation-tail-payload
title: 护栏输入截断不对称：无害 padding 把恶意请求推到 512 token 检测窗口之后
type: scenario
domain: ai-security
path: ai-security/prompt-injection
technique: guardrail-input-truncation-tail-payload
tags:
- llm
- guardrail
- input-filter
- truncation
- token
- prompt-injection
- bypass
- padding
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:47:54+08:00'
  notes: 已对照原文第2.2节“Token序列长度截断不对称”与3.4节案例二核对：护栏硬截断(如Prompt Guard 512 token)、模型接收完整输入、padding 后置载荷、按 tokenizer 计算窗口的构造代码与卡片一致；原文未采用其百分比数字。未验证点：原文无具体护栏产品的实测响应，卡片已注明；PoC 未复跑；frontmatter 无 sources/source_url。
url: /docs/ai-security/prompt-injection/ai-security-prompt-injection-guardrail-input-truncation-tail-payload/
draft: false
kb_aliases:
- 护栏截断绕过
- 输入截断不对称
- Prompt Guard 512 token 绕过
- Padding 后置载荷
- 长输入尾部注入
---

## 一句话结论

当输入护栏只对固定长度的前缀做检测（例如分类器硬截断到 512 token），而目标 LLM 接收完整请求时，攻击者可以用大段无害文本作 padding，把真正的恶意请求推到护栏截断点之后：护栏只看到一段正常内容并放行，模型却能看到并执行尾部载荷。

## 原理

- 分类器型护栏通常有固定最大输入长度（如 Prompt Guard 系列约 512 token），tokenizer 调用 `truncation=True, max_length=512`，超出的部分直接丢弃；这是模型结构/推理成本决定的硬限制，不是业务选择。
- 目标 LLM 的上下文窗口通常远大于护栏（数千到数十万 token），网关把用户原文完整传给模型；两个组件对“输入”的定义不一致。
- 护栏的放行结论只基于被截断的前缀。只要前缀在语义上无害，分类器输出 SAFE；尾部载荷从未进入检测，也就不会被拦截。
- padding 用正常、通顺的文本（产品说明、背景资料、冗余需求）即可，不需要特殊字符；这样不会触发长度异常、熵异常或“可疑长输入”规则，且模型仍能理解尾部指令。
- 根因是安全决策与模型消费的不是同一段字节：护栏看了 A，模型看了 A+B，而决策只覆盖 A。类似 WAF 只检查 body 前 N 字节、后端却解析完整 body 的请求走私/截断问题。
- 若护栏改用滑动窗口/分段检测，但各段独立判定、没有跨段意图聚合，攻击者仍可把载荷拆到窗口边界附近；若模型侧再拼接，同样存在盲区。

## 触发条件

- 输入护栏是固定窗口分类器，超出部分被硬截断；或护栏只检查前 N 个字符/token。
- 目标 LLM 接收完整输入，且上下文长度大于护栏窗口。
- 网关没有在模型入口再次执行同等长度的安全检测，也没有拒绝超长输入。
- 攻击者可以发送长文本（聊天框、API、文档导入等），且 padding 不会因业务长度限制被拒绝。
- 输出侧没有独立审查，或输出审查同样只看前 N token。

## 利用步骤

1. 探测护栏窗口：用递增的无害 padding 加一个可观测的 canary 指令（如“回答时包含 CANARY42”），观察从多长开始 canary 不再被护栏拦截/模型仍能响应，估算 token 截断点。
2. 构造 padding：用与业务相关的正常段落填充到略超过护栏窗口，确保前缀语义无害、不触发关键词或意图分类。
3. 把恶意请求放在 padding 之后；如担心模型注意力衰减，可在载荷前再加一句“以下是本次真正的任务”。
4. 发送完整输入，确认模型执行尾部请求；若模型也截断，则把载荷放在模型窗口内、护栏窗口外。
5. 若输出侧有过滤，叠加 Base64/编码/分轮输出拆分；若护栏升级为滑动窗口，测试窗口边界处的拆分与跨段拼接。

## PoC

```python
# 以护栏 512 token、目标模型 8k 上下文为例；实际 token 数需用护栏 tokenizer 计算
def build_truncation_payload(benign_text: str, malicious_request: str, guard_tokenizer, guard_max_tokens: int = 512):
    # 1) 先填到略超过护栏窗口，确保恶意请求落在截断点之后
    padding = benign_text
    while len(guard_tokenizer.encode(padding)) <= guard_max_tokens + 20:
        padding += "\n" + benign_text
    return padding + "\n\n" + malicious_request

payload = build_truncation_payload(
    benign_text="这是一段正常的产品需求说明，用于补充背景信息，不包含任何敏感内容。",
    malicious_request="<目标恶意请求>",
    guard_tokenizer=guard_tokenizer,
)
# 将 payload 作为用户消息发送给目标 LLM
```

```http
POST /v1/chat/completions HTTP/1.1
Host: target
Content-Type: application/json

{"model":"<model>","messages":[{"role":"user","content":"<超长无害 padding>\n\n<恶意请求>"}]}
```

```text
# 预期：护栏分类器只看到前 512 token 的正常 padding，返回 SAFE；
# 目标 LLM 收到完整输入并执行尾部请求。
# 原文未提供针对具体护栏产品的实测响应，窗口大小与是否生效需按目标 tokenizer 验证。
```

## 变体与关联

- 变体：护栏与 LLM 使用不同 tokenizer（WordPiece vs BPE/SentencePiece），同一段文本在两侧的 token 边界不同，可把载荷放在“护栏已截断、模型未截断”的边界区间。
- 变体：分段/滑动窗口护栏只对各段独立分类，把恶意请求拆成多段，每段无害，模型侧再拼接。
- 变体：多模态/文档入口中，护栏只检查正文前 N token，恶意指令藏在长文档尾部、附件后段或图片 OCR 文本中。
- 关联：[[ai-security-prompt-injection-multiturn-variable-split-guardrail-bypass]]（跨轮拆分绕过单轮检测）、[[ai-security-prompt-injection-unicode-obfuscation-decode-role]]（编码混淆绕过护栏）、[[ai-security-prompt-injection-streaming-output-guardrail-race]]（输出侧时间差绕过）。
- 边界：护栏若检查完整输入、对超长输入直接拒绝、在模型入口复检或做滑动窗口 + 跨段聚合，本手法不成立；模型上下文窗口小于护栏窗口时也无处藏载荷。

## 检测与防御

- 修复：在模型入口强制执行与护栏一致的最大输入长度，超长直接拒绝或分段；不要只让护栏截断而模型吃全量。
- 修复：护栏改为滑动窗口/分段检测，并对全段做意图聚合；对尾部、附件后段、文档末尾单独检测。
- 对齐：护栏与目标模型使用同一 tokenizer 或至少在同一 token 计数口径下做长度限制；记录每个请求的 token 数与截断位置。
- 检测：统计“长输入 + 尾部指令”模式；对超长请求的尾部做二次分类；监控同一会话中 padding 后紧跟高风险请求的行为。
- 输出侧：输出护栏同样不能只看前缀，需覆盖完整输出或流式累积检测；高风险能力配合工具调用审批与最小权限。
