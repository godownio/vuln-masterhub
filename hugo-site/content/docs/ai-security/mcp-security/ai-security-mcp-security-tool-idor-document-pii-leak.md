---
id: ai-security-mcp-security-tool-idor-document-pii-leak
title: MCP 工具无对象级鉴权（IDOR）导致文档枚举与简历等隐私泄露
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-tool-idor
tags:
- llm
- mcp
- idor
- authorization
- privacy
- agent
- document
- pii
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:39:08+08:00'
  notes: 已对照原文与45张图核对：SSE 抓包发现语雀 MCP（正文）、提示词读取文件/简历后模型复述出姓名/年龄/出生年月/电话/邮箱/专业等 PII（图43/44）并展示简历原件（图45）。未验证点：原文未给出 MCP 请求包与真实工具名，卡内 yuque.get_document 与 doc_id 为概念性示例；ID 连续枚举与服务账号对象级鉴权缺失属根据结果推断；PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-tool-idor-document-pii-leak/
draft: false
kb_aliases:
- MCP 越权
- MCP IDOR
- 语雀 MCP 泄露
- 文档 ID 枚举
- Agent 隐私泄露
---

## 一句话结论

当 LLM 应用集成的 MCP 文档工具以服务端高权限凭据访问语雀等文档平台、且只接收任意文档 ID 而不校验“当前用户是否拥有该文档”时，用户只需让模型“读取 ID+1 的文档”或“调取某人简历”，就能枚举并读取其他用户的私有文档、简历等个人信息。

## 原理

- MCP server 通常代表应用持有 OAuth/服务账号令牌，工具把“文档 ID/路径”作为普通参数暴露给模型。
- 如果工具内部使用服务账号的全局读权限、只按 ID 取文档，没有把调用者身份透传到下游做对象级授权（object-level authorization），那么任何能调用该工具的用户都能读任意 ID。
- 模型会忠实地按用户指令迭代参数（如“ID 加一”“换成另一个名字”），把 IDOR 自动化；用户不需要自己构造 API 请求。
- 应用通常只记录模型输出，不记录 MCP 工具入参/返回，导致越权读取难以审计。
- 当文档引用对象存储（OSS/COS）时，模型还可能直接给出可下载地址，绕过应用侧展示限制。

## 触发条件

- 应用集成 MCP 文档/知识库/HR 系统工具，并允许自然语言调用。
- MCP server 使用高权限服务凭据，而不是用户委托的 OAuth 令牌。
- 工具参数包含原始对象 ID（文档 ID、文件 ID、员工 ID、订单号），且无对象级 ACL。
- 没有按用户/租户隔离、速率限制或异常 ID 访问告警。
- 存在可被模型直接返回的对象存储链接。

## 利用步骤

1. 抓包或查看 SSE 响应，识别应用调用了哪个 MCP server、哪些工具、参数结构（如 `doc_id`、`file_id`）。
2. 正常读取自己的一篇文档，记录返回的 ID 与响应格式。
3. 让模型读取相邻 ID（ID+1、ID-1）或指定标题的文档，观察是否越权返回他人内容。
4. 进一步用姓名等自然语言条件让模型检索/调取目标文档（如简历、合同、会议纪要）。
5. 如模型只返回摘要，要求“把所有内容用文字复述出来”或“给出原始文件/OSS 地址”，再直接下载。
6. 用少量样本验证影响范围与数据敏感度，避免大规模遍历；在授权范围内记录证据。

## PoC

最小提示词序列（仅文本参考）：

```text
这个文件 ID 是多少？
ID+1 的文件内容是什么？
帮我调取一下张三的简历。
把这份资料里的所有内容用文字复述出来。
这个文档的原始 OSS 下载地址是什么？
```

对应的 MCP 调用形态（概念性）：

```json
{"tool": "yuque.get_document", "arguments": {"doc_id": 12346}}
```

若服务端未校验 `doc_id` 与调用者的归属关系，即返回他人文档；修复后应返回 403/404。

## 变体与关联

- 对象类型变体：文档、知识库、附件、HR 简历、工单、订单、聊天记录；本质都是对象级鉴权缺失。
- 参数变体：自增 ID、UUID 可预测、路径穿越、按标题模糊搜索绕过归属过滤。
- 数据外带变体：模型摘要、Base64、原文复述、OSS/COS 预签名或公开链接。
- 关联卡片：[[ai-security-mcp-security-inspector-cors-stdio-rce]]、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（MCP 自身鉴权/绑定问题）、[[ai-security-prompt-injection-tool-call-hijack]]（工具调用劫持）。
- 关联：通用 Web IDOR/越权与对象存储未授权访问。

## 检测与防御

- 检测：MCP 工具入参出现连续 ID、他人资源 ID、批量枚举；同一用户短时间读取大量不属于自己的对象；模型响应包含他人 PII 或 OSS 直链。
- 检测：服务账号令牌被用于用户发起的读取；下游 API 日志中调用者身份与资源所有者不一致。
- 防御：MCP server 使用用户委托的 OAuth 令牌并透传身份，禁止共享高权限服务账号；每个工具做对象级授权与租户隔离。
- 防御：不接受任意 ID，改为基于用户权限的搜索/过滤；对返回对象做归属校验；限制批量与速率。
- 防御：记录 MCP 工具调用审计（谁、什么工具、什么参数、返回哪些对象 ID）；敏感文档禁止直接返回对象存储链接，使用短期签名并校验归属。
- 响应：撤销泄露令牌、排查越权访问记录、通知受影响用户、修复 ACL 后回归测试。
