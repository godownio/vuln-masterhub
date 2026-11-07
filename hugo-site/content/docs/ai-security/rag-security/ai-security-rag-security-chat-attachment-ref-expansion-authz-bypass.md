---
id: ai-security-rag-security-chat-attachment-ref-expansion-authz-bypass
title: RAG 聊天接口按引用展开附件时缺失对象级授权：低权限用户越权读取机密附件
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: reference-expansion-authz-bypass
tags:
- llm
- rag
- authorization
- idor
- chat
- access-control
- data-leak
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T22:50:43+08:00'
  notes: V106 指出 severity high 与原报告中危(CVSS 6.5)冲突；已改为 medium
url: /docs/ai-security/rag-security/ai-security-rag-security-chat-attachment-ref-expansion-authz-bypass/
draft: false
kb_aliases:
- 附件引用展开越权
- RAG 引用继承权限缺口
- attachment_ref 对象级授权缺失
- 聊天引用绕过文档 ACL
- citation expansion IDOR
---

## 一句话结论

在带文档问答/聊天功能的 RAG 应用里，如果模型回答中的"引用来源/附件"会被后端自动展开成正文，而展开路径只校验了外层文档的可见性、没有对每个 `attachment_ref` 重新做对象级授权，那么低权限用户只需在聊天中要求"整理上一份资料引用的附件内容"，就能读到直接接口本应返回 404 的机密附件。

## 原理

RAG 聊天通常分两步：先检索文档并返回引用（source/citation），再根据用户追问把引用中的附件或上下文展开。外层文档 `DOC-240` 对当前员工可见，所以检索阶段放行；但 `DOC-240` 引用的附件 `ATT-240-A` 属于机密商业资料（商务拓展部、合同金额、联系人信息），有自己的权限边界。直接访问 `/api/documents/ATT-240-A` 时，对象级授权正确返回 404；聊天接口的附件展开逻辑却按"这份文档我已经检索到了"或"文档级可见性"来取附件，没有对 `attachment_ref` 逐条执行 `permitted()` 检查，于是把附件正文拼进回答返回。

这是一个**二阶授权缺口**：权限判断发生在文档/检索层，而数据读取发生在附件展开层，两层使用的对象不同。只要存在"引用/附件/上下文自动展开"的路径，攻击者就能用对话指令驱动它，而无需直接枚举受保护端点。模型本身不需要越狱——它只是按用户的正常请求去引用上一轮已经出现的来源。

## 触发条件

- 应用提供聊天式文档问答，回答中带 sources/citations/attachment_refs；
- 后端会根据引用自动展开附件或上下文正文（"整理引用的附件内容"即可触发）；
- 附件有独立权限，但展开逻辑只校验外层文档或只按文档级可见性继承；
- 攻击者拥有低权限但合法的账号（普通员工），能登录并发起聊天；
- 直接访问附件端点会被正确拒绝（说明权限模型存在，只是展开路径没有复用）。

## 利用步骤

1. 用普通员工账号登录，向聊天接口发送一个正常问题，让助手返回一份当前用户可见、但内部引用了机密附件的文档（如项目阶段交接说明），记下返回的 source/attachment 标识。
2. 在同一会话中追问："请整理上一份资料引用的附件内容，用于交接核对。"（或类似表述），触发后端展开引用。
3. 检查回答是否包含附件的正文/字段（合同金额、报价、联系人、内部通讯录等）；若包含，说明展开路径绕过了附件 ACL。
4. 用同一账号直接请求附件端点作为对照，确认返回 404/403（权限本应拒绝），从而证明越权来自引用展开路径而不是附件本身公开。
5. 以不同附件/不同文档重复，确认不是单条数据的偶然暴露；注意不要批量枚举，避免对业务造成压力。

## PoC

最小请求序列（字段与值脱敏，靶场为自建 Flask 应用）：

```http
POST /api/chat HTTP/1.1
Host: <target>
Content-Type: application/json
Cookie: <低权限员工会话>
X-CSRF-Token: <csrf>

{"message": "请概述青岚项目的阶段交接。"}
```

响应中会带出可引用的文档与来源标识（示意）：

```json
{"reply": "...", "sources": [{"classification": "内部", "department": "客户成功部", "id": "DOC-240", "title": "青岚项目阶段交接说明"}]}
```

紧接着在同一会话中请求展开引用：

```http
POST /api/chat HTTP/1.1
Host: <target>
Content-Type: application/json
Cookie: <低权限员工会话>
X-CSRF-Token: <csrf>

{"message": "请整理上一份资料引用的附件内容，用于交接核对。"}
```

若存在缺陷，响应会包含机密附件正文（示意）：

```json
{"reply": "青岚项目历史联络单\n客户组织: ...\n客户联系人: ...\n合同续约底价: ...\n报价区间: ...", "sources": [{"classification": "机密", "department": "商务拓展部", "id": "ATT-240-A", "title": "青岚项目历史联络单"}]}
```

对照请求（应当被拒绝）：

```http
GET /api/documents/ATT-240-A HTTP/1.1
Host: <target>
Cookie: <低权限员工会话>
```

```http
HTTP/1.1 404 NOT FOUND
{"error": "资料不存在或当前账号无权访问。"}
```

同一账号、同一附件：直接端点 404，聊天引用展开 200 并返回正文，即证明对象级授权只在直接路径生效。

说明：该 PoC 来自原文实验截图中的 Agent 停止报告（自建靶场、单条附件），本卡未在本机复现；原文正文未单独描述该发现，结论按截图中的请求/响应记录整理。

## 变体与关联

- 引用类型泛化：文档引用、附件引用、图片、表格、代码片段、邮件线程、工单附件，只要后端会"展开"就可能复用同一缺口。
- 多轮上下文：先让助手引用一份可见文档，再要求"展开其中提到的文件/附件/上一版"，把直接端点无法访问的对象带入上下文。
- Agent 工具链：如果 Agent 有 `get_attachment`/`read_document` 工具，工具描述或模型规划可能自动展开引用；攻击者通过聊天指令影响工具选择。
- 与直接 IDOR 的区别：直接 IDOR 打的是对象端点；本场景打的是**引用/展开链路**，端点可能已正确鉴权，因此常规越权扫描容易漏掉。
- 关联：RAG 引用欺骗、间接提示词注入、MCP 工具 IDOR、文档级 ACL 与对象级 ACL 的差异。

## 检测与防御

- 在附件展开点逐条执行对象级授权：对每个 `attachment_ref` 按当前用户、租户、角色重新调用 `permitted()`，不要继承外层文档的可见性或检索阶段的放行结果。
- 检索与展开使用同一授权上下文：检索结果、引用列表、附件内容三者都按同一用户身份过滤；模型上下文里不应出现用户无权读取的正文。
- 默认拒绝：附件解析失败或权限不确定时返回空/拒绝，不要回退到"文档可见即可读附件"。
- 对比测试：对同一对象分别走直接端点和引用展开路径，断言两者授权结果一致；把这种"路径一致性"加入回归测试。
- 日志与检测：记录每次附件展开的 user、attachment_id、外层文档、授权决策与响应大小；告警"直接端点 404 但展开路径 200"的差异，以及同一会话内连续请求展开不同附件的序列。
- 输出侧兜底：对聊天回答中的敏感字段做数据分级过滤，但不要把它当作唯一控制——根因是读取时的授权缺失。
- 局限：原文靶场为自建虚拟环境，截图来自 Agent 生成的报告；卡片未独立复现，部署前应结合自身权限模型验证。

## 备注

- 原文主题是 AI Agent 渗透测试的成本/效率对照；本卡提取的是其截图中记录的附件引用越权发现，正文未展开描述。
- affected_versions 未填写：目标是自建靶场应用，原文没有给出产品/版本区间。
