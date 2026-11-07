---
id: ai-security-rag-security-client-controlled-roles-security-level
title: RAG 分级权限信任请求体 roles/security_level：改请求体即可越权检索高密级文档
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: rag-client-controlled-authorization-claims
tags:
- ai-security
- rag
- access-control
- authorization
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: gov-rag-demo commit 2b7f9ca（修复于 56066f8）
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:29:59+08:00'
  notes: 已对照原文核对（该文无图片，meta.images=0）：行号/代码事实、缺陷现象与修复方案均与原文一致（审计基线 2b7f9ca、修复 56066f8）。未验证点：本库未复跑 PoC，原文未提供修复前实际 HTTP 响应截图，主要依据代码事实与修复后断言；frontmatter 无 sources/source_url。
url: /docs/ai-security/rag-security/ai-security-rag-security-client-controlled-roles-security-level/
draft: false
kb_aliases:
- RAG 越权检索
- 请求体自报角色
- security_level 伪造
- 分级权限绕过
- roles 参数越权
---

## 一句话结论

RAG 开启分级权限后，服务端仍从 HTTP 请求体的 `roles` 与 `security_level` 取身份，并直接用于检索过滤；攻击者发送 `{"roles":["admin"],"security_level":"confidential"}` 即可检索高密级文档，不需要破解登录或绕过认证。

## 原理

- 修复前 `main.py` 把 `req.roles`、`req.security_level` 直接传给 `ask(...)`；`rag.py` 的 `_access_context()` 与 `_access_where()` 只对这些值做归一化，没有校验“该身份是否属于当前调用者”。
- 这是典型的客户端可控授权声明：`roles`/`security_level` 是请求体字段，攻击者可以任意填写；分级权限的开关一旦打开，过滤条件就变成由调用方自己声明。
- 设计层问题比运行时问题更隐蔽：文件下载白名单、参数约束、脱敏等运行时防护都正常，无法阻止“身份从哪来”这一设计缺陷。
- 修复把身份收口到服务端：权限开启时在 `ask()` 顶部强制把 `user_roles`/`security_level` 置空，只取部署注入的 `RAG_USER_ROLES`/`RAG_SECURITY_LEVEL`；`main.py` 的 `ChatRequest` 删除这两个字段（pydantic 默认忽略多余字段，旧客户端多传不会 422）。生产多租户应从 IDP/JWT 的 token claims 推导角色与密级。

## 触发条件

- RAG 部署打开 `RAG_PERMISSION_ENABLED=1`（分级权限启用）；
- 问答接口的请求体接受 `roles` / `security_level`（或同义字段）并由服务端直接采用；
- 服务端未把请求体身份与认证态绑定（无 JWT/会话身份映射）；
- 攻击者能向问答接口发送请求（普通用户即可）。

## 利用步骤

1. 确认目标启用了分级权限：默认请求返回 public 级资料，或响应/前端出现密级选择器。
2. 用默认身份提问一个已知的 confidential 主题，记录检索结果或拒答。
3. 在同一请求体中加 `roles` 与 `security_level`，例如 `["admin"]` 与 `"confidential"`，再次提问。
4. 对比响应：若返回高密级文档内容或引用，说明身份被请求体直接采用。
5. 可进一步枚举 `security_level` 取值（internal/confidential/secret）与角色名，确认过滤条件的实际字段。

## PoC

```bash
# 默认身份（对照）
curl -s -X POST http://<rag>/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"question":"<高密级主题问题>","session_id":"11111111-1111-4111-8111-111111111111"}'

# 请求体自报 admin + confidential（越权）
curl -s -X POST http://<rag>/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"question":"<高密级主题问题>","roles":["admin"],"security_level":"confidential","top_k":8,"session_id":"11111111-1111-4111-8111-111111111111"}'
```

预期：第二次请求返回高密级文档内容或更高密级的引用来源；接口路径与字段名按目标实际实现调整。

## 变体与关联

- 变体：只在检索层做收口。其他调用路径（管理接口、批量问答、内部 SDK）可能绕过检索层的身份检查；身份收口点应放在服务入口 `ask()` 顶部。
- 变体：把 `roles`/`security_level` 放在 query 参数、Cookie 或自定义头里，本质相同，只要服务端从请求侧取值即成立。
- 关联 [[ai-security-rag-security-predictable-session-id-cross-session]]：两者都是把客户端可控值当身份/准凭据；本卡是密级声明，后者是会话标识。
- 关联 [[web-generic-auth-missing-function-level-role-check]]：传统 Web 的“只验登录不验角色”与 RAG 的“信任请求体角色”是同一类垂直越权思路。
- 边界：若服务端从认证态（JWT claims、IDP）推导角色并在检索层强制过滤，请求体字段即使存在也不会生效。

## 检测与防御

- **P0 身份服务端收口**：权限开启时忽略请求体中的 `roles`/`security_level`，只从认证态或部署注入的身份取值；生产多租户接 IDP/JWT，从 token claims 推导角色与密级。
- **接口收敛**：从请求模型中删除这两个字段；保留时也要在服务入口显式丢弃，不能传到检索层。
- **检测**：审计问答接口是否出现 `roles`、`security_level`、`classification` 等请求字段；对携带这些字段的请求记录来源并告警；用“低权身份 + 高密级字段”的测试用例做回归。
- **验证**：修复后应断言 `ask(user_roles=["admin"], ...)` 的传入值被忽略、检索层实际收到 None，默认关闭路径行为不变。
