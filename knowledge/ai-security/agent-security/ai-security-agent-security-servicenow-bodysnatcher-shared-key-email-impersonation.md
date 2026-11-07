---
id: ai-security-agent-security-servicenow-bodysnatcher-shared-key-email-impersonation
title: ServiceNow Agent BodySnatcher：共享静态密钥 + 邮箱自动信任导致管理员冒充与记录篡改（CVE-2025-12420）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: agent-email-identity-shared-key-impersonation
aliases:
- BodySnatcher
- ServiceNow Agent 身份冒充
- 共享静态密钥
- 邮箱自动信任
- CVE-2025-12420
- Agent 身份认证绕过
tags:
- ai-security
- agent-security
- servicenow
- identity
- authentication
- impersonation
- cve-2025-12420
cve:
- CVE-2025-12420
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V132
  verified_at: '2026-11-06T05:49:22+08:00'
  notes: 已对照幻灯片 CASE01 核对：CVE-2025-12420、CVSS 9.3、共享静态密钥+邮箱自动信任+无 MFA→冒充管理员改记录一致；原文仅摘要，无端点/请求格式与版本区间，未独立复现。
---

## 一句话结论

ServiceNow Agent 的认证同时存在「全平台共享静态密钥」「自动信任请求中的邮箱地址」「无 MFA」三个缺陷，攻击者只需伪造一个有效邮箱身份即可绕过 Agent 认证、冒充管理员并驱动 Agent 修改系统记录，形成从身份伪造到权限提升的完整链（CVE-2025-12420，CVSS 9.3）。

## 原理

- **共享静态密钥**：整个平台使用同一把静态密钥做 Agent 身份/请求校验。一旦该密钥在任一实例、日志、客户端或供应链环节泄露，攻击者即可在任意实例上伪造合法 Agent 请求，密钥无法按租户/实例隔离和轮换。
- **邮箱地址自动信任**：服务端把请求中的邮箱地址直接当作已认证身份，没有验证发件人是否真正拥有该邮箱、也没有 MFA。攻击者可以填写/伪造管理员邮箱，服务端即认为请求来自管理员。
- **Agent 权限过大**：Agent 被授权读写系统记录；身份校验被绕过之后，攻击者可以通过 Agent 的合法工具链修改记录、提升权限或破坏业务数据。
- **完整链条**：伪造邮箱身份 → 通过 Agent 认证 → 控制 Agent 执行高权限操作（修改系统记录），三个缺陷叠加使单点弱点升级为管理员级危害。

## 触发条件

- 目标使用受影响的 ServiceNow Agent 集成/版本（原文未给出具体版本区间）。
- Agent 端点接受外部请求，并以请求中的邮箱地址作为身份依据。
- 平台使用共享静态密钥，且攻击者能获得或猜测该密钥。
- Agent 具备修改系统记录等写权限，且没有二次授权/审批。
- 没有 MFA 或邮箱所有权验证。

## 利用步骤

1. 获取或复用平台共享静态密钥（从泄露的配置、日志、客户端或供应链入手）。
2. 构造带有管理员邮箱地址的 Agent 请求，伪造发件人/身份字段。
3. 利用服务端对邮箱的自动信任绕过 Agent 认证。
4. 通过 Agent 的工具调用修改系统记录（如创建/修改用户、角色、业务数据），完成提权或数据篡改。
5. 视权限范围进一步横向或持久化。

## PoC

原文未给出可执行 PoC；利用链为「伪造邮箱身份 → 绕过 Agent 认证 → 驱动 Agent 修改系统记录」。具体请求格式、端点与密钥获取方式需结合目标实例确认。

## 变体与关联

- **身份变体**：OAuth/SAML 断言伪造、JWT 密钥泄露、服务账号静态 token 复用。
- **Agent 变体**：任何以邮箱/用户名作为身份且不做所有权验证的 Agent 平台都可能复现同类链。
- **关联卡片**：[[ai-security-agent-security-capability-closure-tool-memory-identity]]（Agent 工具/记忆/身份三维度风险）、[[ai-security-agent-security-hitl-capability-dangerous-tool-guard]]（高风险工具 HITL 门禁）。
- **边界**：若平台按租户隔离密钥并强制 MFA、验证邮箱所有权，或 Agent 写操作需要二次授权，本链不成立。

## 检测与防御

- **身份认证**：按租户/实例隔离密钥并定期轮换；禁用共享静态密钥；强制 MFA；验证邮箱/域名所有权，不信任请求自报身份。
- **最小权限**：Agent 只授予完成任务所需的最小权限；修改记录等敏感操作需要 Human-in-the-loop 二次授权。
- **审计与检测**：监控同一密钥在多实例/多地域使用；检测异常邮箱身份的高权限 Agent 请求；对记录批量修改告警。
- **供应链**：排查密钥是否出现在客户端、日志、镜像或第三方集成中，泄露后立即轮换。
