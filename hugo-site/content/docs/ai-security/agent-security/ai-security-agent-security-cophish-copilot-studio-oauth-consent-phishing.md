---
id: ai-security-agent-security-cophish-copilot-studio-oauth-consent-phishing
title: CoPhish：Copilot Studio 官方域名托管 Agent 的 OAuth 同意钓鱼与令牌窃取
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: cophish-copilot-studio-oauth-consent-phishing
tags:
- ai-security
- agent-security
- oauth
- cophish
- copilot-studio
- token-theft
- consent-phishing
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:51:02+08:00'
  notes: 已对照原文 AS9 节与图 52-62 核对：copilotstudio.microsoft.com/environments/Default-.../bots/Default_infoSeeker/canvas、unverified 应用、普通用户 Mail/OneNote 权限、管理员 Files/Sites/Application.ReadWrite.All、token.botframework.com 验证码 157898，均一致。未验证点：原文无本地 PoC、仅截图；未复核真实租户；frontmatter 无 sources/source_url。
url: /docs/ai-security/agent-security/ai-security-agent-security-cophish-copilot-studio-oauth-consent-phishing/
draft: false
kb_aliases:
- CoPhish
- Copilot Studio 钓鱼
- OAuth 同意钓鱼
- 官方域名信任滥用
- 验证码回填钓鱼
---

## 一句话结论

攻击者在 Microsoft Copilot Studio 上创建一个托管在 `copilotstudio.microsoft.com` 官方域名的恶意 Agent，以“登录/验证”为名诱导用户完成 OAuth 同意，授予 `Mail.ReadWrite`、`Notes.ReadWrite` 等权限；对管理员则诱导授予 `Application.ReadWrite.All`，随后用 botframework 的验证码完成会话绑定，窃取邮件、笔记或高权限令牌。

## 原理

- **官方域名信任滥用**：Copilot Studio 允许用户创建并发布自定义 Agent，页面托管在 `copilotstudio.microsoft.com` 下；用户看到微软官方域名和熟悉的 Copilot 界面，容易忽略“应用未验证/非微软发布”的提示。
- **OAuth 同意钓鱼**：恶意 Agent 在对话中显示“登录”按钮，跳转到 Microsoft 登录/同意页；同意页列出请求的权限（普通用户为 `Mail.ReadWrite`、`Notes.ReadWrite`，管理员为 `Files.ReadWrite.All`、`Sites.ReadWrite.All`、`Application.ReadWrite.All`）。用户点击“接受”后，攻击者应用获得访问令牌/刷新令牌。
- **验证码回填**：攻击者用 `token.botframework.com` 的 Bot Connection Validation Code（如 `157898`）让用户在聊天窗口输入，完成 bot 与受害者会话的绑定；随后攻击者可在自己的会话中读取邮件/笔记，或利用管理员权限创建持久应用凭据。
- **为什么有效**：钓鱼链接不是明显的假域名，而是微软官方域名；OAuth 同意页也是真实的 Microsoft 页面；普通用户难以区分“官方 Copilot”与“第三方在 Copilot Studio 上发布的 Agent”。管理员一旦同意 `Application.ReadWrite.All`，攻击者可创建新应用/凭据，持久化控制租户。
- **本题**：截图显示 `copilotstudio.microsoft.com/environments/Default-.../bots/Default_infoSeeker/canvas` 的恶意 Copilot；普通用户视图请求读写邮件与 OneNote；管理员视图额外请求 `Files.ReadWrite.All`、`Sites.ReadWrite.All`、`Application.ReadWrite.All`；验证码页显示 `157898`。

## 触发条件

- 组织使用 Microsoft 365 / Copilot Studio，允许用户创建/发布 Agent，或攻击者能托管一个 Agent。
- 用户/管理员会点击 `copilotstudio.microsoft.com` 链接并完成登录；OAuth 同意未限制为已验证发布者。
- 目标租户未配置管理员同意工作流、条件访问或“禁止用户同意未验证应用”。
- 攻击者能通过邮件/聊天/文档投递链接，并诱导用户按对话提示操作。
- 管理员账号可授予租户级应用权限（`Application.ReadWrite.All`）。

## 利用步骤

1. 在 Copilot Studio 创建恶意 Agent，设置名称/头像/欢迎语，伪装成“信息查询/办公助手”。
2. 发布后获得官方域名链接：
   ```text
   https://copilotstudio.microsoft.com/environments/Default-{tenant-id}/bots/Default_{bot-name}/canvas
   ```
3. 通过邮件/IM 把链接发给目标，话术为“请登录验证/授权以继续使用”。
4. 用户点击“Login”，进入 Microsoft OAuth 同意页；普通用户请求 `Mail.ReadWrite`、`Notes.ReadWrite`，管理员账号请求 `Files.ReadWrite.All`、`Sites.ReadWrite.All`、`Application.ReadWrite.All`。
5. 用户点击“Accept”后，攻击者获得令牌；再让用户在聊天窗口输入 `token.botframework.com` 的验证码，完成会话绑定。
6. 攻击者读取邮件/笔记、导出文件，或用管理员权限创建新应用凭据；授权测试只使用测试租户和测试账号。

## PoC

```text
# 恶意 Copilot Studio Agent 链接形态（示意）
https://copilotstudio.microsoft.com/environments/Default-<tenant-id>/bots/Default_<bot-name>/canvas

# 普通用户同意页请求的权限（示意）
Mail.ReadWrite
Notes.ReadWrite

# 管理员同意页请求的高权限（示意）
Files.ReadWrite.All
Sites.ReadWrite.All
Application.ReadWrite.All

# Bot Connection Validation Code（示意）
157898
```

说明：原文给出恶意 Agent 页面、普通用户/管理员同意页、验证码页的截图；未提供可执行 PoC。PoC 仅用于授权测试，不要对真实租户使用。

## 变体与关联

- **设备码钓鱼**：诱导用户在 Microsoft 设备登录页输入攻击者提供的代码，原理类似，都是滥用真实 OAuth 流程。
- **应用冒充**：使用与官方 Copilot 相似的名称/图标/域名；结合 IDN 同形字或开放重定向。
- **权限升级**：先请求低权限建立信任，后续再请求 `Application.ReadWrite.All`；管理员同意一次即可持久化。
- **关联**：[[web-generic-oauth-postmessage-code-theft-sso-bind-xxe]]（OAuth 授权码窃取链）、[[cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent]]（Entra 管理员同意链）、[[ai-security-agent-security-ai-skill-auto-login-default-credential-captcha]]（Agent 自动登录与验证码识别）。

## 检测与防御

- **限制发布者**：只允许受信任用户/团队在 Copilot Studio 发布 Agent；对外部 Agent 做审核与域名/发布者白名单。
- **管理员同意工作流**：禁止用户同意未验证应用，启用“管理员同意请求”流程；对 `Application.ReadWrite.All`、`Mail.ReadWrite`、`Files.ReadWrite.All` 等高权限做严格审批。
- **条件访问**：对 OAuth 同意、设备码登录、异常租户/应用施加条件访问与风险检测；限制管理员账号的常驻高权限。
- **检测**：审计 OAuth 授权（`AuditLogs`/`SignInLogs`）中的新应用同意、`Application.ReadWrite.All` 授予、`copilotstudio.microsoft.com` 链接点击；监控 botframework 验证码流程。
- **响应**：撤销可疑应用同意与 refresh token，删除攻击者创建的应用/凭据，重置受影响管理员凭据。
