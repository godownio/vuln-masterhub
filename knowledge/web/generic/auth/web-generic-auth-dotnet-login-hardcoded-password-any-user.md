---
id: web-generic-auth-dotnet-login-hardcoded-password-any-user
title: .NET 登录接口硬编码口令调用认证 BLL：忽略 userPass，已知用户名即可换取会话 Cookie（LLogin）
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-login-hardcoded-password-any-user
aliases:
- LLogin 任意用户登录
- 登录接口硬编码密码
- 免登录接口换 Cookie
- 用户名换 Token
- FormsAuthenticationBLL 固定口令
- pAssw0rd01!!
tags:
- web
- dotnet
- aspnet
- auth
- login-bypass
- hardcoded-credential
- session
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:05:07+08:00'
  notes: 已对照原文与15张图核对：图14 LLogin Action 接收 userName/userPass/rememberMe/code 但调用 FormsAuthenticationBLL().Login(userName, "pAssw0rd01!!", true, true, "PC")，userPass 未参与校验；图15 Intruder 用多个用户名（lina/liuxia/lijian/chenbo/liwei 等）任意口令请求均 200 且响应 success=true，另见'账号不存在!'失败响应；原文'给个名字，还你个cookie'与卡内任意用户登录结论一致。与既有 redirect-username 签发会话卡机制不同（本卡为认证 BLL 固定口令），与手机号任意密码卡也不同（本卡代码显式传入硬编码口令），dedup top候选 related/new，非重复。severity=critical 合理。原文未给系统名/版本，affected_versions 留空正确。未验证点：未在目标实例复测；卡内已注明固定串是否为全系统通用口令取决于认证BLL实现与租户/锁定限制。卡内 PoC 响应字段为示例（原文响应数据打码）。frontmatter 无 sources/source_url。
---

## 一句话结论

某 .NET MVC 系统的登录 Action `LLogin(userName, userPass, ...)` 完全没有使用客户端传入的 `userPass`，而是把硬编码字符串 `"pAssw0rd01!!"` 直接传给 `FormsAuthenticationBLL().Login(...)`；结果只要知道一个存在的用户名，用任意密码请求该接口就能拿到 `success=true` 的会话数据与 Token/Cookie，实现任意用户登录。

## 原理

- **认证参数被替换**：Action 签名接收 `userName`、`userPass`、`rememberMe`、`code`，但调用认证 BLL 时写死第二个参数：
  ```csharp
  ajaxReturn = new FormsAuthenticationBLL().Login(userName, "pAssw0rd01!!", true, true, "PC");
  ```
  客户端密码 `userPass` 从未参与校验；认证 BLL 使用固定字符串作为口令去验证 `userName`。
- **为什么任意已存在用户都能登录**：该固定串相当于供应商内置的通用口令/免登录凭据（接口上还标了 `[Log("免登录", "0", "", "")]`），只要账户名存在且该认证路径接受此固定口令，就返回成功并签发会话；密码强度、是否泄露都不再重要。
- **返回值即会话**：成功后 `ajaxReturn.data` 是 `SessionUser`，同时返回 `Token`；代码还会调用 `UserLoginInfoBLL().InsertUserLogin(sessionUser, ajaxReturn.Token, "WebUI")` 记录登录。攻击者只需保存响应中的 Cookie/Token 即可冒充目标用户。
- **用户名来源**：同一系统的未授权移动端接口会返回人员通讯录/账号信息（姓名、Account、部门、电话等），为爆破/枚举用户名提供了现成字典；即使没有泄露，AD 账号命名规律也常可猜测。
- **为什么隐蔽**：这是业务代码里的“正常登录接口”，WAF/流量侧看到的是合法登录请求；问题只在代码审计或对比测试（任意密码都能成功）时暴露。
- **边界**：固定串是否是全系统通用口令取决于认证 BLL 的实现；个别环境可能只对特定角色/租户生效，需实测确认；若账户被锁定/不存在则返回失败。

## 触发条件

- 目标为该 .NET MVC 系统的定制/企业版，存在 `LLogin` 或类似登录 Action（示例路径 `/CompositePortal/Home/LLogin`）。
- 攻击者知道至少一个有效用户名（可通过未授权人员接口、AD 命名规律或社会工程获得）。
- 目标未对该接口做额外风控（验证码、频率限制、设备指纹、密码错误锁定）。
- 认证 BLL 接受硬编码固定串作为有效凭据（供应商内置通用口令或免登录逻辑）。

## 利用步骤

1. 枚举有效用户名：调用未授权移动端接口（如 `GetPersonInfo`/`GetModuleList`）读取人员 Account/姓名，或按命名规律生成字典。
2. 向 `/CompositePortal/Home/LLogin` 发送 POST，`userName` 填目标账号，`userPass` 随便填。
3. 观察响应：`success=true` 且 `data` 含 `SessionUser`、`Token` 即成功；`success=false`/“账号不存在”则换下一个用户名。
4. 保存响应中的 Cookie/Token，访问需要登录的接口验证身份。
5. 对高价值账号（管理员、财务、运维）重复上述步骤，评估可访问的功能与数据。

## PoC

```http
POST /CompositePortal/Home/LLogin HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

userName=admin&userPass=anything&rememberMe=true&code=
```

成功响应示例（字段按实际系统）：

```json
{"success":true,"data":{"Account":"admin","Name":"...","ParentDeptID":null,"ParentDeptName":null},"Token":"..."}
```

失败响应示例：`{"success":false,"data":null,"message":"账号不存在!","Token":null}`，可用于判断用户名是否存在。

## 变体与关联

- **变体**：固定串换成默认口令/初始口令；Action 内部对某些来源（内网、特定 UA、特定租户）跳过密码校验；`[AllowAnonymous]` 或 `[Log("免登录")]` 标注的接口直接签发会话。
- **变体**：认证 BLL 的重载参数语义不同（第二参数可能是应用密钥/内部凭据），需结合反编译确认，但利用效果一致——客户端密码不再决定登录结果。
- 关联：[[web-generic-auth-redirect-username-session-issuance]]（另一类按 username 签发会话的接口）、[[web-generic-auth-uid-resetpwd-hardcoded-default-password]]（硬编码默认口令重置）、[[web-generic-auth-myblog-hardcoded-aes-cookie-forgery]]（硬编码密钥伪造 Cookie）。
- 边界：用户名不存在、账户锁定、额外 MFA/设备绑定、认证 BLL 只对特定租户接受固定串时，该路径受限。

## 检测与防御

- **代码审计**：全局搜索登录 Action 中对 `Login(...)` 的调用，检查第二个参数是否为字符串字面量、是否使用 `userPass`；检查 `[AllowAnonymous]`/“免登录”标注的认证接口是否对外暴露；用任意密码/空密码做对比测试（成功即高危）。
- **检测信号**：同一账号短时间内大量“成功登录”但密码字段各异；登录请求缺少验证码/设备信息；同一 IP 用不同用户名批量尝试且成功率高；登录成功后立即访问敏感接口。
- **防御**：移除硬编码凭据与免登录后门，认证 BLL 必须校验客户端口令并加盐哈希存储；对登录接口做失败锁定与频率限制；对 `[AllowAnonymous]` 接口做清单审计；把未授权人员接口的返回字段最小化，避免为登录爆破提供用户名。
