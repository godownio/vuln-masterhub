---
id: web-generic-auth-token-renewal-trusted-user-headers-admin-jwt
title: Token 续期拦截器信任 User-Id/User-Name 请求头：任意用户签发 admin JWT 鉴权绕过
type: scenario
domain: web
path: web/generic/auth
technique: token-renewal-interceptor-trusted-user-headers-admin-jwt-forgery
tags:
- auth
- auth-bypass
- jwt
- token
- spring
- java
- header-trust
- privilege-escalation
- jeecms
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:46:53+08:00'
  notes: 已对照原文及截图01-14核对：WebMvcConfig 中 tokenRenewalInterceptor 未限定 pathPattern，TokenRenewalInterceptor.preHandle 读取 Is-Refresh-Token/User-Id/User-Name 并把 loginTarget 硬编码为 admin、refreshToken 后写 Token 响应头；User-Id 3101/test 与 2172/system 均成功签发；404 路径仍返回 Token 头；200 响应 userInfo 显示 system。JWT 密钥 jeecmsjw 见配置截图。版本 X2.10 仅为 demo systemInfo 显示，非厂商受影响区间声明，已按 brief 清除 affected_versions。未验证点：未在本机复跑。
url: /docs/web/generic/auth/web-generic-auth-token-renewal-trusted-user-headers-admin-jwt/
draft: false
kb_aliases:
- TokenRenewalInterceptor
- Is-Refresh-Token
- User-Id
- User-Name
- loginWithCode
- JEECMS X2.10
- 令牌续期鉴权绕过
---

## 一句话结论

某 Java CMS 的 `TokenRenewalInterceptor` 在收到 `Is-Refresh-Token: true` 时，直接读取客户端提交的 `User-Id`、`User-Name` 请求头，把 `loginTarget` 固定为 `admin`，调用 `refreshToken()` 由服务端签发新 JWT 并放在响应头 `Token` 中；整个过程不校验原 Token、不校验调用者身份，任意请求（包括 404 路由）都能拿到指定用户的管理员令牌，从而绕过鉴权访问 `/server-admin/**`。

## 原理

- **拦截器注册范围**：`TokenRenewalInterceptor` 通过 `registry.addInterceptor(tokenRenewalInterceptor)` 注册，未限定 path pattern，默认对所有路径生效；因此即使请求的 URL 不存在（返回 404），拦截器仍会执行并写入响应头。
- **信任客户端身份头**：`preHandle` 中只要 `Is-Refresh-Token` 非空且布尔值为 true，就从 `User-Id`、`User-Name` 请求头取值，构造 `LoginToken`，并硬编码 `setLoginTarget("admin")`。
- **服务端代签**：`tokenRenewalService.refreshToken(token, loginToken)` 用服务端 JWT 密钥签发新令牌，令牌 `sub` 中包含 `userId`、`userName`、`loginTarget=admin`；随后通过 `response.addHeader("Token", newToken)` 返回给客户端。
- **缺少校验**：没有验证 `User-Id` 对应的用户是否存在/是否有权、没有验证请求中的原 `Token` 是否属于该用户、也没有校验调用者是否已登录；`User-Id` 只是被 `Long.parseLong` 解析后直接使用。
- **下游信任**：网关/后台服务只校验 JWT 签名与 `sub` 中的身份字段，看到的是服务端合法签发的 admin 令牌，因此放行 `/server-admin/sysConfig/systemInfo`、`/server-admin/user/userInfo` 等管理接口。
- **放大因素**：JWT 密钥硬编码在配置中（`jwt.key: jeecmsjw`）；即使不走续期接口，拿到配置/源码的攻击者也可离线伪造任意 `sub` 的令牌。续期接口则让没有源码的攻击者也能在线取得合法令牌。
- **为什么是鉴权绕过而非普通信息泄露**：返回的令牌由服务端签名且带 admin 身份，可直接访问管理 API，属于认证/授权完全绕过，最终可衔接模板上传等后台功能到 RCE。

## 触发条件

- 目标使用该 CMS/网关，存在 `TokenRenewalInterceptor` 且对所有路径生效。
- 请求头可控：`Is-Refresh-Token: true`、`User-Id: <整数>`、`User-Name: <任意>`；`User-Id` 需为可解析的整数。
- 目标用户 ID 已知或可枚举（示例 `3101` 为普通用户、`2172` 为 `system` 管理员）。
- 下游服务信任服务端签发的 JWT；无需预先登录或持有有效 Token。
- 若网关对续期头做了额外校验/白名单，则需先绕过；本文场景默认未做。

## 利用步骤

1. 向任意可达路径（如 `/server-admin/userSecurity/loginWithCode`，甚至不存在的 `/userSecurity/loginWithCode`）发送请求，带上 `Is-Refresh-Token: true`、`User-Id: 2172`、`User-Name: system`。
2. 从响应头读取 `Token`（JWT）与 `Is-Refresh-Token: true`；即使响应体为 404，`Token` 头仍可能出现。
3. 用该 `Token` 访问管理接口，例如 `GET /server-admin/sysConfig/systemInfo`，确认返回系统信息（版本、JDK、数据库地址等）。
4. 用 `GET /server-admin/user/userInfo` 确认当前身份为 `system`/目标用户；按需枚举其他 `User-Id` 获取不同权限身份。
5. 以管理员令牌继续调用后台功能（模板管理、文件上传、系统配置等），把鉴权绕过扩展为文件写入/RCE。
6. 若响应头未直接暴露 Token，检查前端登录逻辑或网关是否把 `Token` 放入 Cookie/响应体；也可用已知硬编码 JWT 密钥离线伪造（需先获得配置）。

## PoC

```http
GET /server-admin/userSecurity/loginWithCode HTTP/1.1
Host: target
Is-Refresh-Token: true
User-Id: 2172
User-Name: system
```

```http
HTTP/1.1 200 OK
Token: eyJhbGciOiJIUzI1NiJ9.<base64url(payload)>.<signature>
Is-Refresh-Token: true
```

```http
GET /server-admin/sysConfig/systemInfo HTTP/1.1
Host: target
Token: <上一步响应头中的 JWT>
Site-Id: 1
```

```http
GET /server-admin/user/userInfo HTTP/1.1
Host: target
Token: <上一步响应头中的 JWT>
```

`payload` 解码后形如：

```json
{"userId":2172,"userName":"system","loginTarget":"admin"}
```

## 变体与关联

- **头名变体**：`User-Id`/`UserId`/`X-User-Id`、`User-Name`/`UserName`/`X-User-Name`；`Is-Refresh-Token` 也可能是 `isRefreshToken`、`Refresh-Token`。
- **触发路径变体**：只要拦截器未限定路径，任意 Controller、静态资源甚至 404 路径都可触发；可优先找返回头未被网关剥离的路径。
- **身份变体**：`loginTarget` 可能被硬编码为 `admin`、`front`、`site` 等；`User-Id` 可枚举，优先尝试小 ID/`system`/`admin`。
- **密钥变体**：JWT 密钥硬编码/弱密钥时，可直接离线伪造 `sub`，见 [[web-generic-jwt-xiaozhi-default-hs256-secret-forgery]]、[[web-generic-jwt-go-binary-hardcoded-secret-admin-forgery]]。
- **关联**：[[web-generic-auth-gettokenbyid-userid-token-issuance]]（未授权接口按 userId 签发令牌的同类缺陷）；[[web-generic-auth-login-header-userid-token-binding-takeover]]（客户端 Userid 头绑定令牌）；[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]（拿到 admin 令牌后的任意文件写入）。
- **边界**：若网关在入口剥离 `Is-Refresh-Token`/`User-Id` 头，或续期接口要求原 Token 有效且与 User-Id 绑定，则本场景失效。

## 检测与防御

- **修复**：续期接口必须校验原 Token 的签名、有效期与归属；`User-Id`/`User-Name` 只能来自已验证的 Token，不能来自请求头；禁止客户端指定 `loginTarget`。
- **修复**：把续期接口限制在明确的 path pattern 与 POST 方法，避免拦截器在任意路径上代签令牌；对 404/静态资源不执行续期逻辑。
- **加固**：JWT 密钥改为随机长密钥并放入密钥管理/环境变量，定期轮换；使用标准刷新令牌（refresh token）机制并绑定设备/会话。
- **检测**：请求头出现 `Is-Refresh-Token: true` 且 `User-Id` 与当前会话不符；同一 IP 枚举 `User-Id`；404 响应却带 `Token` 头；管理接口出现来自新签发令牌的异常访问；配置中出现硬编码 `jwt.key`。
- **审计**：搜索 `getHeader("User-Id")`、`getHeader("User-Name")`、`setLoginTarget`、`refreshToken`，确认身份字段来源是否可信。
