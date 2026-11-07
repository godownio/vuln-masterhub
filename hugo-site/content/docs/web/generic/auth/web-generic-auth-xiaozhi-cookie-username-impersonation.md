---
id: web-generic-auth-xiaozhi-cookie-username-impersonation
title: 小智 ESP32 管理平台：Cookie username 直接查询用户并建会话导致任意账号登录
type: scenario
domain: web
path: web/generic/auth
technique: cookie-username-lookup-auth-bypass
tags:
- auth-bypass
- cookie
- java
- spring
- interceptor
- impersonation
- xiaozhi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:10:28+08:00'
  notes: '已对照原文与图15-18核对：AuthenticationInterceptor#tryAuthenticateWithCookies 遍历 Cookie，name=username 时 selectUserByUsername 并 session.setAttribute；实测 Cookie: username=admin 访问 /api/config/query 返回 200 配置数据并 Set-Cookie JSESSIONID，未带 Cookie 为 401。微信分支 getWechatOpenId 取 X-WX-OPENID/wx_openid/wxOpenId 与卡一致（仅代码分析）。未验证点：微信分支未实测；frontmatter 无 sources/source_url。'
url: /docs/web/generic/auth/web-generic-auth-xiaozhi-cookie-username-impersonation/
draft: false
kb_aliases:
- 小智 ESP32 Cookie 伪造
- username Cookie 认证绕过
- AuthenticationInterceptor Cookie 登录
- X-WX-OPENID 身份伪造
- wx_openid 登录绕过
- 客户端身份标识直接换会话
---

## 一句话结论

小智 ESP32 管理平台的 Spring 拦截器 `AuthenticationInterceptor` 在会话为空时会调用 `tryAuthenticateWithCookies`：只要请求带 `Cookie: username=<任意已存在用户名>`，服务端就用该用户名查库、把用户写入 Session 并放行——攻击者无需密码即可冒充 admin 进入后台；同一逻辑还有 `X-WX-OPENID`/`wx_openid`/`wxOpenId` 微信身份变体。

## 原理

- 鉴权入口：`WebMvcConfig#addInterceptors` 注册 `AuthenticationInterceptor`，排除登录/注册/OTA/静态资源等路径后，其余请求进入 `preHandle`。
- `preHandle` 依次尝试：session 中已有用户 → `tryAuthenticateWithCookies` → `tryAuthenticateWithWechat` → `tryAuthenticateWithToken`。
- Cookie 分支代码：遍历 `request.getCookies()`，若 `cookie.getName()` 等于字符串 `"username"`，取 `cookie.getValue()` 作为用户名，调用 `userService.selectUserByUsername(username)`；查到用户后 `session.setAttribute(SysUserService.USER_SESSIONKEY, user)`、`request.setAttribute(...)`、`CmsUtils.setUser(request, user)`，返回 true 放行。
- 缺陷：Cookie 值只是“用户名”，没有签名、没有与密码/会话绑定、没有二次认证。用户名不是秘密，且系统还有未授权用户查询接口可直接枚举（见关联卡），因此任何已知用户名都能被冒充。
- 微信分支同理：`getWechatOpenId` 依次从 `X-WX-OPENID` 请求头、`wx_openid` Cookie、`wxOpenId` 请求参数取值，再 `selectUserByWxOpenId(wxOpenId)` 查用户并建会话；这些值同样完全由客户端控制，只要知道目标的 openid 即可冒充。
- 危害：直接获得对应账号（含 admin）的会话与后台权限，配合未授权信息泄露可先枚举用户名再接管。

## 触发条件

- 目标为小智 ESP32 Server Java 管理平台，`AuthenticationInterceptor` 按默认逻辑启用。
- 攻击者知道一个已存在的用户名（admin 为默认常见值，或通过 `/api/user/queryUsers` 等接口枚举）。
- 目标用户的 `state` 等字段未阻止该登录路径（文章实测 admin 可直接放行）。
- 微信变体需知道目标用户的 wxOpenId。

## 利用步骤

1. 访问任意受保护接口（如 `/api/config/query?...`）确认未登录返回 401。
2. 在同一请求中加入 `Cookie: username=admin`，无需密码。
3. 服务端按用户名查到 admin 并建立 Session，返回 200 与 `Set-Cookie: JSESSIONID=...`。
4. 携带该 JSESSIONID 访问后台管理接口，确认拥有管理员权限。
5. 若目标用户没有 username 可枚举，改用 `X-WX-OPENID: <目标openid>` 或 `wx_openid` Cookie / `wxOpenId` 参数尝试微信分支。

## PoC

```http
GET /api/config/query?start=1&limit=10&configType=llm&provider=&configName=&modelType= HTTP/1.1
Host: target.example:10808
Accept: application/json, text/plain, */*
Cookie: username=admin
```

```text
# 预期：HTTP/1.1 200，返回配置列表（文章截图 configId/configName/modelType 等），
# 响应带 Set-Cookie: JSESSIONID=...，无需任何密码。
# 对照：不带 Cookie 的同请求返回 401 {"code":401,"message":"用户未登录或登录已过期"}。
```

微信身份变体：

```http
GET /api/config/query?... HTTP/1.1
Host: target.example:10808
X-WX-OPENID: <目标用户 wxOpenId>
```

## 变体与关联

- 变体：`wx_openid` Cookie、`wxOpenId` 查询参数与 `X-WX-OPENID` 头等价，均可控制微信身份。
- 变体：JWT 分支也可伪造（见关联的默认密钥卡），三条路径任一通过即建立会话。
- 关联：[[web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure]]（未授权枚举用户名，为 Cookie 伪造提供输入）；[[web-generic-jwt-xiaozhi-default-hs256-secret-forgery]]（同系统 JWT 默认密钥伪造）；[[web-generic-auth-unsigned-cookie-admin-keys]]（无签名 Cookie 直接作为身份凭证的同类模式）。
- 边界：文章实测 `Cookie: username=admin` 成功访问配置接口；微信 openid 分支只做了代码分析，未给出实际登录回显。

## 检测与防御

- 检测：审计拦截器中任何“客户端可控标识直接查库建会话”的分支；监控带 `username` Cookie、`X-WX-OPENID`、`wx_openid`、`wxOpenId` 的请求；关注无密码登录却产生新 JSESSIONID 的行为。
- 修复：删除 Cookie/微信身份直接建会话的逻辑；Cookie 只允许保存服务端签发的随机 SessionID，并对 Cookie 做签名/加密；微信登录必须校验微信服务端签发的凭证（code 换 openid）而非客户端自报 openid。
- 加固：统一认证走标准 Session/JWT 并校验签名与过期；管理后台增加二次认证；对用户名枚举接口做鉴权与限流。
