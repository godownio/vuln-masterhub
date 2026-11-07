---
id: web-generic-auth-ignoreauth-resetpass-username-hardcoded-password
title: Spring Boot @IgnoreAuth 免鉴权 resetPass：username 参数直接重置任意用户为 123456，默认管理员接管
type: scenario
domain: web
path: web/generic/auth
technique: ignoreauth-resetpass-username-hardcoded-password
aliases:
- '@IgnoreAuth 未授权接口'
- resetPass 未授权
- username 参数重置密码
- 默认管理员 abo
- 密码重置为 123456
- Spring Boot 拦截器白名单
tags:
- web
- auth
- password-reset
- unauthorized
- spring-boot
- interceptor
- account-takeover
- hardcoded-password
- annotation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V234
  verified_at: '2026-11-07T09:05:23+08:00'
  notes: 已对照 18713 原文与全部 12 张图片核对：@IgnoreAuth 放行逻辑、resetPass 的 username 参数绑定与 setPassword("123456")、默认管理员 abo/管理员角色、GET /users/resetPass?username=abo 返回 {"msg":"密码已重置为：123456","code":0}、数据库中 abo 密码变为 123456 均与截图一致；dedup 候选 authenticated-change-password-idor、uid-resetpwd、xiaozhi 等均为不同入口/条件，非同一利用链。未在真实环境复现；username 枚举路径为卡片补充推测。
---

## 一句话结论

Spring Boot 拍卖系统的鉴权拦截器会把带 `@IgnoreAuth` 注解的控制器方法直接放行，而 `/users/resetPass` 正好被标了 `@IgnoreAuth`：它用 GET 参数 `username` 绑定目标用户，不校验旧密码、验证码或调用者身份，直接把密码重置为硬编码的 `123456`；目标站存在默认管理员账号 `abo`，因此未登录请求 `GET /users/resetPass?username=abo` 返回 `{"msg":"密码已重置为：123456","code":0}`，数据库密码随即变为 `123456`，攻击者可直接以管理员登录。

## 原理

- **拦截器与注解白名单**：`InterceptorConfig extends WebMvcConfigurationSupport` 在 `addInterceptors` 中把 `AuthorizationInterceptor` 注册到 `/**`（排除 `/static/**`）；拦截器对 `HandlerMethod` 读取 `@IgnoreAuth`，若存在则 `return true`，跳过后续 Token 校验。登录、注册等公开接口使用该注解是常见设计，但一旦把它用在密码重置等敏感接口上，就形成未授权入口。
- **Token 校验模型**：正常接口从请求头取 `Token`，`tokenService.getTokenEntity(token)` 用 MyBatis-Plus `selectOne` 按 `token` 查询（参数化查询，无 SQL 注入），有效则把 `userId/role/tableName/username` 写入 Session。未带 Token 的请求只有 `@IgnoreAuth` 接口能通过。
- **resetPass 的实现缺陷**：控制器方法为 `@IgnoreAuth @RequestMapping("/resetPass") R resetPass(String username, HttpServletRequest request)`，没有 `@RequestBody`，Spring MVC 会把 GET/POST 同名参数 `username` 直接绑定到入参；随后按 `username` 查询用户，存在则 `setPassword("123456")` 并更新。整个过程不要求旧密码、短信/邮箱验证码、重置 token，也不检查调用者是否为管理员。
- **默认管理员账号**：数据库中存在 `username=abo`、`role=管理员` 的默认账号；攻击者无需枚举即可直接命中。即使不知道默认账号，`username` 也可通过登录/注册/用户列表等接口枚举，或按常见管理员名猜测。
- **为什么是完整接管**：攻击者获得的是可登录的管理员账号，而非仅一个密码字段；登录后可继续利用后台的文件上传、配置修改等功能。根因是“注解白名单 + 敏感操作缺少身份验证 + 固定弱口令”三者叠加。

## 触发条件

- 目标为 Spring Boot + 自定义拦截器的应用，存在 `@IgnoreAuth`（或类似免鉴权注解/白名单）机制。
- 密码重置、修改密码、绑定手机号等敏感接口被误标为免鉴权，或位于拦截器排除路径中。
- 接口用请求参数（username/uid/email）定位目标用户，且不校验旧密码/验证码/重置凭证。
- 目标存在默认/可枚举的管理员账号；重置结果为固定弱口令（本例 `123456`）。

## 利用步骤

1. 审计 `InterceptorConfig`/`AuthorizationInterceptor`，搜索 `@IgnoreAuth`、`excludePathPatterns`、白名单配置，列出所有免鉴权接口。
2. 在免鉴权列表中寻找密码重置、修改密码、用户信息更新等敏感接口；关注参数名 `username`、`uid`、`id`、`email`。
3. 确认目标用户名：默认管理员（如 `abo`）、注册接口返回的用户名、用户列表/登录报错泄露的用户名。
4. 未登录发送 `GET /users/resetPass?username=abo`；观察响应是否为 `code:0` 且提示密码已重置为 `123456`。
5. 用 `abo/123456` 登录后台，确认角色为管理员；必要时再通过后台上传/配置功能扩大影响。
6. 在授权测试中及时恢复密码并清理测试账号。

## PoC

```http
GET /users/resetPass?username=abo HTTP/1.1
Host: target

HTTP/1.1 200 OK
Content-Type: application/json

{"msg":"密码已重置为：123456","code":0}
```

```bash
# 重置后登录
curl -s -X POST 'http://target/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"abo","password":"123456"}'
```

## 变体与关联

- **注解/白名单变体**：`@IgnoreAuth`、`@Anonymous`、`@PermitAll`、`excludePathPatterns`、Swagger/Actuator 白名单；审计时把所有免鉴权接口与敏感操作做交集。
- **目标定位变体**：username、uid、id、email、手机号；GET/POST 参数自动绑定；隐藏字段篡改。
- **重置结果变体**：固定 `123456`、`admin/admin`、空密码、随机密码回显在响应中。
- **关联**：[[web-generic-auth-dev-reset-admin-password-default]]（开发接口未授权重置管理员为 admin/admin）、[[web-generic-auth-uid-resetpwd-hardcoded-default-password]]（登录后按 uid 重置为 123456）、[[web-generic-auth-password-reset-username-tampering]]（重置表单 username 可篡改）。

## 检测与防御

- **最小化白名单**：`@IgnoreAuth` 只用于登录、注册、验证码等确实无需身份的接口；密码重置必须校验旧密码或一次性重置 token（邮箱/短信），且不能由 username 单独定位。
- **强制鉴权**：敏感接口统一要求已登录 + 管理员/本人校验；服务端从 Session/JWT 取当前用户，不信任请求参数中的身份。
- **默认口令**：首次登录强制改密；禁止默认管理员账号使用弱口令；重置密码使用高熵临时密码并绑定过期时间。
- **检测**：审计所有 `@IgnoreAuth` 与拦截器排除路径；监控未登录调用 `/resetPass`、`/resetPwd`、`/updatePassword` 等接口；对同一 IP 枚举 username 的行为告警。
