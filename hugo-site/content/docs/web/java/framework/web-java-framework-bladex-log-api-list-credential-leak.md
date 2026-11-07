---
id: web-java-framework-bladex-log-api-list-credential-leak
title: BladeX /api/blade-log/api/list 低权限读取全量日志：params 明文泄露管理员口令与 refresh_token
type: scenario
domain: web
path: web/java/framework
technique: bladex-log-api-param-credential-leak
tags:
- java
- bladex
- spring-cloud
- log
- credential-leak
- authz
- jwt
- refresh-token
- information-disclosure
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T13:43:13+08:00'
  notes: 已对照原文与 img/20、img/21 核对：/api/blade-log/api/list 日志中 params 泄露 refresh_token 与 username=admin&password=73...；卡片正确区分“token 被日志泄露”与“JWT 签名密钥硬编码”（原文称 JWT 硬编码但截图不能证明）。低权限 test1 会话可读日志与原文一致；未复跑目标。原文只显示 BladeX 2.8.1 目标环境，未给受影响区间，affected_versions 保持为空。
url: /docs/web/java/framework/web-java-framework-bladex-log-api-list-credential-leak/
draft: false
kb_aliases:
- BladeX 日志泄露
- blade-log api list
- BladeX 操作日志明文密码
- BladeX refresh_token 泄露
- Spring Cloud 后台日志接口越权
---

## 一句话结论

BladeX 的日志查询接口 `/api/blade-log/api/list` 只校验登录、不按角色或数据范围过滤，低权限账号即可拉取全站 API 日志；日志的 `params` 字段原样保存了 `/blade-auth/oauth/token` 的请求参数，直接暴露管理员 `username`/`password` 以及可用的 `refresh_token`，据此可登录后台或续期管理员会话。

## 原理

- BladeX 的日志模块会记录每次 API 调用的 `requestUri`、`methodName`、`params`、`title`、`createBy` 等字段，`/api/blade-log/api/list` 用于分页查询这些日志。
- BladeX 的认证接口 `/blade-auth/oauth/token` 使用 query/form 参数传递凭据：密码模式为 `tenantId=...&username=...&password=...&code=...`，刷新模式为 `tenantId=...&refresh_token=...&grant_type=refresh_token&scope=all`。
- 日志组件没有对认证类请求做脱敏，登录请求的整个参数串被写入 `params` 字段；日志查询接口又没有管理员角色判断和租户数据范围过滤，因此任何登录用户都能读到其他人的登录参数。
- 于是审计日志变成了凭据仓库：攻击者用低权限账号读日志，就能拿到管理员明文口令，或者拿到一条仍在有效期的 refresh_token 用于续期。
- 该案例还出现了一条 `params` 为 `tenantId=...&username=admin&password=73...` 的“登录用户验证”日志；这是比“日志里有 token”更直接的明文口令泄露。作者把泄露 refresh_token 称为“JWT 硬编码漏洞”，但截图只能证明 token 被日志泄露，不能证明 JWT 签名密钥硬编码，二者需要区分验证。

## 触发条件

- 目标使用 BladeX，且日志模块开启并把 API 请求参数持久化到数据库。
- 攻击者持有任意有效登录态（该案例以爆破得到的低权限 `test1` 账号访问）；若接口可未授权访问，则危害更大，需实测确认。
- `/api/blade-log/api/list` 未做管理员角色校验、租户/数据范围过滤。
- 日志中已记录过管理员登录或 token 刷新请求（通常只要管理员登录过即可）。

## 利用步骤

1. 用低权限账号登录，取得有效 token/Cookie（或直接匿名访问尝试）。
2. 请求日志列表接口；若默认无数据，补充 `current`、`size`、`page` 等分页参数。
3. 在响应 JSON 中搜索 `params`、`username=`、`password=`、`refresh_token=`、`access_token=` 等关键字。
4. 取出管理员 `tenantId`、`username`、`password`，按目标登录流程请求 `/api/blade-auth/oauth/token`（验证码按实际站点填写）验证管理员权限。
5. 或者使用泄露的 `refresh_token` 走 `grant_type=refresh_token` 续期；注意 token 可能过期、绑定 client_id/tenantId，且服务端可能轮换 refresh_token。
6. 登录成功后，用管理员权限继续查看用户、数据源等模块（参见 [[pentest-lateral-movement-bladex-datasource-plaintext-credential-db-takeover]]）。

## PoC

```http
GET /api/blade-log/api/list HTTP/1.1
Host: target
Authorization: Bearer <低权限 token>
Cookie: <低权限会话>
```

响应中可见类似记录（字段值已占位）：

```json
{
  "requestUri": "/blade-auth/oauth/token",
  "methodName": "token",
  "params": "tenantId=000000&username=admin&password=<REDACTED>&code=<REDACTED>",
  "title": "登录用户验证"
}
```

以及刷新 token 的日志：

```json
{
  "requestUri": "/blade-auth/oauth/token",
  "methodName": "token",
  "params": "tenantId=000000&refresh_token=<JWT>&grant_type=refresh_token&scope=all"
}
```

用泄露口令登录：

```http
POST /api/blade-auth/oauth/token?tenantId=000000&username=admin&password=<REDACTED>&code=<验证码> HTTP/1.1
Host: target
```

## 变体与关联

- 变体：同类日志接口还有 `/api/blade-log/error/list`、`/api/blade-log/usual/list` 等；有的版本可能直接未授权返回。
- 变体：日志 `params` 还可能包含其他接口的身份证号、手机号、文件路径、内部 token 等敏感参数，可按 `params` 关键字批量筛选。
- 变体：拿到 refresh_token 后可尝试刷新 access_token；若签名密钥确为默认/硬编码（需另行验证），还可直接伪造 JWT。
- 关联：[[web-generic-auth-authlog-userid-enumeration-authz-bypass]]（认证日志泄露 userId 后枚举用户详情）。
- 关联：[[web-java-framework-spring-actuator-heapdump-credential-leak]]（另一类凭据泄露面，可对比泄露形态）。
- 边界：日志可能按租户或时间分页，需要遍历 `current`/`size`；管理员改密后旧口令失效，应尽快使用。

## 检测与防御

- 日志脱敏：在写入日志前过滤 `password`、`passwd`、`token`、`refresh_token`、`access_token`、`code`、`secret` 等字段，认证接口不要记录完整请求参数。
- 权限控制：日志查询接口必须校验管理员角色，并按租户/数据范围过滤；不要只依赖前端隐藏菜单。
- 访问审计：对日志接口的批量查询、异常账号访问、超大分页请求告警。
- 凭据处置：发现泄露后立即重置管理员口令、吊销 refresh_token、排查管理员登录记录与后续操作。
- 最小化：关闭不必要的日志查询 API，日志保留期限最小化，日志库与业务库权限隔离。
