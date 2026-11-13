---
id: web-generic-jwt-exp-not-validated
title: JWT exp 过期声明未被校验：过期令牌仍通过认证长期有效
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-exp-not-validated
aliases:
- JWT 过期不生效
- 过期 token 仍可使用
- exp 未校验
- JWT 无限使用
- 过期令牌继续会话
tags:
- jwt
- exp
- session
- token-lifecycle
- authentication
- credential-reuse
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V674
  verified_at: '2026-11-13T11:42:23+08:00'
  notes: 已对照原文核对：'会话续期-无限使用'节实测1小时JWT过期后仍可继续会话操作，支撑卡片的exp未校验结论；原理/利用步骤与原文一致，PoC为示意curl且原文无独立脚本已注明。61张本地图均为JWT基础/PG靶场/Burp/jwt_tool/hashcat操作截图，未见额外技术信息。原文未显式标注受影响版本，未设置。未复现。
---

## 一句话结论

JWT 的 `exp` 只是 Payload 里的一个声明，服务端若只验证签名与用户身份、不检查 `exp`（或在会话/缓存层没有额外的过期控制），已过期的令牌仍能继续访问受保护接口，令牌一旦泄露将无法通过自然过期失效，攻击者可长期复用。

## 原理

- JWT 是自包含令牌，`exp` 的约束力完全取决于验证方代码：库的验签接口只有在校验 claims（如 `jwt.verify`）时才检查过期；若实现只做签名校验和解码（或自行解析 claims 后忽略 `exp`），过期时间形同虚设。
- 部分实现把 JWT 放到服务端会话/缓存中，鉴权时只看缓存命中而不看 `exp`，同样会让过期令牌继续可用。
- 后果：令牌生命周期由服务端实现细节而非 `exp` 决定；攻击者拿到抓包、日志、分享链接等途径泄露的 JWT 后，即使原定 1 小时过期仍可反复使用，入侵窗口被无限拉长；用户改密、注销也无法让旧令牌失效（除非另有吊销机制）。
- 与续期缺陷叠加时更严重：若过期旧令牌还能在续期接口换取新令牌，令牌可被无限滚续。

## 触发条件

- 攻击者持有目标用户曾经有效的 JWT（抓包、日志泄露、终端被控等）。
- 服务端鉴权链路不校验 `exp`，且没有基于会话/黑名单/版本号的吊销控制。
- 令牌未与 IP/设备等额外因子绑定（否则重放受限）。

## 利用步骤

1. 获取一枚合法 JWT（如抓包获得 Cookie 中的会话令牌），Base64 解码确认 `exp` 字段存在。
2. 等待其 `exp` 时间过期（或直接使用已过期的旧令牌）。
3. 用该过期令牌重放请求（如访问用户信息、业务接口）。
4. 若仍返回正常数据/可执行操作，说明 `exp` 未生效，令牌可长期复用；结合泄露渠道持续访问。
5. 若发现续期接口可用过期令牌换新令牌，可无限续签。

## PoC

```bash
# 过期后直接重放原 Cookie（示意）
curl -H 'Cookie: session=<过期JWT>' https://target/api/user/info
# 若返回 200 与用户数据，而非 401/重新登录，则 exp 未生效
```

无独立 PoC 脚本：原文为产品实测截图（登录签发的 1 小时 JWT 过期后仍可继续会话操作），未给出服务端代码。

## 变体与关联

- 变体：续期接口允许旧/过期令牌换取新令牌且不绑定一次性 refresh token，令牌可无限滚续（原文实测：续期窗口内旧令牌可生成多个新有效令牌）。
- 关联：[[web-generic-auth-deleted-user-cached-jwt-still-login]]（删除用户后缓存中的 JWT 未撤销，同为令牌生命周期失控）；[[web-generic-jwt-unverified-signature-payload-tamper]]（完全不验签）。
- 边界：服务端严格校验 `exp`/`nbf` 并有吊销机制时本手法不成立；`exp` 缺失时是否放行也取决于实现。

## 检测与防御

- 修复：验签时强制校验 `exp`/`nbf`/`iat`；鉴权入口统一走会检查 claims 的验证函数，禁止只 decode 不 verify。
- 加固：引入服务端会话状态或令牌版本号/黑名单，支持注销、改密后立即失效；refresh token 一次性轮换并与用户/设备绑定。
- 检测：重放过期令牌应返回 401；监控同一令牌在过期后的继续使用；定期审计 JWT 验证代码路径是否包含 expire 校验。
