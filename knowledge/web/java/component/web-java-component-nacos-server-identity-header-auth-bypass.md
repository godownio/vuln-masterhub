---
id: web-java-component-nacos-server-identity-header-auth-bypass
title: Nacos serverIdentity 请求头鉴权绕过：配置 server.identity.key/value 后带对应头即跳过 JWT 校验
type: scenario
domain: web
path: web/java/component
technique: nacos-server-identity-header-auth-bypass
aliases:
- Nacos serverIdentity 绕过
- nacos.core.auth.server.identity.key
- Nacos 服务端身份头
- Nacos 请求头鉴权绕过
- Nacos 弱 identity 配置
tags:
- nacos
- java
- auth-bypass
- header
- weak-config
- component
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:05:43+08:00'
  notes: 已对照原文与全部35张图核对：server.identity.key=serverIdentity/value=security配置（图14）、请求头serverIdentity:security POST创建用户返回400 caused:user 'test' alreadyExist（图15）、AuthFilter先判userAgentAuthWhite再比较identity value后放行（图17）均一致。原文明确此更像危险配置/弱口令，卡内severity medium符合。
---

## 一句话结论

Nacos 1.4.1 引入的 serverIdentity 机制本意是让集群节点互访时免 JWT：`AuthFilter` 读取请求头中 `nacos.core.auth.server.identity.key` 指定的键，若其值等于 `nacos.core.auth.server.identity.value`，就直接 `chain.doFilter` 放行。当这两个值使用文档示例、弱口令或被泄露时，攻击者只需在请求中带一个形如 `serverIdentity: security` 的头，就能绕过全部 JWT 鉴权调用管理 API。

## 原理

- `AuthFilter.doFilter` 在鉴权开启且 `enable.userAgentAuthWhite=false` 时，会检查是否配置了 serverIdentity：`String serverIdentity = req.getHeader(authConfigs.getServerIdentityKey()); if (authConfigs.getServerIdentityValue().equals(serverIdentity)) { chain.doFilter(...); return; }`。
- 该分支位于 JWT/accessToken 校验之前，且匹配成功即 return，不再走后续鉴权。因此只要知道 key 名与 value，任何客户端都能伪装成“其他 Nacos 服务端”。
- 配置项成对出现：`nacos.core.auth.server.identity.key=nacosKey` / `nacos.core.auth.server.identity.value=nacosValue`（原文测试用 `serverIdentity`/`security`）。它们不是密钥派生的凭据，而是明文比较的固定字符串；一旦使用弱值或默认示例，等价于弱口令。
- 为什么成立：这是把“服务间共享秘密”简化为静态请求头，且没有来源 IP、mTLS 等额外约束；知道值即可重放。
- 边界：需要目标已开启鉴权且配置了 serverIdentity；若 key/value 为强随机且未泄露，无法直接猜中；原文也明确指出这更像危险配置/弱口令而非独立漏洞。

## 触发条件

- Nacos 开启鉴权（`nacos.core.auth.enabled=true`）且 `enable.userAgentAuthWhite=false`。
- 配置了 `nacos.core.auth.server.identity.key`/`value`，且值为默认示例、弱口令或已从配置泄露中获知。
- 攻击者可访问 Nacos API，并能自定义请求头。
- 仅用于授权测试。

## 利用步骤

1. 确认目标开启鉴权：无凭据请求 `/nacos/v1/auth/users` 返回 403 `unknown user!`。
2. 从源码/文档/泄露配置中获取或猜测 identity key 与 value（常见 `nacosKey/nacosValue`、`serverIdentity/security`）。
3. 在请求中加入该头，例如 `serverIdentity: security`，访问用户列表或创建用户。
4. 若返回正常数据（或创建用户返回“已存在/成功”而非 403），说明绕过成功。
5. 记录请求；若同时存在默认 JWT 密钥，可交叉验证哪种方式可用。

## PoC

```http
POST /nacos/v1/auth/users HTTP/1.1
Host: 192.168.1.4:8848
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
serverIdentity: security

username=test&password=test
```

响应 `400 caused:user 'test' alreadyExist!` 或 `200 create user ok!` 都说明已通过鉴权（不再是 `403 unknown user!`）。原文同时配有 `enable.userAgentAuthWhite=false`、`server.identity.key=xxx`、`server.identity.value=zzz` 的配置截图。

## 变体与关联

- **默认/弱值**：`nacosKey/nacosValue`、`serverIdentity/security` 等文档示例直接可用；从配置中心泄露的 identity 值同样可复用。
- **User-Agent 白名单**：`nacos.core.auth.enable.userAgentAuthWhite=true` 时 `User-Agent: Nacos-Server` 是另一条免鉴权分支（已有卡覆盖）。
- **路径末尾斜杠**：即使关闭 UA 白名单并配置 identity，末尾斜杠仍可能让 `ControllerMethodsCache` 取不到 method 而放行，见 [[web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass]]。
- **默认 JWT 密钥**：不需要 identity 值，直接用默认密钥伪造 token，见 [[web-java-component-nacos-default-token-secret-key-jwt-forge]]。
- 关联：[[web-java-component-nacos-default-auth-disabled-user-admin]]。

## 检测与防御

- **检测**：访问日志中出现带有配置项对应头的请求，且来源 IP 不是集群节点；同一头值被多个外部 IP 使用；与 403 请求交替出现的成功请求。
- **防御**：把 `server.identity.key/value` 设为强随机值并定期轮换；仅允许集群节点网段访问 8848（网络 ACL/安全组）；开启 mTLS 或改用更强的服务间认证；不要把 identity 值写入可被普通用户读取的配置。
- **注意**：该机制本身不是强鉴权，安全边界应依赖网络隔离与最小暴露面。
