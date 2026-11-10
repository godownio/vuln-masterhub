---
id: web-generic-graphql-batch-alias-rate-limit-brute-force
title: GraphQL 批量查询/别名放大暴力破解：单 HTTP 请求内 100 个别名或 100 条批量 mutation，绕过每请求/IP 速率限制
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-batch-alias-rate-limit-brute-force
aliases:
- GraphQL 批量查询
- 别名重载
- Alias Overloading
- Array-based Query Batching
- 速率限制绕过
- 登录爆破放大
- graphql-cop batch
tags:
- graphql
- brute-force
- rate-limit-bypass
- batching
- alias
- authentication
- api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:52:52+08:00'
  notes: 已对照 content.md 与 img22-23 核对：q1..q100 别名 login 与 JSON 数组批量 mutation 两种形态、100x100=10000 次尝试、绕过每请求/IP 限速均与原文一致；PoC 为通用 login 示意。未验证点：未实际运行批量爆破；原文未给出具体限速实现代码。
---

## 一句话结论

GraphQL 允许在一条文档中用不同别名重复调用同一字段（`q1: login(...)`, `q2: login(...)`, …），也允许一次 HTTP 请求发送查询数组；若登录接口只按“每 HTTP 请求/每 IP 10 次”限速，攻击者可在单个请求里放 100 个别名或 100 条批量 mutation，把 100 次 HTTP 请求放大成 10,000 次认证尝试，从而绕过限速进行口令爆破。

## 原理

- **别名让同一字段执行多次**：GraphQL 文档中每个字段可以取别名，`q1: login(username:"account", password:"password1"){...}`、`q2: login(...password2)` 等在同一 `mutation` 下会被解析为多个独立字段，服务端顺序/并行执行每个 resolver，响应中按别名返回各结果。对限速器来说这仍只是 1 个 HTTP 请求。
- **批量请求**：部分实现支持 JSON 数组形式的批量查询（`[{"query":"..."},{"query":"..."}]`），一次 HTTP 请求执行多条查询；文章用 100 条 `mutation login` 的数组演示。
- **限速维度错配**：如果防护只在反向代理/网关按 HTTP 请求数或 IP 计数（例如 10 req/s），而应用层不限制单请求内的 operation/alias 数量，攻击者可将请求数压到限制以下而实际认证尝试数放大 100 倍；文章描述 100 个请求 × 100 个别名 = 10,000 次尝试。
- **响应可区分**：每个别名/批量项都返回自己的 data/errors，攻击者可据此判断哪个口令成功；即使响应被截断/合并，也可通过错误文本或状态差异区分。
- **与 DoS 的区别**：同样的批量/别名能力也可用于资源耗尽（graphql-cop 会报 Alias Overloading/Array-based Query Batching 为 DoS 风险），本文关注的是“绕过速率限制做暴力破解”这一认证攻击面。

## 触发条件

- GraphQL 端点允许字段别名、且未限制单文档内同字段的重复次数；或允许批量查询数组。
- 存在敏感的登录/验证 mutation（用户名+口令、OTP、邀请码等），且响应能区分成功/失败。
- 防护仅按 HTTP 请求数/IP/连接数限速，应用层没有按 operation/认证尝试计数、没有账号锁定/CAPTCHA。
- 攻击者可接受较高的单请求延迟/响应体；服务端未对单请求 operation 数做上限。

## 利用步骤

1. 通过 introspection/错误信息确认登录 mutation 的名称、参数与返回字段（如 `login(username,password){ accessToken mySecret }`）。
2. 构造别名单文档：在一个 `mutation` 中写 100 个 `q1: login(...password1)` … `q100: login(...password100)`，每个别名对应一个候选口令。
3. 或构造批量数组：`[{"query":"mutation login {...password1...}"}, ..., {"query":"...password100..."}]`，一次 POST 发送。
4. 发送并解析响应：按别名/数组下标提取成功标识（token、mySecret、错误差异）；命中后停止。
5. 将 100 个候选口令分成多批，每批一个 HTTP 请求，控制在网关限速以下；重复直到字典耗尽或命中。
6. 若服务端限制别名数量，尝试分批、嵌套 fragment、指令重复（directive overloading）、字段重复（field duplication）等变体；注意不要触发资源耗尽告警。

## PoC

```graphql
# 单文档 100 别名（截断示例）
mutation login {
  q1: login(username: "account", password: "password1") { mySecret }
  q2: login(username: "account", password: "password2") { mySecret }
  # ...
  q100: login(username: "account", password: "password100") { mySecret }
}
```

```json
// 批量数组（截断示例）
[
  {"query": "mutation login { login(username:\"account\", password:\"password1\"){ accessToken } }"},
  {"query": "mutation login { login(username:\"account\", password:\"password2\"){ accessToken } }"}
]
```

```python
import requests
url = "http://target/graphql"
passwords = [f"password{i}" for i in range(1, 101)]
aliases = "\n".join(
    f'q{i}: login(username:"account", password:"{p}") {{ mySecret }}'
    for i, p in enumerate(passwords, 1))
r = requests.post(url, json={"query": f"mutation login {{\n{aliases}\n}}"})
print(r.status_code, r.text)
```

## 变体与关联

- 变体：别名重载（Alias Overloading）用于 DoS 或爆破；指令重载（Directive Overloading）、字段重复（Field Duplication）同样可放大单请求工作量。
- 变体：批量数组可换成多 operation 文档 + `operationName` 切换，或 GET 查询参数（若端点支持 GET，可能同时带来 CSRF 风险）。
- 变体：把用户名也做成别名维度，一次请求尝试多个账号×多个口令（password spray），进一步放大。
- 关联：[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（先拿 schema 找 login mutation）、[[web-generic-graphql-operation-name-authz-field-bypass]]（操作名鉴权绕过）、[[web-generic-graphql-importpaste-command-injection]]。

## 检测与防御

- 检测：graphql-cop 会把 Alias Overloading/Array-based Query Batching 标为风险；监控单请求中 operation/alias/字段数量、响应体大小、单 IP 的认证失败率；对 login mutation 单独统计尝试次数。
- 防御：限制单文档的 operation/alias/字段总数与查询深度/复杂度；禁用或严格限制批量查询数组；按 operation 与认证尝试（而非仅 HTTP 请求）限速；对登录加账号锁定、CAPTCHA、MFA；对敏感 mutation 禁止批量；返回统一错误避免 oracle。
- 说明：本文是 GraphQL 批量/别名放大认证爆破技术，severity 记为 medium；仅用于授权测试。
