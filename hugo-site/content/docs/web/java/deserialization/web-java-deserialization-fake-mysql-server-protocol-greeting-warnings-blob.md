---
id: web-java-deserialization-fake-mysql-server-protocol-greeting-warnings-blob
title: 手写恶意 MySQL 服务端：greeting 固定字节 + 必回 SHOW WARNINGS + BLOB 列，才能让驱动把结果集当对象反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: fake-mysql-server-protocol-greeting-session-status-blob
tags:
- java
- mysql
- jdbc
- deserialization
- fake-server
- protocol
- autodeserialize
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:57:57+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文 JDBC_Attack_server 的分支（session.auto_increment_increment 时回 SHOW SESSION STATUS 结果集、SHOW WARNINGS 必回、SET NAMES/SET character_set_results 回 OK）、ResultSetImpl.getObject 的 case BLOB 触发 readObject，以及 queryInterceptors(8.x)/statementInterceptors(6.x/5.x)/detectCustomCollations(5.1.19-5.1.40) 的版本分流均与卡内描述一致；原文未给 MySQL 驱动受影响版本区间（8.0.13 为复现环境），故未设 versions；PoC 为协议骨架、未对真实目标执行
url: /docs/web/java/deserialization/web-java-deserialization-fake-mysql-server-protocol-greeting-warnings-blob/
draft: false
kb_aliases:
- 恶意 MySQL 服务端实现
- ServerStatusDiffInterceptor 协议细节
- SHOW SESSION STATUS 回包
- SHOW WARNINGS 必须回复
- BLOB 列触发 getObject 反序列化
---

## 一句话结论

用现成工具（MySQL_Fake_Server 等）打 JDBC 反序列化时经常“连上了但没触发”，根因是伪服务端只回了结果集、没有满足驱动的协议要求。要让 `autoDeserialize=true` + `ServerStatusDiffInterceptor` 真正走到 `readObject`，伪服务端必须按顺序完成：回一段合法的 greeting 握手包 → 对客户端每条语句回 OK → 在收到 `SHOW SESSION STATUS` 时回结果集 → 在客户端随后发来的 `SHOW WARNINGS` 上也回一个合法结果集（不回会导致客户端解析报错、后续流程中断）→ 把要反序列化的字节放进结果集的 **BLOB 类型列**里，由 `ResultSetImpl.getObject` 的 `case BLOB` 分支调用 `readObject`。

## 原理

- **`autoDeserialize` 只是开关，不是触发点**：它让驱动在读取某些列时对字节做 Java 反序列化；真正走到反序列化的路径取决于哪条代码路径去读结果集。
- **`ServerStatusDiffInterceptor` 提供触发时机**：驱动在连接初始化阶段（`initializePropsFromServer → handleAutoCommitDefaults → setAutoCommit` 之前）通过 `invokeQueryInterceptorsPre` 调拦截器的 `preProcess`，`ServerStatusDiffInterceptor.populateMapWithSessionStatusValues` 会执行 `SHOW SESSION STATUS` 并遍历结果集，这就给了伪服务端“返回恶意结果集”的机会——发生在发送 `SET autocommit=1` 之前。
- **协议完整性是硬要求**：
  - greeting 包决定握手能否完成（版本串、能力位、字符集、插件名都要合法，否则客户端直接异常）；
  - 每条客户端语句都要回 OK 包（`SET NAMES`、`SET character_set_results` 等），否则客户端卡在等响应；
  - `SHOW SESSION STATUS` 的结果集之后，客户端还会发 `SHOW WARNINGS`（`scanForAndThrowDataTruncation → convertShowWarningsToSQLWarnings`），这个也必须回一个合法结果集，否则解析失败、链路中断。
- **必须用 BLOB 类型的列**：`resultSetToMap` 循环 `rs.getObject(i)`，对 BLOB 列走 `case BLOB` → 取字节 → `ObjectInputStream.readObject`；如果列被声明成 VARCHAR/VARBINARY，走的是字符串/字节读取分支，反序列化不会发生。
- **gadget 由 `user` 决定**：伪服务端读握手包里的用户名（有的工具还读库名），按前缀（`deser_`/`yso_`）解析出链名与命令，因此“能收到握手”之后还要保证 `user` 里带正确的选择标识。

## 触发条件

- 目标应用会把连接指向攻击者控制的 MySQL 服务端（JDBC URL/数据源配置可控），并启用了 `autoDeserialize=true` 与 `ServerStatusDiffInterceptor`（或 `detectCustomCollations`）。
- 伪服务端能完整实现 greeting / OK / 结果集 / SHOW WARNINGS 四类包。
- 目标 classpath 有可用 gadget（原文用 commons-collections）。
- 目标能出网到伪服务端端口（或走本机管道/文件变体）。

## 利用步骤

1. 起伪服务端，先只回 greeting，用官方客户端/目标应用连接，确认握手成功、能收到客户端后续语句（`SET NAMES` 等）。
2. 按语句内容分支回包：普通语句回 OK；`SHOW SESSION STATUS` 回构造的结果集；`SHOW WARNINGS` 回空结果集（列结构合法）。
3. 把序列化字节作为 BLOB 列的值放进 `SHOW SESSION STATUS` 的结果集中；列类型字节必须声明为 BLOB。
4. 确保 `user` 值带上 gadget 选择前缀与命令（如 `user=deser_CC6_calc`），并在 URL 里追加 `autoDeserialize=true&queryInterceptors=...ServerStatusDiffInterceptor`。
5. 让目标用该 URL 建连，观察是否触发 gadget（计算器/回连/内存马）；若失败，逐段核对：greeting 是否被接受、是否收到 `SHOW WARNINGS`、BLOB 分支是否命中。

## PoC

```java
// 伪服务端主循环骨架（原文 JDBC_Attack_server 的结构）
try (ServerSocket serverSocket = new ServerSocket(3306, 50, InetAddress.getByName("0.0.0.0"))) {
    while (true) {
        try (Socket s = serverSocket.accept()) {
            sendData(s, GREETING_DATA);            // 固定 greeting 字节
            while (true) {
                receiveData(s);                     // 客户端登录/查询
                sendData(s, RESPONSE_OK_DATA);       // 先回 OK
                String data = receiveData(s);
                if (data.contains("session.auto_increment_increment")) {
                    sendData(s, SHOW_SESSION_STATUS_WITH_BLOB);   // 结果集，BLOB 列内是 cc6.ser
                    data = receiveData(s);
                } else if (data.contains("SHOW WARNINGS")) {
                    sendData(s, SHOW_WARNINGS_EMPTY_RESULTSET);   // 必须回，否则客户端解析失败
                }
            }
        }
    }
}
```

```text
# 结果集列的要点（十六进制包里的字段顺序）
- 列定义包：catalog / schema / table / org_table / name / org_name ... 类型字节 = 252 (BLOB) / 字符集 / 长度
- 行数据包：长度编码的字节串，内容 = 序列化 gadget 字节
- 结尾 EOF/OK 包，表明结果集结束
```

说明：PoC 为协议骨架，具体字节需按 MySQL 协议文档组装（原文贴出了 `GREETING_DATA`、`RESPONSE_OK_DATA` 与 `SHOW SESSION STATUS` 结果集的完整十六进制串）；未对真实目标执行。

## 变体与关联

- **触发路径变体**：`queryInterceptors`/`statementInterceptors`（8.x/6.x/5.x 参数名与包名不同）、`detectCustomCollations=true`（5.1.19–5.1.40）、连接后主动触发查询。原文列出各版本对应写法与不适用版本（5.1.18 以下与 5.1.41 以上）。
- **落地形态变体**：直接出网连伪服务端；不出网时把协议包写成 pipe 文件/本地文件，配合 `NamedPipeSocketFactory` 或 `allowLoadLocalInfile` 变体。
- **同一原语的其他数据库**：伪造 PostgreSQL（`socketFactory`）、H2（`INIT`）、Derby（复制流）等服务端，思路都是“让客户端在读响应时进入反序列化/类加载分支”。
- **关联**：`web-java-deserialization-mysql-jdbc-url-autodeserialize-rce`（同一漏洞的利用总述与版本分流）、`web-java-deserialization-fake-mysql-custom-gadget-user-key-newline`（`user` 值选择 gadget 与自定义 payload 的换行坑）、`web-java-deserialization-fake-mysql-signedobject-jackson-second-order-bypass`（结果集列被类黑名单限制时的二次反序列化）、`web-java-deserialization-mysql-jdbc-namedpipe-proc-fd-no-egress`（不出网时把协议包落成文件的变体）。
- **边界**：驱动版本不支持 `autoDeserialize`/拦截器、URL 参数被白名单拦、目标无法出网且无本地文件变体、gadget 不在 classpath 时链不成立；`SHOW WARNINGS` 不回包会让客户端在解析阶段抛异常，是最常见的“看起来连上了但没反应”。

## 检测与防御

- **入口收口**：JDBC URL 的 host/参数不由用户控制；数据源测试接口做管理员鉴权与驱动/URL 白名单。
- **参数黑名单**：拒绝 `autoDeserialize`、`detectCustomCollations`、`queryInterceptors`、`statementInterceptors`、`allowLoadLocalInfile`、`allowUrlInLocalInfile`、`namedPipePath` 等键（含大小写/编码变体）。
- **出站控制**：应用服务器不应能连任意 MySQL 端口；出站白名单 + 异常连接告警（尤其“握手后只回结果集不提供服务”的对端）。
- **运行时**：JEP 290 全局过滤器（`jdk.serialFilter`）阻断 CC 等 gadget；JDK 升级；禁用 `ObjectInputStream` 反序列化不可信来源。
- **检测**：JDBC URL 出现上述参数；应用进程连接陌生 3306/高位端口且握手后立即收到结果集；异常栈出现 `ResultSetImpl.getObject`/`ResultSetImpl.getBytes` 与 `ObjectInputStream.readObject` 相邻；`SHOW SESSION STATUS`/`SHOW WARNINGS` 出现在非数据库客户端的流量中。
