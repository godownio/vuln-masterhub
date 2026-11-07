---
id: web-java-deserialization-ibm-jcc-serverlistcache-getconnection
title: IBM Db2 JCC createLicenseCache 触发本地 jccServerListCache.bin 反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: ibm-jcc-serverlistcache-deserialization
aliases:
- CVE-2026-9762
- IBM JCC 反序列化
- Db2 JDBC getConnection RCE
- createLicenseCache
- jccServerListCache.bin
- JCC ServerListCache readObject
tags:
- java
- jdbc
- db2
- ibm-jcc
- deserialization
- readobject
- local-file
- drda
- rce
cve:
- CVE-2026-9762
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 'IBM Db2 Client 11.5：11.5.0-11.5.9（修复：V11.5.9 Special Build #87098 或更高）；IBM Db2 Client 12.1：12.1.0-12.1.4（修复：12.1.5 或 V12.1.4 Special Build #87349 或更高）；JCC 12.1.4.0（内部版本 4.37.4）受影响，12.1.5.0（4.38.7）已修复'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T03:02:12+08:00'
  notes: 已对照原文全文与6张图核对：DB2Driver URL createLicenseCache→DB2BaseDataSource→Connection.createLicenseCache_→t4.b#ai() 的 source/状态传播；am.k9#a(String,boolean) 无过滤 ObjectInputStream.readObject、cast 后置；completeConnect 222 置位与 383 步 QSQ serverType3 license flow 断开→t4.r#a→t4.b#a(c6) loadServerListCache 的 getConnection 内链路；ao#n() tmpdir 回退、12.1.5 整体删除磁盘缓存均与原文/图06 marker 栈一致；原文明确 11.5.0-11.5.9、12.1.0-12.1.4 受影响，已 set-versions。探针仅证明 sink 可达，gadget→RCE 边界卡片已写明；PoC 未在本机执行。
---

## 一句话结论

当低权限攻击者能影响 JDBC URL（注入 `createLicenseCache=true`）并向连接端的系统临时目录预置 `jccServerListCache.bin` 时，IBM JCC 12.1.4 会在 `getConnection` 的通信错误恢复路径中用无过滤的 `ObjectInputStream` 读取该文件；目标 classpath 存在可用 gadget 时即可在连接建立阶段触发反序列化 RCE。

## 原理

- **Source 在 URL 属性**：`DB2Driver#tokenizeURLProperties()` 把 JDBC URL 分号后的属性写入 `Properties`，`DB2Driver#getDataSource()` 对 `createLicenseCache` 单独处理并调用 `DB2BaseDataSource#setCreateLicenseCache(true)`。这是攻击者可控的开关。
- **状态传播**：物理连接建立后，`am.Connection#initPostConnectionProperties()` 把 DataSource 上的值复制到 `Connection.createLicenseCache_`；Type 4 连接类 `t4.b#ai()` 直接返回该字段。它只决定“是否允许读本地服务器列表缓存”，本身不触发反序列化。
- **Sink 在本地缓存读取**：`am.k9#a(String, boolean)` 遇到 `jccServerListCache.bin` 时解析出缓存路径，执行 `new ObjectInputStream(...).readObject()`，没有 `ObjectInputFilter`、类白名单、签名校验或自定义 `resolveClass`。读完后才强转 `(ServerListCache)`，而 Java 反序列化会先构建对象图并执行 `readObject`/`readResolve` 等回调，强转失败也不影响 gadget 已执行。
- **为什么会在 `getConnection` 内部触发**：`am.Connection#completeConnect(boolean)` 第 222 步置位 `createLicenseCache_`。对非 LUW 家族（ACCRDBRM 中 PRDID 前缀 `QSQ`/`ARI`，serverType 2/3），第 383 步 `checkForLicenseRestrictions()` 还会发起 `CALL SYSIBM.DB2CON_LIC` 网络 flow；恶意 DRDA 服务端在该 flow 断开 TCP，驱动进入通信错误恢复 `t4.a -> t4.r#a(Exception, aj) -> t4.b#a(c6) loadServerListCache`。当全局内存缓存 `ao.dX == null` 且 `ai() == true` 时，恢复逻辑读取磁盘上的 `jccServerListCache.bin`，进入上述 sink。LUW（`SQL` 前缀，serverType 4）第 383 步无网络 flow，只能在 `getConnection` 返回后的首次 SQL flow 触发。
- **保持内存缓存为空的服务端手法**：`firstConnectionEstablished` 只在 `rdbAccessed -> updateAlternateDataSource()` 且 `alternateServerNameIP_ != null` 时置位。恶意服务端在 ACCRDBRM 中不携带 SRVLST，客户端 URL 也不配 `clientRerouteAlternateServerName`，即可保持 `firstConnectionEstablished == false`、`ao.dX == null`，让错误恢复走磁盘读取分支。
- **tmpdir 回退放宽前提**：未配置全局属性 `db2.jcc.outputDirectory` 时，`am.ao#n()` 的字节码尾部会把缓存目录回退为 `System.getProperty("java.io.tmpdir")`（Linux/macOS 通常为对所有本地用户可写的 `/tmp`）。该回退在 CFR 反编译输出中不可见，只有 `javap` 才能确认。`outputDirectory` 不是 URL 属性，攻击者不能借 URL 任意指定目录，但默认 tmpdir 已足够满足文件预置条件，与官方 `AV:L/PR:L` 评级吻合。

## 触发条件

- 使用受影响版本：JCC 12.1.0-12.1.4 或 11.5.0-11.5.9（12.1.4.0 / 内部 4.37.4 可复现，12.1.5.0 / 4.38.7 不触发）。
- 攻击者能影响 JDBC URL 或连接属性，使 URL 中出现 `createLicenseCache=true`（典型：SaaS 数据源配置、测试平台、ETL 工具允许用户填连接串）。
- 攻击者能向连接端 `java.io.tmpdir`（或已配置的 `db2.jcc.outputDirectory`）写入 `jccServerListCache.bin`；共享主机、CI runner、容器内低权限用户通常满足。
- 目标 JVM classpath 存在可用的 Java 原生反序列化 gadget。
- 目标连接到攻击者控制的 DRDA 服务端（或可被中间人操纵的服务端），该服务端返回 `QSQ` 类 PRDID、ACCRDBRM 不带 SRVLST，并在 license flow 断开 TCP 制造通信错误。
- 首次触发窗口中服务器列表内存缓存尚未初始化（`ao.dX == null`）。

## 利用步骤

1. 确认目标应用使用 JCC 受影响版本，并存在用户可控的 JDBC URL 或数据源配置入口。
2. 生成反序列化 payload（真实 gadget 链，或仅写 marker 的无害探针），序列化后写入受害端 `java.io.tmpdir/jccServerListCache.bin`；跨机器时需先通过其他本地/远程写入能力落盘。
3. 启动恶意 DRDA stub：完成 EXCSAT/ACCSEC/SECCHK/ACCRDB 握手，PRDID 使用 `QSQ12010`（serverType 3），ACCRDBRM 不携带 SRVLST，在收到握手后的首个请求（`CALL SYSIBM.DB2CON_LIC`）时直接断开 TCP。
4. 让受害应用使用 `jdbc:db2://<恶意服务端>:50000/TESTDB:createLicenseCache=true;` 建连；不配置 `clientRerouteAlternateServerName`。
5. `getConnection` 在 license flow 遇到通信错误，恢复逻辑 `loadServerListCache` 读取 `jccServerListCache.bin`，`readObject` 执行 gadget。

## PoC

最小触发代码（攻击者只需让应用使用该 URL）：

```java
String url = "jdbc:db2://127.0.0.1:50000/TESTDB:createLicenseCache=true;";
DriverManager.getConnection(url, "db2user", "db2pass");
```

预置 payload（探针形态，真实利用替换为 gadget 序列化字节）：

```java
// 与 JCC 同包的探针，继承 t4.ServerListCache 让驱动侧强转通过；
// readObject 只写 marker，用于证明 sink 可达。
package com.ibm.db2.jcc.t4;

public final class VerificationPayload extends ServerListCache {
    private final String markerPath;
    public VerificationPayload(String markerPath) { this.markerPath = markerPath; }
    private void readObject(java.io.ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        java.nio.file.Files.write(java.nio.file.Paths.get(markerPath),
                Thread.currentThread().getStackTrace().toString().getBytes("UTF-8"));
    }
}
```

```java
// PayloadBuilder：写入驱动默认会读取的缓存文件
try (ObjectOutputStream out = new ObjectOutputStream(
        new FileOutputStream(System.getProperty("java.io.tmpdir") + "/jccServerListCache.bin"))) {
    out.writeObject(new VerificationPayload("/tmp/deserialization-marker.txt"));
}
```

恶意 DRDA stub 的关键行为：按 serverType 3 回包（PRDID `QSQ12010`），ACCRDBRM 省略 SRVLST，握手完成后收到 `CALL SYSIBM.DB2CON_LIC` 请求即断开连接。触发成功的唯一判定标准是 marker 文件出现，`getConnection` 抛出的 license 异常（`ERRORCODE=-4230`）在修复版同样会出现，不能作为判定依据。

探针需用 12.1.4 编译（12.1.5 已删除 `t4.ServerListCache`）；真实 gadget payload 不受此限制，写盘后即可被读取。

## 变体与关联

- **全局属性路径**：`DB2BaseDataSource#isCreateLicenseCache()` 同时合并实例字段与全局 `db2.jcc.createLicenseCache`（`ao.dM`）。即使不经过 URL，只要应用或其他配置入口能打开该全局开关，磁盘缓存读取能力仍存在。
- **连接池重连路径**：恶意服务端可在池化 `reset_()` 的第二次握手期间断开（killreset 模式），在重连握手阶段制造通信错误后进入同一恢复链。
- **`connlicj.bin`（LicenseCache）路径**：12.1.4 中 `LicenseCache#writeLicenseCacheToFile()` 已无调用者，属死代码；活跃 sink 只有 `jccServerListCache.bin` 读写路径。
- **同类 JDBC 驱动入口**：MySQL `autoDeserialize` / `ServerStatusDiffInterceptor`（恶意服务端返回序列化结果集）、H2 `INIT` + `CREATE ALIAS`（JDBC URL 直接执行 SQL/Java）与本链同属“用户可控 JDBC URL → 驱动侧危险能力”。参见 [[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]、[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]。
- **边界**：目标无可用 gadget 时只能证明反序列化 sink 可达，不能直接升级为 RCE；无法向 tmpdir 或 outputDirectory 写文件时不成立；12.1.5 删除了整条磁盘缓存设施（source、状态传播、触发分支、sink 四层同时消失），旧 `.bin` 即使存在也不会被打开。

## 检测与防御

- **检测（入口）**：JDBC URL 或数据源配置中出现 `createLicenseCache=true`；连接串指向非预期数据库主机；应用日志出现 `com.ibm.db2.jcc.am.k9.a` 调用 `ObjectInputStream.readObject` 的异常栈。
- **检测（主机）**：`java.io.tmpdir` 或 `db2.jcc.outputDirectory` 下出现非驱动正常生成的 `jccServerListCache.bin`、`serverlist.lock`；应用进程在连接数据库时读取该文件。
- **检测（网络）**：DRDA 服务端返回 `QSQ`/`ARI` 前缀 PRDID、ACCRDBRM 不带 SRVLST，并在 license flow 前后异常断开；同一客户端短时间内重复握手。
- **修复**：升级到 `com.ibm.db2:jcc:12.1.5.0` 或更高；必须停留 12.1.4 时使用 V12.1.4 Special Build #87349 或更高；11.5 线使用 V11.5.9 Special Build #87098 或更高。官方标记无 workaround，仅删除 URL 中的 `createLicenseCache` 不足以覆盖全局属性路径。
- **加固**：禁止用户输入直接进入 JDBC URL/连接属性，数据源使用预置白名单；收紧系统临时目录权限（每用户私有 tmp、容器内隔离）；对 Java 反序列化入口部署 `ObjectInputFilter` 类白名单作为纵深防御；盘点 Maven 依赖、应用服务器共享库、`WEB-INF/lib`、fat JAR、容器镜像与 Db2 产品内置副本中的 JCC 版本。
