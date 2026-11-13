---
id: web-java-deser-rome-badattribute-tostringbean-templatesimpl
title: ROME ToStringBean + BadAttributeValueExpException 反序列化触发 TemplatesImpl 字节码加载
type: scenario
domain: web
path: web/java/deserialization
technique: rome-badattribute-tostringbean-templatesimpl
tags:
- java
- deserialization
- gadget
- rome
- badattributevalue
- tostringbean
- templatesimpl
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:35:50+08:00'
  notes: 已对照原文第2/3/6节与图10核对：BAVE.readObject 在无 SecurityManager 时对 val 调 toString、构造传 null 后再反射设 val、ToStringBean(Templates.class, TemplatesImpl) 反射 getOutputProperties 加载 AbstractTranslet 字节码，均与原文与截图一致。dedup 与既有 rome HashMap+EqualsBean.hashCode 卡仅共享下游 ToStringBean→TemplatesImpl，入口类与触发方法不同，非同链，append_scenario 理由成立。原文仅第3节写环境依赖 rome 1.0，未声明受影响版本/区间，affected_versions 已 --clear。PoC 未在本机执行。
url: /docs/web/java/deserialization/web-java-deser-rome-badattribute-tostringbean-templatesimpl/
draft: false
kb_aliases:
- BAVE Rome 链
- BadAttributeValueExpException ToStringBean
- Rome 单对象触发链
- BAVE 触发 TemplatesImpl
- rome badattributevalue
---

## 一句话结论

目标存在 Java 原生反序列化入口且 classpath 有 rome 1.0 时，不需要 HashMap/HashSet 承载，直接反序列化一个 `BadAttributeValueExpException`（`val` 字段反射设为 `ToStringBean(Templates.class, TemplatesImpl)`）即可：`readObject` 对 `val` 调用 `toString()`，`ToStringBean` 反射调用 `TemplatesImpl.getOutputProperties()`，加载并实例化 `_bytecodes` 中的 AbstractTranslet 子类，执行任意代码。

## 原理

- **BAVE 的 toString 触发分支**：`BadAttributeValueExpException.readObject` 用 `GetField` 读出 `val`；当 `val` 非 null、不是 String，且 `System.getSecurityManager() == null`（或 val 是 Long/Integer/Float/Double/Byte/Short/Boolean）时，执行 `val = valObj.toString()`。默认未安装 SecurityManager，因此任意非 String 的 val 都会被调用 `toString()`。
- **ToStringBean 的反射 getter 逻辑**：无参 `toString()` 先按 `_obj.getClass().getName()` 算出 prefix，再调用 `toString(prefix)`；后者用 `BeanIntrospector.getPropertyDescriptors(this._beanClass)` 取得属性描述符，对每个满足“read 方法非空、声明类不是 Object、无参数”的属性执行 `pReadMethod.invoke(this._obj, NO_PARAMS)`。getter 列表来自 `_beanClass`，实际调用发生在 `_obj` 上，两个字段可分别赋值。
- **为什么用 Templates 接口**：`javax.xml.transform.Templates` 只声明 `newTransformer()` 与 `getOutputProperties()` 两个方法，getter 集合最小；若直接用 `TemplatesImpl.class`，大量无关 getter 可能先抛异常中断遍历。
- **危险 sink**：`TemplatesImpl.getOutputProperties()` → `newTransformer()` → `getTransletInstance()` → `defineTransletClasses()` → `TransletClassLoader.defineClass()` 加载 `_bytecodes` 中继承 `AbstractTranslet` 的类，其静态初始化块/构造器在实例化时执行。
- **为什么成立**：JDK 为了让 JMX 属性异常可读，在 readObject 里主动对 val 调 `toString()`；Rome 把“对象转字符串”实现成通用反射 getter 调用；TemplatesImpl 的 getter 又恰好会加载字节码。三者都是库的既有语义，不依赖任何缺失补丁。
- **构造期注意**：`BadAttributeValueExpException(Object val)` 构造函数本身会对非 null 的 val 调 `toString()`，直接传入 ToStringBean 会在生成端提前触发；应先用 `new BadAttributeValueExpException(null)`，再反射设置 `val` 字段。

## 触发条件

- 存在 Java 原生反序列化入口（`ObjectInputStream.readObject`），攻击者可控序列化字节流。
- classpath 含 rome 1.0（`com.sun.syndication.feed.impl.ToStringBean`）。
- JDK 提供可反射写入的 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`（JDK 8 最直接；高版本需模块 opens 或外部 Xalan）。
- 反序列化时未安装 SecurityManager（否则 val 不是基本类型包装类时不会走 toString 分支）。
- 反序列化过滤器未拦截 `BadAttributeValueExpException`、`ToStringBean`、`TemplatesImpl`。
- `Runtime.exec` 等命令执行未被策略阻断。

## 利用步骤

1. 用 Javassist/ASM 生成继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的类，在静态初始化块中执行命令，取 `toBytecode()`。
2. 新建 `TemplatesImpl`，反射设置 `_bytecodes = new byte[][]{bytes}`、`_name`（原文同时把 `_tfactory` 置 null；JDK8 原生反序列化时其 readObject 会重建工厂）。
3. 构造 `new ToStringBean(Templates.class, templateImpl)`，把 `_beanClass` 收窄为 `Templates` 接口、`_obj` 指向填好字节码的 `TemplatesImpl`。
4. `new BadAttributeValueExpException(null)`，反射把 `val` 字段设为该 `ToStringBean`。
5. 序列化该 BAVE 对象并发送到目标入口；目标 `readObject` 调用 `val.toString()` → `ToStringBean.toString(prefix)` → `TemplatesImpl.getOutputProperties()` → 字节码执行。
6. 验证：本地反序列化应执行命令；未触发时检查 SecurityManager、`TemplatesImpl` 字段可写性、过滤器与 rome 版本。

## PoC

```java
// 关键构造（省略 translet 生成与 setField 辅助方法；未在本机复跑）
byte[] translet = makeAbstractTranslet("java.lang.Runtime.getRuntime().exec(\"calc\");");

TemplatesImpl templates = new TemplatesImpl();
setField(templates, "_bytecodes", new byte[][]{translet});
setField(templates, "_name", "test");
setField(templates, "_tfactory", null);

ToStringBean toStringBean = new ToStringBean(Templates.class, templates);

BadAttributeValueExpException bave = new BadAttributeValueExpException(null);
setField(bave, "val", toStringBean);   // 构造函数传 null，避免生成端提前 toString

try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("bave.ser"))) {
    oos.writeObject(bave);
}
```

## 变体与关联

- [[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]：同一个 ToStringBean→TemplatesImpl 下游，入口换成 HashMap+EqualsBean.hashCode；本卡入口是 BAVE.readObject 直接 toString，单对象、不依赖 Map 容器。
- [[web-java-deser-commonscollections-cc5-badattribute-tostring]]：同一个 BAVE 触发原语，下游换成 TiedMapEntry/LazyMap/ChainedTransformer。
- [[web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain]]：同一个 BAVE 触发原语，下游换成 fastjson JSONArray 的 toString 反射 getter；本卡下游是 Rome ToStringBean，依赖与 PoC 不同。
- [[web-java-deser-vaadin-propertysetitem-nestedmethodproperty-templatesimpl]]、[[web-java-deser-rhino1-nativeerror-tostring-memberbox-invoke]]：同为“BAVE→某 toString 桥→反射 getter/调用”的同类组合。
- 变体：`_beanClass` 可换成其它只含危险 getter 的接口/类；下游可换成 `JdbcRowSetImpl.getDatabaseMetaData`（JNDI）、`SignedObject.getObject`（二次反序列化）等；BAVE 的 `val` 也可放其它 toString 会进入危险路径的对象。
- 边界：有 SecurityManager 且 val 非包装类时链断；JDK17+ 对 `TemplatesImpl` 模块强封装；过滤器拦截任一环时失效。

## 检测与防御

- 检测：序列化流中同时出现 `javax.management.BadAttributeValueExpException`、`com.sun.syndication.feed.impl.ToStringBean`、`TemplatesImpl`/`AbstractTranslet`；反序列化调用栈出现 `BadAttributeValueExpException.readObject → ToStringBean.toString → BeanIntrospector.getPropertyDescriptors → TemplatesImpl.getOutputProperties`。
- 防御：JEP 290 `ObjectInputFilter` 类白名单，拒绝非业务类；移除不必要的 rome 依赖；升级 JDK 并开启模块强封装；限制 `Runtime.exec` 与可疑进程创建。
- 响应：保留原始序列化流作为证据，确认是否已执行命令，排查同入口的其它 gadget 尝试。
