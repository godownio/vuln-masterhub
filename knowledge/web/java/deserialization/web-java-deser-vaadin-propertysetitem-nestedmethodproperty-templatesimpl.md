---
id: web-java-deser-vaadin-propertysetitem-nestedmethodproperty-templatesimpl
title: Vaadin PropertysetItem.toString → NestedMethodProperty.getValue 反射 getter 链：nested property 指向 TemplatesImpl.outputProperties 直接触发 translet 加载
type: scenario
domain: web
path: web/java/deserialization
technique: vaadin-propertysetitem-nestedmethodproperty-getter-rce
aliases:
- Vaadin 反序列化链
- NestedMethodProperty getValue
- PropertysetItem toString 触发
- outputProperties TemplatesImpl
- BadAttributeValueExpException 触发 toString
tags:
- java
- deserialization
- vaadin
- gadget-chain
- templatesimpl
- tostring-trigger
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:56:41+08:00'
  notes: 已对照原文核对；NestedMethodProperty.initialize/getValue、PropertysetItem.toString/getItemProperty/addItemProperty 源码与正文逐段一致，payload（TemplatesImpl+NestedMethodProperty(templates,outputProperties)+BadAttributeValueExpException.val 反射写入）与原文代码一致；与同篇 JNDI 链卡的差异（不碰 SQLContainer/TableQuery/J2EEConnectionPool）成立；本次核对未读取图片，弹计算器效果仅见截图，未复跑；7.7.14 是原文测试依赖，非受影响版本区间，未设 affected_versions
---

## 一句话结论

classpath 存在 Vaadin 7.x（`vaadin-server`/`vaadin-shared`）时，`PropertysetItem.toString()` 会遍历自身的属性 map 并逐个调用 `Property.getValue()`；把某个属性做成 `NestedMethodProperty(templatesImpl, "outputProperties")`，`getValue()` 就按属性名逐级反射调用 getter，最终调用 `TemplatesImpl.getOutputProperties()` 触发 `newTransformer()` → 加载攻击者构造的 translet 字节码，形成一条不依赖 TemplatesImpl 直接出现在触发器上的原生反序列化链。

## 原理

- **触发点**：`BadAttributeValueExpException.readObject` 会对 `val` 字段调用 `toString()`（JDK 内建的经典 toString 触发器）；把 `val` 反射改成 `PropertysetItem` 即可进入其 `toString`。
- **`PropertysetItem.toString`**：遍历 `getItemPropertyIds()`，对每个 id 调 `getItemProperty(propertyId).getValue()` 并拼接结果。`getItemProperty` 只是从内部 map 取值，而 `addItemProperty(id, property)` 是公开方法，可在序列化前把任意 `Property` 放进 map —— 攻击者完全控制将被调用的 `Property` 实例。
- **`NestedMethodProperty.getValue` 为什么危险**：
  ```java
  Object object = instance;
  for (Method m : getMethods) { object = m.invoke(object); if (object == null) return null; }
  ```
  `instance` 由构造参数决定，`getMethods` 在构造时由 `initialize(beanClass, propertyName)` 按**点分属性名**逐段解析：`propertyName.split("\\.")`，每段用 `MethodProperty.initGetterMethod` 找 getter 并记录。因此 `new NestedMethodProperty<>(templatesImpl, "outputProperties")` 生成的链就是「对 `TemplatesImpl` 调 `getOutputProperties()`」。
- **为什么等于 RCE**：`TemplatesImpl.getOutputProperties()` 内部调用 `getTransletInstance()` → `defineTransletClasses()`，把 `_bytecodes` 里的字节码定义为 `AbstractTranslet` 子类并实例化；子类的静态初始化块/构造器即攻击者代码。这条路径与反序列化过滤器里常见的「直接出现 `TemplatesImpl` 就拦」形成错位：只有当过滤器按字节/类名黑名单匹配 `TemplatesImpl` 时才会命中。
- 成立的两个前提：`BadAttributeValueExpException` 的 `val` 未被 JDK 补丁封死（JDK 8 系可用反射写入），以及 `TemplatesImpl` 所在模块未被强限制（原文环境为 JDK 8 + Javassist 动态生成 translet）。

## 触发条件

- 目标有 Java 原生反序列化入口（`ObjectInputStream.readObject`）。
- classpath 含 Vaadin 7.x（原文 `vaadin-server` / `vaadin-shared` 7.7.14），提供 `PropertysetItem`、`NestedMethodProperty`。
- 反序列化过滤器未禁用 `PropertysetItem`/`NestedMethodProperty`/`BadAttributeValueExpException`（黑名单型过滤常只写 `TemplatesImpl`、`InvokerTransformer` 等常见类名）。
- `_bytecodes` 的字节码可被 `defineClass` 加载（JDK 版本允许定义、无模块强封装限制）。

## 利用步骤

1. 用 Javassist 生成 `AbstractTranslet` 子类，把命令执行放进 `static` 初始化块，取 `toBytecode()`。
2. 反射设置 `TemplatesImpl._bytecodes`、`_name`，并把 `_tfactory` 置 null（避免依赖 `TransformerFactoryImpl`）。
3. `new NestedMethodProperty<>(templates, "outputProperties")`，用 `PropertysetItem.addItemProperty("任意id", prop)` 放入。
4. `new BadAttributeValueExpException("x")`，反射把 `val` 改成该 `PropertysetItem`。
5. 序列化并投递到目标反序列化入口；`readObject` 时 `val.toString()` → `getValue()` → `getOutputProperties()` 触发命令执行。

## PoC

```java
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{ makeTranslet() }); // AbstractTranslet 子类 + static{Runtime.exec}
setFieldValue(templates, "_name", "x");
setFieldValue(templates, "_tfactory", null);

PropertysetItem item = new PropertysetItem();
item.addItemProperty("k", new NestedMethodProperty<>(templates, "outputProperties"));

BadAttributeValueExpException ex = new BadAttributeValueExpException("x");
setFieldValue(ex, "val", item);      // 反射写入 val
// 序列化 ex，投递
```

`makeTranslet()` 用 `ClassPool.makeClass` 继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，`makeClassInitializer().insertBefore("Runtime.getRuntime().exec(...)")` 后取 `toBytecode()`。原文该 payload 在本机弹出计算器验证通过。

## 变体与关联

- **nested property 可指向任意 getter**：把 `outputProperties` 换成其它「getter 内触发危险操作」的类即可复用，例如 `getDatabaseMetaData`（JDBC 驱动侧 JNDI）、`getContent` 等；链式多级属性还能跨对象多跳（`a.b.c` 会依次 invoke 多个 getter）。
- **触发点变体**：任何对可控对象调 `toString` 的入口都能替代 `BadAttributeValueExpException`（如 `HashMap` 键、日志框架、`Xslt`/`ToStringBean`）。
- 关联：`web/java/deserialization` 下「resolveProxyClass 黑名单绕过（Hutool MapProxy）」把 Vaadin `PropertysetItem`/`NestedMethodProperty` 当作外层触发器去桥接**二次反序列化**，本卡是同两个类直接打到 `TemplatesImpl`，没有第二次反序列化，触发器与 sink 都不同；TemplatesImpl 本体见同目录 JDK 原生链卡。
- 边界：过滤器若对 `AbstractTranslet`/`NestedMethodProperty` 做白名单式拒绝则失效；JDK 17 需 `--add-opens` 才能反射改 `_bytecodes`；Vaadin 8+ 包名/类结构变化后不通用。

## 检测与防御

- 检测：反序列化流中出现 `com.vaadin.data.util.PropertysetItem`、`NestedMethodProperty`、`BadAttributeValueExpException` 组合；`TemplatesImpl` 父类为 `AbstractTranslet` 的新类被 `defineClass`；同一请求内 `Method.invoke` 反射调用密集且发生在 `readObject` 栈上。
- 防御：使用 `ObjectInputFilter`/类白名单（不要只靠黑名单）；反序列化入口做认证与来源限制；移除不必要的 Vaadin 反序列化可达类；升级 JDK 并保持模块封装，使 `TemplatesImpl` 字段不可反射写。
