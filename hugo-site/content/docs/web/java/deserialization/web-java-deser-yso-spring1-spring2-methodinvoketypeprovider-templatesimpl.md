---
id: web-java-deser-yso-spring1-spring2-methodinvoketypeprovider-templatesimpl
title: ysoserial Spring1/Spring2：MethodInvokeTypeProvider.readObject 入口经三层动态代理到 TemplatesImpl.newTransformer 的 Spring 反序列化链
type: scenario
domain: web
path: web/java/deserialization
technique: methodinvoketypeprovider-triple-proxy-templatesimpl
tags:
- java
- deserialization
- spring
- ysoserial
- dynamic-proxy
- templatesimpl
- rce
affected_versions: Spring 3.0.0 - 4.1.4
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-35
  verified_at: '2026-11-08T18:24:03+08:00'
  notes: 已对照原文核对：Spring1/Spring2 链结构、三层动态代理、MethodInvokeTypeProvider 入口、TemplatesImpl sink 与原文及 23 张调试图（img04-19）一致，PoC 完整且 img12/img19 弹计算器证明打通；affected_versions「Spring 3.0.0 - 4.1.4」与原文「spring版本范围在3.0.0到4.1.4」一致；原文 java 8u65 为测试环境版本未写入正确；与 Jackson/Fastjson 入口的 AOP 卡入口与 gadget 结构不同，dedup 理由成立；未验证点：未自行复现环境
url: /docs/web/java/deserialization/web-java-deser-yso-spring1-spring2-methodinvoketypeprovider-templatesimpl/
draft: false
kb_aliases:
- Spring1 链
- Spring2 链
- yso spring gadget
- MethodInvokeTypeProvider 反序列化
- ObjectFactoryDelegatingInvocationHandler 链
- JdkDynamicAopProxy 链
---

## 一句话结论

classpath 含 Spring core/beans（3.0.0–4.1.4）且存在原生反序列化入口时，用 `SerializableTypeWrapper$MethodInvokeTypeProvider.readObject` 作入口，借三层 JDK 动态代理（AnnotationInvocationHandler → ObjectFactoryDelegatingInvocationHandler / JdkDynamicAopProxy）把 `getType()`/`newTransformer()` 的调用引导到 `TemplatesImpl.newTransformer()`，实现任意类加载 RCE；两条链结构相同，仅中间层 InvocationHandler 不同，Spring2 证明 ObjectFactoryDelegatingInvocationHandler 被禁时仍有替代路径。

## 原理

- 入口 `MethodInvokeTypeProvider.readObject` 反序列化后执行 `ReflectionUtils.invokeMethod(method, provider.getType())`：`methodName` 可反射改为任意方法名，`method` 在构造时传 `Object.class.getMethod("toString")` 绕过构造器对方法返回类型的检查（返回类型需为 Type）。
- `provider` 是实现了 `TypeProvider` 接口的动态代理，`getType()` 调用转发到 `AnnotationInvocationHandler.invoke`：memberValues 是可控 Map，键 `getType` 对应的值原样返回。
- 返回值必须是 `Type` 类型且后续还要能触发 `newTransformer`，因此该值本身又是一个同时实现 `Type` 与 `Templates` 双接口的代理对象——这就是需要多层代理的原因：
  - Spring1：该双接口代理的 handler 是 `AutowireUtils$ObjectFactoryDelegatingInvocationHandler`，其 invoke 默认分支执行 `method.invoke(this.objectFactory.getObject(), args)`；`objectFactory` 再是第三个代理（handler 仍为 AnnotationInvocationHandler，memberValues 键 `getObject` 值为 TemplatesImpl），于是 `getObject()` 返回 TemplatesImpl，最终等价于 `TemplatesImpl.newTransformer()`。
  - Spring2：双接口代理的 handler 换成 Spring AOP 的 `JdkDynamicAopProxy`，其 `advised.targetSource` 通过 `AdvisedSupport.setTargetSource(new SingletonTargetSource(templates))` 直接持有 TemplatesImpl，invoke 无拦截器时走 `AopUtils.invokeJoinpointUsingReflection(target, method, args)` 反射调用 target 的 newTransformer。
- 最终 sink 是经典的 `TemplatesImpl.newTransformer → getTransletInstance → defineTransletClasses → TransletClassLoader.defineClass`：`_bytecodes` 中继承 AbstractTranslet 的恶意类在 defineClass 后实例化，static 块执行 `Runtime.exec`。
- 成立根源：Spring 把可序列化的类型包装/工具类（SerializableTypeWrapper、AutowireUtils）与 JDK 原生 AnnotationInvocationHandler 组合后，反序列化过程中"取值"与"调方法"的每一步都变成攻击者可控的反射跳板。

## 触发条件

- 目标 classpath 存在 spring-core/spring-beans（Spring2 另需 spring-aop），版本 3.0.0–4.1.4（更高版本 SerializableTypeWrapper 的相关类已修补/结构变化）；
- 存在可用的 ObjectInputStream 反序列化入口；
- JDK 8（8u65 实测；AnnotationInvocationHandler 的 memberValues 可控性在 JDK8u71 后被修改，链路需相应调整）。

## 利用步骤

1. 准备恶意 Translet 类（继承 AbstractTranslet，static 块放 payload），字节码填入 TemplatesImpl 的 `_bytecodes`，补 `_name`、`_tfactory`。
2. 构造 ObjectFactory 层：HashMap{getObject: templates} → AnnotationInvocationHandler → 代理 ObjectFactory 接口（Spring1）。
3. 构造中间层：`ObjectFactoryDelegatingInvocationHandler(objectFactory代理)`（Spring1）或 `AdvisedSupport + SingletonTargetSource(templates) → JdkDynamicAopProxy`（Spring2），生成实现 Type+Templates 双接口的代理。
4. 构造外层：HashMap{getType: 双接口代理} → AnnotationInvocationHandler → 代理 TypeProvider 接口。
5. 实例化 `MethodInvokeTypeProvider(typeProviderProxy, Object.class.getMethod("toString"), 0)`，反射把 `methodName` 改为 `newTransformer`，序列化输出。
6. 目标端 readObject 即触发 RCE。

## PoC

Spring1 核心 PoC（完整可运行，见原文，节选关键三步）：

```java
// 第三层：ObjectFactory 代理 -> getObject() 返回 templates
InvocationHandler h = (InvocationHandler) ctor.newInstance(Target.class, mapOf("getObject", templates));
ObjectFactory<?> of = (ObjectFactory<?>) Proxy.newProxyInstance(cl, new Class[]{ObjectFactory.class}, h);
// 第二层：双接口代理 -> method.invoke(objectFactory.getObject(), args)
InvocationHandler h2 = (InvocationHandler) ctor2.newInstance(of);
Type type = (Type) Proxy.newProxyInstance(cl, new Class[]{Type.class, Templates.class}, h2);
// 第一层：TypeProvider 代理 + 入口
Object o = ctor3.newInstance(typeProviderProxy, Object.class.getMethod("toString"), 0);
setField(o, "methodName", "newTransformer");
```

Spring2 仅第 2 步不同：`AdvisedSupport as; as.setTargetSource(new SingletonTargetSource(templates));` 后用 `JdkDynamicAopProxy` 生成双接口代理。两条链均实测弹出计算器。

## 变体与关联

- 变体：中间层 handler 还可换成其他能把调用转发到可控对象的 InvocationHandler；sink 可从 TemplatesImpl 换成 JNDI（见 LdapAttribute.getAttributeDefinition 卡）；
- 关联：与 CC 链共享 TemplatesImpl sink 与 defineTransletClasses 原理；ObjectFactoryDelegatingInvocationHandler 在 Hessian 场景的组合见 hessian-spring-proxy-invocationhandler-jndi 卡；
- 与 Spring AOP 相关代理链（JdkDynamicAopProxy 包装 Templates 绕黑名单）同族，但本链入口是原生反序列化而非 JSON 序列化。

## 检测与防御

- 升级 Spring 到 4.1.5+ / 5.x（SerializableTypeWrapper 与 AutowireUtils 相关可序列化内部类已收紧）；
- 反序列化入口加黑/白名单过滤（如 SerialKiller、JEP 290 agent）：重点拦截 `SerializableTypeWrapper$MethodInvokeTypeProvider`、`AutowireUtils$ObjectFactoryDelegatingInvocationHandler`、`sun.reflect.annotation.AnnotationInvocationHandler`；
- JDK 8u71+ 对 AnnotationInvocationHandler 的修改可打断该链的 memberValues 可控性；
- 监控反序列化点出现的 `TemplatesImpl.newTransformer` 与异常的 TransletClassLoader.defineClass。
