---
id: web-java-deser-cc4-transformer-reuse-object-multicall
title: Commons Collections4 Transformer 链内复用同一对象完成两段式反射调用
type: scenario
domain: web
path: web/java/deserialization
technique: cc4-transformer-object-reuse
tags:
- java
- deserialization
- gadget
- commons-collections4
- transformer
- chained-transformer
- unsafe
- chain-construction
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T01:56:12+08:00'
  notes: 已对照原文核对：ClosureTransformer 执行 iClosure.execute(input) 后 return input、TransformerClosure.execute 忽略返回值、InvokerTransformer(input.getClass()) 在 Unsafe.class 上调用 getDeclaredField/setAccessible/get 的组合与原文 2.1 节一致；该手法在原文完整 CC4→TemplatesImpl 链中已打通；未验证点：单独 PoC 仅取得 Unsafe，最终危害依赖后续调用（卡片已注明）
url: /docs/web/java/deserialization/web-java-deser-cc4-transformer-reuse-object-multicall/
draft: false
kb_aliases:
- ClosureTransformer TransformerClosure
- Transformer 链同一对象调用两次
- ChainedTransformer 多步反射
- 链内构造 Unsafe 调用
- Transformer functor 分支
---

## 一句话结论

commons-collections4 的 `ChainedTransformer` 默认把上一步结果作为下一步输入，单步 `InvokerTransformer` 只能调用一次方法；用 `ClosureTransformer` + `TransformerClosure` 可在链内对同一对象先执行一次副作用调用（如 `Field.setAccessible(true)`），再把该对象原样交给后续步骤（如 `Field.get(null)`），从而在纯 Transformer 数组里完成需要同一对象连续两次调用的反射操作（原文据此取得 `Unsafe` 并最终 RCE）。

## 原理

- `ChainedTransformer.transform(input)` 依次执行 `iTransformers[i].transform(object)`，每步返回值成为下一步输入。`InvokerTransformer.transform(input)` 只做一次 `input.getClass().getMethod(...).invoke(input, args)` 并返回结果，无法对同一个对象先做“无返回值或返回新值”的副作用再继续使用。
- 典型卡点是 JDK 的 `Unsafe` 获取：
  ```java
  Field f = Unsafe.class.getDeclaredField("theUnsafe");
  f.setAccessible(true);          // 返回 void，且必须作用于同一个 Field 对象
  Unsafe u = (Unsafe) f.get(null);
  ```
  `setAccessible` 与 `get` 必须落在同一个 `Field` 实例上，而 `Field` 不可序列化，不能预先在链外做好再放进 payload。
- `ClosureTransformer.transform(input)` 的实现是 `iClosure.execute(input); return input;`；`TransformerClosure.execute(input)` 的实现是 `iTransformer.transform(input);`（忽略返回值）。把 `InvokerTransformer("setAccessible", {boolean.class}, {true})` 包进 `TransformerClosure`，再包进 `ClosureTransformer`，就得到一个“执行副作用、原样返回输入”的链节。后续 `InvokerTransformer("get", {Object.class}, {null})` 收到的仍是同一个 `Field`。
- 为什么 `InvokerTransformer("getDeclaredField", ...)` 能在 `Unsafe.class` 上调用：`InvokerTransformer` 取的是 `input.getClass()`。传入 `Unsafe.class`（一个 `Class` 对象）时 `input.getClass()` 为 `Class.class`，而 `getDeclaredField` 是 `Class` 的公有方法，因此可正常反射调用；同理 `getMethod`、`getDeclaredMethod` 也可作为链内反射入口。
- 该组合是通用链构造手法，不限于 `Unsafe`：凡是“先配置对象/开放访问，再用同一对象执行真正动作”的两段式调用，都可用此链节拼接。原文最终用它取得 `Unsafe`，执行 `getAndSetObject` 改写 `Class.packageName`，进而绕过 JDK17 模块校验触发 `TemplatesImpl`。

## 触发条件

- classpath 含 commons-collections4（`ClosureTransformer`、`TransformerClosure`、`InvokerTransformer`、`ConstantTransformer`、`ChainedTransformer` 均可序列化，原文 4.0）；
- 存在能触发 `Transformer.transform` 的反序列化入口（如 `TransformingComparator` + `PriorityQueue`、`LazyMap` 等）；
- 目标方法可被反射调用（目标类/方法可见，或已有模块绕过手段）；
- 需要构造的链节对象满足序列化要求（`Field`、`Method` 等反射对象不可直接序列化，必须在链内生成）。

## 利用步骤

1. 用 `ConstantTransformer(Class对象)` 固定链的初始输入，避免依赖触发点传入的参数；
2. 用 `InvokerTransformer` 调 `getDeclaredField`/`getDeclaredMethod` 取得反射对象；
3. 用 `ClosureTransformer(new TransformerClosure(new InvokerTransformer("setAccessible", {boolean.class}, {true})))` 对该反射对象执行 `setAccessible(true)` 并原样返回；
4. 用后续 `InvokerTransformer` 执行真正的动作（如 `get(null)` 取单例、`invoke(...)` 调方法）；
5. 把上述 `Transformer[]` 交给 `ChainedTransformer`，再接到任意 `transform` 触发点。

## PoC

```java
// 链内取得 sun.misc.Unsafe 实例（最终危害取决于后续如何调用）
Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");

Transformer[] ts = new Transformer[]{
    new ConstantTransformer(unsafeClass),
    new InvokerTransformer("getDeclaredField", new Class[]{String.class}, new Object[]{"theUnsafe"}),
    new ClosureTransformer(new TransformerClosure(
        new InvokerTransformer("setAccessible", new Class[]{boolean.class}, new Object[]{true}))),
    new InvokerTransformer("get", new Class[]{Object.class}, new Object[]{null})
};

Transformer chain = new ChainedTransformer(ts);
Object unsafe = chain.transform(null);   // 返回 Unsafe 实例
```

```text
# 等价 Java 语义：
# Class.getDeclaredField("theUnsafe").setAccessible(true).get(null)
# ClosureTransformer 负责“调用 setAccessible 后仍把 Field 传下去”
```

## 变体与关联

- 同类可组合的 functor（原文筛选过的候选）：
  - `IfTransformer`：`iPredicate.evaluate(input) ? iTrueTransformer.transform(input) : iFalseTransformer.transform(input)`，可用谓词控制走哪条分支，三元表达式会实际求值两个分支中的被选中者；
  - `TransformedPredicate.evaluate`：`iTransformer.transform(object)` 后把结果交给 `iPredicate.evaluate`，可作“执行 transform 并继续判断”的链节；
  - `TransformerPredicate.evaluate`：`iTransformer.transform(object)` 要求返回 `Boolean`，适合 `setAccessible` 这类返回 `void` 之外、需要布尔结果的场景；
  - `ComparatorPredicate` / `EqualPredicate`：通过 `compare`/`equals` 间接进入 `transform`，可把比较器链与 Transformer 链拼接。
- 关联：[[web-java-deser-jdk17-cc4-package-name-bypass-templatesimpl]]（本手法在原文中的完整利用链）；[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（CC4 基础触发链）。
- 边界：commons-collections 版本差异导致 functor 可序列化性不同；JEP 290 过滤 `ChainedTransformer`/`ClosureTransformer` 等类型会使链失效。

## 检测与防御

- 检测：序列化流中出现 `ChainedTransformer` 内嵌 `ClosureTransformer`/`TransformerClosure` 的组合，尤其是同一条链里同时出现 `getDeclaredField`/`setAccessible`/`get` 方法名；运行期异常的反射字段开放与 `Unsafe` 访问。
- 修复/加固：不使用不可信 Java 原生反序列化；JEP 290 白名单拒绝 commons-collections 的 Transformer/Closure 类型；移除或升级 commons-collections4；限制 `Unsafe` 与深度反射。
