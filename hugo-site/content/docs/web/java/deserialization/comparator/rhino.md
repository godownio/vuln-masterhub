---
id: web-java-deser-comparator-rhino
title: Rhino 环境下 Comparator 链触发 toString
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: comparator-gadget
tags:
- java
- deserialization
- gadget
- rhino
- comparator
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-04'
updated: '2026-11-04'
url: /docs/web/java/deserialization/comparator/rhino/
draft: false
kb_aliases:
- compara链
- Comparator gadget
- comparator toString
---

## 一句话结论

当反序列化入口可控、且 classpath 中存在 Rhino 时，可以构造 `PriorityQueue`/`TreeMap` 一类依赖 `Comparator.compare` 的容器，把比较过程引到 `toString`，再由 Rhino 的对象转换逻辑触发脚本执行。

## 原理

`Comparator.compare(a, b)` 的实现如果对参数做了字符串拼接、日志输出或 `String.valueOf`，就会调用参数的 `toString()`。攻击者把可控对象放进依赖比较器的容器，在 `readObject` 恢复容器时触发比较，从而把调用链推进到目标类的 `toString`。

Rhino 场景下，`NativeJavaObject`/`ScriptableObject` 的 `toString` 可能进入脚本运行时；若之前已通过其它 gadget 或应用逻辑把脚本上下文准备好，就能把 `toString` 升级为脚本执行。

## 触发条件

- 存在可控的反序列化入口；
- classpath 中有 Rhino，且应用暴露了脚本执行能力；
- 容器在 `readObject` 期间会调用 `Comparator.compare`；
- 比较器对参数调用了 `toString` 或等价方法。

## 利用步骤

1. 确认目标依赖包含 Rhino，并确认反序列化入口；
2. 选择一个在反序列化时触发 `compare` 的容器（如 `PriorityQueue`）；
3. 构造 comparator，使 `compare` 路径调用 `toString`；
4. 把 Rhino 相关对象放入容器，调整元素顺序，确保 `compare` 被调用；
5. 序列化并发送，观察 `toString` 是否进入脚本执行路径。

## PoC

```java
// 结构示意：实际利用需按目标 classpath 调整 comparator 与元素
PriorityQueue<Object> queue = new PriorityQueue<>(2, comparatorThatCallsToString);
queue.add(rhinoWrappedObject);
queue.add(new Object());
// serialize(queue) -> readObject -> compare -> toString
```

## 变体与关联

- 变体：`TreeMap`、`TreeSet`、`PriorityQueue` 等依赖比较器的容器；
- 关联：其它以 `toString` 为 sink 的 gadget。

## 检测与防御

- 检测：反序列化流量中的 `PriorityQueue`/`TreeMap` 与异常 comparator；
- 防御：禁用不必要的 Rhino、限制反序列化入口、使用白名单/黑名单与 JEP 290 过滤。
