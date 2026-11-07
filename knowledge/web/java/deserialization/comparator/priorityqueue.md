---
id: web-java-deser-comparator-priorityqueue
title: PriorityQueue 比较器触发 toString 的通用构造
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: comparator-gadget
aliases: [PriorityQueue gadget, 比较器 toString]
tags: [java, deserialization, gadget, priorityqueue, comparator]
cve: []
severity: high
confidence: medium
status: draft
created: 2026-11-04
updated: 2026-11-04
---

## 一句话结论

`PriorityQueue` 在反序列化恢复堆结构时会调用 `Comparator.compare`，把可控对象作为比较参数即可触发其 `toString`，作为更大 gadget 链的一环。

## 原理

`PriorityQueue.readObject` 读取元素后调用 `heapify`，`heapify` 通过 `siftDown` 调用 `comparator.compare`。因此 comparator 是攻击者可控的，且元素也是可控对象时，比较过程会把元素传给 comparator 的任意方法，常见 sink 是字符串拼接导致的 `toString`。

## 触发条件

- 可控的 `PriorityQueue` 反序列化；
- comparator 可序列化且可控；
- comparator 的 `compare` 对参数调用 `toString`/`hashCode`/`equals`；
- 目标对象在 `toString` 中进入危险路径。

## 利用步骤

1. 构造一个序列化 comparator，其 `compare` 对参数做字符串操作；
2. 构造目标对象并放入 `PriorityQueue`；
3. 保证队列中至少两个元素，使 `heapify` 触发比较；
4. 序列化发送，观察目标 `toString` 是否被调用。

## PoC

```java
class TouchComparator implements Comparator<Object>, Serializable {
    public int compare(Object a, Object b) {
        return String.valueOf(a).compareTo(String.valueOf(b));
    }
}
PriorityQueue<Object> q = new PriorityQueue<>(2, new TouchComparator());
q.add(target);
q.add("x");
```

## 变体与关联

- `TreeMap`/`TreeSet` 在 `readObject` 中同样依赖比较器；
- 若 comparator 不可序列化，可寻找可序列化的替身或通过其它入口注入。

## 检测与防御

- 检测：反序列化对象图中的 `PriorityQueue` 与自定义 comparator；
- 防御：JEP 290 过滤、禁止不可信反序列化、限制 comparator 类型。
