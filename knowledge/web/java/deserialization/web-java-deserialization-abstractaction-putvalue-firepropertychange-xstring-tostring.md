---
id: web-java-deserialization-abstractaction-putvalue-firepropertychange-xstring-tostring
title: AbstractAction.readObject 同名键触发 putValue→firePropertyChange→XString.equals 任意 toString
type: scenario
domain: web
path: web/java/deserialization
technique: abstractaction-putvalue-firepropertychange-xstring-tostring
aliases:
- AbstractAction 反序列化
- putValue firePropertyChange
- ArrayTable 同名键
- XString.equals JSONArray
- 任意 toString 触发
- BadAttributeValueExpException 替代
tags:
- java
- deserialization
- gadget
- javax.swing
- abstractaction
- xstring
- tostring
- fastjson
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V261
  verified_at: '2026-11-07T17:33:39+08:00'
  notes: 已对照原文与25张图核对：15-25图覆盖AbstractAction构造器putValue(Action.NAME)→ArrayTable创建/put、writeArrayTable按数量写键值、readObject循环putValue、firePropertyChange在changeSupport非空且oldValue!=null时调XString.equals→JSONArray.toString；23图显示十六进制把key2的0x32改为0x31制造同名key1，24图firePropertyChange守卫与changeSupport反射修改吻合；正文380-440行及EXP与卡内步骤一致。dedup recommendation new：候选为HashMap/HotSwappableTargetSource、EventListenerList、TextAndMnemonicHashMap、CC5等其它toString触发入口，本卡为AbstractAction.readObject入口，非同一链。未验证点：PoC未复跑；依赖javax.swing可用与changeSupport非空，卡内已注明。
---

## 一句话结论

`javax.swing.AbstractAction.readObject` 会读取序列化流中的键值对并逐对调用 `putValue`；若把两个条目的键改成同名（如把 `key2` 的字节 `0x32` 改成 `0x31`），第二次 `putValue` 会取到第一次存入的 `XString` 作为 `oldValue`，随后 `firePropertyChange(key, oldValue, newValue)` 调用 `oldValue.equals(newValue)`，由 `XString.equals` 触发 `newValue`（`JSONArray`）的 `toString()`，进入 fastjson2 的 getter 序列化链加载 `TemplatesImpl` 字节码；这是在 `BadAttributeValueExpException`、`EventListenerList`、`TextAndMnemonicHashMap` 等触发类被黑名单封禁时的替代触发点。

## 原理

- `AbstractAction` 用 `transient` 的 `ArrayTable` 保存动作属性，自定义 `writeObject` 调 `ArrayTable.writeArrayTable(s, arrayTable)`，先写有效键值对数量，再依次写 key/value；`readObject` 先 `defaultReadObject()`（恢复 `changeSupport` 等非 transient 字段），再读数量并循环 `putValue((String) s.readObject(), s.readObject())`。
- `putValue(String key, Object newValue)` 的逻辑：`oldValue = null`；若 `arrayTable.containsKey(key)` 则 `oldValue = arrayTable.get(key)`；`newValue != null` 时 `arrayTable.put(key,newValue)`；最后无条件调用 `firePropertyChange(key, oldValue, newValue)`。
- `firePropertyChange` 的守卫是：`changeSupport == null`，或 `oldValue != null && newValue != null && oldValue.equals(newValue)` 时直接返回；否则调用 `changeSupport.firePropertyChange(...)`。因此要触发 equals，必须同时满足 `changeSupport != null`、`oldValue != null`、`newValue != null`。
- 正常构造时 `putValue("key1", XString)` 与 `putValue("key2", JSONArray)` 的 oldValue 都是 null，不会触发 equals；但序列化后手工把第二个键的字节改成 `key1`，反序列化时第二个 `putValue("key1", JSONArray)` 会命中已存在的 `key1`，`oldValue` 就是先前的 `XString`，于是 `firePropertyChange("key1", XString, JSONArray)` 调用 `XString.equals(JSONArray)`。
- Xalan 的 `XString.equals(Object)` 在比较时会调用对方对象的字符串表示（`toString()`），因此 `JSONArray.toString()` 被触发；fastjson2 在序列化 `JSONArray` 元素时调用代理 getter，最终走到 `TemplatesImpl.getOutputProperties()` 加载恶意字节码。
- `AbstractAction` 的 `arrayTable` 是 transient、由 `writeObject/readObject` 手工读写，所以序列化流中的键值对完全可以被离线编辑；`changeSupport` 不是 transient，构造时反射设置的 `SwingPropertyChangeSupport` 会随对象一起序列化，保证反序列化后非空。

## 触发条件

- 存在 Java 原生反序列化入口，且目标 classpath 含 `javax.swing.AbstractAction`（桌面模块可用；JDK 8 常见，精简 JRE 可能没有）。
- 目标未把 `javax.swing.AbstractAction`、`ArrayTable`、`XString` 列入反序列化黑名单。
- 攻击者可构造/修改序列化字节流（离线生成后改键名），或能用等价方式构造出“同名键”的 ArrayTable。
- 下游存在可被 `toString()` 触发的 gadget（本例为 fastjson2 `JSONArray` + `Templates` 代理 + `TemplatesImpl`）。

## 利用步骤

1. 构造 `SwingPropertyChangeSupport` 并反射写入 `AbstractAction.changeSupport` 字段（示例用 `StyledEditorKit.AlignmentAction`，其构造器会先 `putValue(Action.NAME, name)`）。
2. 依次 `putValue("key1", new XString("1"))`、`putValue("key2", gadgetChain)`，其中 `gadgetChain` 是含恶意代理的 `JSONArray`；两次 putValue 的 oldValue 均为 null，不触发。
3. 序列化该 `AbstractAction`，得到包含 3 个键值对（Name、key1、key2）的字节流。
4. 用十六进制编辑器把第二个键 `key2` 的字节 `32` 改成 `31`，使其变成 `key1`；此时流中有两个 `key1` 条目，前一个值为 `XString`，后一个值为 `JSONArray`。
5. 反序列化：`readObject` 按顺序 `putValue`，第二次 `putValue("key1", JSONArray)` 取到 `oldValue=XString`，`firePropertyChange` 调用 `XString.equals(JSONArray)` → `JSONArray.toString()` → fastjson2 getter → `TemplatesImpl` RCE。
6. 观察命令执行/计算器；将命令替换为实际载荷。

## PoC

```java
import javax.swing.*;
import javax.swing.event.SwingPropertyChangeSupport;
import javax.swing.text.StyledEditorKit;
import java.lang.reflect.Field;

public static Object buildAbstractActionGadget(Object gadgetChain) throws Exception {
    SwingPropertyChangeSupport changeSupport = new SwingPropertyChangeSupport("11");
    StyledEditorKit.AlignmentAction alignmentAction =
            new StyledEditorKit.AlignmentAction("111", 1);

    Field field = Class.forName("javax.swing.AbstractAction")
            .getDeclaredField("changeSupport");
    field.setAccessible(true);
    field.set(alignmentAction, changeSupport);

    XString xString = new XString("1");
    alignmentAction.putValue("key1", xString);
    alignmentAction.putValue("key2", gadgetChain);
    return alignmentAction;
}

// 序列化后把字节流中的 "key2"（0x6b 0x65 0x79 0x32）改成 "key1"（0x6b 0x65 0x79 0x31）
// 再 ObjectInputStream.readObject() 反序列化即可触发
```

```text
# 关键字节修改（十六进制视图）
... 6B 65 79 32 ...   ->   ... 6B 65 79 31 ...
         key2                      key1
```

## 变体与关联

- 变体：不修改键名，也可用其他能在序列化流中制造“同名键”的方式（手工构造 ArrayTable/自定义 writeObject）达到同样效果。
- 变体：`oldValue` 不限于 `XString`；任何 `equals` 会调用对方 `toString()` 的类都可作为桥接，`newValue` 也可换成其他会触发 getter 的 fastjson 容器。
- 关联：[[web-java-deserialization-jdk-xstring-equals-tostring]]（HashMap/HotSwappableTargetSource 入口的 XString.equals 触发，本卡是 AbstractAction 入口的替代）、[[web-java-deserialization-jdk-eventlistenerlist-tostring]]、[[web-java-deserialization-jdk-hashtable-textandmnemonic-tostring]]、[[web-java-deser-commonscollections-cc5-badattribute-tostring]]（其他 toString 触发点）、[[web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass]]（下游 fastjson2 getter 链）。
- 边界：依赖 `javax.swing` 可用；`changeSupport` 必须非空；键名修改需精确匹配序列化流的字节长度（`key1`/`key2` 等长，改一个字节即可）；JDK 模块封装/黑名单会使其失效。

## 检测与防御

- 检测：反序列化流中出现 `javax.swing.AbstractAction`、`javax.swing.ArrayTable`、`com.sun.org.apache.xpath.internal.objects.XString`、`com.alibaba.fastjson2.JSONArray` 组合；同一序列化流中出现重复键名也是可疑信号。
- 防御：`ObjectInputFilter` 黑名单应包含 `javax.swing.AbstractAction`、`ArrayTable`、`XString` 及其下游容器；不能只封 `BadAttributeValueExpException`/`EventListenerList` 等常见入口。
- 加固：升级 JDK 限制 `TemplatesImpl` 反射；移除不必要的 fastjson2/xalan/javassist 依赖；禁止对不可信数据做原生反序列化。
