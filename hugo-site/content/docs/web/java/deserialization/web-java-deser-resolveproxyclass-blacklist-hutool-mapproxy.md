---
id: web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy
title: ObjectInputStream 漏拦 resolveProxyClass：动态代理 + Hutool MapProxy 二次反序列化绕过黑名单
type: scenario
domain: web
path: web/java/deserialization
technique: resolveproxyclass-blacklist-bypass-hutool-mapproxy
tags:
- java
- deserialization
- blacklist-bypass
- resolveproxyclass
- dynamic-proxy
- hutool
- mapproxy
- guava
- vaadin
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:46:53+08:00'
  notes: 已对照原文与 06-11、27 图核对：SafeObjectInputStream 仅重写 resolveClass、未拦 resolveProxyClass；MapProxy 经 Convert/BeanConverter/ObjectUtil.deserialize 二次反序列化；Vaadin PropertysetItem/NestedMethodProperty 与 Guava Equivalence.Wrapper 触发链、JavaChains 中 MapProxy getBounds 说明均一致。未验证点：原文文字说 getBounds 触发而代码示例用 MarginHandler+property=margin，卡内同时保留两种表述，存在轻微不一致；PoC 未复跑；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy/
draft: false
kb_aliases:
- resolveProxyClass 绕过
- 动态代理黑名单绕过
- Hutool MapProxy 二次反序列化
- MapProxy getBounds
- SafeObjectInputStream 缺陷
- 二次反序列化
---

## 一句话结论

`SafeObjectInputStream` 只重写 `resolveClass()` 做类名黑名单、却没有重写 `resolveProxyClass()`，攻击者可用 `Proxy.newProxyInstance` 生成黑名单外的动态代理类；代理的 `getBounds()` 进入 Hutool `MapProxy`，经 `Convert → BeanConverter → ObjectUtil.deserialize` 触发 `SerializeUtil.deserialize` 对内层字节做第二次反序列化，从而绕过外层黑名单执行任意 gadget。

## 原理

- **反序列化过滤器应覆盖两条类解析路径**：`ObjectInputStream` 在普通对象走 `resolveClass`，在动态代理走 `resolveProxyClass`。只重写前者时，代理类名（`com.sun.proxy.$Proxy*`/`jdk.proxy*`）不经过黑名单，直接放行。
- **动态代理只暴露接口**：攻击者让代理实现 `Layout.MarginHandler`（Vaadin）与 `Serializable` 等黑名单外接口；代理的 `InvocationHandler` 是 Hutool `MapProxy`。
- **Hutool MapProxy 的二次反序列化**：`MapProxy` 代理 `Map` 接口；当调用 `getBounds()`（或 `get` 等）时，`MapProxy.invoke` 把值交给 `Convert.convert`，`BeanConverter.convertInternal` 调用 `ObjectUtil.deserialize` → `SerializeUtil.deserialize` → `IoUtil.readObj` → `ValidateObjectInputStream.readObject`；该内部流黑白名单为 null，内层 payload 不再受外层过滤器约束。
- **外层触发链**：Guava `Equivalence.Wrapper` 的 `hashCode` 在 `HashMap.readObject` 重哈希时被调用，`toStringFunction` 把引用转成 `PropertysetItem.toString()` → `NestedMethodProperty.getValue()` → `Method.invoke(instance, getter)`；getter 设为 `getBounds` 即触发 `MapProxy`。
- **为什么最终危害成立**：外层只看到动态代理和 Guava/Vaadin 类（黑名单外），内层任意 Templates/JNDI gadget 在第二次反序列化时执行，等价于完全绕过 Java 反序列化黑名单。

## 触发条件

- 存在 Java 原生反序列化入口，使用自定义 `ObjectInputStream` + 类名黑名单。
- 过滤器只覆盖 `resolveClass`，未覆盖 `resolveProxyClass`/`ObjectInputFilter`。
- classpath 含 Hutool（MapProxy/Convert/SerializeUtil）、Guava（Equivalence/Functions）、Vaadin（PropertysetItem/NestedMethodProperty）或等价类。
- 攻击者可控制外层序列化字节，且内层 payload 可被第二次反序列化执行。

## 利用步骤

1. 确认过滤器实现：只重写 `resolveClass`、`resolveProxyClass` 未校验，或黑名单遗漏 `java.lang.reflect.Proxy`/`com.sun.proxy`/`jdk.proxy`。
2. 准备内层 payload（如 TemplatesImpl/JNDI 链），序列化成字节数组。
3. 用 Hutool `MapProxy.create(map)` 作为 `InvocationHandler`，`map` 中放入内层 payload 字节（示例 key `margin`）。
4. 用 `Proxy.newProxyInstance` 代理黑名单外接口（示例 `Layout.MarginHandler` + `Serializable`），得到代理对象。
5. 构造外层：Guava `Equivalence.equals().onResultOf(toStringFunction()).wrap(...)` + `HashMap`，把 wrapper 的 `reference` 反射改成 `PropertysetItem`；`PropertysetItem` 的 `NestedMethodProperty` 绑定代理与 getter 名称（`getBounds`）。
6. 序列化外层 HashMap 发送；反序列化时触发 `hashCode → toString → getter → MapProxy → 二次反序列化`。
7. 验证：内层 payload 执行（命令/回显/内存马），并检查外层过滤器日志未被触发。

## PoC

```java
// 外层：Guava HashMap -> PropertysetItem.toString -> NestedMethodProperty.get -> MapProxy
Map<String, Object> proxyMap = new HashMap<>();
proxyMap.put("margin", innerPayload);          // 内层 gadget 字节
MapProxy mapProxy = MapProxy.create(proxyMap);
Object proxy = Proxy.newProxyInstance(
        loader,
        new Class[]{Layout.MarginHandler.class, Serializable.class},
        mapProxy);

NestedMethodProperty<?> prop = new NestedMethodProperty<>(proxy, "margin");
PropertysetItem item = new PropertysetItem();
item.addItemProperty("x", prop);

Equivalence<Object> eq = (Equivalence<Object>) (Equivalence<?>)
        Equivalence.equals().onResultOf(Functions.toStringFunction());
Equivalence.Wrapper<Object> wrapper = eq.wrap("dummy");
HashMap<Object, Object> map = new HashMap<>();
map.put(wrapper, "v");
Field ref = Equivalence.Wrapper.class.getDeclaredField("reference");
ref.setAccessible(true);
ref.set(wrapper, item);                        // toString 时触发 item

// 序列化 map 并发送到目标反序列化入口
```

原文实测：外层黑名单把 `SignedObject` 等常见二次反序列化类封了，但 `resolveProxyClass` 未拦；该链成功触发内层 Templates 链执行。

## 变体与关联

- **过滤器变体**：只重写 `resolveClass`、只做类名黑名单、`ObjectInputFilter` 未配置、代理类未列入黑名单。
- **二次反序列化载体变体**：Hutool `MapProxy`/`Convert`/`SerializeUtil`、Jackson `POJONode`、Fastjson `JSONArray`、`SignedObject`（被黑名单时换其他）。
- **toString 触发变体**：Guava `Equivalence.Wrapper`/`ImmutableSetMultimap`/`UsingToStringOrdering`、Vaadin `PropertysetItem`、Rome `ToStringBean`、Jackson `POJONode`。
- **关联卡片**：[[web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass]]（动态代理绕过类名黑名单）、[[web-java-deser-hessian-aspectj-lazymethodgen-second-order]]（二次反序列化）、[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]]（toString 触发链）。
- **边界**：若过滤器覆盖 `resolveProxyClass` 并禁止代理类、或用 `ObjectInputFilter` 做全图白名单，本链失效；Hutool/Guava/Vaadin 版本需匹配。

## 检测与防御

- **过滤器实现**：同时重写 `resolveClass` 与 `resolveProxyClass`；禁止 `java.lang.reflect.Proxy`、`com.sun.proxy`、`jdk.proxy`；优先使用 JEP 290 `ObjectInputFilter` 做类/数组/深度/引用数全图限制，而不是单点黑名单。
- **依赖治理**：移除不必要的 Hutool/Guava/Vaadin 反序列化可达类；对 `MapProxy`、`Convert`、`SerializeUtil` 等二次反序列化入口做代码审计。
- **检测信号**：反序列化流中出现动态代理类、`MapProxy`、`Equivalence$Wrapper`、`PropertysetItem`、`NestedMethodProperty`；外层过滤器未命中的类却触发内层 `readObject`；同一请求中出现两次 `ObjectInputStream` 读取。
- **响应**：升级过滤器、加代理类黑名单、排查内层 payload 落地与执行痕迹。
