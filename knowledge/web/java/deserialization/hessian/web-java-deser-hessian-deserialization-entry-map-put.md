---
id: web-java-deser-hessian-deserialization-entry-map-put
title: Hessian 反序列化入口：MapDeserializer 的 map.put 触发 hashCode/equals/compareTo
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-deserialization-map-put-entry
aliases:
- Hessian 反序列化原理
- Hessian MapDeserializer 入口
- Hessian map.put gadget
- hessian1 hessian2 反序列化流程
- Hessian 反序列化利用条件
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- hessian
- deserialization
- gadget
- mapdeserializer
- hashcode
- equals
- compareto
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:31:47+08:00'
  notes: 已对照原文与图 01-46 核对 Hessian1/2 序列化/反序列化流程、M/C/H 首字节、MapDeserializer 的 map.put 入口、transient/static 字段被跳过；卡内一句话中 'HashMap 写入 M+null（后续 H）' 混述了 hessian1(M t) 与 hessian2(H) 的字节，原理段已分别说明，不影响理解；PoC 未在本机执行。
---

## 一句话结论

Hessian 默认把自定义对象和 `HashMap` 都按 Map 编码，反序列化时 `MapDeserializer.readMap()` 逐对执行 `map.put(in.readObject(), in.readObject())`；`HashMap.put` 会调用 key 的 `hashCode`/`equals`，`TreeMap.put` 会调用 `compareTo`，因此 Hessian 反序列化的利用入口是这三个方法，且 gadget 链中不能依赖 `transient`/`static` 字段（`UnsafeSerializer`/`UnsafeDeserializer` 会跳过它们）。

## 原理

- Hessian1 序列化自定义对象时，`UnsafeSerializer.writeObject` 调用 `writeObjectBegin`，写入 `M` + `t` + 类名，然后按字段名/字段值写成 Map；`HashMap` 则写入 `M` + 类型 `null`（后续字节为 `H` 标识无类型 Map）。Hessian2 对自定义对象改用 `C` + 类名 + 字段定义 + 值，对无类型 Map 仍用 `H`。
- 反序列化 `HessianInput.readObject()`/`Hessian2Input.readObject()` 按首字节 switch：`M` 走 `SerializerFactory.readMap`，`H`/无类型 Map 走 `MapDeserializer`。
- `MapDeserializer.readMap` 的核心循环是 `map.put(in.readObject(), in.readObject())`。`HashMap.putVal` 先计算 key 的 hash（调用 `hashCode`），哈希冲突或同一桶时调用 `equals`；`TreeMap.put` 用 `compareTo` 比较。这是整个 Hessian gadget 生态的 source。
- `SerializerFactory.getDeserializer(String type)` 对类型名调用 `Class.forName` 加载类，默认没有允许列表；`UnsafeDeserializer` 用 `Unsafe` 直接实例化对象，再按字段名反射赋值。这使攻击者可以在序列化流中指定任意类，而不需要目标代码显式 new。
- `UnsafeSerializer.introspect` / `UnsafeDeserializer.getFieldMap` 都会跳过 `Modifier.isTransient` 与 `Modifier.isStatic` 的字段。因此经典 `TemplatesImpl` 链不可直接用：`_tfactory` 是 transient，Hessian 不会还原它；需要换用不依赖该字段的 sink（如 `ProxyLazyValue`、`System.load`、JNDI 等）。
- `readMap(in, obj)` 还允许通过 `resolve`/`readResolve` 做重定义；`MapDeserializer` 对 `SortedMap` 返回 `TreeMap`，其他 Map 用无参构造实例化，final 字段也可由 Unsafe 写入。

## 触发条件

- 目标暴露 Hessian 协议入口（HessianServlet、Hessian RPC、Dubbo/Nacos 等使用 Hessian 序列化的接口），且攻击者能控制请求体。
- 类路径存在 `com.caucho:hessian`（Hessian1/2 均可），反序列化未启用类白名单/黑名单。
- 反序列化流中指定的 gadget 类在目标 classpath 上；链所需字段非 transient/static。
- 有可用的 hashCode/equals/compareTo 入口链（见后续分卡）。

## 利用步骤

1. 确认目标接受 Hessian 编码（请求头/内容类型、`HessianServlet` 路径、RPC 方法）。
2. 用 `Hessian2Output`（或 `HessianOutput`）构造一个 `HashMap`，把 gadget 对象作为 key，触发点放在 key 的 `hashCode`/`equals`/`compareTo`。
3. 必要时设置 `SerializerFactory.setAllowNonSerializable(true)`，让未实现 `Serializable` 的 gadget 也能被序列化。
4. 发送序列化字节；服务端 `readMap` 的 `map.put` 触发 gadget。
5. 按目标依赖选择 sink：JDK-only（`ProxyLazyValue`）、Spring JNDI、Groovy、Rome 等。

## PoC

最小验证结构（把 `gadget` 换成任一在 hashCode/equals/compareTo 上可触发的对象）：

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
Hessian2Output out = new Hessian2Output(baos);
SerializerFactory sf = out.getSerializerFactory();
sf.setAllowNonSerializable(true);
out.setSerializerFactory(sf);

HashMap<Object, Object> map = new HashMap<>();
map.put(gadget, "any");
out.writeObject(map);
out.flush();

byte[] payload = baos.toByteArray();   // 发送给目标 Hessian 入口
```

服务端对应路径：

```java
Hessian2Input in = new Hessian2Input(new ByteArrayInputStream(payload));
in.readObject();   // MapDeserializer.readMap → map.put → gadget.hashCode/equals
```

原文分析确认：Hessian1 自定义对象首字节为 `M`，Hessian2 首次出现的类为 `C`，无类型 Map 为 `H`；`MapDeserializer` 的 `map.put` 是统一入口。

## 变体与关联

- 入口方法不限于 `HashMap`：`TreeMap` 触发 `compareTo`（Groovy `ContinuationDirContext` 链、`QName` 链用 TreeMap）。
- 其他 Map 实现（`ConcurrentHashMap`、`LinkedHashMap`）在 put 时的哈希/等值逻辑也可作为触发点。
- Hessian1 与 Hessian2 的差异主要在对象编码（Map vs 类定义），最终都落到 `MapDeserializer`/`UnsafeDeserializer`。
- 后续链：JDK-only lazy value 链、Spring/Rome/Resin/XBean JNDI 链、Groovy GString 链、HessianProxyFactory JNDI 链。

## 检测与防御

- 不要直接反序列化不可信 Hessian 数据；在入口统一鉴权、限制来源 IP，禁止匿名访问 HessianServlet/RPC。
- 使用自定义 `SerializerFactory` 做**允许列表**（不是仅黑名单）：只允许业务需要的类，`getDeserializer(String)` 中校验类型名；黑名单可用 UTF-8 overlong 等方式绕过（见独立卡片）。
- 升级 Hessian 并关注官方安全公告；禁用 `setAllowNonSerializable(true)`。
- 监控反序列化流中的异常类名（`TemplatesImpl`、`JdbcRowSetImpl`、`InitialContext`、`ProxyLazyValue`、`MethodClosure` 等）与 `Class.forName` 高频加载。
- 网络层限制服务端对外的 JNDI/LDAP/RMI 与 HTTP 出站，降低出网链成功率。
