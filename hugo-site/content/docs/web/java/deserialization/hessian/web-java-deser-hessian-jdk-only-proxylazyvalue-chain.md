---
id: web-java-deser-hessian-jdk-only-proxylazyvalue-chain
title: Hessian JDK-only 链：UIDefaults/ProxyLazyValue 触发任意静态方法或构造
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-jdk-proxylazyvalue-chain
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- hessian
- deserialization
- jdk-only
- uidefaults
- proxylazyvalue
- swinglazyvalue
- tostring
- rce
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:31:49+08:00'
  notes: 已对照原文图 50-61 核对 SwingLazyValue/ProxyLazyValue.createValue、UIDefaults.get、PKCS9Attributes/MimeTypeParameterList/XString/AudioFileFormat.Type 触发 toString、ServerManagerImpl/JavaWrapper/MethodUtil/Trampoline 等 sink；原文多数 sink 仅给 POC 链接未内联完整代码，卡内已如实注明；PoC 未在本机执行。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-jdk-only-proxylazyvalue-chain/
draft: false
kb_aliases:
- Hessian JDK 原生链
- UIDefaults ProxyLazyValue 链
- SwingLazyValue 链
- ProxyLazyValue createValue
- Hessian toString 触发
- Hessian 无依赖利用链
---

## 一句话结论

Hessian 反序列化触发 `toString` 后，可经 `UIDefaults.get()` 调用 `ProxyLazyValue`/`SwingLazyValue.createValue()`，反射执行任意类的 public static 方法或 public 构造方法；配合 `System.load`、`ServerManagerImpl` 的 `Runtime.exec`、`ClassPathXmlApplicationContext` 等 sink，在只有 JDK（无第三方依赖）的环境也能完成 RCE。

## 原理

- `javax.swing.UIDefaults` 继承 `Hashtable`，其 `get(key)` 在取到 `LazyValue` 时会调用 `createValue(this)`。`ProxyLazyValue` 与 `sun.swing.SwingLazyValue` 都实现了该接口。
- `ProxyLazyValue.createValue()`：
  - `Class.forName(className, true, cl)` 加载类（带系统类加载器回退）；
  - 若 `methodName != null`，按参数类型 `getMethod`，再 `MethodUtil.invoke(m, c, args)`——即调用该类的 **public static 方法**；
  - 否则按参数类型 `getConstructor`，`constructor.newInstance(args)`——调用 **public 构造方法**。
- `SwingLazyValue.createValue()` 逻辑相同，但 `Class.forName(..., loader=null)` 使用 Bootstrap ClassLoader，只能加载核心 JDK 类；且 JDK 11 后该类被移除。`ProxyLazyValue` 在 JDK 11+ 仍存在，适用性更广。
- 触发 `UIDefaults.get` 的路径是 `toString`：`PKCS9Attributes.toString()` 遍历内部 `Hashtable` 并调用 `getAttribute`/`get`；`MimeTypeParameterList.toString()` 同样访问内部表；`Hashtable.equals` 经 `HashMap.putVal` 也能进入 `UIDefaults.get`。
- 把对象塞进反序列化流并令其 `toString` 被调用，有几种方式：
  - **expect/类型失败**：Hessian2 流首字节写 `C` 之后直接写对象，`readString` 读取类型失败进入 default 分支，异常拼接字符串时隐式调用对象 `toString`；
  - **XString 家族**：`HashMap.putVal → AbstractMap.equals → XString.equals → 目标.toString`；
  - **AudioFileFormat.Type**：`Type.equals` 触发 `toString`；
  - **ConcurrentHashMap**：在 `HashMap` 被禁用时作为平替触发 equals/hashCode。
- 典型 sink：
  - `ServerManagerImpl.getActiveServers` → `ServerTableEntry.activate` → `Runtime.getRuntime().exec(activationCmd)`（getter 触发，也可配合 fastjson/jackson）；
  - `ClassPathXmlApplicationContext(String)` 构造方法加载远程/本地 XML（需 spring-context）；
  - `com.sun.tools.javac.processing.JavaWrapper._main` → `runMain` 反射调用目标类 public static void `_main(String[])`（JDK<8u251，可配合 BCEL 加载字节码）；
  - `com.sun.org.apache.xalan.internal.utils.JavaUtils.writeBytesToFilename` 写文件 + `System.load` 加载 dll/so（一次请求完成写文件与加载）；
  - `DumpBytecode.dumpBytecode`（nashorn.jar，JDK8，需 ProxyLazyValue 加载）；
  - `MethodUtil.invoke` 把可调用范围从 public static 扩展到 public 实例方法。

## 触发条件

- Hessian 反序列化入口可控（见入口卡）。
- 目标 JDK 含 `javax.swing.UIDefaults.ProxyLazyValue`（JDK 11+ 使用 `ProxyLazyValue`；JDK 8 还可使用 `SwingLazyValue`）。
- 链所需 sink 类存在：`System`（所有 JDK）、`ServerManagerImpl`（JDK 自带 CORBA 实现）、`ClassPathXmlApplicationContext`（有 spring-context）、`JavaWrapper`（JDK<8u251）等。
- 目标未对 `UIDefaults`/`ProxyLazyValue`/`XString` 等类做黑名单。

## 利用步骤

1. 确认 Hessian 入口与 JDK 版本、classpath 依赖（决定 sink）。
2. 构造 `UIDefaults`，把 `ProxyLazyValue` 放入目标 key；`ProxyLazyValue` 的 `className`/`methodName`/`args` 指向 sink。
3. 构造一个能触发 `UIDefaults.get` 的 `toString` 载体（`PKCS9Attributes`、`MimeTypeParameterList`、`XString`、`AudioFileFormat.Type` 等）。
4. 用 Hessian2 序列化该对象（必要时设置 `AllowNonSerializable`），或使用 `C`+对象 的 expect 触发格式。
5. 发送 payload，服务端 `map.put`/`toString` 触发 `createValue`，执行 sink。
6. 按 sink 验证：命令回显、文件写入、加载 dll/so 或远程 XML。

## PoC

sink 最小验证（不含 Hessian 入口，直接演示 `ProxyLazyValue` 的执行能力）：

```java
UIDefaults ui = new UIDefaults();
ui.put("k", new UIDefaults.ProxyLazyValue(
        "java.lang.System", "load", new Object[]{"/tmp/evil.so"}));
ui.get("k");   // createValue -> System.load("/tmp/evil.so")
```

写文件并加载的 sink 组合（一次请求完成落地与执行）：

```java
// 通过 JavaUtils.writeBytesToFilename 写入 dll/so，再 System.load
// 具体类名/参数按目标 JDK 调整；ProxyLazyValue 方法名与参数类型需与 sink 签名匹配
```

expect 触发 `toString` 的编码方式（关键点）：

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
baos.write('C');                 // 让 Hessian2 走对象定义/字符串读取失败分支
Hessian2Output out = new Hessian2Output(baos);
SerializerFactory sf = out.getSerializerFactory();
sf.setAllowNonSerializable(true);
out.setSerializerFactory(sf);
out.writeObject(toStringGadget); // toStringGadget.toString() -> UIDefaults.get -> createValue
out.close();
```

原文未在正文内给出所有 sink 的完整可运行 POC，而是给出公开 POC 路径与调用链；本卡记录机制与 sink 清单，具体类/参数需按目标 JDK 与依赖适配。

## 变体与关联

- 若 `TemplatesImpl` 可用，`TrAXFilter` 构造链更短；但 Hessian 无法还原 `TemplatesImpl._tfactory`（transient），原文明确该链不可直接用。
- `MethodUtil.invoke` 扩展了可调用方法范围，可用于调用 public 实例方法（如 `getDatabaseMetaData` 触发 JNDI）。
- `AudioFileFormat.Type` 的 equals 触发可配合 `ServerManagerImpl` getter 链，形成“equals → toString → getter → Runtime.exec”。
- 与 fastjson/jackson 的 getter 触发可组合：`ServerManagerImpl.getActiveServers` 是 getter，可被 JSON 反序列化库直接调用。
- 后续可接 Spring JNDI、Groovy 等第三方链（见分卡）。

## 检测与防御

- 禁止反序列化不可信 Hessian；入口鉴权与来源限制。
- 允许列表过滤：在 `SerializerFactory.getDeserializer` 中只放行业务类，拒绝 `javax.swing.UIDefaults`、`ProxyLazyValue`、`SwingLazyValue`、`PKCS9Attributes`、`MimeTypeParameterList`、`XString`、`ServerManagerImpl`、`JavaWrapper`、`MethodUtil` 等。
- 升级 JDK（`SwingLazyValue` 在 11+ 移除、`JavaWrapper` 在 8u251 后受限）只是抬高门槛，不能替代允许列表。
- 限制出站与文件写权限；监控 `System.load`、`Runtime.exec`、`ClassPathXmlApplicationContext` 加载远程 XML、`/tmp` 下新 dll/so。
- 运行时监控 `UIDefaults.get` 调用与异常 `toString` 链（可用 JFR/字节码审计）。
