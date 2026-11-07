---
id: defense-forensics-java-native-deser-jndi-log-triage
title: 从应用异常堆栈识别 Java 原生反序列化 JNDI 链
type: scenario
domain: defense
path: defense/forensics
technique: java-native-deser-jndi-log-triage
tags:
- java
- deserialization
- jndi
- log-analysis
- forensics
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:41:14+08:00'
  notes: 来源 93065；已对照原文及堆栈截图核对；JtaTransactionManager.readObject、JNDI location [rmi://、TypeMismatchNamingException 与 ELProcessor、Hashtable.readObject、EOFException 试探后 38 秒完整利用均一致；已将“查找失败”修正为“返回类型不符或查找失败”。
url: /docs/defense/forensics/defense-forensics-java-native-deser-jndi-log-triage/
draft: false
kb_aliases:
- JtaTransactionManager 日志
- JNDI location rmi 取证
- ELProcessor 异常
- 原生反序列化识别
- fastjson 区分
---

## 一句话结论

当 Java 应用没有中间件访问日志、只有异常堆栈时，可以用 `JtaTransactionManager.readObject`、`JNDI location [rmi://`、`TypeMismatchNamingException ... javax.el.ELProcessor`、`Hashtable.readObject` 这组特征确认“原生 Java 反序列化触发 JNDI”的利用链，并与 fastjson 的 `@type`/`checkAutoType` 链区分开。

## 原理

- Java 原生反序列化入口对请求体调用 `ObjectInputStream.readObject`；异常堆栈会保留完整的类与方法调用链。
- `Hashtable.readObject` 会递归反序列化键值对象，常作为外层容器；`JtaTransactionManager.readObject` 在反序列化回调中执行 JNDI 查找。
- JNDI 返回对象类型不符（如返回 `ELProcessor`）或查找失败时，应用日志通常出现：
  - `org.springframework.transaction.TransactionSystemException: JTA UserTransaction is not available at JNDI location [rmi://...]`
  - `org.springframework.jndi.TypeMismatchNamingException: Object of type [class javax.el.ELProcessor] is not assignable to [javax.transaction.UserTransaction]`
  - 调用栈包含 `JtaTransactionManager.readObject`、`ObjectInputStream.readObject`、`Hashtable.readObject`。
- 这与 fastjson 链不同：fastjson 的堆栈会出现 `DefaultJSONParser`、`checkAutoType`、`@type` 解析，而不是 `ObjectInputStream`/`JtaTransactionManager`。
- 利用前的试探请求常表现为 `java.io.EOFException`，位置在 `ObjectInputStream` 读取流头阶段；几十秒后出现完整利用异常，可作为“先探测、再打点”的时间特征。

## 触发条件

- Java 应用把异常堆栈写入应用日志（如 `fw-log.log`）；
- 没有中间件访问日志或 WAF 日志，无法直接看到 URI、来源 IP、请求体；
- 反序列化入口可达，且 classpath 中存在 `JtaTransactionManager` 等 gadget；
- 日志保留时间覆盖攻击窗口。

## 利用步骤

（本卡为日志取证判读，不提供攻击操作。）

1. 在应用日志中检索 `sprmonitorServlet`、`JtaTransactionManager`、`JNDI location [rmi://`、`ELProcessor`、`readObject`；
2. 区分 `EOFException` 试探与后续完整 `TransactionSystemException`；
3. 提取 JNDI 地址、返回对象类型、异常时间与线程；
4. 用同一时间的 PowerShell 4104、文件落地时间、进程执行记录交叉印证；
5. 若日志中只有 fastjson 特征（`@type`、`checkAutoType`），按 fastjson 链另案分析；
6. 将无法证明的环节标注为“未知”，不要用推测补时间线。

## PoC

```text
# 应用日志关键行（示意）
... $$msg=####sprmonitorServlet Exception
java.io.EOFException
  at java.base/java.io.ObjectInputStream$PeekInputStream.readFully(...)
  at nc.bs.framework.spr.monitor.SprMonitorServlet.doAction(SprMonitorServlet.java:32)

... $$msg=####requestEntry Exception
org.springframework.transaction.TransactionSystemException:
  JTA UserTransaction is not available at JNDI location [rmi://x.x.x.x:1099/x];
  nested exception is org.springframework.jndi.TypeMismatchNamingException:
  Object of type [class javax.el.ELProcessor] is not assignable to [javax.transaction.UserTransaction]
  at org.springframework.transaction.jta.JtaTransactionManager.readObject(...)
  at java.base/java.util.Hashtable.readObject(...)
```

```bash
grep -nE 'sprmonitorServlet|JtaTransactionManager|JNDI location \[rmi://|ELProcessor|Hashtable.readObject' fw-log.log
```

## 变体与关联

- 变体：JNDI 地址为 `ldap://`；返回对象换成其他可利用类型；外层容器换成其他 `readObject` gadget；日志只保留异常摘要时，需结合线程名与时间窗。
- 关联：[[web-java-deserialization-jndi-ufida-sprmonitorservlet]]（该入口的漏洞原理）；[[web-java-deserialization-jndi]]（通用 JNDI 链）；[[defense-forensics-multisource-timeline-log-clear]]（多源时间线）。
- 不确定点：不同应用/框架的日志格式不同，`ELProcessor` 到命令执行的衔接在日志中可能不可见。

## 检测与防御

- 检测：应用日志出现上述异常组合；同一入口短时间重复出现 `EOFException` 与完整利用异常；异常时间与 WebShell 落地、PowerShell 执行、加密器落地对齐。
- 防御：在反序列化入口加 `ObjectInputFilter` 类白名单；限制服务器出站 RMI/LDAP/DNS；修补入口；启用中间件访问日志并集中留存。
- 取证：保留原始日志文件并计算哈希；记录日志时区；不要只截图异常摘要，完整堆栈才是链路证据。
