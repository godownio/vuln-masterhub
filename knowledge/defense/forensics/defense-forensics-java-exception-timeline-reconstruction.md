---
id: defense-forensics-java-exception-timeline-reconstruction
title: 无访问日志时用 Java 异常堆栈重建 Web 入侵时间线
type: scenario
domain: defense
path: defense/forensics
technique: java-exception-timeline-reconstruction
aliases:
- 异常堆栈时间线
- 应用日志溯源
- 无中间件访问日志
- JNDI 日志特征
tags:
- incident-response
- forensics
- java
- log-analysis
- timeline
- powershell
- webshell
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-D
  verified_at: '2026-11-04T19:21:14+08:00'
  notes: 已对照原文核对：以05:02:59 EOFException、05:03:37 JtaTransactionManager/ELProcessor、05:03:38 4104及10-18 08:15/20:34三轮异常为锚点的方法与原文时间线一致；属取证方法卡，未做现场复现。
---

## 一句话结论

当应用只保留异常堆栈、没有中间件访问日志和请求体时，仍可用异常出现的精确时间、堆栈中的类/方法/JNDI 地址，与 PowerShell 4104、文件修改时间、AppCompatCache、安全日志清除等主机痕迹逐条对齐，重建多轮漏洞利用与 WebShell 落地时间线。

## 原理

- Java 应用日志即使不记录 URI、来源 IP 和 POST body，异常堆栈仍会暴露触发路径：顶层异常类型、业务 Servlet 类、`ObjectInputStream`/`readObject` 调用、JNDI location、返回对象类型等。
- 攻击链不同阶段会留下不同主机痕迹：漏洞试探可能只产生 `EOFException`；成功利用后 1 秒内出现 PowerShell 4104；JSP 落地可由文件修改时间与大小确认；加密器执行可由 AppCompatCache/进程记录确认；日志清除会留下 Security 日志事件。
- 这些痕迹来自不同数据源、不同时钟，但同一动作在秒级时间窗内高度相关。把异常时间作为锚点，向主机侧逐条对齐，可以还原“哪次异常对应哪次落地、哪次执行”。
- 即使部分日志被删除，文件系统时间、注册表/兼容性缓存、进程创建记录仍可能保留，能补上缺失环节。

## 触发条件

- 应用日志可读，至少包含异常类型、时间和堆栈。
- 有主机侧日志或痕迹：PowerShell 4104、Security 日志、文件系统 MFT/时间戳、AppCompatCache、EDR 进程记录。
- 攻击者尚未彻底清理所有痕迹，或清理动作本身留下记录。
- 已知或可推测业务 Servlet/组件名称，便于把堆栈映射到路由。

## 利用步骤（取证分析）

1. 固定证据：导出应用日志、Windows 事件日志、文件列表（含修改时间/大小）、内存与可疑样本，记录哈希。
2. 从应用日志中提取所有异常时间点、异常类型、顶层业务类、调用链关键帧（如 `readObject`、`lookup`、`ELProcessor`）。
3. 按时间排序，识别“短间隔内的异常簇”：试探性 EOF 异常后数十秒出现完整利用异常，通常对应一轮攻击。
4. 对每个异常时间窗，向主机侧对齐：4104 脚本块、进程创建、文件写入、网络连接、计划任务/服务变更。
5. 用文件修改时间与大小确认 WebShell/加密器落地；用 AppCompatCache 等确认可执行文件运行。
6. 检查日志清除事件与安全日志缺口，标记时间线不可信区间。
7. 把多轮利用按基础设施（JNDI/RMI 地址、下载地址、WebShell 密码）分组，判断是否同一工具链。

## PoC

```text
# 应用日志锚点（示例）
2026-10-17 05:02:59  ####sprmonitorServlet Exception  java.io.EOFException
2026-10-17 05:03:37  ####requestEntry Exception
  JtaTransactionManager.readObject -> JNDI location [rmi://X:1099/x]
  -> javax.el.ELProcessor
2026-10-17 05:03:38  PowerShell 4104：下载 ncsync.jsp 到 webapps/nc_web

# 对齐后得到：试探 -> 反序列化利用 -> JNDI 回连 -> PowerShell 落地 WebShell
# 同型异常在 10-18 08:15、20:34 再次出现，对应第二枚 WebShell 与加密器
```

```powershell
# 快速汇总候选锚点（在取证副本上运行）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Sort-Object TimeCreated |
  Select-Object TimeCreated, @{n='Script';e={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}}
```

## 变体与关联

- 变体：没有 4104 时，可用 Sysmon 进程创建、EDR 遥测、Prefetch/Amcache、文件系统日志替代。
- 变体：攻击者删除应用日志时，可用集中日志平台、备份、容器 stdout、WAF/负载均衡日志补齐。
- 变体：多节点集群中，异常可能落在不同节点，需要按负载均衡/会话分布逐节点收集。
- 关联：[[defense-forensics-multisource-timeline-log-clear]] 讲日志被清除后的多源重建；本卡侧重“以 Java 异常堆栈为锚点”的应用层溯源。

## 检测与防御

- 检测：应用日志中同一 Servlet 的异常簇、`ObjectInputStream`/`readObject`、`JNDI location [rmi://`、`javax.el.ELProcessor` 等组合。
- 检测：异常时间后秒级出现 PowerShell 4104、Web 目录新增文件、异常外连。
- 防御：应用日志记录 URI、来源 IP、关键请求体摘要（注意脱敏）；中间件访问日志集中留存。
- 防御：PowerShell Script Block Logging 与进程创建审计开启并集中采集；Windows 安全日志设置足够的保留与转发。
- 取证：发现入侵先隔离并保全现场，不要重装或批量删除文件；优先导出日志、内存和可疑样本。
