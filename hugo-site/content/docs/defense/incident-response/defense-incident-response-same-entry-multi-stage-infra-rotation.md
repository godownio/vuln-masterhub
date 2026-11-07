---
id: defense-incident-response-same-entry-multi-stage-infra-rotation
title: 同一漏洞入口多轮利用与基础设施切换的关联分析
type: scenario
domain: defense
path: defense/incident-response
technique: multi-stage-infra-rotation-correlation
tags:
- incident-response
- ransomware
- attribution
- infrastructure
- webshell
- correlation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:42:24+08:00'
  notes: 来源 93065；已对照原文核对；三轮同一 sprmonitorservlet 入口、ncsync.jsp 7KB 与 gzms.jsp 22KB、共用密码 ncw3b2026、第三轮 C2 切换至 192.151.233.247 均一致；已把“每轮使用不同 C2”更正为“各轮之间 C2 发生切换”。
url: /docs/defense/incident-response/defense-incident-response-same-entry-multi-stage-infra-rotation/
draft: false
kb_aliases:
- 多轮利用关联
- 基础设施切换
- WebShell 同源
- 打点验证加密三阶段
- 攻击者交接推断
---

## 一句话结论

同一漏洞入口在短时间内被多轮利用、且各轮之间 C2 发生切换时，可以用“相同入口路径、相同 WebShell 连接密码、相同落地脚本骨架、时间紧接”判断前几轮属于同一工具链，而 C2 切换既可能是同一攻击者轮换基础设施，也可能是权限/漏洞细节在不同人员间流转，不能仅凭 IP 变化下结论。

## 原理

- 漏洞未修复前可被反复利用；每轮利用都会在应用日志留下同型异常堆栈，可作为关联锚点。
- 同一工具链通常复用：JNDI 路径、WebShell 文件名/大小/类加载骨架、连接密码、落地 PowerShell 脚本结构、下载回执格式。
- 基础设施切换的常见原因：C2 被封、主动轮换、不同阶段使用不同团队/工具、权限或漏洞细节被转卖。
- 时间关系很重要：先打点并验证可用性，再投放加密通信 WebShell 维持访问，最后换基础设施部署勒索载荷，呈现“侦察/验证 → 驻留 → 变现”的分阶段特征。
- 归因边界：IP 地理位置、ASN、C2 复用只能说明基础设施关系，不能单独证明同一人或存在交易；需要样本同源、通信、资金等证据。

## 触发条件

- 同一漏洞入口出现多次利用记录（应用日志、WAF、流量）；
- 每轮落地不同 WebShell 或载荷，C2 地址/网段发生变化；
- 能获取 WebShell 样本、脚本、连接密码、文件大小与时间；
- 事件日志可能被清，但应用日志、PowerShell 4104、文件时间仍保留。

## 利用步骤

（本卡为应急关联分析，不提供攻击操作。）

1. 以入口路径和异常堆栈为锚点，列出每轮利用的时间、源 IP（若有）、JNDI/C2 地址；
2. 对比每轮落地的 WebShell：文件名、大小、类加载骨架、注册路由、连接密码、加密方式；
3. 对比落地脚本：下载 URL 结构、路径遍历列表、回执编码方式、变量命名；
4. 对比 C2：IP、ASN、端口、证书、同网段关系、威胁情报标签；
5. 用 PowerShell 4104、文件时间、加密器落地时间建立阶段时间线；
6. 给出“同一工具链/同一攻击者/可能交接”的分级结论，并列出证据与反证；
7. 对同网段、同版本资产扩大排查，避免只处置单台。

## PoC

```text
关联矩阵（示例字段）
轮次 | 时间 | 入口 | JNDI/C2 | WebShell | 大小 | 连接密码 | 脚本骨架 | 结论
1    | D1 05:03 | sprmonitorservlet | A:1099 | ncsync.jsp | 7KB | 相同 | 明文命令 | 同一工具链
2    | D2 08:15 | sprmonitorservlet | A:1099 | gzms.jsp | 22KB | 相同 | AES+Base64 | 同一工具链
3    | D2 20:34 | sprmonitorservlet | B:1099 | 加密器 | - | - | 混淆PowerShell | 入口复用，C2切换
```

```powershell
# 提取每轮 PowerShell 4104 脚本并对比结构
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Select-Object TimeCreated, Message
```

## 变体与关联

- 变体：同一 C2 多轮利用（更明确同源）；不同入口同一 C2；C2 复用但工具链不同；供应链/初始访问经纪人转卖。
- 关联：[[web-java-deserialization-jndi-ufida-sprmonitorservlet]]（本案入口）；[[web-java-classloader-jsp-memory-servlet-webshell]]（两枚 WebShell 的加载骨架）；[[defense-incident-response-ransomware-pre-encryption-cleanup]]（最后阶段加密前置行为）。
- 不确定点：本案没有通信、资金或样本同源证据，“漏洞/权限流转”只是合理推测；confidence 定为 medium。

## 检测与防御

- 检测：同一入口短时间多次异常；不同 C2 但相同 WebShell 密码/脚本骨架；WebShell 文件大小与时间规律；加密器落地前的 PowerShell 混淆。
- 响应：保留每轮样本与日志，按轮次隔离时间线；不要因为删除了第一枚 WebShell 就认为事件结束，需检查内存马与后续轮次。
- 防御：修补入口是根治；限制出站 RMI/LDAP/DNS；集中留存应用日志与 4104；对同版本资产批量排查。
- 归因规范：区分“基础设施关联”“工具链关联”“人员关联”，证据不足时明确写“未知/推测”。
