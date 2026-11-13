---
id: defense-detection-callstack-unbacked-ransomware-file-rename
title: 调用堆栈检测注入进程的勒索文件重命名：签名进程 + Unbacked 帧 + 文档扩展名被改为非文档扩展名
type: scenario
domain: defense
path: defense/detection
technique: callstack-unbacked-ransomware-file-rename
aliases:
- 勒索软件重命名检测
- 签名进程注入检测
- Unbacked 调用栈重命名
- KNIGHT 勒索检测
- CYCLOPS 勒索检测
- Elastic Defend 文件重命名
tags:
- defense
- detection
- call-stack
- elastic
- kql
- edr
- windows
- ransomware
- process-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:11+08:00'
  notes: 已对照原文与 img17/22 核对：签名进程 + Unbacked/Unknown 调用栈 + 文档扩展名改为非文档扩展名的检测逻辑与原文一致；两批截图分别 7838 hits（.htm→knight1）与 7800 hits（→knight_1），均为 explorer.exe rename、Unknown 帧。原卡 PoC 漏了原文列表中的 wow64 长变体（ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|kernelbase.dll|Unbacked|kernel32.dll|ntdll.dll），已补回并去掉原文重复项。dedup 候选为勒索白名单绕过/ETW unbacked beacon 卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
---

## 一句话结论

部分勒索软件在加密前把代码注入已签名的受信任进程（如 `explorer.exe`），使文件重命名/修改事件看起来来自可信程序，可能绕过“签名进程即误报”的启发式；若这些重命名事件来自签名进程，但线程调用栈包含 Unbacked/Unknown 帧，且把 jpg/bmp/png/pdf/doc(x)/xls(x)/ppt(x) 等文档改成非文档扩展名，则可高置信度判定为注入后的勒索行为。

## 原理

- **注入掩盖来源**：文件重命名/写操作由被注入的宿主进程发起，事件里的 `process.code_signature.status` 为 `trusted`，只看签名的检测会放行。
- **调用栈暴露注入**：注入代码位于未支持内存（unbacked），其返回地址不属于任何已加载模块，调用栈摘要出现 `Unbacked`/`Unknown` 与非预期的模块顺序（如 `ntdll.dll|kernelbase.dll|Unknown|kernel32.dll|ntdll.dll`）。正常签名进程的文件操作栈通常由系统模块与自身模块组成。
- **重命名模式**：勒索软件批量把用户文档改成加密后的扩展名（如 `.knight`）；规则要求“原始扩展名属于常见文档类型”且“新扩展名不属于临时/压缩/备份/快捷方式等正常变体”，从而聚焦文档被批量改名这一加密前置行为。
- **为什么有效**：注入点无法避免在调用栈中留下未映射帧；批量重命名是加密前的固定动作，两者组合可把签名进程的正常文件操作与恶意注入区分开。
- **边界**：攻击者可用调用栈欺骗或改用内核态操作；正常软件（同步盘、压缩工具）也可能重命名文档，需要白名单与频率基线。

## 触发条件

- EDR 采集文件重命名事件、进程签名状态与线程调用栈（Elastic Defend `process.thread.Ext.call_stack_summary`）。
- 被注入的宿主进程已签名（如 explorer.exe），勒索软件执行批量文档重命名。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 KQL：文件重命名为 rename、进程签名 trusted、原文件名为文档扩展名、新扩展名不在正常变体集合、调用栈摘要匹配 Unbacked/Unknown 模式。
2. 命中后检查同一进程短时间内的重命名数量与扩展名分布（批量 `.knight` 等）。
3. 抓取宿主进程内存，检查注入的 PE/shellcode 与线程起始地址；确认是否与已知勒索家族（KNIGHT/CYCLOPS）匹配。
4. 检查同时间窗的卷影删除、服务停止、加密说明文件落地等关联行为。

## PoC

```kql
file where event.action : "rename" and

process.code_signature.status : "trusted" and file.extension != null and

file.Ext.original.name : ("*.jpg", "*.bmp", "*.png", "*.pdf", "*.doc",
"*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx") and

not file.extension : ("tmp", "~tmp", "diff", "gz", "download", "bak",
"bck", "lnk", "part", "save", "url", "jpg", "bmp", "png", "pdf", "doc",
"docx", "xls", "xlsx", "ppt", "pptx") and

process.thread.Ext.call_stack_summary :
("ntdll.dll|kernelbase.dll|Unbacked",
 "ntdll.dll|kernelbase.dll|kernel32.dll|Unbacked",
 "ntdll.dll|kernelbase.dll|Unknown|kernel32.dll|ntdll.dll",
 "ntdll.dll|kernelbase.dll|kernel32.dll|Unknown|kernel32.dll|ntdll.dll",
 "ntdll.dll|kernelbase.dll|kernel32.dll|mscorlib.ni.dll|Unbacked",
 "ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|kernelbase.dll|
 Unbacked", "ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|
 kernelbase.dll|Unbacked|kernel32.dll|ntdll.dll", "ntdll.dll|Unbacked",
 "Unbacked", "Unknown")
```

原文截图中 KNIGHT 勒索注入的 `explorer.exe` 对 `.htm` 等文件批量 rename，调用栈摘要含 `Unknown` 帧（7838 条命中示例）；另一组截图显示同一模式持续出现。

## 变体与关联

- **关联卡**：`pentest-c2-edr-ransomware-decoy-whitelist-process-name-bypass`（勒索绕过防护的攻方视角）、`pentest-c2-trusted-system-process-file-drop-c2-proxy`（借系统进程写文件）、`pentest-c2-windows-process-hollowing-pe-injection`（注入手法）。
- **变体**：注入 `notepad.exe`、`RuntimeBroker.exe` 等其他签名进程；加密扩展名随家族变化；也可用 `MoveFileEx`/重命名 API 的等价行为。
- **边界**：同步客户端、备份软件、归档工具会正常重命名文档，需按进程与目录白名单；栈欺骗可让 Unbacked 帧消失。

## 检测与防御

- **检测**：上述 KQL；补充“签名进程 + 短时间内大批量文档重命名 + 非文档扩展名”的频率规则；监控卷影副本删除、备份服务停止等勒索前置行为。
- **降噪**：按进程路径、签名、目标目录、扩展名分布建立基线；排除已知同步/压缩/办公软件。
- **加固**：启用受控文件夹访问（CFA）、ASR 规则、EDR 内存防护；限制宏与脚本；定期离线备份。
- **响应**：立即隔离主机、停止加密进程、保留内存镜像；从备份恢复并排查注入源与初始访问。
