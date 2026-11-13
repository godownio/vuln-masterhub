---
id: defense-detection-callstack-office-ole-embedded-object-drop
title: 调用堆栈检测 Office 文档 OLE 嵌入对象落地：OleSaveToStream/OleLoad + 可疑扩展名或 PE/CHM 头
type: scenario
domain: defense
path: defense/detection
technique: callstack-office-ole-embedded-object-drop
aliases:
- Office OLE 嵌入对象检测
- OleSaveToStream 检测
- OleLoad 检测
- 恶意文档落地载荷
- Elastic Defend Office 检测
tags:
- defense
- detection
- call-stack
- elastic
- eql
- edr
- windows
- office
- ole
- malware-delivery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:09+08:00'
  notes: 已对照原文与 img15/16 核对：OleSaveToStream/OleLoad 调用栈锚点、可疑扩展名集合与 4d5a*/49545346*（MZ/ITSF-CHM）头判据与原文一致；截图命中 WINWORD.EXE 写出 Client.log（file.Ext.header_bytes 4d5a00000000），调用栈含 ole32.dll!OleLoad+0x6b。img15 为 Word 文档内嵌 222.chm 对象。dedup 候选为宏文档/外部 OLE 投递卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
---

## 一句话结论

恶意 Office 文档常用嵌入 OLE 对象释放初始访问载荷：`winword.exe`/`excel.exe`/`powerpnt.exe` 进程写出 `exe/dll/js/vbs/vbe/jse/url/chm/bat/mht/hta/htm/search-ms` 等可疑扩展名，或写出以 `4D 5A`（MZ）或 `49 54 53 46`（ITSF，CHM）开头的文件，且调用栈中出现 `!OleSaveToStream`/`!OleLoad`，即可判定为从文档嵌入对象落地。

## 原理

- **OLE 复合文档机制**：Office 文档以 OLE 复合文件格式保存，可将任意文件作为嵌入对象（OLE object/package）存放在流中。打开/激活对象时由 `OleLoad` 读出，保存/释放时由 `OleSaveToStream` 写回流或解包到文件系统。
- **调用栈锚点**：正常“另存为”走文档格式写盘路径；而嵌入对象解包/保存必然经过 `ole32!OleSaveToStream`/`OleLoad` 或其内部函数，因此文件创建事件的调用栈同时出现 Office 进程与 OLE API 帧，是“从文档内嵌对象落盘”的强信号。
- **二次判据**：仅凭 OLE 锚点可能是正常对象（如图片、嵌入表格），再叠加①落地扩展名属于可执行/脚本/快捷方式/帮助文件类，或②文件头为 MZ（PE）或 ITSF（CHM），可把误报压到很低。
- **为什么有效**：恶意文档投递链（宏、外部 OLE、远程模板、CVE-2017-8570 类）最终都要把载荷写到磁盘或内存；OLE API 是这条路径的必经点，攻击者难以在不触发该锚点的情况下解包标准 OLE 嵌入对象。
- **边界**：纯内存加载/无文件链可能不产生文件事件；嵌入对象也可能是无害的；需结合签名、路径与后续执行行为。

## 触发条件

- EDR 采集文件创建/修改事件及进程线程调用栈符号（Elastic Defend `process.thread.Ext.call_stack`）。
- 目标运行 Microsoft Office（winword/excel/powerpnt），文档包含 OLE 嵌入对象。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 EQL：文件事件非删除、进程为 Office 三件套、调用栈含 `OleSaveToStream` 或 `OleLoad`，且扩展名或文件头命中可疑集合。
2. 命中后核对文件路径（`%TEMP%`、`%APPDATA%`、下载目录）、签名与来源文档；提取文件做静态分析（PE/脚本/CHM）。
3. 检查父文档的 OLE 流（`oleobj`/`olevba` 等工具）与外部关系（`.rels` 中的 `Target` 是否指向远程 scriptlet）。
4. 关联同进程的创建/执行行为（`ShellExecute`、`CreateProcess`、脚本解释器启动）定性。

## PoC

```eql
file where event.action != "deletion" and

process.name : ("winword.exe", "excel.exe", "powerpnt.exe") and

_arraysearch(process.thread.Ext.call_stack, $entry,
  $entry.symbol_info : ("*!OleSaveToStream*", "*!OleLoad*")) and
(
 file.extension : ("exe", "dll", "js", "vbs", "vbe", "jse", "url",
                   "chm", "bat", "mht", "hta", "htm", "search-ms") or

 /* PE 与 CHM 文件头 */
 file.Ext.header_bytes : ("4d5a*", "49545346*")
)
```

原文截图中命中 `WINWORD.EXE` 写出的 `Client.log`，其 `file.Ext.header_bytes` 为 `4d5a...`（实为 MZ/PE），调用栈含 `ole32.dll!OleLoad` 等帧。

## 变体与关联

- **外部 OLE/远程 scriptlet**：`.rels` 指向 `script:http://...` 或 `mhtml:`，不落盘但同样经 OLE 加载，需结合网络事件；见 `pentest-initial-access-ppsx-external-ole-script-remote-scriptlet-cve-2017-8570`。
- **宏与远程模板**：`Document_Open`/`AutoOpen` 下载执行，见 `pentest-initial-access-office-macro-document`。
- **CVE-2021-40444 类**：OLE 投递 CAB + CPLApplet，见 `code-analysis-reverse-windows-graphite-customui-40444-cab-cplapplet-loader`。
- **边界**：合法嵌入对象与模板也会命中；需按扩展名/头/路径/签名收敛。

## 检测与防御

- **检测**：上述 EQL；补充监控 Office 进程创建脚本解释器、`ShellExecute`、注册表 Run 键与网络下载。
- **降噪**：排除已知业务模板与签名文件；按文档来源（邮件/下载）加权。
- **加固**：启用 Office 受保护视图、ASR 规则（阻止 Office 创建子进程/可执行内容）、禁用不必要的 OLE/宏；对来自互联网的文档加 MOTW。
- **响应**：隔离主机，提取文档 OLE 流与落地文件，排查同时间窗的脚本执行与外联。
