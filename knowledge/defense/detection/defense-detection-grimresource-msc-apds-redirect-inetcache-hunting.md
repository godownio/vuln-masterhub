---
id: defense-detection-grimresource-msc-apds-redirect-inetcache-hunting
title: GrimResource 狩猎：mmc.exe→apds.dll→INetCache redirect[?].html 序列 + DotNetToJScript RWX 调用栈 + YARA
type: scenario
domain: defense
path: defense/detection
technique: grimresource-msc-apds-hunting
aliases:
- GrimResource 检测
- MSC 文件威胁狩猎
- mmc.exe apds.dll 检测
- redirect[?].html 检测
- DotNetToJScript RWX EQL
- MMC 控制台脚本执行检测
tags:
- defense
- detection
- threat-hunting
- windows
- msc
- mmc
- apds
- eql
- yara
- edr
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V308
  verified_at: '2026-11-08T12:03:48+08:00'
  notes: 已对照原文与 17 张图核对四条 EQL 与 YARA 逐字一致、mmc 库加载基线 193/jscript9 51.3%/jscript 48.2%/msxml3 0.5% 一致；未真实部署调优。dup-scan 与攻击卡 likely_duplicate 按原文裁决为攻击/检测两原子并列保留。
---

## 一句话结论

GrimResource 的每个阶段都有可观测痕迹：`mmc.exe` 以 `.msc` 启动后打开 `C:\Windows\System32\apds.dll`（该 DLL 通常不作为库加载）、在 `INetCache\IE\*\redirect[?]` 生成被 APDS XSS 重定向的 HTML、脚本引擎经 `mscoree.dll|combase.dll|vbscript.dll/jscript.dll` 在非 `cscript/wscript` 进程里分配 RWX、随后 `mmc.exe` 创建 `dllhost.exe`；用 EQL 序列规则 + YARA 即可覆盖，且需先用环境基线（正常 mmc 也会加载 jscript/jscript9/msxml3）控制误报。

## 原理

- **阶段 1：MSC 打开**。用户双击 `.msc` 时 `mmc.exe` 命令行带该 `.msc` 路径；正常系统管理单元通常来自 `C:\Windows\System32\*.msc`、SysWOW64、Program Files 等可信目录，且不会随意从用户下载目录启动。旧式 MSC Taskpad 和 GrimResource 都从这里开始。
- **阶段 2：APDS 资源加载**。GrimResource 在 `StringTable` 引用 `res://apds.dll/redirect.html?...`，MMC 通过 CreateFile 打开 `apds.dll`（它以资源/协议方式被读取，而不是作为 DLL 加载到模块列表），Procmon/EDR 的 file open 事件可见；这是比“mmc 加载脚本引擎”更强的特征。
- **阶段 3：APDS XSS 重定向**。`redirect.html` 读取 `target` 参数并 `window.location.replace(decodeURIComponent(...))`，浏览器/MSHTML 在 `INetCache\IE\<随机>\redirect[?]` 落一个临时 HTML；文件内容含 `targetParamRegex = /[\?&]target=([^\&\#]+)/i` 与 `location.replace`，可做内容匹配。
- **阶段 4：脚本引擎执行与 DotNetToJScript**。mmc.exe 加载 `jscript.dll/jscript9.dll/msxml3.dll/vbscript.dll` 属于其正常能力（原文基线：193 条 mmc 库加载事件中 jscript9 占 51.3%、jscript 48.2%、msxml3 0.5%），所以“加载脚本引擎”本身不足以告警；更有价值的是**非 WSH 宿主进程**（mmc.exe）通过 `mscoree.dll/combase.dll/vbscript.dll` 调用链分配 RWX 内存，这对应 DotNetToJScript 的 .NET 加载行为。
- **阶段 5：注入与 C2**。PASTALOADER 启动 `dllhost.exe` 并注入，Cobalt Strike 在 dllhost 内存中出现网络模块/可疑栈；`mmc.exe → dllhost.exe` 的父子关系在正常 MMC 使用中很少见。
- **为什么要组合检测**：单条规则都可被运营性规避（换子进程、换注入目标、去掉 DotNetToJScript），但“MSC 启动 → apds.dll 打开 → redirect[?].html 生成”这条 APDS 利用链的序列难以完全避免；把文件事件与进程事件按 `process.entity_id` 关联可显著提高信噪比。

## 触发条件

- 具备进程启动、文件打开/创建、API 调用与调用栈遥测（Elastic Defend、Sysmon + EDR、Microsoft Defender XDR、CrowdStrike 等）。
- 能采集 mmc.exe 的 file open/create 事件与 `process.Ext.api`（VirtualAlloc）调用栈；否则只能退化为进程行为规则。
- 有正常 mmc 使用基线（哪些目录的 MSC、常加载哪些 DLL、是否常创建 dllhost 子进程）。
- 规则平台支持 EQL sequence 或等价的时间窗关联（1 分钟内）。

## 利用步骤

1. 部署“MSC 启动 → apds.dll 打开”序列规则（EQL），捕获 `mmc.exe` 命令行含 `.msc` 与随后 file open `apds.dll` 的事件；记录 msc 文件路径作为取证线索。
2. 部署“MSC 启动 → INetCache redirect[?].html 创建/覆盖”序列规则，匹配 `file.name : "redirect[?]"` 与 `INetCache\IE\*\redirect[?]` 路径。
3. 部署 DotNetToJScript 规则：非 cscript/wscript 的 Microsoft 签名进程（如 mmc.exe）分配 RWX，且调用栈含 `mscoree.dll|combase.dll|jscript.dll`、`vbscript.dll`、`jscript9.dll` 或 `chakra.dll`。
4. 部署 mmc 子进程规则：`process.parent.executable` 为 mmc.exe 且父进程参数含 `.msc`，排除可信目录的 MSC 与常见正常子进程（mmc、wermgr、WerFault、Program Files 程序、spool 驱动等）。
5. 用 YARA 扫描 MSC/文件：`<?xml` at 0、`MMC_ConsoleFile`、`apds.dll`、`res://`、`javascript:eval(`、`.loadXML(` 中至少 2 个组合命中。
6. 基线校准：统计正常 mmc 的库加载分布，确认 jscript/jscript9/msxml3 的常见度；排除正常 MMC 任务垫/管理单元；对告警按 msc 来源（下载目录/邮件附件）排序。
7. 响应：隔离 `redirect[?].html` 与 MSC 样本、检查 `dllhost.exe` 内存/网络、排查 Cobalt Strike 与横向；保留 EQL 命中与进程树证据。

## PoC

```text
# 1) MSC 启动后 mmc.exe 打开 apds.dll（核心 APDS 利用链）
sequence by process.entity_id with maxspan=1m
 [process where event.action == "start" and
  process.executable : "?:\\Windows\\System32\\mmc.exe" and process.args : "*.msc"]
 [file where event.action == "open" and file.path : "?:\\Windows\\System32\\apds.dll"]
```

```text
# 2) MSC 启动后 mmc.exe 在 INetCache 创建 redirect[?].html
sequence by process.entity_id with maxspan=1m
 [process where event.action == "start" and
  process.executable : "?:\\Windows\\System32\\mmc.exe" and process.args : "*.msc"]
 [file where event.action in ("creation", "overwrite") and
  process.executable : "?:\\Windows\\System32\\mmc.exe" and
  file.name : "redirect[?]" and
  file.path : "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*\\redirect[?]"]
```

```text
# 3) 非 WSH 进程中的 DotNetToJScript：Microsoft 签名进程分配 RWX，
#    调用栈来自 mscoree/combase + 脚本引擎
api where
  not process.name : ("cscript.exe", "wscript.exe") and
  process.code_signature.trusted == true and
  process.code_signature.subject_name : "Microsoft*" and
  process.Ext.api.name == "VirtualAlloc" and
  process.Ext.api.parameters.allocation_type == "RESERVE" and
  process.Ext.api.parameters.protection == "RWX" and
  process.thread.Ext.call_stack_summary : (
    "*|mscoree.dll|combase.dll|jscript.dll|*",
    "*|mscoree.dll|combase.dll|vbscript.dll|*",
    "*|mscoree.dll|combase.dll|jscript9.dll|*",
    "*|mscoree.dll|combase.dll|chakra.dll|*"
)
```

```text
# 4) mmc.exe 派生异常子进程
process where event.action == "start" and
 process.parent.executable : "?:\\Windows\\System32\\mmc.exe" and
 process.parent.args : "*.msc" and
 not process.parent.args : ("?:\\Windows\\System32\\*.msc", "?:\\Windows\\SysWOW64\\*.msc",
                            "?:\\Program files\\*.msc", "?:\\Program Files (x86)\\*.msc") and
 not process.executable : ("?:\\Windows\\System32\\mmc.exe", "?:\\Windows\\System32\\wermgr.exe",
                           "?:\\Windows\\System32\\WerFault.exe", "?:\\Windows\\SysWOW64\\mmc.exe",
                           "?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe",
                           "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.EXE",
                           "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")
```

```yara
rule Windows_GrimResource_MMC {
    meta:
        author = "Elastic Security"
        reference = "https://www.elastic.co/security-labs/GrimResource"
        reference_sample = "14bcb7196143fd2b800385e9b32cfacd837007b0face71a73b546b53310258bb"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $xml = "<?xml"
        $a = "MMC_ConsoleFile"
        $b1 = "apds.dll"
        $b2 = "res://"
        $b3 = "javascript:eval("
        $b4 = ".loadXML("
    condition:
       $xml at 0 and $a and 2 of ($b*)
}
```

未在真实环境部署/调优以上规则；EQL 语义按原文规则转录，YARA 为原文规则。

## 变体与关联

- 变体：没有 file open 遥测时，用 Sysmon EventID 11（FileCreate）匹配 `redirect[?]`，或用 EventID 1（ProcessCreate）匹配 mmc→dllhost；没有调用栈时，退化为“mmc 非可信路径 .msc + 子进程网络连接”。
- 变体：旧式 MSC Taskpad 攻击只触发“mmc.exe 异常子进程”规则（如 powershell/cmd/msiexec），不触发 apds.dll/redirect 规则；两类规则应同时部署。
- 关联：[[pentest-initial-access-grimresource-msc-apds-xss-dotnettojscript-injection]]（本检测对应的攻击链与样本哈希）、[[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]（Cobalt Strike 后续流量检测）、[[defense-detection-etw-stack-unbacked-wininet-winhttp-beacon-process-url]]（内存/网络行为检测）。
- 边界：攻击者改用其它 XSS/资源、换注入目标或改用无文件执行时，部分规则失效；正常 MMC 管理单元也可能打开 apds.dll/创建 redirect 缓存（需用 msc 来源、签名、文件内容与后续行为做二次判定）。

## 检测与防御

- 检测调优：先统计正常 mmc 的库加载与子进程分布（原文基线 193 条库加载事件），把 `C:\Windows\System32\*.msc`、Program Files 管理单元列入白名单；对用户下载目录/邮件附件中的 `.msc` 提高权重。
- 防御：通过组策略/ASR 限制 `.msc` 执行与 MMC 管理单元；阻止从 Internet 下载的 MSC；启用 Microsoft Defender ASR 与 EDR 内存扫描。
- 响应：命中 apds.dll 序列后立即隔离 MSC 与 redirect 文件，检查 `dllhost.exe` 内存、网络连接与 Cobalt Strike 特征，排查同源投递与横向。
- 加固：更新 Windows/MMC/APDS 组件；对管理控制台文件做来源白名单与文件类型管控；对 `mmc.exe` 创建 `dllhost.exe` 等异常父子关系告警。
