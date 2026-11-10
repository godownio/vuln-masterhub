---
id: defense-detection-etw-stack-unbacked-wininet-winhttp-beacon-process-url
title: 基于 ETW 栈回溯 unbacked 地址检测 sRDI/Beacon：WinINet/WinHTTP 事件定位 http(s) beacon 进程与通信 URL
type: scenario
domain: defense
path: defense/detection
technique: etw-stack-walk-unbacked-beacon-detection
aliases:
- BeaconKiller
- ETW 栈回溯检测 beacon
- unbacked 地址
- sRDI shellcode 检测
- Microsoft-Windows-WinINet
- Microsoft-Windows-WebIO
- Windows Kernel Trace
- 不加载内核模块不注入 dll
- ntdll!EtwEventWrite patch 绕过
tags:
- defense
- detection
- etw
- beacon
- cobaltstrike
- srdi
- shellcode
- stack-walk
- unbacked
- wininet
- winhttp
- incident-response
- threat-hunting
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:05:51+08:00'
  notes: 已对照原文(942字)与唯一截图核对：三类数据源(Windows Kernel Trace / Microsoft-Windows-WinINet / Microsoft-Windows-WebIO)、unbacked 栈回溯原理、启动/通信两类检测点、以及 PoC 段落的截图值(Unbacked(Used) PID 25432 beacon_wininet.exe、6100 beacon_winhttp.exe、WinINet/UsageLogRequest、URL https://127.0.0.1:10443/cx、Status 200、ntdll.dll!LdrSystemDllInitBlock+0x28414、unbacked true、WinHttp/Request|Response|Create|ApiInit|Session)均与图01一致；绕过段(patch ntdll!EtwEventWrite)与原文一致。未验证点：原文为工具发布说明，无检测脚本/规则代码，PoC 仅为截图示意，confidence=medium 恰当；『检测与防御』中多特征评分等建议属卡片延伸、非原文内容；frontmatter 无 sources/source_url；affected_versions 为空合规(非组件漏洞)。dedup 复跑无同链候选，nttestalert 卡为攻击侧绕过同一 EDR 规则、结论相反，不构成重复。
---

## 一句话结论

针对 http/https 的 CobaltStrike beacon，用纯 ETW（不加载内核模块、不注入 DLL）采集 Windows Kernel Trace 的进程/镜像事件与 Microsoft-Windows-WinINet / Microsoft-Windows-WebIO（WinHTTP）事件；由于 beacon 用 sRDI 等 shellcode 加载技术，其在加载 wininet.dll/winhttp.dll 及通信时的**栈回溯会出现 unbacked 地址**（无法对应任何已加载镜像、落在动态申请的可执行内存），据此可在应急场景快速定位 beacon 进程 PID 与通信 URL；攻击者可用 patch `ntdll!EtwEventWrite` 阻断应用层 ETW 日志绕过通信时检测。

## 原理

- **beacon 的内存特征**：sRDI 等 shellcode 加载技术把 beacon 反射加载到进程内动态申请的可执行内存（非磁盘镜像、无模块 backing），因此其代码地址不属于任何已加载模块。
- **栈回溯暴露 unbacked**：当这样的 shellcode 调用系统 API（启动时 `LoadLibrary(wininet.dll/winhttp.dll)`、通信时 WinINet/WinHTTP 的 HTTP 请求 API）触发 ETW 事件时，事件携带的调用栈里会出现返回地址落在"无镜像对应"的动态可执行内存，即 unbacked。正常进程的调用栈每一帧都能对应到已加载模块（Loaded）；工具界面里 `beacon_wininet.exe`/`beacon_winhttp.exe` 被标 `Unbacked(Used)`，而 `DingTalk.exe`/`svchost.exe` 等为 `Loaded`。
- **数据源（纯 ETW，稳定）**：进程/镜像相关事件由 `Windows Kernel Trace` 提供（Image/Load 等）；WinINet 事件由 `Microsoft-Windows-WinINet` 提供（WinINet/UsageLogRequest 等）；WinHTTP 事件由 `Microsoft-Windows-WebIO` 提供（WinHttp/Request、Response、Create、ApiInit、Session 等）。仅用 ETW 不需要加载内核模块、不需要注入 DLL，稳定性/兼容性更好。
- **定位进程与 URL**：把"含 unbacked 栈帧"的 ETW 事件按 PID 聚合即可得到可疑 beacon 进程；再看 WinINet/WinHTTP 事件详情里的 `URL`、`RequestHeaders`、`ResponseHeaders`、`Status` 与 `stacks` 字段，直接拿到 C2 通信 URL（截图示例 `https://127.0.0.1:10443/cx`）与 `"unbacked": true` 判定。
- **检测点分两类**：① 启动时——加载 wininet.dll/winhttp.dll 的 Image/Load 事件栈回溯 unbacked；② 通信时——每次 HTTP(S) 请求/响应的栈回溯 unbacked。后者覆盖面更广。
- **绕过与边界**：启动时检测已有公开绕过手法；通信时检测可通过修改 `ntdll!EtwEventWrite`（ETW 写事件的应用层入口，donut 等 loader 的 bypass 思路）阻断应用层 ETW 日志，使检测失效。因此该检测适合应急快速排查，不能作为唯一防线。
- **为什么成立（本质）**：反射加载/无文件 shellcode 的代码页没有模块 backing，而 ETW 事件自带栈回溯且应用层 API 调用必经系统 DLL；把"栈帧地址是否落在已加载模块"作为判据，即可在无需内核驱动/注入的情况下从海量事件中筛出 beacon 与其 C2 通信。

## 触发条件

- 目标是 http/https 类型 beacon，且使用 sRDI 等 shellcode 反射加载（代码在无模块 backing 的动态可执行内存）。
- 目标通过 WinINet 或 WinHTTP 发起通信（触发对应 ETW provider）。
- 采集端能开启并消费 `Windows Kernel Trace` + `Microsoft-Windows-WinINet` + `Microsoft-Windows-WebIO` 三类 ETW 会话（用户态权限即可，无需内核模块/注入）。
- 目标未 patch `ntdll!EtwEventWrite`（否则应用层 ETW 日志被阻断）。

## 利用步骤（检测/排查步骤）

1. 启动 ETW 会话，订阅 Windows Kernel Trace 的进程/镜像事件、Microsoft-Windows-WinINet、Microsoft-Windows-WebIO。
2. 对每个事件取 PID/Process 与调用栈，逐帧判断返回地址是否落在已加载镜像范围内；标记含 unbacked 栈帧的事件（Type = Unbacked(Used)）。
3. 按 PID 聚合，定位可疑 beacon 进程；对照 Image/Load 事件确认其是否加载 wininet.dll/winhttp.dll。
4. 双击 WinINet/UsageLogRequest、WinHttp/Request 等事件查看详情，读取 `URL`/`RequestHeaders`/`stacks`/`unbacked` 字段，得到 C2 通信 URL 与请求特征。
5. 应急处置：结束进程，并据 URL 在防火墙/代理侧封禁、排查同源进程。

## PoC

无独立 PoC（检测结果示意，来自工具截图）：

```text
Type=Unbacked(Used)  PID=25432  beacon_wininet.exe
Type=Unbacked(Used)  PID=6100   beacon_winhttp.exe
Type=Loaded          DingTalk.exe / svchost.exe / ... （正常）
EventName=WinINet/UsageLogRequest  PID=25432  beacon_wininet.exe
详情 JSON: "URL": "https://127.0.0.1:10443/cx", "Status": 200,
           "stacks": ["ntdll.dll!LdrSystemDllInitBlock+0x28414", "wininet.dll!...", ...],
           "unbacked": true
```

文章只给工具与外链、无独立可复现的检测脚本，故 confidence 标 medium。

## 变体与关联

- **数据源变体**：除 ETW 外，也可基于内核回调/ETW TI、进程内存扫描（VirtualAlloc/VirtualProtect RWX 私有页、模块列表比对）找"无模块可执行内存"，思路同源（见 Linux memfd 无文件进程检测、PTE Walk / NMI 栈扫描 unbacked 内核页、Linux 进程注入检测等卡）。
- **协议变体**：WinINet 与 WinHTTP 栈不同；也可扩展对 DNS/HTTPS(SNI)/命名管道 beacon 的 ETW provider。
- **绕过变体**：patch `ntdll!EtwEventWrite`（或 `EtwEventWriteFull`）、直接 syscall 绕过用户态 ETW、栈 spoofing/自定义调用栈使栈帧看似来自合法模块、模块踩踏把代码放进已加载模块 .text 消除 unbacked；库内 pentest/c2 下已有多张 ETW patch / 调用栈伪造卡。
- **关联卡**：CobaltStrike 流量侧检测（checksum8/JA3、域前置配置、TLS 中间人解密后 Suricata 规则）、C2 流量解密与 beacon 配置提取；本卡是**主机侧 ETW 栈特征**检测，与流量侧互补。
- **边界**：非 http/https beacon、beacon 已 patch ETW、使用合法模块内加载（非反射 shellcode）时漏报；正常 JIT/CLR/加壳程序也可能出现 unbacked 栈帧，需结合进程签名、父子关系、URL 信誉降误报。

## 检测与防御

- **加固/采集**：在终端开启并集中采集上述三类 ETW provider，持久化保留栈回溯与 URL 字段；对 Unbacked(Used) 事件做实时告警与自动处置。
- **对抗绕过**：监控 `ntdll!EtwEventWrite` 被 inline patch/钩子改写、ETW 会话被禁用、进程大量使用直接 syscall；用内核侧 ETW/回调（不只依赖应用层日志）交叉验证。
- **降误报**：把 unbacked 与"wininet/winhttp 加载 + 外联 URL + 无签名/异常父进程 + 心跳周期"组合成多特征评分，而非单条栈帧。
- **应急**：定位到 PID 后结束进程、内存 dump 留证、按 URL/域名封禁并横向排查。
