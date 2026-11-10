---
id: code-analysis-reverse-windows-com-activation-child-process-createprocessinternalw-capture
title: COM 激活子进程逆向捕获：svchost 父进程 CreateProcessInternalW 断点定位 TiWorker.exe
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: com-activation-child-process-capture
aliases:
- COM 激活进程捕获
- CreateProcessInternalW 断点
- svchost 子进程 TiWorker
- COM 启动进程调试
- TiWorker.exe -Embedding
tags:
- windows
- reverse-engineering
- com
- createprocessinternalw
- svchost
- tiworker
- debugging
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T02:57:35+08:00'
  notes: 已对照原文与图片核对：CoCreateInstance CLSID {8F5DF053-3013-4dd8-B5F4-88214E81C0CF}/IID {90ED9FAA-A6E5-4671-8E50-1C060F8B9C47}、SFP Repair Class/AppID {752073A2-23F2-4396-85F0-8FDB879ED0ED}、InprocServer32=%systemroot%\servicing\wrpintapi.dll、svchost(880)→TiWorker.exe(1012)、kernelbase!CreateProcessInternalW 断点命中 TiWorker.exe -Embedding 与常驻后附加 TiWorker 均与原文/截图一致；无 sources/文章ID/长段摘录，路径合法。未验证点：不同 COM 宿主(dllhost/RuntimeBroker 等)变体为合理外推未实测。
---

## 一句话结论

`CoCreateInstance` 指向服务类 COM 时，真正承载对象的进程（如 TiWorker.exe）往往由 svchost.exe 等宿主另行 `CreateProcess` 启动，而不是在调用者进程内运行；用 Process Explorer 找到父 svchost 的 PID，对父进程附加 xdbg 并在 `kernelbase!CreateProcessInternalW` 下断，再触发 COM 调用，即可从断点栈上直接读到子进程命令行（案例为 `TiWorker.exe -Embedding`）；若子进程首次运行后转为常驻，也可在首次触发后直接附加它。

## 原理

- R3 层创建进程最终都要走 `kernelbase!CreateProcessInternalW`（`CreateProcessW`/`CreateProcessAsUser` 等的公共下层）。COM 服务激活由 SCM/svchost 侧的代码发起创建进程，所以断在父进程的 `CreateProcessInternalW` 能看到启动子进程时传入的 `lpApplicationName`/`lpCommandLine`。
- 案例链路：`sfc.exe` 调 `CoCreateInstance(CLSID_SFPIntegrityCheckAndRepair {8F5DF053-3013-4dd8-B5F4-88214E81C0CF}, IID_ISFPIntegrityCheckAndRepair {90ED9FAA-A6E5-4671-8E50-1C060F8B9C47})`，注册表 `HKCR\CLSID\{8F5DF053-...}` 名为 “SFP Repair Class”、AppID `{752073A2-...}`，`InprocServer32` 为 `%systemroot%\servicing\wrpintapi.dll`；实际校验由 COM 激活的 `TiWorker.exe -Embedding` 完成，进程树中 TiWorker.exe 的父进程是 svchost.exe（案例 PID 880）。
- 直接对 sfc.exe 或 wrpintapi.dll 下断抓不到子进程创建，因为创建动作发生在父 svchost 中；只对最终子进程下断又可能错过其短暂启动窗口。对父进程下 CreateProcess 断点是稳定入口。
- TiWorker.exe 第一次被拉起后常驻（作为 COM 服务器等待后续请求），因此第二次运行 `sfc` 时可直接附加已存在的 TiWorker；但要在命令执行后尽快附加并在目标函数断点命中，否则可能错过本次调用。

## 触发条件

- 已知目标 COM 类由服务/代理进程承载（LocalServer/服务激活），且能通过 Process Explorer 等工具看到目标子进程的父进程。
- 有管理员权限对父进程（svchost.exe 等）附加调试器；部分系统进程受保护，需要相应权限或内核调试替代。
- 触发动作可重复（案例反复执行 `sfc /VERIFYFILE=...`）。

## 利用步骤

1. 先跑一次触发命令（如 `sfc /VERIFYFILE=c:\windows\system32\kernel32.dll`），在 Process Explorer 中展开进程树，记下目标子进程（TiWorker.exe）的父进程（svchost.exe 及其 PID）。
2. 对父 svchost 附加 xdbg/其它用户态调试器，执行 `bp kernelbase!CreateProcessInternalW`（或在 `kernelbase.CreateProcessInternalW` 的序言下断）。
3. 再次执行触发命令，断点命中后读栈参数：`lpApplicationName` 与 `lpCommandLine` 指向 UTF-16 字符串，案例中可见 `C:\Windows\winsxs\x86_microsoft-windows-servicing...` 与内存中的 `TiWorker.exe -Embedding`。
4. 记下子进程路径后，可在后续调用中直接附加 TiWorker.exe，对目标函数（如 `Windows::Cms::Rtl::FileHashAlgorithmToDigest`）下断；注意 TiWorker 常驻但单次请求很短，附加与断点要抢时间。
5. 若断点来不及，可在首次触发后保持 TiWorker 存活，反复触发同一 COM 操作以命中下一次调用。

## PoC

xdbg 命令与命中现场示意：

```text
bp kernelbase!CreateProcessInternalW
```

```text
Breakpoint at kernelbase.CreateProcessInternalW
[ebp+10]: L"C:\Windows\winsxs\x86_microsoft-windows-servicing..."
[esp+4] : 0x03772230  L"C:\Windows\winsxs\x86_microsoft..."
memory  : 54 00 69 00 57 00 6f 00 72 00 6b 00 65 00 72 00 ...  "TiWorker.exe -Embedding"
```

触发命令：

```cmd
sfc /VERIFYFILE=c:\windows\system32\kernel32.dll
```

## 变体与关联

- 变体：不同 COM 服务可能由 `dllhost.exe`、`RuntimeBroker.exe`、`SearchProtocolHost.exe` 等宿主创建子进程，思路相同：先看进程树找到真正的创建者，再对创建者下 CreateProcess 断点。
- 变体：若父进程受保护无法附加，可用 Process Monitor 先观察 Process/Thread Start 事件与命令行（部分系统会记录），或用 ETW 的进程创建事件替代。
- 关联：本案最终用于分析 SFC 校验链，见 [[code-analysis-reverse-windows-sfc-verifyfile-deriveddata-s256-tiworker-hash]]；文件名保护判定见 [[code-analysis-reverse-windows-sfc-isfileprotected-filemaps-pnp-lockdown]]。
- 边界：断点法是“抓一次调用”的时序技巧，不保证每次都能命中；对常驻 COM 服务器直接附加更稳，但需要知道目标函数偏移/符号。

## 检测与防御

- 该手法是逆向分析手段而非攻击载荷；从防御视角，调试器附加到 svchost.exe 等系统进程需要管理员权限，EDR 可将“非调试工具进程对 svchost 的 DebugActiveProcess/调试附加”作为高价值告警。
- 监控 `CreateProcess` 事件中 svchost.exe 创建 `TiWorker.exe -Embedding` 等异常父子关系；正常系统更新/修复期间出现属预期，但频繁触发并伴随调试附加可疑。
- 对分析者：优先快照进程树与命令行再附加，避免断点窗口错过；对蓝队：保护调试权限（SeDebugPrivilege）的授予与使用。
