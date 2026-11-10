---
id: code-analysis-dynamic-debugging-windows-message-breakpoint-wndproc-locate
title: Windows 消息断点：在 WndProc 分发处按 [ESP+8] 消息号拦截，定位按钮点击处理代码
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: windows-message-breakpoint-wndproc-locate
aliases:
- 消息断点
- WM_LBUTTONUP 断点
- 202 断点
- WndProc 定位
- ClassProc 断点
- OllyDbg 消息断点
- 按钮点击处理定位
- 注册框按钮断点
tags:
- reverse-engineering
- windows
- debugging
- breakpoint
- message
- wndproc
- ollydbg
- gui
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:49:20+08:00'
  notes: 已对照原文与37张截图核对；原理/步骤与原文一致，仅保留调试器通用机制补充；未在本机复现调试过程
---

## 一句话结论

Windows GUI 程序由消息驱动，调试器可以在窗口过程（WndProc/ClassProc）入口下断并按消息号过滤（如按钮抬起消息 `WM_LBUTTONUP = 0x202`），命中时栈上 `[ESP+8]` 就是消息号；把该断点改成“从不暂停、只记录参数”的条件记录断点，就能无中断地记录所有窗口消息及参数，进而定位按钮点击等事件最终进入的自写处理代码，用于分析注册校验等逻辑。

## 原理

- **消息分发路径**：标准窗口的每个点击、移动、键入都由系统产生消息，最终交给窗口过程 `WndProc(hWnd, msg, wParam, lParam)` 处理。在 WndProc 入口处栈布局为 `[ESP]=返回地址`、`[ESP+4]=hWnd`、`[ESP+8]=msg`、`[ESP+C]=wParam`、`[ESP+10]=lParam`，因此用 `[ESP+8]` 就能过滤消息类型。
- **与 INT3 断点的区别**：INT3 断点可以在程序启动前设置；消息断点必须等窗口创建之后才能设置和拦截消息，因为它依赖窗口/类信息由调试器枚举出来。
- **本质仍是 CC 断点**：消息断点是在窗口过程入口写入 `0xCC`，命中后按消息号过滤；文章指出它类似于条件记录断点，可以配置条件、表达式、记录参数和暂停次数。
- **对话框与普通窗口的差异**：标准窗口消息直接进入自写 WndProc；对话框的消息先经过系统维护的对话框管理器，再由管理器传给自写窗口过程，因此从断点位置到最终校验代码之间可能还要继续跟踪几层。
- **为什么能定位处理代码**：按钮点击会产生 `WM_LBUTTONUP`（`0x202`）等消息，在分发入口按消息号断下后，回溯调用栈/单步进入自写处理函数，即可找到“点击 OK 后读取输入并比较注册码”的那段代码。

## 触发条件

- 目标为 Windows GUI 程序（标准窗口或对话框），注册/输入等交互通过按钮等标准控件完成。
- 目标窗口已经创建，调试器能枚举到其标题和窗口类（如 Button）。
- 调试器支持消息断点或条件记录断点（如 OllyDbg）。
- 分析者能接受系统 DLL 地址在每次运行/重启后变化，断点需要按当前进程重设。

## 利用步骤

1. 运行程序到目标界面（如注册对话框），保持窗口打开。
2. OllyDbg 点击“W”按钮打开窗口列表并刷新，按标题（如 Register）和类名（如 Button）定位 OK 按钮对应窗口。
3. 在该窗口上右键，选择“在 ClassProc 上设置消息断点”或“在 WndProc 上设置条件断点”，消息选择 `202_WM_LBUTTONUP`（按钮抬起）；也可以直接对 Button 类的消息下断。
4. 回到程序点击 OK 按钮，在抬起时程序被中断；检查栈上 `[ESP+8] == WM_LBUTTONUP`（即 `0x202`）确认命中。
5. 若不想每次点击都停下，把断点改为条件记录断点：条件 `[ESP+8] == 0x202`（或 `[ESP+8] == WM_LBUTTONUP`），暂停程序选择“从不”，勾选记录函数参数；在日志窗口（`Alt+L`）中查看每条消息的 `hWnd`、`Message`、`wParam`、`lParam`。
6. 在日志中定位按钮消息后，回到 WndProc 分发代码单步或在其自写处理函数上下断，分析注册码读取、比较与跳转逻辑；随后可在关键比较处改寄存器或补丁。

## PoC

无 PoC（调试器操作技巧）；关键条件表达式为 `[ESP+8] == WM_LBUTTONUP`，等价写法 `[ESP+8] == 0x202`。

## 变体与关联

- **ClassProc 条件断点**：对窗口类过程下条件断点可监视同类窗口的所有实例，比 WndProc 更通用。
- **API 断点定位法**：`GetDlgItem` 条件断点 + `GetWindowTextA` 读取输入，是从“取值 API”入手定位注册框代码；消息断点从“消息分发”入手，两者互补。
- **条件记录断点**：消息断点内部即按消息号过滤的记录型断点，同样的配置可用来记录任意函数参数/表达式值。
- **窗口枚举**：不依赖调试器 UI 时，可用 `EnumWindows`/`EnumChildWindows`/`GetClassName`/`GetWindowText` 自行枚举窗口并读取句柄。
- **消息循环分析**：也可在 `GetMessage`/`DispatchMessage` 等 API 上下断，观察消息流向，适合非标准窗口框架。

## 检测与防御

- **检测**：消息断点会在 USER32 等系统 DLL 代码段写入 `0xCC`，程序可校验系统模块代码段完整性或扫描 `0xCC`；也可检测调试器是否枚举窗口/附加进程。
- **分析者应对**：若系统 DLL 被保护或校验，改用硬件断点或对自写处理函数下断；每次调试需重新定位 USER32 地址与窗口地址。
- **防御视角**：把关键校验放在非 UI 线程或独立计算流程、点击后延迟处理，会增加消息断点定位处理代码的成本。
