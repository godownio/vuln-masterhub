---
id: code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate
title: Delphi 注册对话框输入定位：DialogBoxParamW 回调 + GetDlgItem 条件断点 + GetWindowTextA
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: delphi-dialogboxparam-callback-getdlgitem-conditional-breakpoint-getwindowtexta
aliases:
- Delphi 注册框定位
- DialogBoxParamW 断点
- DialogFunc 回调
- GetDlgItem 条件断点
- GetWindowTextA 读取注册码
- 全局内存搜索特征字符串
- Resource Hacker 对话框 ID
- WinHex 注册对话框
tags:
- reverse
- windows
- delphi
- debugging
- x64dbg
- dialog
- breakpoint
- license
- gui
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

对 Delphi 桌面程序的注册/密码对话框，先对 `DialogBoxParamW`（或 `A`/`CreateDialogParamW`）下断，取第 4 个参数得到对话框消息回调 `DialogFunc`；再用 Resource Hacker 按第 2 个参数的对话框模板 ID 查 EDIT 控件 ID；随后在 `GetDlgItem` 上以 `[esp+8] == <控件ID>` 条件断点过滤干扰，命中后执行到返回并跟进 `GetWindowTextA`，即可定位程序读取输入字符串的代码与后续校验函数。不要在 `GetWindowTextW` 上盲断——对话框显示时会持续调用它，造成大量噪声。

## 原理

- **Delphi 对话框创建**：Delphi 的 `TForm`/对话框最终调用 Windows 的 `DialogBoxParamW/A` 或 `CreateDialogParamW/A`。`DialogBoxParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)` 的第 2 个参数通常是对话框模板 ID（本文为 0x2C=44），第 4 个参数是消息处理回调 `DialogFunc`。
- **输入读取路径**：程序读取 EDIT 控件内容通常先 `GetDlgItem(hDlg, nIDDlgItem)` 拿控件句柄，再 `GetWindowTextA/W` 或发送 `WM_GETTEXT`；也可能响应 `WM_COMMAND` 下的 `EN_CHANGE`。无论哪种，`GetDlgItem` 都是必经点，因此在它上面下条件断点比在 `GetWindowText*` 上盲断更有效。
- **控件 ID 来源**：运行时界面可能与资源模板差异很大（程序会动态调整/多语言加载控件文本），但控件 ID 一般保持资源里的定义。用 Resource Hacker 打开对话框 ID（0x2C），读取 `CONTROL` 行的 ID：本文有 EDIT 778(0x30A)、779(0x30B)、102(0x66)，按钮 100/1 等；运行时只显示一个 EDIT，但资源里有三个，因此需要同时监控多个候选 ID。
- **条件断点过滤**：x86 stdcall 下 `GetDlgItem` 参数位于栈上；在 `GetDlgItem` 断点条件中写 `[esp+8] == 0x30A || [esp+8] == 0x30B || [esp+8] == 0x66`，只有目标控件 ID 命中才中断。本文在点击“确定”后命中 `[esp+8] == 0x30A`，返回后即为 `GetWindowTextA(hWnd, buf, 0x7FF)`。
- **为什么要点击“确定”**：注册对话框可能在显示时就调用 `GetWindowTextW` 读取/刷新控件，若只在 `GetWindowTextW` 下断会被淹没；而 `GetWindowTextA` 只在用户点击确定、程序真正取 license 时被调用。配合全局内存搜索特征字符串与硬件访问断点，可快速判断字符串是否被读入以及后续处理位置。
- **排除其他路径**：若 `EN_CHANGE` 路径在每次输入后触发但全局内存搜索不到特征串、硬件断点不命中，说明字符串只在点确定时由 `GetWindowTextA` 读取；`WM_GETTEXT` 方案同样需要先 `GetDlgItem`，因此条件断点仍是入口。
- **适用范围**：只要是 Win32/Delphi 对话框程序的输入框，且资源未被完全动态创建/混淆，这一套“对话框 ID → 控件 ID → `GetDlgItem` 条件断点 → `GetWindowTextA`”流程都可复用。

## 触发条件

- 目标为 Windows Delphi/Win32 程序，注册/密码输入通过标准对话框控件（EDIT）完成。
- 能获取程序资源（未加壳或已脱壳），可用 Resource Hacker 查看对话框模板；运行时控件 ID 与资源定义一致或可推断。
- 能在 x64dbg 中对 API 下断并设置条件断点；程序未对 `GetDlgItem`/`GetWindowTextA` 做强力反调试/钩子。
- 需要用户交互（点击确定/提交）才能触发真正的输入读取；纯静态分析或只跟踪消息循环不够。

## 利用步骤

1. 用 `peinfo`/Detect It Easy 确认 Delphi、32/64 位、是否加壳。
2. 在 x64dbg 对 `DialogBoxParamW`（及 A 版本）下断，打开注册对话框；命中后记录第 2 个参数（对话框模板 ID，如 0x2C）与第 4 个参数（`DialogFunc` 回调地址）。
3. 用 Resource Hacker 按模板 ID 查看对话框资源，列出所有 EDIT 控件的 ID（如 0x30A、0x30B、0x66）和按钮 ID（确定通常为 1）。
4. 在 `GetDlgItem` 下断，条件设为 `[esp+8] == 0x30A || [esp+8] == 0x30B || [esp+8] == 0x66`（按位数/调用约定调整栈偏移），输入特征字符串并点击“确定”。
5. 命中后执行到 `GetDlgItem` 返回，观察后续 `GetWindowTextA(hWnd, buf, 0x7FF)` 调用与缓冲区地址；确认读入的正是输入字符串。
6. 对缓冲区下硬件访问断点，或在返回后单步/回溯，定位调用 `GetWindowTextA` 的函数及其上级校验函数（本文为 `sub_5C943C`）。
7. 若怀疑 `EN_CHANGE`/`WM_GETTEXT` 路径，先在输入后做全局内存搜索 + 硬件访问断点验证；若字符串只在点确定时出现，则回到第 4 步的 `GetWindowTextA` 路径。
8. 进入校验函数后继续分析 license 解析、CRC32、日期等逻辑（可衔接 Keygen 卡）。

## PoC

x64dbg 操作要点（地址以实际程序为准）：

```text
# 1) 拦截对话框创建
bp DialogBoxParamW
# 打开“注册”菜单，命中后记录：
#   第2参数 lpTemplateName = 0x2C（对话框ID）
#   第4参数 lpDialogFunc = 0x4DC468（DialogFunc）

# 2) GetDlgItem 条件断点：只关心三个 EDIT 控件
bp GetDlgItem
# 右键断点 -> 编辑 -> 条件：
[esp+8] == 0x30A || [esp+8] == 0x30B || [esp+8] == 0x66

# 3) 在注册框输入特征串，点击“确定”；命中 0x30A 后执行到返回
# 反汇编显示：
#   push 7FFh          ; nMaxCount
#   lea eax, [esp+0D44h+var_82C]
#   push eax           ; lpString
#   push 30Ah          ; nIDDlgItem
#   mov eax, [ebx]
#   push eax           ; hDlg
#   call GetDlgItem
#   push eax           ; hWnd
#   call GetWindowTextA

# 4) 返回后对 var_82C 下硬件访问断点，回溯校验函数
```

辅助判断：

```text
- 全局内存搜索输入的特征字符串，确认是否被读入。
- 对字符串内存下硬件访问断点；若从不命中，说明后续没有直接处理（可能只在回调内处理）。
- 只在 GetWindowTextW 下断会被对话框刷新干扰；优先 GetWindowTextA 或 GetDlgItem 条件断点。
```

## 变体与关联

- 对话框 API 变体：`DialogBoxParamA`、`CreateDialogParamW/A`；Delphi 也可能用 `CreateWindowEx` 自绘对话框，此时需回到窗口过程 `WM_COMMAND`/`EN_CHANGE` 分支。
- 读取方式变体：`SendMessage(WM_GETTEXT)`、`GetWindowTextW`、`GetDlgItemText`、`GetDlgItemInt`；共同前置仍是 `GetDlgItem`，可先在此下条件断点。
- 反调试变体：若 API 被 IAT 钩子/内联 hook，先恢复原始 API 或直接在调用点下断；若控件 ID 运行时动态创建，可在 `CreateWindowExW` 的 `hMenu`/控件 ID 参数上下断。
- 关联：[`code-analysis-reverse-windows-winhex-license-crc32-keygen`](code-analysis-reverse-windows-winhex-license-crc32-keygen.md)（本文后续 license 校验与 Keygen）、[`code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint`](code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint.md)（Qt 程序的注册码输入定位）、[`code-analysis-dynamic-debugging-crackme-password-check-patch`](code-analysis-dynamic-debugging-crackme-password-check-patch.md)（定位后改寄存器/ZF 绕过校验）。

## 检测与防御

- 软件保护方：不要依赖“控件 ID 不可见”作为保护；关键校验可放在自定义控件/加密输入控件中，减少标准 `GetWindowText` 可观测性。
- 反调试/反注入：检测 `GetDlgItem`/`GetWindowText*` 上的断点与 API 钩子，启用完整性校验；对调试器附加做检测。
- 输入处理：把 license 校验放到服务端或使用非对称签名，避免本地明文比对；对输入做完整性/防篡改校验。
- 防御方视角：监测进程对 `DialogBoxParam*`、`GetDlgItem`、`GetWindowTextA` 的异常断点/钩子行为，可作为调试器检测信号之一。
