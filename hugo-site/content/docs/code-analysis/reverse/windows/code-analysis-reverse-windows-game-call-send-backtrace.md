---
id: code-analysis-reverse-windows-game-call-send-backtrace
title: 网络游戏功能 call 定位：send 断点与调用栈回溯
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-call-send-backtrace
tags:
- reverse-engineering
- game
- x32dbg
- cheat-engine
- call
- send
- stack-backtrace
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:06:24+08:00'
  notes: 已对照原文与截图 1-14 核对：bp send→Ctrl+F9/F8 逐层回溯、仅目标功能断下验证唯一性、add esp,0x8 外平栈两参数、ecx=0x18 索引与 edx=0x2 固定值、call 测试工具 push 18/push 2/call 0x00CC7710 执行成功且物品数量 1455→1454，均与原文一致。无漏洞/CVE；地址为示例。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-game-call-send-backtrace/
draft: false
kb_aliases:
- 游戏找 call
- send 断点堆栈回溯
- 发包函数回溯
- x32dbg 找功能 call
---

## 一句话结论

网络游戏的功能操作最终要发包，对 `send`/`sendto`/`WSASend` 下断点，触发目标功能后沿调用栈向外回溯，并用“仅该功能能断下”验证，即可定位可直接调用的功能 call 及其参数。

## 原理

每次执行 `call` 时 CPU 把返回地址压栈，`ret` 再弹出。因此断在 `send` 时，栈上自然保留了从 `send` 到游戏主循环的完整调用链。沿着返回地址逐层向上（`Ctrl+F9` 执行到返回、`F8` 单步越过 call），每一层就是“谁调用了下一层”。

功能 call 一般不会直接调用 `send`，而是经过少数几个统一的发包封装。从 `send` 往上追到这些封装后，再继续向上找到“只在目标功能触发时执行”的那一层，就得到功能入口。判断参数时看平栈方式：`add esp, N` 是外平栈（cdecl），N/4 为参数个数；`ret N` 是内平栈（stdcall）；若函数内部使用 `ecx` 传对象，则是 thiscall。参数含义通过改变游戏内取值（物品索引、数量等）并再次断下比对确定。

## 触发条件

- 目标功能会向服务器发包（使用物品、技能、交易、移动等）；
- 客户端使用 Win32 常见发包 API：`send`、`sendto`、`WSASend`；
- 有调试器可附加（x32dbg/x64dbg）与 CE 用于辅助查看内存；
- 能反复触发目标功能以验证 call 的唯一性。

## 利用步骤

1. 附加调试器，`bp send`；触发目标功能，命中断点；
2. 在 `send` 处 `Ctrl+F9` 执行到返回，再 `F8` 单步，落到调用 `send` 的指令之后，即上一层；
3. 重复第 2 步逐层向外；也可用调用堆栈窗口辅助，但手工回溯更可靠；
4. 每追到一层就下断点，触发其他功能测试：只有目标功能能断下的才是候选；
5. 分析候选 call：看 `add esp, N` / `ret N` 判断参数数，看 `ecx` 是否作为对象；
6. 通过改变游戏内索引/数量等值再次断下，比对寄存器确认参数含义；
7. 用 call 测试工具执行候选 call，观察游戏内效果验证。

## PoC

调试命令与回溯：

```text
bp send
# 触发使用物品后断下
Ctrl+F9   ; 执行到当前函数返回
F8        ; 单步越过返回地址处的 call，进入上一层
```

候选 call 的参数分析（示例）：

```asm
; add esp, 0x8 → cdecl，两个参数
push 0x18        ; 物品在背包中的索引（24）
push 0x2         ; 固定值/数量
call 0x00CC7710
add esp, 0x8
```

call 测试工具中执行：

```asm
push 18
push 2
call 0x00CC7710
```

执行成功后回到游戏确认物品已被使用。

## 变体与关联

- `sendto`、`WSASend` 断点适用于不同网络实现；部分引擎封装了 `WS2_32` 调用，需要在封装层而非 API 层下断；
- 虚函数调用型功能用虚表定位（见同层“虚函数表访问断点”卡）；
- 不发包功能（打开窗口、自动寻路）需改用对象访问断点或参数写入断点（见同层其余卡片）；
- 内平栈 call 的清理由被调函数完成，编写 call 脚本时不要额外 `add esp`。

## 检测与防御

- 检测：调试器附加、`send` 等 API 的硬件/软件断点、异常调用序列、非游戏模块发起的 call；
- 防御：服务端权威校验（客户端只做表现，关键逻辑以服务器结果为准）、关键功能加时间/频率/状态校验、反调试与完整性校验、代码混淆与控制流平坦化；
- 注意：客户端 call 调用只能复现客户端行为，不能绕过服务端校验；防御重点应放在服务端。
