---
id: code-analysis-reverse-windows-game-call-window-object-access
title: 本地 UI 功能 call 定位：窗口对象坐标搜索与访问断点
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-call-window-object-access
tags:
- reverse-engineering
- game
- ui
- window-object
- cheat-engine
- x32dbg
- local-call
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:06:27+08:00'
  notes: 已对照原文与截图 30-35 核对：不发包判定、窗口坐标 CE 搜索得窗口对象 0x61637F40、对对象下访问断点、回溯到 push 0x61637F40/push 0x0/call 0x00AA5590/add esp,0x8 以及 [模块基址+15561F0]+0x2C8 来源，均与原文一致。无漏洞/CVE；地址为版本绑定示例。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-game-call-window-object-access/
draft: false
kb_aliases:
- NPC 服务 call
- 窗口对象访问断点
- 不发包功能 call
- 游戏 UI call 定位
---

## 一句话结论

对不发包的本地 UI 功能，先用窗口坐标在 CE 中定位窗口对象，再对对象下访问断点，触发菜单功能后回溯调用栈，即可找到“窗口对象 + 功能索引”参数的 call。

## 原理

游戏中的右键菜单、NPC 服务窗口等操作只在客户端完成，不经过 `send`，因此不能用发包回溯。但功能执行必然访问窗口对象（读取控件、索引、状态）。窗口对象在内存中包含坐标（浮点数，通常越往右下越大）、标题字符串、控件列表等。先用 CE 对坐标做变动搜索定位对象，再对对象基址或特征字段设置“谁访问了该地址”断点，触发目标菜单项，断下的指令就位于处理该功能的调用链上。沿栈返回地址逐层回溯，找到只由该功能触发的 call，并分析其参数（常见为窗口对象指针 + 功能/服务索引）。

## 触发条件

- 目标功能是纯客户端 UI 操作，不发包（或发包路径不确定）；
- 窗口/控件对象可通过坐标、标题或可见数值在内存中定位；
- 能反复打开菜单并点击目标项；
- 调试器可附加，CE 可做访问断点与未知值搜索。

## 利用步骤

1. 打开目标窗口，用 CE 以未知初始值扫描，移动窗口后“再次扫描”变化值，逐步缩小到窗口坐标字段；
2. 将窗口拖到屏幕最左/最上，利用坐标为 0 或较小值筛出唯一地址，得到窗口对象；
3. 对窗口对象地址执行“找出是什么访问了该地址”，记录基线；
4. 点击目标菜单项，刷新访问列表，筛出新增指令；
5. 在新增指令处断下，记录调用栈，从外向内逐层回溯；
6. 逐层下断并点击其他功能，选出只由目标功能触发的 call；
7. 分析参数：`add esp, N` 判断参数数；示例为窗口对象指针 + 索引；
8. 编写 call 脚本并补平栈，测试功能是否执行。

## PoC

定位到窗口对象后，典型访问指令：

```asm
00E8E210  mov edx, [ecx+0x9C]   ; 访问窗口对象字段
00E93EDC  mov ebx, [esi+0x9C]
```

回溯到功能 call（示例）：

```asm
; esi = 服务索引, eax = 窗口对象
00AA98B1  mov eax, [esp+0x8]
...
00AE7572  mov ecx, [esi+0x2C8]
00AE7579  push ecx          ; 窗口对象 0x61637F40
```

call 测试：

```asm
push 0x61637F40   ; 窗口对象
push 0x0          ; 功能/服务索引
call 0x00AA5590
add esp, 0x8      ; cdecl 平栈，缺少会导致游戏崩溃
```

## 变体与关联

- 也以标题字符串定位窗口，但同名字符串多，坐标法更稳；
- 控件对象与窗口对象可能分层，访问断点应下在实际被点击逻辑读取的对象上；
- 若菜单项触发发包，可改走 send 回溯；
- 关联：虚表访问断点（对象方法）、自动寻路坐标写入断点（参数特征定位）。

## 检测与防御

- 检测：对 UI 对象内存的异常访问断点、调试器附加、非游戏模块调用 UI 处理函数；
- 防御：服务端权威校验、关键操作二次确认、反调试与内存完整性检查、UI 逻辑与敏感操作解耦（敏感操作仍走服务端）。
