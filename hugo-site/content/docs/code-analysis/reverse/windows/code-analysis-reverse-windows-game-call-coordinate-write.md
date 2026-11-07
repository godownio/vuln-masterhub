---
id: code-analysis-reverse-windows-game-call-coordinate-write
title: 自动寻路 call 定位：目标坐标写入断点与参数回溯
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-call-coordinate-write
tags:
- reverse-engineering
- game
- auto-path
- coordinates
- cheat-engine
- x32dbg
- write-breakpoint
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:06:29+08:00'
  notes: 已对照原文与截图 36-44 核对：人物/NPC 坐标在对象 +0x3C、CE 浮点搜索得目标坐标 0x01953FFC、写入断点回溯到 10 参数寻路 call 0x007386D0、第 5 参数目标坐标/第 6 参数 0x43 地图 ID 推测、玩家对象链 [[[[0x15282D8]+0x24]+0x8C]+0x274]，均与原文一致。无漏洞/CVE；地址为版本绑定示例。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-game-call-coordinate-write/
draft: false
kb_aliases:
- 寻路 call 查找
- 坐标写入断点
- 游戏坐标定位
- 自动寻路 call
---

## 一句话结论

自动寻路必然把目标坐标传给某个函数；先在 CE 中按坐标数值定位目标坐标存储地址，再对该地址下写入断点，触发寻路后回溯调用栈，即可找到含目标坐标、地图 ID、玩家对象等参数的寻路 call。

## 原理

游戏内坐标通常是连续的 32 位浮点数，目标坐标在点击寻路时被写入。不同 NPC/地点对应不同坐标，反复对目标位置寻路并在 CE 中搜索该浮点值，可以定位到唯一的目标坐标缓冲区/对象；对该地址下硬件写入断点，触发寻路后断下，断点指令就在写入目标坐标的代码路径上，沿返回地址回溯即可到达寻路函数。

寻路函数参数较多且多为对象指针：目标坐标、起始坐标（常来自玩家对象内部的坐标链）、地图 ID、标志位等。通过改变目的地（同地图内不变、跨地图变化的参数即地图 ID）和追踪参数来源（对象指针链）可逐个确认。

## 触发条件

- 游戏提供自动寻路/点击寻路功能，且客户端计算路径（并非完全由服务器下发）；
- 坐标以浮点数连续存放，可通过 CE 搜索定位；
- 能向不同 NPC/地点反复发起寻路以缩小地址；
- 调试器支持硬件写入断点。

## 利用步骤

1. 选中一个 NPC，记录其坐标（如 x=55），发起自动寻路；
2. CE 搜索该浮点值，到达后再换另一个 NPC/坐标重复搜索，逐步收敛；
3. 得到唯一的目标坐标地址（示例 `0x01953FFC`）；
4. 对该地址下写入断点，再次寻路，断下；
5. 记录调用栈，向外交替 `Ctrl+F9`/`F8` 回溯若干层；
6. 选择只由寻路触发的帧，分析参数：目标坐标、地图 ID、玩家对象指针链；
7. 追踪对象参数来源（如 `[[[[0x15282D8]+0x24]+0x8C]+0x274]`）；
8. 编写 call 脚本，按 cdecl 压入全部参数并平栈测试。

## PoC

目标坐标定位后写入断点断下，回溯到寻路 call（示例 `0x007386D0`，10 个参数）：

```asm
pushfd
pushad
push 0x0
push 0x1
mov ecx, [0x15282D8]      ; 玩家对象链
mov ecx, [ecx+0x24]
mov ecx, [ecx+0x8C]
mov ecx, [ecx+0x274]      ; 起始坐标/玩家对象
push ecx
push 0x0
push 0x001AE9C4           ; 目标坐标地址（示例）
push 0x00000043           ; 地图 ID（示例）
push 0x0
push 0x0
push 0x0
push 0x0
call 0x007386D0
popad
popfd
```

参数含义按实测：第 5 个参数为目标坐标，第 6 个参数在同地图内不变、跨地图变化，推断为地图 ID；第 3 个参数来自玩家对象链，用于获取起始坐标。

## 变体与关联

- 点击寻路与 NPC 寻路可能调用同一底层 call 但入口不同；在某个入口下断不一定被另一入口命中，应对目标入口单独下写入断点回溯；
- 地图切换后地图 ID 与坐标对象会变化，需重新确认；
- 坐标也可能以整数（放大倍数）存储，搜索时需按实际类型尝试；
- 关联：窗口对象访问断点（本地 UI 功能）、send 断点回溯（发包功能）。

## 检测与防御

- 检测：对坐标内存的硬件写入断点、异常寻路频率/路径、非 UI 线程调用寻路函数；
- 防御：服务端校验移动路径与位置合法性（速度、碰撞、可达性）、关键寻路结果由服务器计算、反调试与内存校验；
- 说明：找到并调用客户端寻路只改变本地表现，服务端仍需校验最终位置。
