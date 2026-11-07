---
id: code-analysis-reverse-windows-game-state-boolean-pointer-chain
title: 游戏布尔状态数据定位：0/1 值搜索、候选筛选与访问断点回溯指针链
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-game-state-boolean-backtrace
tags:
- windows
- reverse-engineering
- game
- cheat-engine
- x32dbg
- pointer-chain
- boolean-state
- 32bit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T02:53:06+08:00'
  notes: 已对照原文与 16 张截图核对：骑马链 [[[[[0x15282D8]+0x24]+0xA0]+0x1C]+0x4]+0x8=0x104983A8 与图 2-9 逐层一致；寻路链 [[[[[0x15282D8]+0x24]+0x90]+0x10]+0x20]+0x48 与图 11-16 及原文明确给出的表达式一致。未验证点：寻路 PoC 注释中 'mov esi,ecx ; ecx=0x341EA720' 把 sub_51D480 与 sub_DF8690 两帧压缩在一处，该处实际 ecx=0x34816958（0x341EA720 为上一帧值），中间省略了 [esi+0x20] 的取值与第二次 mov esi,ecx，属注释表述不严谨，不影响链本身正确性。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-game-state-boolean-pointer-chain/
draft: false
kb_aliases:
- 游戏状态类数据查找
- 骑马状态定位
- 寻路状态定位
- CE 0/1 搜索
- 状态值回溯基址偏移
- 布尔状态指针链
- x32dbg 状态数据回溯
---

## 一句话结论

游戏里的“骑马中/寻路中”等状态只有 0/1 两种取值，先在 Cheat Engine 中反复切换状态并搜索 0/1 收敛候选，再按动画/行为时序筛掉“提前变化”的伪地址；对候选地址下访问/写入断点，沿“当前帧寄存器来源 → 上一层调用帧”逐层回溯，直到到达模块静态基址，即可得到“基址 + 多级偏移”的状态指针链。

## 原理

- 状态类数据没有血量、坐标那样连续变化的数值，通常只有“是/否”两态，用 0/1 表示最自然。因此 CE 的搜索策略是：初始搜索 0，触发状态后搜索 1，再取消状态搜索 0，反复收敛。
- 收敛后仍可能有多个候选，因为它们都在状态切换时变化。必须用行为时序区分：例如骑马状态在“点击骑马”时和“人物真正骑上马”时变化的数据不是同一个；要找的是与角色最终状态同步的那一个，而不是 UI 按钮或请求标志。
- 对候选地址下访问/写断点时，断点可能只在“取消状态”时命中而不在“进入状态”时命中（上下马走不同代码路径）。这并不代表追错，应继续在命中的指令上分析。
- 回溯方法：断点指令形如 `add dword ptr ds:[ebx+8], -1` 或 `mov dword ptr ds:[esi+48], ebx`，先确定目标数据的基址寄存器（`ebx`/`esi`），再在当前帧找该寄存器的来源（常见 `mov esi, ecx`），返回上一层继续找 `ecx` 的来源，重复“寄存器 ← 寄存器/内存”直到某个值为模块静态基址（如 `0x15282D8`）。
- 每一级 `[reg+offset]` 或 `lea reg,[reg+offset]` 都贡献一个偏移；把从静态基址到状态地址的所有层拼起来，就是可复用的指针链。链中的中间层通常是玩家对象、角色对象、移动组件、寻路组件等结构。
- 为什么优先追目的操作数的基址而不是值来源：状态写入函数常写成“状态不满足才赋值”，值来源（如常量 1 或布尔临时变量）没有结构意义；真正有意义的是“状态被写到哪个对象”，因此跟 `[esi+48]` 的 `esi` 才能到达持有状态的对象。

## 触发条件

- 目标为 32 位 Windows 游戏/应用，状态数据以整数/布尔形式存放在用户态对象中。
- 能使用 Cheat Engine 附加进程并反复扫描内存；能使用 x32dbg（或同类调试器）下访问/硬件断点。
- 目标未启用阻止附加/断点的强反调试，或已绕过。
- 能在游戏内稳定地进入/退出目标状态（上马/下马、开始/停止寻路），以便制造值变化。

## 利用步骤

1. **建立状态基线**：在未进入状态时用 CE 搜索精确数值 0（4 字节或按实际类型），进入状态后搜索 1，退出后搜索 0，反复直到候选数量可接受。
2. **按行为筛选候选**：对照动画/角色动作的时序，排除“点击瞬间就变化”的按钮/请求标志，保留“角色真正进入状态才变化”的数据；也可通过打开其他面板、切换地图等操作观察哪些地址随之变化，进一步排除。
3. **下断点**：对候选地址下访问或写入断点（硬件断点优先），在游戏内切换状态触发；注意可能只有退出状态时才断下。
4. **定位写入指令**：记录命中指令与寄存器，例如 `add dword ptr ds:[ebx+8], -1`（状态地址 = `ebx+8`）或 `mov dword ptr ds:[esi+48], ebx`（状态地址 = `esi+48`）。
5. **逐层回溯**：先找目的操作数基址寄存器的来源；若当前帧是 `mov esi, ecx`，回到调用者找 `ecx` 的赋值；遇到 `lea ecx,[esi+4]`、`lea ecx,[ebx+1C]`、`mov eax,[eax+A0]` 等，记录偏移并继续向上。
6. **到达静态基址**：当某一级寄存器的值来自固定模块地址（如 `[0x15282D8]`）或不再随对象变化时停止；把沿途偏移按顺序拼接。
7. **验证链**：重启游戏或切换角色后，按“基址 + 偏移链”重新读取状态地址，确认读写该地址能反映/改变状态；再用 CE 指针扫描或重新下断交叉验证。

## PoC

以下地址/偏移仅对原文所测版本有效，换版本/换进程必须重新回溯。

骑马状态（逐层回溯得到的链）：

```text
[[[[[0x15282D8]+0x24]+0xA0]+0x1C]+0x4]+0x8  -> 0x104983A8（状态值）
```

关键回溯片段：

```asm
; 状态写入（ebx = 0x104983A0）
add dword ptr ds:[ebx+8], 0FFFFFFFF     ; 状态地址 = ebx+8 = 0x104983A8
; 上一层：ecx = 0x104983A0
lea ecx, dword ptr ds:[esi+4]           ; esi = 0x1049839C
; 上一层：ebx = 0x10498380
lea ecx, dword ptr ds:[ebx+1C]          ; -> 0x1049839C
; 上一层：eax = 0x115CA0D0
mov eax, dword ptr ds:[eax+A0]          ; -> 0x10498380
; 静态基址层：返回 [0x15282D8]+0x24
mov eax, dword ptr ds:[15282D8]
mov eax, dword ptr ds:[eax+24]          ; -> 0x115CA0D0
```

寻路状态（原文明确给出的链）：

```text
[[[[[0x15282D8]+0x24]+0x90]+0x10]+0x20]+0x48  -> 状态值
```

关键回溯片段：

```asm
; 状态写入（esi = 0x34816958）
mov dword ptr ds:[esi+48], ebx          ; 状态地址 = esi+48
; 上一层：esi 来自 ecx
mov esi, ecx                            ; ecx = 0x341EA720
; 上一层：ecx = [esi+0x20]
mov ecx, dword ptr ds:[esi+20]
; 上一层：ecx = [eax+0x10]，eax = 0x20BBD1E0
mov ecx, dword ptr ds:[eax+10]
; 静态基址层：返回 [[0x15282D8]+0x24]+0x90
mov eax, dword ptr ds:[15282D8]
mov eax, dword ptr ds:[eax+24]
mov eax, dword ptr ds:[eax+90]          ; -> 0x20BBD1E0
```

CE 侧操作序列：

```text
未骑马 -> 搜索 0
骑上马 -> 搜索 1
下马   -> 搜索 0
重复收敛；再按“角色真正骑上/开始寻路才变化”筛选
```

## 变体与关联

- 变体：多态状态（站立/行走/奔跑/游泳）可按枚举值逐档搜索，或对同一地址观察不同状态下的取值。
- 变体：64 位游戏寄存器/调用约定不同（`rcx/rdx/r8/r9`），指针宽度 8 字节，但“值搜索 + 断点 + 逐层回溯”方法不变。
- 变体：链路过长时先用 CE Pointer Scan 批量生成 `base+offset` 候选，再用 x32dbg 对每一级下断验证。
- 关联：[[code-analysis-reverse-windows-game-control-pointer-chain]]（同样用 CE 值扫描 + 写断点 + 寄存器回溯定位对象指针链，对象为 UI 控件）。
- 关联：[[code-analysis-reverse-windows-game-call-coordinate-write]]（坐标/寻路 call 定位，可与本卡的寻路状态链互相印证）。
- 关联：[[code-analysis-reverse-windows-game-call-vtable-access]]、[[code-analysis-reverse-windows-game-call-window-object-access]]（同一套游戏逆向 call 定位方法）。
- 边界：地址与偏移随游戏版本、编译选项、ASLR 变化；若状态被加密、拆分存储或由服务端权威判定，客户端内存链可能只反映表现层。

## 检测与防御

- 从游戏安全/反作弊视角：
  - 检测 Cheat Engine、x32dbg 的进程/窗口/驱动特征，以及 `OpenProcess`、`ReadProcessMemory`、`WriteProcessMemory`、调试寄存器 `DR0-DR7`、`int3` 断点。
  - 对关键状态做服务端权威校验（位置、移动、寻路结果），不要仅依赖客户端内存状态；客户端状态只作为表现。
  - 对状态字段做指针加密、校验和或完整性校验，增加直接改写的门槛；监控异常的状态切换频率与非 UI 线程调用。
- 从逆向工程视角：每次回溯都用条件断点验证数据值，记录模块基址与版本；不要因为断点只在单向切换时命中就判定追错。
