---
id: code-analysis-reverse-windows-game-call-vtable-access
title: 游戏对象方法 call 定位：虚表访问断点与槽位分析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-call-vtable-access
tags:
- reverse-engineering
- game
- vtable
- virtual-function
- cheat-engine
- x32dbg
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:06:25+08:00'
  notes: 已对照原文与截图 17-29 核对：对象 0x416831A0 偏移 0 的 vptr=0x0123BA74、访问计数差分筛出 00A5B9BA mov eax,[ebp+0]、call [eax+0x60] 虚函数、ecx=0x416831A0 且 [ecx+0x70] 为物品数量，均与原文一致。无漏洞/CVE；槽位与地址为版本绑定示例。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-game-call-vtable-access/
draft: false
kb_aliases:
- 虚函数表找 call
- vtable 访问断点
- 虚表槽位定位
- CE 找出什么访问了该地址
---

## 一句话结论

C++ 游戏对象的方法地址存放在对象偏移 0 的虚表里；对虚表指针下“谁访问了该地址”断点，触发目标功能后筛出新增的 `call [reg+offset]` 指令，即可得到方法 call 与作为 this 的对象指针。

## 原理

含虚函数的 C++ 类会生成虚函数表（vtable），对象实例偏移 0 处存放 vptr 指向该表，表中按顺序保存各虚函数地址。功能调用通常表现为：

```asm
mov eax, [ecx]      ; eax = vptr
call dword ptr [eax + 0x60]  ; 调用虚表 +0x60 槽位
```

`ecx`/`esi` 等寄存器此时就是对象 this 指针。由于 vtable 只在调用该对象方法时被读取，对 vtable 地址设置访问断点（CE 的“找出是什么访问了该地址”），执行目标功能前后对比访问计数，只在目标功能触发时递增的指令就是相关调用点；再在指令处断下，查看寄存器即可得到对象指针与槽位偏移。参数与对象含义可通过读取对象已知偏移（如背包数量在 +0x70）验证。

## 触发条件

- 目标对象是 C++ 对象且方法通过虚表调用；
- 已定位对象基址（可通过列表/背包数据搜索得到）；
- 能反复触发目标功能，并对访问计数做差分；
- 调试器可附加，CE 可读进程内存。

## 利用步骤

1. 用 CE 定位对象基址，读取偏移 0 的 vptr；
2. 对 vptr 地址使用“找出是什么访问了该地址”，记录初始访问列表；
3. 触发一次目标功能，再刷新列表，筛出计数新增/递增的指令；
4. 分组按地址范围归类，选一条进入调试器下断；
5. 断在 `mov edx,[esi]` / `call [eax+offset]` 等指令，查看寄存器确定 vptr 与槽位偏移；
6. 验证对象：读取 `[ecx + 已知偏移]` 是否等于游戏内可见数值（如物品数量）；
7. 在 call 测试工具中以该对象为 `ecx`、按需压栈参数后调用虚表槽位。

## PoC

对象与虚表（示例）：

```text
对象基址: 0x416831A0
[0x416831A0] = 0x0123BA74   ; vptr
[vptr + 0x60] = 使用物品方法
```

触发使用的调用点（示例）：

```asm
00A5B9BA  mov eax, [ebp+0]
00A5B9BD  mov edx, [eax+0x60]   ; 虚表 +0x60
00A5B9C4  call edx              ; this 在 ecx
```

验证 this：

```text
ecx = 0x416831A0
[ecx + 0x70] = 物品数量，与背包显示一致
```

调用：

```asm
mov ecx, 0x416831A0
mov eax, [ecx]
call dword ptr [eax + 0x60]
```

（实际参数按该方法签名补 push；this 由 ecx 传递。）

## 变体与关联

- 多重继承下可能有多个 vptr，需确认是哪一个基类子对象；
- 虚表槽位偏移随版本/类布局变化，需重新定位；
- 非虚方法直接 `call 固定地址`，用堆栈回溯或访问断点定位；
- 关联：send 断点堆栈回溯（经发包功能）、窗口对象访问断点（本地 UI 功能）。

## 检测与防御

- 检测：对 vtable 区域的异常读访问、调试断点、非游戏模块调用虚表槽位；
- 防御：服务端权威逻辑、对象与操作校验、反调试、虚表加密/运行时重建、控制流完整性；
- 说明：定位到 call 只代表能复现客户端行为，服务端仍需自行校验合法性。
