---
id: code-analysis-reverse-windows-game-packet-pipeline-code-injection
title: 游戏封包链路重建与代码注入：send1→加密 call→send2 顺序判定与参数复原
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-packet-pipeline-code-injection
tags:
- reverse-engineering
- game
- windows
- packet
- code-injection
- send
- encryption
- x32dbg
- thiscall
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:33:35+08:00'
  notes: 已对照原文与61张图核对：send1→加密call→send2 顺序判定、全局 socket [0x1D6A368]、封包对象 +4/+8 取 buf/len、加密对象 ecx/[ecx+0x3C]、代码注入汇编序列与重启后地址变化提示均一致（图53-61）。未验证点：未在游戏进程重放注入；原文无版本区间；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-game-packet-pipeline-code-injection/
draft: false
kb_aliases:
- 手搓封包工具
- 代码注入发包
- send1 加密call send2
- 发包 call 组装
- 自定义封包发送
---

## 一句话结论

确认一次发包由 send1→加密 call→send2 多段组成后，逐段复原 socket、明文 buffer、长度、加密对象与调用约定，就能用代码注入在游戏进程内按相同顺序调用这些内部函数，发出任意自定义封包。

## 原理

- 游戏常把一次发包拆成多个内部函数：前置 send1（写包头/保活/日志）、加密 call（thiscall，ecx 传对象）、send2（`ws2_32!send` 包装）。它们可能都调用同一个底层 send 包装，所以 send 断点会命中多次；只凭一次断点无法判断顺序，需要在三个地址同时下断并发送一条消息，按命中先后确定顺序。文中实测为 send1→加密 call→send2。
- socket 句柄通常保存在全局对象中（示例 `[0x1D6A368]`），登录后固定；加密对象通过 this 指针（ecx）传入，对象字段和虚函数地址需要条件断点与 dump 逐层确认。
- 封包 buffer 结构：`+4` 起始指针、`+8` 结束指针，长度 = `[obj+8]-[obj+4]`；send2 的 buf 与 len 都来自该结构。
- 代码注入（远程线程、调试器代码注入器等）在目标进程地址空间执行汇编，直接 push 游戏已初始化好的 socket/对象并 call 内部函数，可以复用游戏自身的协议与加密，省去重写成本；前提是服务端只校验客户端本应能发出的内容。
- 调用约定必须匹配：`ws2_32!send` 是 stdcall（参数从右往左 push，函数自己平栈）；游戏内部 call 可能是 cdecl（调用方 `add esp,N`）或 thiscall（ecx 传 this）。

## 触发条件

- 游戏已登录，socket 有效、加密对象已初始化；
- 已定位 send1/加密 call/send2 的地址与参数来源；
- 能在目标进程注入并执行代码（调试器代码注入器、远程线程等）；
- 服务端未对包内容、序号、频率做严格校验（否则自定义包会被拒绝）。

## 利用步骤

1. 在 send1、加密 call、send2 三处同时下断，发送一条聊天消息，记录命中顺序（文中为 send1→加密 call→send2）。
2. 在 send2 追参数：socket 取全局 `[0x1D6A368]`；buf 取封包对象的 `[obj+4]`；len 取 `[obj+8]-[obj+4]`。
3. 在 send1 追它使用的 socket 与固定参数；在加密 call 追 ecx 指向的对象，dump `[ecx+0x3C]` 等字段，确认加密对象与虚函数地址。
4. 用代码注入器把最小汇编序列写入目标进程并执行。
5. 观察游戏内效果与服务端回包；若无效，检查地址是否随重启变化（改为动态取址）、对象是否为空、调用约定是否正确平栈。
6. 把要发送的字符串转成十六进制字节，替换明文 buffer 内容，再用同一链路发送，即可完成自定义封包。

## PoC

文中给出的可执行调用序列（地址随目标与重启变化，仅作结构示例）：

```asm
; send1：socket 来自全局对象
push 0
push 0x1
push 0x1326B7E
mov ebx, 0x1D6A368
mov ebx, [ebx]
push ebx
mov eax, 0x772A7630
call eax

; 加密 call：ecx = 加密对象，参数按目标函数约定
mov ecx, 0x778906F0
push 0x11650000
mov eax, 0x00DAFAF0
call eax

; send2：buf/len 来自封包对象
push 0
mov eax, [0x1D6F0DD4]
mov eax, [eax+0x4]
mov esi, eax
mov esi, [esi+0x4]
mov eax, [eax+0x14]
mov ecx, eax
mov ecx, [ecx+0x8]
mov eax, [eax+0x4]
sub ecx, eax
push ecx
push eax
push esi
mov eax, 0x772A7630
call eax
```

注意：send1 的地址在重启后会变化（示例中 ebx 恒为 0，eax 变化），实际使用应动态取址，不要硬编码。

## 变体与关联

- 单线程同步模型下可以直接 push 参数 call 业务功能 call，不必走 send1/加密/send2 三段链路。
- 加密 call 可能是虚函数，需要通过 vtable 槽位或对象字段二次取址。
- 部分游戏会对包做压缩或校验和，需要在 buffer 层同步修正。
- 关联卡片：[[code-analysis-reverse-windows-game-call-send-backtrace]]、[[code-analysis-reverse-windows-game-packet-buffer-encryption-locate]]、[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]。

## 检测与防御

- 服务端：包结构/长度/序号/时间戳/频率校验，关键操作二次校验，异常包直接丢弃。
- 客户端：代码完整性校验、反注入、反调试、函数头校验（对抗 inline hook）。
- 注意：代码注入只能复用客户端已有能力，不能突破服务端权威逻辑。
