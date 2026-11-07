---
id: code-analysis-reverse-windows-game-packet-buffer-encryption-locate
title: 封包缓冲区硬件写入断点：从密文 send 回溯明文缓冲区与加密 call
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: packet-buffer-write-watchpoint
aliases:
- 封包 buffer 回溯
- 硬件写入断点定位加密 call
- 明文包定位
- memmove 回溯
- 组包缓冲区结构
tags:
- reverse-engineering
- game
- windows
- packet
- hardware-breakpoint
- memmove
- encryption
- x32dbg
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:33:31+08:00'
  notes: 已对照原文与61张图核对：对 buffer 0x68750008 下硬件写入断点、命中系统领空 memmove、Ctrl+F9/F8 跳出、edi/esi/ecx 语义、源结构 +4/+8 指针、加密前后明文变密文均与原文一致（图25-44、图57）。未验证点：0x1D 长度与 7DA909F0 源地址来自截图现场，未独立复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

当 send 断点处看到的是密文时，对封包缓冲区地址下硬件写入断点，抓 memmove/赋值 call 的写入现场并跳出系统函数，再沿源 buffer 结构回溯，就能定位明文组包位置以及“明文→密文”的加密 call。

## 原理

- 加密版本的发包链路通常为：组包（明文写入临时 buffer）→ 加密 call（原地加密或加密到新 buffer）→ 缓冲区拷贝/交换 → send。send 断点看到的 buf 往往已经是密文，只沿 send 回溯只能看到拷贝壳函数。
- CPU 调试寄存器（DR0-DR3）的硬件写入断点监视“某地址被写”这一事件，不依赖代码断点，因此能在任意线程、任意模块命中，包括 CRT 的 `memmove`/`rep movsd`。
- `memmove` 的寄存器语义在 32 位下固定：`edi`=目的地址、`esi`=源地址、`ecx`=拷贝长度。对 `edi` 下条件断点（如 `&edi==<目标buffer>`）可以只保留目标缓冲区的拷贝；`Ctrl+F9` 执行到返回、`F8` 单步越过 call，即可跳出系统领空回到游戏自己的调用者。
- 封包对象常见布局：`+4` 为缓冲区起始指针、`+8` 为结束指针（或 `+0xC` 为容量），长度 = `[obj+8]-[obj+4]`。buffer 每次重新申请导致地址变化时，先对保存指针的字段（如 `[obj+4]`）下硬件写入断点抓“地址被赋值”，再对新地址下数据写入断点。
- 明文/密文分界：在加密 call 前后分别观察同一 buffer 的字节。若 call 前是可读字符串的十六进制（如聊天内容），call 后变成高熵字节，则该 call 是加密 call。

## 触发条件

- 已定位业务 send 的 buf 地址，或保存 buf 指针的结构体字段；
- 调试器支持硬件断点（x32dbg/CE，x86 通常 4 个槽位）；
- buffer 地址在单次会话内可复现；若动态分配，需要先定位指针字段；
- 目标使用“组包→加密→拷贝→send”链路（多数网游）。

## 利用步骤

1. 在业务 send 断下，记录 `[esp+8]` 的 buf 与 `[esp+C]` 的 len；在内存窗口查看 buf，确认内容为密文。
2. 对 buf 地址下“硬件写入、4 字节”断点；触发一次聊天或技能发包，等待命中。
3. 若命中在系统领空（`memmove`/`rep movsd`），查看调用栈确认；`Ctrl+F9` 执行到返回、`F8` 单步跳出系统函数，回到游戏模块的拷贝 call。
4. 确认 `memmove` 现场的 edi/esi/ecx；对 edi 下条件断点再次触发，排除其它拷贝干扰。
5. 跳回调用者后分析源指针：若是结构体，dump `[esi+4]` 与 `[esi+8]`，用 end-start 得到长度，确认其为封包 buffer；再对源 buffer 下硬件写入断点，向上找到组包/填充函数。
6. 在疑似加密 call 前后各下断，比较同一 buffer 的字节变化；确定“明文→密文”的 call 后，dump 其 this/参数（如 `[edi+0x3C]`、`[esi+0xC]`）继续追密钥或加密对象。
7. 若 buffer 地址每次变化：先对保存指针的字段（如 `[obj+4]`）下硬件写入断点，断下时记录新地址，再对新地址下数据写入断点。

## PoC

无独立利用脚本；以下为调试命令与现场示例（地址按目标替换）：

```text
; buf = 0x68750008，源 buffer 结构体指针字段在 +4
hr 0x68750008, 4, w          ; 硬件写入断点（x32dbg：断点 -> 硬件，写入，4 字节）
; memmove 内条件断点
&edi == 0x68750008
; 跳出 memmove 后 dump 源结构
[esi+4]                      ; 起始指针
[esi+8]                      ; 结束指针
```

文中实测：在 `memmove` 处断下时目的地址为 `0x68750008`、长度为 `0x1D`、源地址为 `0x7DA909F0`；跳出后定位到游戏内的赋值 call，并观察到发送的 `111111` 在该链路中由明文变为密文。

## 变体与关联

- `rep movsd`、`memcpy`、手写循环的寄存器/栈参数语义不同，但“目的地址条件断点 + 跳出系统函数”的方法相同。
- CE 的“找出是什么改写了这个地址”等价于硬件写入断点。
- 双线程模型下，本方法同时承担从消费者线程回到生产者线程的作用。
- 关联卡片：[[code-analysis-reverse-windows-game-send-architecture-heartbeat]]、[[code-analysis-reverse-windows-game-call-send-backtrace]]、[[code-analysis-reverse-windows-game-packet-pipeline-code-injection]]。

## 检测与防御

- 检测：硬件调试寄存器被占用、调试器附加、对封包 buffer 的内存写入断点、异常线程与调用栈。
- 防御：服务端包校验与加密、客户端完整性校验、反调试；加密算法与密钥不要以可直接读取的形式放在客户端。
- 注意：定位到加密 call 不等于取得密钥，仍需继续分析对象字段与虚函数。
