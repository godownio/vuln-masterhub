---
id: binary-pwn-format-string-single-shot-dual-write-hhn-low-byte-trampoline
title: 一次格式化字符串机会完成两处写入：顺序参数 %hn 建跳板指针后混用 N$ 定位 %hhn，配合 %hhn 只写总字节数尾字节技巧改返回地址为后门
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-order-write-npos-hhn-trampoline-dual-write-single-shot
aliases:
- 非栈上 fmt 双写
- '%hhn 尾字节技巧'
- 顺序写入与 N$ 分离计数
- 一次 fmt 改两处
tags:
- binary
- pwn
- format-string
- fmt
- hhn
- trampoline
- one-shot
- ctf
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T18:02:31+08:00'
  notes: 已对照原文与图核对：img05错误思路(%15$hn/%45$hhn分开写失败)、img06正确payload(%p*13+顺序%hn+%45$hhn)、img08返回地址改为后门成功、img10强网题getshell均佐证；与循环版卡(劫持printf返回地址造多次fmt循环)机制不同，单次调用双写差异成立；第二题强网拟态链与既有循环版卡同一链未重复成卡正确
---

## 一句话结论

只有一次 printf(buf) 且 buf 在非栈上（bss）时，可用一条 payload 同时完成「在栈上写跳板指针 + 借跳板改第二处」：`b'%p'*13 + b'%'+str((stack&0xffff)-138)+b'c%hn' + b'%'+str(0x10008-(stack&0xffff))+b'c%45$hhn'`——前面的 `%p*13` 顺序排参数使后续不带 `$` 的 `%hn` 按顺序落在第 15 个参数写入跳板，再用 `%45$hhn` 在跳板指向的地址上改尾字节；`%hhn` 只把输出总字节数的最后一个字节写入，因此用远大于实际输出量的 0x10008 计数即可把目标字节改成 0x08（原文验证返回地址跳到与 main 仅差一字节的后门 execve("/bin/sh")）。

## 原理

- `%hhn` 语义：把 printf 到目前为止输出的**总字节数**的低 8 位写入对应指针处。只要后面注入的字节数远大于前面的累计（如 0x10008 > 全部已输出），总字节数尾字节即被控制为目标值——例：0x10000000c/0x1000000c/0x10000c 最终都写 0x0c。
- 顺序写入与 `N$` 定位分离计数：不带 `$` 的 `%hn` 按参数顺序取值（`%p*13` 占了 13 个 + `%xxxc` 占 2 个 = 第 15 个参数），带 `$` 的 `%45$hhn` 则直接取第 45 个参数为指针；两者结合可在一次调用里先按顺序往栈上目标（如返回地址低 16 位）写值，再经栈上已布置的指针链（a->b->ret）改第二处。
- 非栈上 fmt：buf 位于 bss，栈上没有指向它的指针，因此必须先在栈上写出一个指向目标地址的跳板指针，再让 `%N$hhn` 以该指针为落脚点写值。
- 字节数校准：`%p*13` 泄露的字符总量计入输出字节数，需按泄露字符串实际长度（recvall 计 len 再减 1 个换行）扣除，否则写偏。

## 触发条件

- 存在格式化字符串漏洞（printf(用户输入)），机会有限（一次）。
- buf 不在栈上或无现成指针，需自建跳板。
- 目标返回地址与后门地址仅差低字节（或可一次尾字节写覆盖）。
- 程序泄露了一个栈地址（printf("gift: %p\n", &v1)）用于定位。

## 利用步骤

1. 接收 gift 栈地址，计算返回地址位置（stack+0x18 等）。
2. 构造 `%p*13` 先泄露并占满参数槽，再 `%<x>c%hn`（按顺序写第 15 参数=跳板指针）+ `%<y>c%45$hhn`（沿跳板改第二处）。
3. 用 `recvall()` 的 len-1 统计 `%p*13` 实际输出字节数（含尾部 \n 需减 1），从 `%c` 计数中扣除。
4. 第二段计数取 0x10008-(stack&0xffff)，利用 %hhn 尾字节语义把返回地址尾字节改为与后门一致。
5. 发送 payload，程序返回时落到后门 execve("/bin/sh") getshell。

## PoC

```python
payload=b'%p'*13+b'%'+str((stack&0xffff)-138).encode()+b'c%hn'+b'%'+str(0x10008-(stack&0xffff)).encode()+b'c%45$hhn'
s(payload)
```

## 变体与关联

- 若第一次写不生效（两处都被 `$` 定位干扰），把跳板写改成纯顺序参数 `%hn`（不带 `$`）是关键修正——顺序写入与 `$` 定位写入计数分离。
- 多次 fmt 的版本见「劫持 printf 返回地址多次利用」卡（同一文章姊妹题）。

## 检测与防御

- 永远不把用户输入作为格式串：printf("%s", buf)。
- 编译期 FORTIFY_SOURCE 将 %n 与非常量格式串告警/阻断；启用 RELRO/PIE 增加利用成本。
