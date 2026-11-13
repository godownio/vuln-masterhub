---
id: binary-pwn-format-string-full-protect-hhn-reenter-rop-staging
title: 全保护格式化字符串：泄漏 PIE/libc/栈后用 %hhn 改返回地址重入 run，分轮在栈上布置 ROP 链
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-hhn-return-reenter-rop-staging
aliases:
- 2023HWS fmt
- 格式化字符串重入
- '%hhn 改返回地址'
- call run 重入
- 分轮布置 ROP
tags:
- pwn
- format-string
- pie
- full-relro
- hhn
- rop
- one-gadget
- stack-pivot
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V693
  verified_at: '2026-11-13T17:47:01+08:00'
  notes: 已对照原文核对（42 图全读）：全保护 checksec、run 两轮 read(0,s,80)+printf(s)、%19$p/%9$p/%14$p 泄漏 PIE/libc/rbp 与 exp 一致；图42 显示最终 whoami 拿 shell。原文贴出的 exp 片段只到 one_gadget 三字节写入，未含 run 返回地址重入 call run 与最后 leave 低字节改写轮次（按原文叙述核对，未本地复现）；one_gadget 约束由填充满足属作者补充说明，未验证。
---

## 一句话结论

在 PIE+Canary+NX+Full RELRO 全开、只有两轮 `read(0,s,80); printf(s)` 的格式化字符串场景中，第一轮用 `%19$p,%9$p,%14$p` 同时泄漏 PIE、libc 与栈地址；之后每轮用 `%hhn` 把 run 函数返回地址的低字节改成 main 中 `call run` 的地址，实现"返回即再次进入 run"的循环，从而在返回地址下方分轮写入 one_gadget 地址三字节；最后把返回地址低字节改为同页的 `leave` gadget，利用栈迁移跳入已布置好的 one_gadget 链 getshell。

## 原理

- 全保护下没有 GOT/固定地址可写，但栈上返回地址仍可写；PIE 只随机化高位，返回地址与同模块 `call run` 指令低字节偏移固定，`%hhn` 只改低 1 字节即可把返回地址重定向到 `call run`，实现函数级循环。
- 泄漏：`%19$p` 为 PIE 内地址（减 main 偏移得 pie 基址），`%9$p` 为 libc 内地址（减 `_IO_file_setbuf+13` 得 libc 基址），`%14$p` 为 rbp，`ret=rbp+8`；由此得到返回地址槽与 `__libc_start_main` 返回地址槽。
- 分轮写：每次 `printf` 前把目标地址（ret 下方槽位置）作为 `%11$hhn/%12$hhn/%13$hhn` 的参数槽（配合输入长度 80 字节可容纳多个 p64 地址），逐字节写入 one_gadget 的三个字节（libc 基址 + 0xe3b01 等）。
- 循环控制：本轮把 run 的返回地址低字节改为 `call run`，run 返回后再次执行 run，保留已经写入的 ROP 数据；最后一轮把返回地址低字节改为同页 `leave`（pie+0x1301 的低字节），`leave; ret` 把 rsp 迁到布置好的 one_gadget 链执行。
- 为什么可行：格式化字符串的任意写 + 返回地址重入把"一次性输入"扩展成多轮写原语；one_gadget 只需三字节写入即可完成 libc 内跳转，约束（如 rsp+0x30==NULL）由布置的填充满足。

## 触发条件

- 全保护 64 位程序（PIE/Canary/NX/Full RELRO），存在 `printf(用户输入)` 且每轮输入长度足够（本例 80 字节）承载多个目标地址；
- 能稳定泄漏 PIE、libc、栈地址（格式串偏移固定）；
- 有可用的 one_gadget 与同页 `leave`/`ret` gadget；run 可被重复调用且不会破坏已布置数据。

## 利用步骤

1. 第一轮发送 `%19$p,%9$p,%14$p`，解析得到 pie、libc、rbp；计算 ret=rbp+8、pie 基址、libc 基址、one_gadget 与 leave 地址。
2. 计算 one_gadget 三字节 ogg1/ogg2/ogg3 与 `call run` 低字节；把 `__libc_start_main` 返回地址槽（ret+0x10）等目标地址按 8 字节放在每轮输入尾部，供 `%11$hhn/%12$hhn/%13$hhn` 使用。
3. 循环多轮：每轮 payload=`%<ogg1>c%11$hhn` + `%<ogg2-ogg1>c%12$hhn` + `%<ogg3-ogg2>c%13$hhnaaaaaaa` + p64(目标地址×3)，把 one_gadget 三字节写入栈上链位置；同时保持 run 返回地址指向 `call run` 以再次进入。
4. 最后一轮把 run 返回地址低字节改为 leave gadget；run 返回时 `leave; ret` 迁移到 one_gadget 链执行。
5. 交互验证 shell。

## PoC

```python
payload='%19$p,%9$p,%14$p'
sl(payload); ru(b'0x'); pie=int(p.recv(12),16)-elf.sym['main']-28
ru(b'0x'); libcbase=int(p.recv(12),16)-libc.sym['_IO_file_setbuf']-13
ru(b'0x'); rbp=int(p.recv(12),16); ret=rbp+8; start=ret+0x10
ogg=libcbase+0xe3b01
o1,o2,o3=ogg&0xff,(ogg>>8)&0xff,(ogg>>16)&0xff
payload=b'%'+str(o1).encode()+b'c%11$hhn'+b'%'+str(o2-o1).encode()+b'c%12$hhn'+b'%'+str(o3-o2).encode()+b'c%13$hhnaaaaaaa'+p64(start)+p64(start+1)+p64(start+2)
sl(payload); p.interactive()
```

## 变体与关联

- 类似"改返回地址重入/循环 + 多轮写"的思路见 [[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]、[[binary-pwn-format-string-non-stack-fini-array-loop-write]]；全保护单次两 %n 写见 [[binary-pwn-format-string-one-shot-stack-return-address-two-n-writes]]。
- 无 one_gadget 时可布置 system("/bin/sh") 的 ROP 链（需 pop rdi 与 /bin/sh 地址）。

## 检测与防御

`printf("%s",buf)`；PIE+Canary+Full RELRO 仍需防格式化字符串；过滤 `%n`/`$`；监控同一进程高频 printf 与返回地址改写行为。
