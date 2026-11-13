---
id: binary-pwn-stack-pie-page-bruteforce-fork-partial-overwrite
title: fork 共享 PIE 基址逐页爆破：p16 部分覆盖返回地址低 2 字节，16 次尝试命中后门所在页
type: scenario
domain: binary
path: binary/pwn/stack
technique: pie-base-page-brute-force-partial-overwrite
aliases:
- PIE 爆破
- PIE 基址爆破
- 部分覆盖爆破 PIE
- p16 覆盖返回地址
- 页对齐爆破
- funcanary PIE
tags:
- pwn
- stack
- pie
- aslr
- bruteforce
- partial-overwrite
- fork
- ctf
- linux
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V590
  verified_at: '2026-11-12T15:19:21+08:00'
  notes: 已对照原文与18张截图核对：funcanary checksec（Full RELRO/Canary/NX/PIE）、main fork+wait（父wait/子puts welcome→vuln）、vuln buf[104] read 0x80、后门 0x1231（lea rax,aBinCatFlag;/bin/cat flag; call system）、canary 逐字节爆破（0x68偏移、stack smashing oracle）、p16 候选 0x0231 起每次+0x1000 经 0xb231/0xc231 命中 flag 的 pwntools 日志均与卡片一致；触发条件/边界（同64KB窗口、fork不exec、跨页进位）核对成立。dedup：与 binary-pwn-stack-fork-canary-bytewise-bruteforce（爆破对象canary）、binary-pwn-stack-pie-base-leak-csu-init-return-address（泄露而非爆破）、ctf-pwn-onebyte-ret-overwrite-backdoor-system（同页单字节、32位、不跨页）均不同链；dup-scan.json 无涉及本卡。CTF 题无受影响版本，不设。未实测 PoC；已修正两处表述（bits16+一致性的同64KB窗口前提、welcome 由 fork 后新子进程打印）。
---

# 一句话结论

当二进制开启 PIE、程序以 fork server 处理请求（子进程继承同一 PIE 基址），且栈溢出可以只覆盖返回地址低 2 字节时，把返回地址低 16 位改成二进制内后门的静态低 16 位，并以 0x1000 为步长枚举 16 个页内候选值；错误候选导致子进程崩溃、正确候选执行后门输出 flag，最多 16 次尝试即可在无任何地址泄露的情况下绕过 PIE。

# 原理

- **PIE 基址页对齐**：开启 PIE 后，代码段被映射到随机的页对齐基址（0x1000 的倍数）。二进制内某符号的实际地址 = PIE base + 静态偏移；其低 12 位只由静态偏移决定（如后门偏移 0x1231 → 低 12 位恒为 0x231），而第 12–15 位随基址的页号变化，只有 16 种可能。
- **部分覆盖只改低 2 字节**：栈溢出 payload 在返回地址处只写 `p16(候选值)`（或写 2 字节后即结束），高 6 字节保留原返回地址内容。原返回地址同样位于该二进制的代码段，与后门共享同一 PIE base；只要二者静态偏移落在同一个 64KB 窗口（小体积二进制常见），低 16 位以上的位就一致，攻击者只需要确定"后门落在 64KB 窗口内的哪一页"。
- **16 次枚举**：候选序列为 `0x0231, 0x1231, 0x2231, …, 0xf231`（每次 +0x1000）。基址页号对齐意味着真实低 16 位必在其中；若 `base_low16 + 后门偏移` 发生跨 64KB 进位，可能还需额外覆盖第 3 字节或扩大候选范围（小体积 PIE 二进制通常不需要）。
- **fork 是前提**：`fork()` 创建的子进程是父进程地址空间的副本，PIE 基址原样继承；父进程不为每次连接重新 exec，所有爆破尝试都在同一基址上进行。若每次连接 `execve` 新进程，基址重新随机化，逐页枚举无法收敛。
- **成功 oracle**：错误候选跳到非法地址/错误函数，子进程崩溃且没有预期输出；正确候选调用后门（如 `system("/bin/cat flag")`），输出中包含 flag。父进程在下一轮循环 fork 的新子进程会继续 `puts("welcome")`，也可作为每次尝试的同步点与"子进程是否正常返回"的旁证。
- **与 canary 爆破的组合**：若同时开启 canary，先用逐字节爆破（fork 子进程 canary 相同）还原 canary 并填入 payload，再用本方法爆破 PIE；两者可以共用同一个 fork 会话与 oracle 逻辑。

# 触发条件

- Linux x86-64 二进制开启 PIE，且存在栈缓冲区溢出，溢出长度可控到"只覆盖返回地址低 2 字节"。
- 程序使用 fork server 模式（主循环 `fork()`，子进程处理输入、父进程 `wait()`），fork 后不 exec、不重新随机化地址空间。
- 二进制内存在可直接调用的后门/目标函数（如调用 `system("/bin/cat flag")`），其静态偏移已知（可通过 IDA/objdump 获得）。
- 若开启 canary，需先泄露或爆破 canary；若开启 Full RELRO/NX 不影响本方法（不依赖 GOT/栈执行）。
- 攻击者可发起多次连接以完成最多 16 次（外加 canary 爆破）尝试。

# 利用步骤

1. 确认保护：`checksec` 显示 PIE enabled；反编译主循环确认 `fork()` 且父进程 `wait()`。
2. 在 IDA/objdump 中找到后门函数，记录其实例地址对应的静态低 16 位（如 `0x1231`）。
3. 若存在 canary，先按逐字节爆破或泄露获得 canary。
4. 构造 payload：`填充到 canary 前 + canary + 保存的 rbp（任意 8 字节） + p16(候选低 16 位)`。
5. 循环 16 次：每次发送 payload，读取子进程输出；若收到预期输出（flag）即成功；若子进程崩溃/无输出，把候选值 +0x1000 继续。（文章中每次出错后父进程仍会 fork 新子进程，由新子进程打印 welcome，可用 `recvuntil(b'welcome\n', timeout=...)` 同步。）
6. 命中后进入交互，读取 flag。

# PoC

```python
from pwn import *

p = process('./pwn')
p.recvuntil(b'welcome\n')

canary = b'\x00'          # 已通过爆破/泄露得到完整 canary
backdoor = 0x0231         # 后门函数地址的静态低 16 位

while True:
    for _ in range(16):
        p.send(b'a'*0x68 + canary + canary + p16(backdoor))
        data = p.recvuntil(b'welcome\n', timeout=0.5)
        if b'welcome\n' in data:      # 本轮未崩溃，继续尝试下一页
            backdoor += 0x1000
        if b'flag' in data:           # 命中后门，后门输出 flag
            print(data)
            p.interactive()
```

# 变体与关联

- 变体：一次覆盖 3 字节（`p24`）可同时覆盖跨 64KB 进位的场景，但候选空间变为 16×256 级，通常仍可行。
- 变体：若程序每次连接都重新 exec，可改为在同一进程内利用格式化字符串/栈泄露直接读 PIE 基址（见 `binary-pwn-stack-pie-base-leak-csu-init-return-address`）。
- 关联：`binary-pwn-stack-fork-canary-bytewise-bruteforce`（同一 fork oracle 先爆破 canary；本卡是其 PIE 收尾）、`ctf-pwn-onebyte-ret-overwrite-backdoor-system`（同页内单字节部分覆盖，不需要 EXP 基址；本卡是跨页爆破）、`binary-pwn-stack-win32-aslr-partial-overwrite-jmp-eax`（Windows 部分覆盖思路）。
- 边界：PIE 基址随机化位数更高（如 bits 12–15 之外还随机化更高位且原返回地址不在同一 64KB 窗口）时，2 字节枚举不成立；fork 后 exec、或每次连接重建地址空间时失效；目标二进制体积超过 64KB 时进位情况需单独分析。

# 检测与防御

- 检测：短时间内同一服务出现大量连接且每个连接都导致子进程异常退出（crash oracle），可视为爆破特征；进程出现 `stack smashing detected`/段错误的高频重复；请求 payload 呈现"固定填充 + 疑似 canary + 2 字节地址"结构。
- 防御：服务端避免使用 fork server 直接继承父进程地址空间处理不可信输入（每次 exec 新进程）；启用完整 ASLR/PIE 并保证随机化位数；修复栈溢出（改用有界拷贝）；开启 canary/FORTIFY；对高频崩溃连接做速率限制与告警。
