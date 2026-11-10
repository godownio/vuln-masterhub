---
id: binary-pwn-sandbox-escape-orw-flag-byte-bruteforce-time-clean-oracle
title: 沙箱禁写下的 ORW flag 逐字节爆破：cmp+je 自环挂起，用 clean 耗时差做 oracle 并二分收敛
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: orw-shellcode-flag-byte-bruteforce-time-oracle
aliases:
- ORW 时间盲注
- shellcode 逐字节爆破 flag
- clean 耗时 oracle
- 禁 write 侧信道
- je 自环爆破
- ja 二分支爆破
- nepbox 时间盲注
tags:
- binary
- pwn
- shellcode
- orw
- side-channel
- timing
- seccomp
- brutesort
- flag
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:49:53+08:00'
  notes: 已对照原文核对：open+read(3,rsp,0x80) 前置、cmp al,byte[rsi+i] 后 je 自环挂起、用 r.clean(2) 耗时大于 2 秒判定命中、ja 二分版本、原文的寄存器抖动与重启靶机复测经验、nepbox 例题的 syscall_id!=1 校验与 rand()/ptrace(PTRACE_SETREGS) 改写寄存器均与原文一致；卡内已把原文未明说的放行 syscall 清单改为需按目标复核。未验证点：未复跑原文 nepbox 靶机，HOST/PORT 与提示串需按目标调整；原文二进制版本中 cmp al,{ord(j)} 用了未定义的 j 属原文笔误，卡内已改用 ord(j)。
---

## 一句话结论

当题目允许提交 shellcode、但沙箱禁掉 `write`（或像本例那样用 `ptrace` 把 `write` 的参数改坏、只放行某几个 syscall）时，可以让 shellcode 先 `open("flag")`+`read` 把内容读到固定缓冲区，再逐位与猜测值 `cmp`：相等就 `je` 跳到自身进入死循环；攻击端用“读空缓冲耗时明显变长”作为 oracle 逐字节还原 flag，字符集大时改用 `ja` 做二分把每次的候选数压到 log 级。

## 原理

- **前提是能读不能写**：`open`/`read` 未被禁，flag 对进程可读；`write`（或 `sendfile`/`splice`）被封，或被程序用 `ptrace(PTRACE_SETREGS)` 之类手段把 `write` 的参数/系统调用号改坏，导致即使调用 `write` 也没有有效输出。
- **把“是否命中”编码成运行时长**：`cmp al, guess` 后接 `je $-2`（跳回 `cmp` 自身）形成紧循环。命中时进程一直转圈、连接不结束；未命中时执行流走到 `ret`/`exit` 立即返回。二者在攻击端表现为“读超时/耗时约等于超时窗口”与“秒回”的差别。
- **oracle 的两种实现**：① `recv(timeout)`/`can_recv` 判断是否仍挂着；② 像本例那样先 `sendlineafter` 再调 `r.clean(2)`，用这一步的耗时当信号——命中时 `clean` 要等满超时（约 2 秒），未命中时几乎瞬时返回。后者不依赖连接是否关闭，适合服务端连接保持的远程靶。
- **顺序爆破 + 二分收敛**：字符集小（如 hex/数字/`{}`）直接按序枚举；字符集大（含大小写字母与符号）时用 `cmp`+`ja` 判断“真值大于猜测”，命中即挂起，从 `0x20..0x80` 二分，每字节约 7 次连接即可收敛。
- **为什么必须每次一条新连接/新进程**：进程一旦进死循环就无法复用；每次探测都是新连接（本地是 `process(['./pwn'])`，远程是 `remote(...)`），并且要在发 payload 前确认服务端“输入 shellcode”的提示，避免时序噪声。
- **误差来源与修正**：远程连接建立本身有抖动，`clean(2)` 的 2 秒阈值要大于抖动、小于服务端超时；同一目标反复探测会越来越慢（服务端资源/连接复用/监控），原文的做法是“把已爆破出的前缀当作已知再做后续”“必要时重启靶机”“对同一字节多次复测”。
- **边界**：若服务端有 watchdog/超时强杀，命中也会被提前杀掉而误判；此时可把自环换成 `nanosleep` 长延时循环，让挂起时长稳定且可控。

## 触发条件

- 题目接受用户 shellcode（函数指针调用、RWX 页、`mmap` 后跳转等），且 flag 位于进程可读的固定路径（如 `./flag`）。
- `open`/`read` 可用，`write` 及替代输出 syscall 被 seccomp 禁止，或被程序篡改参数（本例 `syscall_id != 1` 即拒绝、并用 `rand()` 选一项 `off_4020` 改写寄存器）。
- 攻击端能测量单次交互耗时（`clean(timeout)`、`recv(timeout)`、`can_recv`）且抖动小于判定阈值。
- 允许同一目标多次连接；flag 内容在比赛期间稳定。

## 利用步骤

1. 先用原始 shellcode 打一次 `open/read`+无条件 `je $-2`，确认连接确实挂起、`clean` 耗时≈阈值，建立基线。
2. 逐位确定长度与字符：对位置 `i`，枚举候选 `j`，payload = `open("flag")` + `read(fd, rsp, 0x80)` + `mov al,[rsi+i]; cmp al, j; je $-2; ret`。
3. 每次探测：`remote(...)` → `sendlineafter('right', payload)` → 计时 `r.clean(2)` → 耗时超过阈值即认为命中，`close()`；未命中立即重试下一个候选。
4. 命中后把该字符并入已知前缀，`i += 1`；遇到 `}` 或达到最大长度停止。
5. 字符集大时改二分：payload 里用 `cmp al, mid; ja $-2; ret`，若挂起说明真值 > mid，否则 ≤ mid，7 轮内定位。
6. 复测：对每个新确定的字节用相同 payload 再打 2~3 次，剔除抖动导致的误判；若整体变慢，重启靶机或缩短每轮探测次数。
7. 收集所有命中字符拼成完整 flag，与题面格式（如 `NepCTF{...}`）核对。

## PoC

```python
from pwn import *
import time

context(arch='amd64', os='linux', log_level='error')
charset = '0123456789abcdef'
flag = 'NepCTF{'
THRESH = 2.0            # clean(2) 的等待窗口

for i in range(len(flag), 50):
    for j in charset:
        r = remote(HOST, PORT)     # 每次探测一条新连接（本地可换 process(['./pwn'])）
        payload  = asm(shellcraft.open('flag'))
        payload += asm(shellcraft.read(3, 'rsp', 0x80))
        payload += asm(f'''
            mov al, byte ptr [rsi+{i}]
            cmp al, {ord(j)}
            je $-2
            ret
        ''')
        t = time.time()
        r.sendlineafter('right', payload)
        r.clean(2)                    # 命中时这一步要等满 2s
        dt = time.time() - t
        r.close()
        if dt > THRESH:
            flag += j
            break
    if flag.endswith('}'):
        break
print(flag)
```

二分版本把 `je $-2` 换成 `ja $-2`，维护 `left/right` 区间，命中（挂起）则 `left = mid + 1`，否则 `right = mid`。

说明：上面只给出 oracle 骨架，`HOST/PORT`、提示字符串 `'right'`、`open` 的文件名与 `read` 的 fd 需按目标调整；本条未复跑原文靶机。

## 变体与关联

- 变体：把死循环换成 `nanosleep`/长循环，让挂起时长可控、抗 watchdog；或用 `pause`/`sigwait` 挂起。
- 变体：oracle 换成“进程退出码”（`waitpid` 超时 vs 正常退出）、或“CPU 时间”（服务端有计时），本质仍是把比较结果映射成可观测差异。
- 变体：`open` 被禁时用 `openat`/`openat2`；`read` 被禁时用 `pread64`/`mmap` 映射 flag 文件后直接比较内存。
- 变体：不爆破内容而爆破“第 i 字节是否等于某集合中的值”，先用 `ja` 二分缩到单字节再顺序确认，减少远程连接数。
- 关联：[[binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle]]（同族技术，用 `can_recv` 超时判断；本条补的是 `clean(timeout)` 耗时差 + `ja` 二分 + 远程抖动/复测经验，环境与 PoC 不同）、[[ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw]]、[[ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw]]。
- 边界：网络抖动大于阈值、服务端对同 IP 限速、watchdog 强杀挂起进程时，误判率上升；纯本地 `process` 上抖动小、最可靠。

## 检测与防御

- 检测（出题/防守）：同一目标被大量“短连接 + 每次 shellcode 只差一两个字节”的请求命中，且部分连接长时间无数据、CPU 占用高；这是典型的时间 oracle 爆破特征。
- 防御：seccomp 同时限制 `open`/`read`（只留 `write` 到固定 fd），或把 flag 放在进程不可读的位置（由父进程读完再传内容）；对连接设短超时并强杀挂起进程，压缩 oracle 的可观测差异。
- 防御：限制单 IP 连接频率与总尝试数；对 shellcode 做长度/字节白名单，减少任意代码执行面。
