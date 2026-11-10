---
id: ctf-pwn-time-seed-hash-replay-partial-leak-libc
title: srand(time(0)) 作为 hash 混淆密钥：本地同秒复算 rand 序列 + 指针特征校验（高 4 位/低 12 位）恢复 libc 基址
type: scenario
domain: ctf
path: ctf/pwn
technique: prng-hash-replay-libc-partial-leak
tags:
- pwn
- prng
- srand
- libc-leak
- bruteforce
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-27
  verified_at: '2026-11-08T15:12:21+08:00'
  notes: 已对照原文与全部 29 张图片核对：img/11 确认 seed = time(0); srand(seed)；img/12 确认 hash 混入 rand 值且常数 0x1145140478/0xF84075ECD213097F/0x95A024EE03460DFF 与卡一致；img/13 确认题目给出 glibc 2.31-0ubuntu9.17（同版本复算前提成立）；原文 exp 用 int(time.time()) 加 [0,-1,+1,+2,-2,+3,-3] 七组偏移各生成 100 个 rand 同秒复算，命中条件 (v>>44)&0xF==7 且 v&0xFFF==0xdff、libc_base=v-0x21A000 与卡完全一致。related 候选 srand-time-seed-2fa-code-prediction 为 Web 2FA 预测，入口/目的不同，判 new 成立。未验证点：原文无本链成功的输出截图，『恢复 libc 后 ORW 成功读 flag』仅为作者 exp 推断（exp 内置特征校验与重试循环），未独立复现。
url: /docs/ctf/pwn/ctf-pwn-time-seed-hash-replay-partial-leak-libc/
draft: false
kb_aliases:
- 时间种子 hash 复算泄露 libc
- rand 序列重放指针恢复
---

# 一句话结论

程序把 libc 指针经 `hash ^= rand() & MASK` 两轮掩码混淆后输出（本题 hash 输入还叠加了分配计数），而 `srand(seed)` 的 seed 是 `time(0)`——攻击者在本地用同一 glibc 以当前秒及 ±N 秒各生成一段 rand 序列，对每个候选秒复算 hash 逆运算得到候选指针，再用 64 位用户态指针的固定特征（高 4 位=0x7、页内低 12 位偏移已知固定）筛选，一次连接内即可恢复 libc 基址，无需任何传统信息泄露原语。

# 原理

- 混淆函数形如：`v |= 0x95A024EE03460DFF; v ^= (randA & 0x1145140478); v = (v1 & 0xF84075ECD213097F) ^ v`，其中 randA/randB 来自全局缓冲区中程序启动时 `srand(time(0))` 之后连续 `rand()` 的取值（与 add/delete 操作次数绑定）。glibc rand 是确定性 LCG 衍生（TYPE_3 加法反馈），同种子同消耗次数下序列完全一致——攻击端只要用题目提供的同一 libc.so.6 以 `ctypes` 调用 `srand/rand` 重放即可。
- 时间种子熵极低：seed 只有 `time(0)` 的秒级值，交互时差通常 <1s；对 ±3 秒各生成 100 个 rand() 覆盖即可。
- 恢复的候选值是「hash 输入 = 某 libc 相关地址」的混淆结果：正确候选满足用户态映射特征——高 4 位 = 0x7（0x7f.. 开头），且 libc 固定符号相对某已对齐区域有固定低 12 位页内偏移（本题 0xdff）。用这两个特征做过滤器，±3 秒×7 组序列中唯一命中即 libc 地址，`libc_base = 候选 - 0x21A000`（题目 libc 中该符号偏移）。
- 该技巧本质是「把低熵 PRNG 当作可逆编码」：只要混淆不含未知秘密、只依赖可预测/可枚举的 seed 与操作计数，就可在本地完全复算。

# 触发条件

- 二进制中存在 `srand(time(0))` 或其他低熵/可枚举种子，且 PRNG 输出参与对敏感数据（libc/栈/堆指针）的混淆运算并被输出回显。
- 攻击者可获得与目标一致的 libc（题目附带或可指纹识别版本），保证 rand() 序列一致。
- 混淆可逆（纯 XOR/掩码类），或输出空间可穷举。

# 利用步骤

1. 逆向确认：`seed = time(0); srand(seed)`；hash 函数中 rand 值的消耗次序（本题与 add/delete 次数相关，本地用计数器同步）。
2. 本地 `ctypes.CDLL('./libc.so.6')`，对 t-3..t+3 每秒 `srand(t+off)` 预生成 ≥100 个 rand() 存表。
3. 交互触发一次 hash 输出，按相同消耗次序从各候选序列取 randA/randB 代入逆运算（`hash ^= randB & 0xF84075ECD213097F; hash ^= randA & 0x1145140478` 的逆即同操作 XOR）。
4. 过滤候选：`(v >> 44) & 0xF == 7` 且 `v & 0xFFF == 0xdff`（按实际页内偏移调整）；命中后清低位对齐得 libc 相关地址，减去固定偏移得 libc_base。
5. 用恢复的 libc 继续原漏洞利用（本题后续为 tcache/负 size 任意写 + 伪 _IO_2_1_stdout_ 的 _IO_wfile_jumps 迁移 + setcontext ORW 打沙箱）。

# PoC

```python
from ctypes import *
import time
libcR = cdll.LoadLibrary('./libc.so.6')
t = int(time.time())
seqs = []
for off in (0,-1,1,2,-2,3,-3):
    libcR.srand(t + off)
    seqs.append([libcR.rand() for _ in range(100)])
# 按与程序同步的消耗下标 xxx 取 randA/randB 逆 XOR
def myencode(h, lst, xxx):
    randA = lst[xxx-4] + (lst[xxx-3] << 32)
    randB = lst[xxx-2] + (lst[xxx-1] << 32)
    h ^= randB & 0xF84075ECD213097F
    h ^= randA & 0x1145140478
    return h
# 命中条件: (v>>44)&0xF==7 and v&0xFFF==0xdff -> 清低 12 位对齐, libc_base = v - 0x21A000
```

原文实测：7 组候选序列中唯一命中，恢复 libc 后接 house-of-cat 式 IO_FILE 利用与 ORW ROP 成功读取 flag。

# 变体与关联

- 同源思路：任何「种子可枚举的 PRNG 参与指针/数据混淆」的泄露都可本地复算恢复——如 `rand()%256` 异或的 canary、以 pid/时间作种的白盒。
- 时间种子爆破在 reverse 场景的对应变体是「按文件 mtime 窗口枚举 seed 逆置换还原明文」（ctf-reverse-time-seed-shuffle-mix-bruteforce-mtime）：那里 seed 不可从密文恢复需枚举，本题 seed 即当前时间可直接枚举且输出可逆。
- 指针特征校验可推广：x86-64 Linux 用户态指针高 4 位=0x7、libc 页内偏移低 12 位固定，是通用低噪声过滤器；堆地址则高 12 位固定为 0x55/0x56（PIE）。

# 检测与防御

- 程序侧不要用 `srand(time(0))` 处理敏感数据；混淆必须引入攻击者不可知的秘密（如 /dev/urandom 保存于进程内）。
- 服务端可限制同一连接的操作次数使 rand 消耗不可同步，或直接避免回显混淆后的指针。
- 蓝队审计：源码中出现 `srand(time` 且输出含指针运算结果即为风险信号。
