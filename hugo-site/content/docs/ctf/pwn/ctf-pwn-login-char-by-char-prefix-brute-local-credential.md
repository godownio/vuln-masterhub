---
id: ctf-pwn-login-char-by-char-prefix-brute-local-credential
title: 凭据在本地逐字符比较且错在不同位置：用返回文案差异逐个字符爆破出用户名与密码，先进门再打后面的堆
type: scenario
domain: ctf
path: ctf/pwn
technique: login-prefix-oracle-char-by-char-credential-brute
tags:
- pwn
- ctf
- auth
- bruteforce
- oracle
- credential
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片；login 有本地逐字符比较、以文案差异当 oracle、先爆用户名再爆密码、之后进菜单堆题的框架与正文一致（原文脚本把 Invalid username length! 当成「该字符正确」的信号，卡内 PoC 已按相反判定注明须以目标实际文案为准）；字符集分段为 0x20-0x5A 与 0x5B-0x7E 亦与正文一致
url: /docs/ctf/pwn/ctf-pwn-login-char-by-char-prefix-brute-local-credential/
draft: false
kb_aliases:
- 逐字符爆破用户名
- Invalid username length 提示
- 登录前缀 oracle
- 本地校验凭据爆破
- pwn 登录门爆破
---

## 一句话结论

当 pwn 题在进入菜单前先要求登录、凭据又是**编译进二进制里逐字符比较**时，返回值/文案差异就是现成的 oracle：猜对前缀会走到下一层判断并返回不同的提示（本例 "Invalid username length!" 与 "Username correct!"），于是可以从空串开始一个字符一个字符地把用户名、密码完整爆破出来，再进去打真正的漏洞。

## 原理

- **逐字符比较短路**：典型实现是 `for (i = 0; i < n; i++) if (input[i] != secret[i]) return 0;`，比较一旦不等就立即返回。攻击者虽然不知道 `secret`，但能观察到「在第 i 个位置失配」与「前 i 个字符都正确、在第 i+1 个位置失配」这两种情况的**响应不同**。
- **oracle 来自不同的提示文案**：本例输入长度不对时返回 `Invalid username length!`，前缀匹配但长度不够/内容不全时返回 `Username correct!` 之类；只要两种结果的文案（或返回时机、耗时）可区分，就能判定「当前前缀是否被接受」。
- **逐位贪心即可恢复明文**：维持已知前缀 `known`，遍历字符集 `c`，发送 `known + c`；若响应显示"进入了下一层"，则 `known += c` 并继续，否则换下一个字符。字符集按目标实现裁（原文脚本分两段：先 `空格~Z`，再 `[~z`，共 95 个可打印字符）。
- **密码同理**：拿到用户名后，密码的校验通常是同一套路（同一函数或同一循环），把 oracle 换成对应提示即可复用同一脚本。
- **为什么值得单独成卡**：这类"pwn 题先过登录门"在比赛里极常见，凭据往往硬编码在二进制里但被加密/混淆到难以静态提取；前缀 oracle 是**不需要漏洞**的入口，与后面的堆/栈利用解耦，先拿下它才谈得上打洞。

## 触发条件

- 登录校验在本地完成（凭据硬编码或本地文件），不依赖远程认证，因此猜测次数不受服务端限速。
- 比较是逐字符短路，且不同失配位置会产生**可区分的响应**（文案、长度、时序、退出码）。
- 进程不因失败次数直接退出（本例每次失败仍可重连或继续尝试）；若是 `fork` 每连接一进程，则每连接可试 95 次。
- 字符集已知或可枚举（本例可打印字符 0x20–0x7E）。

## 利用步骤

1. 静态审计登录函数，确认凭据是本地比较、且比较在首个不等字符处返回。
2. 抓取三种响应：长度不对、前缀不对、前缀正确——记下各自的文案/耗时。
3. 用「正确前缀会得到不同文案」作为判定条件，从空串逐字符扩展。
4. 用户名爆完后用同一手法爆密码（若校验函数不同则调整判定字符串）。
5. 用得到的凭据登录，进入真正的漏洞函数（本例是随后的堆菜单）。

## PoC

```python
from pwn import *
context.log_level = 'error'
p = remote(host, port)

charset = [chr(c) for c in range(0x20, 0x7f)]     # 95 个可打印字符

def brute(prompt, ok_marker, bad_marker):
    known = ''
    while True:
        progressed = False
        for ch in charset:
            p.sendlineafter(prompt, (known + ch).encode())
            res = p.recvuntil((bad_marker, ok_marker), timeout=1)
            if ok_marker in res:            # 前缀被接受 -> 该字符正确
                known += ch
                progressed = True
                break
        if not progressed:
            return known

user = brute(b'Input your username:\n', b'Username correct!', b'Invalid username length!')
passwd = brute(b'Input your password:\n', b'Password correct!', b'Invalid password length!')
print(user, passwd)
```

（原文脚本的判定方向相反：出现 `Invalid username length!` 才说明"长度不足"，即前面已全部正确、正要补下一个字符；实际以目标返回的文案为准，逐条确认后再定判定。）

## 变体与关联

- 变体：oracle 换成时序（逐字符 `sleep`、`memcmp` 提前返回造成的耗时差）——参见盲注类卡片的阈值做法。
- 变体：凭据存在本地文件而非二进制时，配合任意文件读可直接读出，无需爆破。
- 变体：字符集未知时，用二分（`strcmp` 返回正/负）把每字符压缩到 `log2(N)` 次查询。
- 关联：[[binary-pwn-stack-fork-canary-bytewise-bruteforce]]（同样逐字节、但爆的是 canary）、[[ctf-pwn-login-failure-prints-correct-password]]（登录失败直接把正确口令打印出来，比爆破更省事）、[[web-generic-auth-per-char-sleep-timing-password-oracle]]（Web 侧同构的时间 oracle）。
- 边界：若比较用 `strcmp` 且只在完全相等/不等时返回，没有中间态，则前缀 oracle 不成立；若服务端有失败次数上限或连接限速，需换思路。

## 检测与防御

- 检测（CTF/审计）：登录函数里出现逐字符 `for` 循环 + 不同分支返回不同文案；同一连接可无限次尝试。
- 修复：比较改用恒定时间的 `memcmp`/`crypto_verify` 并对所有失败返回**同一文案与同一耗时**；加入失败次数计数与延迟。
- 加固：不要把凭据硬编码进二进制（改用服务端校验 + 强哈希）；对每连接/每 IP 的尝试次数设上限。
