---
id: ctf-crypto-challenge-response-xor-fold-checksum-1in256
title: 挑战响应认证的 XOR 折叠校验：8 字节比较降为单字节，1/256 概率通过
type: scenario
domain: ctf
path: ctf/crypto
technique: challenge-response-xor-fold-checksum-bypass
aliases:
- Dro4_Null5
- XOR checksum
- 1/256 auth bypass
- challenge-response
- HMAC mask
- 认证校验和折叠
tags:
- ctf
- crypto
- authentication
- hmac
- xor
- checksum
- probabilistic-bypass
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T10:01:34+08:00'
  notes: 已对照原文（无图片）核对：verify_credential 将 8 字节 expected/provided/HMAC mask 逐字节异或后只判 checksum==0，单次 1/256，单连接 0x1337 次重试几乎必然成功；卡片纠正了原文“expected=challenge”的误判（state[16+step]^=scan[0] 确实改写尾部），并修正原脚本 remote 被 process 覆盖的问题。PoC 未在本机执行
---

## 一句话结论

挑战响应认证的 `verify_credential` 把 `expected`、用户 `provided` 与 HMAC 掩码逐字节异或后再整体异或，最终只判断一个字节 `checksum == 0`；8 字节的响应比较被折叠成 1 字节校验，随机响应每次有 1/256 概率通过，配合无限重试（单连接 0x1337 次）即可稳定鉴权 `Administrator` 并拿到 flag。

## 原理

- **协议流程**：
  1. 用户输入 8 字节 `challenge` 与用户名；
  2. 服务器生成 8 字节随机 `server_token` 并公开；
  3. `navigation_key = HKDF(master=backpack[user], key_len=16, salt=challenge + server_token, hash=SHA256)`；
  4. `expected_path = compute_path(navigation_key, challenge)`；
  5. 用户提交 8 字节 `response`，`verify_credential(navigation_key, expected_path, response)` 决定是否通过。
- **校验函数**：
  ```python
  h = HMAC.new(session_key, expected, SHA256)
  mask = h.digest()[:8]
  checksum = 0
  for i in range(8):
      checksum ^= expected[i] ^ provided[i] ^ mask[i]
  return checksum == 0
  ```
  `checksum` 是 8 个字节逐字节异或后的一个字节（0..255），`checksum == 0` 只约束 8 位，而不是比较完整的 8 字节响应。
- **概率**：当 `expected`、`provided`、`mask` 近似随机时，`checksum` 在 0..255 上近似均匀，单次通过概率 `1/256`。每次连接/每次登录都会生成新的 `server_token`，因此 `expected` 与 `mask` 重新随机，重试之间近似独立。
- **重试放大**：单连接允许 `0x1337 = 4919` 次登录；至少成功一次的概率为 `1 - (255/256)^4919 ≈ 1 - e^-19.25 ≈ 1 - 4.4e-9`，实际几乎必然成功。固定 `challenge` 与 `response` 为全零即可，无需知道 secret、HKDF 或 AES 的任何输出。
- **关于 `compute_path` 的常见误判**：`state = bytearray(16) + challenge`，循环中 `state[16 + step] ^= scan[0]` 确实改写了返回的尾部 8 字节，因此 `expected_path` 并不等于原始 `challenge`，而是由 `navigation_key` 决定。攻击成立的关键不是“expected 可控”，而是校验被折叠成单字节且允许无限重试；即使 expected 完全不可预测，1/256 的随机通过率仍然成立。
- **为什么能直接猜**：认证没有把“本次会话的 expected”与“用户提供的 response”做完整比较，也没有把失败次数计入锁定；XOR 折叠丢失了 7 个字节的约束，剩下的 1 字节可用重试覆盖。

## 触发条件

- 认证采用挑战-响应流程，最终比较用 XOR/求和/CRC 等可折叠运算，且只比较一个字节或很短的结果。
- 每次尝试都会刷新随机 challenge/token，但允许同一会话或新连接反复尝试。
- 没有速率限制、账号锁定、失败计数或服务端风控。
- 通过认证后可直接获得敏感结果（flag、管理员会话等）。

## 利用步骤

1. 阅读 `verify_credential`，展开循环，确认 `checksum` 是单字节且只与 `== 0` 比较；记录参与异或的字段数量。
2. 确认每次尝试的 `server_token` 是否刷新、失败是否计数、连接是否可重连。
3. 选择目标用户名（如 `Administrator`），准备固定的 8 字节 `challenge` 和 8 字节 `response`（全零即可）。
4. 在单连接内循环登录，或失败后重连；每次读取返回，匹配 `flag:`/成功标记。
5. 按 `1 - (255/256)^n` 估算尝试次数；通常几百到几千次内命中。
6. 命中后保存会话/输出，停止爆破，避免无谓请求。

## PoC

```python
from pwn import remote, process
import sys

DEBUG = False
HOST, PORT = "target.example", 1337

def attempt_once(p):
    p.sendline(b"1")
    p.recvuntil(b"challenge (hex): ")
    p.sendline(b"0" * 16)              # 8 字节 challenge，全零
    p.recvuntil(b"username: ")
    p.sendline(b"Administrator")
    p.recvuntil(b"response (hex): ")
    p.sendline(b"0" * 16)              # 8 字节 response，全零
    return p.recvuntil(b"choose ").decode(errors="replace")

while True:
    p = process(["python3", "challenge.py"]) if DEBUG else remote(HOST, PORT, ssl=True)
    p.recvuntil(b"choose ")
    for i in range(0x1337):
        res = attempt_once(p)
        if "flag: " in res:
            print(res)
            p.close()
            sys.exit(0)
    p.close()
```

说明：以上为按原题逻辑整理的结构化 PoC，未在本机执行；原题脚本中 `remote(...)` 下一行被 `process(...)` 无条件覆盖，远程利用需保留上面的 `DEBUG` 分支。固定 challenge/response 为全零只是最简形式；任何固定值都等价于每轮抽一次 1/256。

## 变体与关联

- **折叠运算变体**：XOR 累加、`sum(...) % 256`、CRC8、只取 HMAC 前 1 字节比较；本质都是把多字节约束降为 1 字节。
- **重试变体**：单连接内循环、断线重连、多线程/多账号并行；有速率限制时可降低并发并拉长尝试窗口，但无法改变单次 1/256 的概率。
- **协议变体**：挑战响应、一次性口令、HMAC 掩码、HKDF 派生会话密钥；只要最终比较被折叠，协议其余部分的密码学强度都不影响绕过。
- **关联卡片**：[[web-generic-auth-rsa-signature-weak-checksum-collision-exec]]（签名只绑定弱校验和导致碰撞）、[[ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root]]（密码学协议实现缺陷的另一类）、[[ctf-reverse-predictable-score-derived-aes-key-iv]]（可预测状态派生密钥）。
- **边界**：若服务端比较完整 8 字节（`hmac.compare_digest`）、失败计数/锁定、或每次尝试需要不可预测的一次性挑战且限制重试，1/256 爆破不成立。

## 检测与防御

- **CTF/验证**：成功响应中应出现 `authentication successful` 与 `flag:`；同一 challenge/response 对新 server_token 的通过次数应接近 1/256。
- **检测信号**：认证代码中出现 `checksum ^= ...` 后只比较 `== 0`、只取 `digest()[:1]`、或对多字节响应做 XOR/求和折叠；登录接口存在大量失败后仍可继续尝试。
- **防御**：用 `hmac.compare_digest(expected, provided)` 比较完整 MAC；不要用 XOR/求和折叠代替逐字节比较；服务端记录失败次数并做速率限制/锁定/延迟；挑战一次性使用并与会话绑定。
- **加固边界**：把认证判断放在服务端、使用成熟库的常量时间比较；客户端/协议层的混淆不能替代完整校验。
