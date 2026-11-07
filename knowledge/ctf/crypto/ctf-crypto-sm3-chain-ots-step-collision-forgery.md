---
id: ctf-crypto-sm3-chain-ots-step-collision-forgery
title: SM3 链式单次签名伪造：按步长数组逐段收集其他消息的签名拼接目标签名
type: scenario
domain: ctf
path: ctf/crypto
technique: sm3-chain-ots-step-collision-forgery
aliases:
- Nepsign
- SM3 单次签名
- 哈希链签名伪造
- 步长数组
- 多消息签名拼接
- 一次性签名 oracle
tags:
- ctf
- crypto
- sm3
- one-time-signature
- hash-chain
- forgery
- signature
- oracle
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:02+08:00'
  notes: 已对照原文核对；SM3步长数组(32字符ASCII+16校验和)、48段碰撞拼接签名与PoC一致；已修正frontmatter domain为ctf；PoC未复跑
---

## 一句话结论

服务端用 SM3 实现了一个“单次签名”：把 `SM3(message)` 的 32 个十六进制字符和 16 个按字符位置求和的校验字节拼成 48 个步长值，每个步长对应一条哈希链上的元素，签名就是这 48 个链元素。签名本应只给一次，但服务端允许对任意消息多次请求；攻击者可以对目标消息的 48 个步长逐位寻找“第 k 步长相同”的随机消息，分别请求签名并只取第 k 个元素，最后拼成目标消息的完整签名提交，从而伪造任意消息的签名。

## 原理

- **步长数组**：`compute_steps(m)` 先算 `sm3(m)` 的十六进制串（32 字符），把每个字符的 ASCII 值作为前 32 个步长；再对字符集 `0123456789abcdef` 分别求“该字符在哈希串中所有出现位置的 1-based 下标和 mod 255”，得到 16 个校验步长，共 48 个。
- **哈希链签名**：每个步长 `s` 对应 `H^s(secret_k)`（对第 k 段的密钥反复做 SM3）的链元素；签名者公开/返回这 48 个链元素。验证时按消息的步长数组对每个元素继续做 `H^(max-s)` 次哈希，与承诺/公钥比较。只要步长相同，验证方无法区分该链元素来自哪条消息。
- **单次签名被多次使用**：正常 OTS 只应签一条消息，签第二条就可能泄露不同步长的链元素；服务端却允许对任意消息多次请求（原文的菜单 1），于是攻击者获得一个“按位置选择链元素”的 oracle。
- **逐段伪造**：对目标消息 `happy for NepCTF 2025` 计算 48 个步长；对第 k 段，随机生成 8 字节消息，直到 `compute_steps(rnd)[k] == target_steps[k]`，请求该消息的签名，取 `sig[k]`。因为第 k 段步长相同，这个链元素对目标消息的第 k 段也有效。48 段全部收集后拼成目标签名，提交（菜单 2）即可通过验证。
- **为什么可行**：哈希链是单向的，无法从低步长推到高步长；但“相同步长”的链元素可以互换。48 段独立，每段只需找到一个同 step 的随机消息（平均 256 次尝试），总成本约 48×256 次哈希，远低于破解 SM3。
- **约束**：目标消息必须提前知道（题目给出 `happy for NepCTF 2025`）；若签名方案还绑定消息哈希/长度/会话，单纯拼接会失败；原文环境没有这些绑定。

## 触发条件

- 服务端提供“对任意消息签名”的 oracle，且没有强制一次性/每消息一次/速率限制；签名算法是基于 SM3 的哈希链 OTS。
- 攻击者知道目标消息内容（或能预测其步长数组），并能提交伪造签名。
- 步长数组只由消息的 SM3 与字符位置校验决定，不含随机盐/会话绑定。
- 每段哈希链长度 ≤255（步长字节），允许逐段碰撞；签名元素可被单独选取/拼接。
- 目标验证逻辑只按步长数组验证链元素，不检查签名来源消息。

## 利用步骤

1. 逆向/观察签名协议：确认签名是 48 个元素，`compute_steps(m)` 由 SM3 hex 字符 + 16 个校验和组成；确认服务端允许多次请求签名。
2. 计算目标消息的 48 个步长。
3. 对每个 k=0..47：随机生成消息，计算其步长数组，直到第 k 个值等于目标第 k 个值；向服务端请求该消息的签名，保存 `sig[k]`。
4. 把 48 个元素按顺序拼成列表，作为目标消息的签名提交。
5. 验证通过后读取 flag；若服务端限制请求速率，加入随机延迟/重试。

## PoC

```python
import socket, ssl, random
from ast import literal_eval
from gmssl import sm3

def sm3_bytes(m: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(list(m)))

def compute_steps(m: bytes) -> list[int]:
    hx = sm3.sm3_hash(list(m))
    a = list(hx.encode())              # 32 个十六进制字符的 ASCII 值
    checksum = []
    for sym in "0123456789abcdef":
        s = sum(pos for pos, ch in enumerate(hx, 1) if ch == sym) % 255
        checksum.append(s)
    return a + checksum                # 48 个步长

target = b"happy for NepCTF 2025"
tsteps = compute_steps(target)
qqs = [None] * 48

# 与服务端交互：菜单 1 请求签名，菜单 2 提交伪造签名
for k in range(48):
    want = tsteps[k]
    while True:
        rnd = random.randbytes(8)
        if compute_steps(rnd)[k] != want:
            continue
        # s.sendall(b"1\n"); recv_until(b"msg: "); s.sendall(rnd.hex().encode()+b"\n")
        line = recv_until(s, b"\n").decode().strip()
        sig = literal_eval(line)
        qqs[k] = sig[k]
        break

# s.sendall(b"2\n"); recv_until(b"give me a qq: ")
forged = "[" + ",".join(repr(x) for x in qqs) + "]"
# s.sendall(forged.encode()+b"\n"); print(recv_until(s, b"\n"))
```

原文使用 SSL socket 连接靶场，按菜单 1 获取随机消息签名、菜单 2 提交拼接签名；本卡未复跑。

## 变体与关联

- **其他哈希链 OTS**：Lamport/Winternitz 一次性签名也有“多签泄露/步长碰撞”风险；若服务端允许多次签名，可类推伪造。
- **步长碰撞优化**：不必为每段找全新随机消息，可预先构造一批消息、建立每个位置的步长→签名元素索引，减少交互次数。
- **绑定消息的变体**：若签名元素与消息哈希绑定（如签名值包含消息 hash），需找哈希碰撞或利用实现缺陷，不能直接拼接。
- **关联**：`[[crypto-implementation-gmssl-sm2-publickey-lstrip-hex-case]]`（国密实现细节）、`[[ctf-crypto-linear-hash-collision-lll]]`（哈希碰撞构造）、`[[ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root]]`（密码协议重用问题）。

## 检测与防御

- **协议设计**：一次性签名必须真正一次性——每消息/每密钥只签一次，签名后立即作废密钥；不要提供任意消息签名 oracle。
- **绑定**：签名元素应绑定消息哈希/长度/会话/随机数，避免跨消息拼接；使用标准签名（Ed25519/ECDSA/SM2）而不是自研哈希链 OTS。
- **限速与审计**：限制单位时间签名请求数，检测“大量随机短消息 + 最终提交目标消息”的模式；记录签名消息与提交签名的不一致。
- **验证端**：验证时检查签名来源消息/承诺，不只按步长数组验证链元素；对异常签名列表做长度/格式校验。
