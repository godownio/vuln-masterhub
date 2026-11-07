---
id: crypto-ecc-ecdsa-private-key-public-constant-derivation
title: ECDSA 私钥由公开字符串 SHA-512 模曲线阶派生：直接计算恢复私钥
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-private-key-public-constant-derivation
aliases:
- ECDSA 私钥可预测
- 公开常量派生私钥
- sha512 模曲线阶
- NIST521p 私钥恢复
tags:
- crypto
- ecdsa
- ecc
- private-key
- key-generation
- predictable
- nist521p
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:57:27+08:00'
  notes: 已对照原文 ECDSA 题核对：digest_int=int(sha512(b'Welcome to this challenge!'))，priv_int=digest_int % NIST521p.order，long_to_bytes(priv_int,66) 后 SigningKey.from_string 生成私钥；曲线阶与字符串均公开，攻击者可直接重算私钥并用导出公钥比对；60 条签名与 nonce 为干扰。卡片 PoC 与原文代码一致。未验证点：未运行 ecdsa 库复算；无 CVE/版本；frontmatter 无 sources/source_url。
---

## 一句话结论

签名程序把 ECDSA 私钥定义为 `int(sha512(公开固定字符串)) mod curve_order`，曲线阶与字符串都公开，因此攻击者不需要 nonce 复用或格攻击，直接按同样公式计算即可恢复私钥并伪造任意签名。

## 原理

- ECDSA 私钥本应是 `[1, n-1]` 内的均匀随机数；若用公开常量经确定性哈希派生，私钥空间退化为常量计算。
- 题目中 `digest_int = int.from_bytes(sha512(b"Welcome to this challenge!").digest(), "big")`，`priv_int = digest_int % curve_order`，曲线为 NIST521p；`long_to_bytes(priv_int, 66)` 后 `SigningKey.from_string` 创建签名密钥。
- 字符串、哈希算法、曲线阶均公开（曲线参数是标准值），攻击者本地重算得到相同 `priv_int`，再用 `SigningKey.from_string` 恢复私钥；公钥/签名文件只是干扰。
- 即使私钥长度看起来是 66 字节、签名文件有 60 条，也不影响：私钥生成逻辑完全在源码中，且没有加盐/秘密熵。
- 同类问题还包括：私钥由低熵口令、时间戳、进程 ID、固定种子、可预测 PRNG 派生；一旦派生输入可枚举，私钥即可恢复。

## 触发条件

- 目标源码/二进制泄露私钥派生逻辑，或派生输入是公开常量、低熵口令、时间戳等可枚举值。
- 使用标准曲线，曲线阶 `n` 可公开获取；派生过程没有秘密盐值或 HSM 保护。
- 攻击者能获得至少一份签名/公钥用于验证恢复结果，或直接知道曲线与派生公式。
- 私钥未做额外加密/分片，或加密密钥同样可预测。

## 利用步骤

1. 从源码/逆向结果提取私钥派生公式、哈希算法、公开字符串与曲线类型。
2. 查表获取曲线阶 `curve_order`（如 NIST521p 的标准 order）。
3. 本地计算 `digest = sha512(公开字符串)`，`priv_int = int(digest) % curve_order`。
4. 用相同字节长度（如 66 字节）构造私钥，创建 `SigningKey` 并导出公钥，与目标公钥比对确认。
5. 用恢复的私钥对任意消息签名，伪造身份/交易/证书；或直接解密依赖该私钥的会话。

## PoC

```python
from ecdsa import SigningKey, NIST521p
from hashlib import sha512
from Crypto.Util.number import long_to_bytes

curve_order = NIST521p.order
digest_int = int.from_bytes(sha512(b"Welcome to this challenge!").digest(), "big")
priv_int = digest_int % curve_order
priv_bytes = long_to_bytes(priv_int, 66)

sk = SigningKey.from_string(priv_bytes, curve=NIST521p)
print(sk.to_pem())                 # 恢复的私钥
print(sk.verifying_key.to_pem())   # 与目标公钥比对
```

无真实目标 PoC：原文为 CTF 题，公开字符串与曲线为该题参数；真实目标需替换为实际派生输入。

## 变体与关联

- **可枚举输入**：固定字符串、用户名、时间戳、递增 ID、进程 PID、MAC 地址、低熵口令。
- **弱 PRNG**：`random.seed(time)`、MT19937 状态恢复、Python `random` 生成私钥。
- **Nonce 问题**：确定性 nonce（RFC6979）本身安全；但 nonce 复用/偏置会导致私钥恢复（与本题不同）。
- **关联**：ECDSA nonce 复用、低熵私钥、可预测随机数、密钥派生函数误用。

## 检测与防御

- **私钥生成**：使用操作系统 CSPRNG（`secrets`/`os.urandom`/HSM）生成私钥；禁止用公开常量、时间戳、口令哈希直接派生。
- **KDF**：若必须从口令派生，使用 Argon2/scrypt/PBKDF2 + 高熵盐，并限制尝试次数；私钥最好由 HSM 生成且不可导出。
- **代码审计**：搜索 `SigningKey.from_string`、`private_key = hash(...) % order`、`random.seed`、固定字符串派生等模式。
- **检测**：监控同一公钥对应多份可疑签名、私钥派生代码中的固定常量；对已知 CTF/样本派生公式做指纹匹配。
- **响应**：一旦私钥可预测，立即轮换密钥、吊销证书、作废相关签名与会话。

## 可信度与边界

- 原文为 CTF crypto 题，源码直接给出派生公式，恢复私钥的计算简单且可验证；攻击链完整。
- 具体字符串/曲线为该题参数；真实目标需按实际派生逻辑复现。
- 未在真实目标复跑；卡内不包含题目 flag。
