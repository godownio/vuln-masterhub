---
id: crypto-aes-short-password-sha256-triple-cbc-bruteforce
title: 三重 AES-CBC + sha256(3 字符) 密钥穷举：PKCS7 与 UUID 格式剪枝恢复 flag
type: scenario
domain: crypto
path: crypto/aes
technique: short-password-sha256-triple-aes-cbc-bruteforce
aliases:
- EasyAES
- 3 字符密钥穷举
- sha256 派生 AES 密钥
- 三重 AES-CBC
- PKCS7 剪枝爆破
- UUID 格式校验
tags:
- crypto
- aes
- cbc
- brute-force
- sha256
- pkcs7
- short-key
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:06:05+08:00'
  notes: 已对照原文核对加密链：k0=sha256(3字符)对flag做AES-CBC得c0，k1=sha256(3字符)对c0连续三次AES-CBC得c3；62³≈23.8万密钥空间、PKCS7+UUID正则双重剪枝与原文脚本一致，卡内unpad修正为≤16字节。未验证点：原文给出完整脚本但未展示最终flag输出，卡已标confidence=medium；未复跑；frontmatter无sources/source_url；无版本。
---

## 一句话结论

加密流程为 `c0 = AES-CBC(flag, key0)`、`c3 = AES-CBC(AES-CBC(AES-CBC(c0, key1), key1), key1)`，其中 `key = sha256(3 字符明文)`；由于每个密钥空间只有 62³≈23.8 万，可先对 `c3` 连续三次 AES-CBC 解密并用 PKCS7 补位合法性筛出 `key1`，再对得到的 `c0` 用 `key0` 候选解密并用 UUID/flag 格式正则校验，即可恢复明文 flag。多进程/批量处理可加速。

## 原理

- **短密钥派生**：密钥不是随机 128/256 位，而是 `sha256(3 字符明文)`；3 字符字母数字组合只有 62³=238,328 种，穷举成本极低。
- **三重加密**：同一 `key1` 对 `c0` 连续加密三次，每层都是 AES-CBC 且密文格式为 `IV(16 字节) || ciphertext`；解密时按相反顺序做三次，只有正确的 `key1` 才能让三层都得到合法 PKCS7 填充。
- **PKCS7 剪枝**：错误密钥解密出的最后一字节恰好是 1..16 且尾部重复的概率约 1/256 左右（甚至更低），三次都通过的概率极低；因此 `key1` 的 23.8 万候选只需少量 AES 运算即可筛到唯一/极少候选。
- **格式剪枝 `key0`**：`c0` 解密后应是以 `flag{` 开头的 UUID 形式（如 `^[0-9A-Fa-f]{8}-...$`）；用正则匹配可直接确认 `key0`，无需再做额外 oracle。
- **复杂度**：k1 穷举约 23.8 万次三层解密；k0 可在命中 k1 后穷举，或用同样 PKCS7/格式校验提前筛选；多进程按批次并行即可在秒级到分钟级完成。

## 触发条件

- 已知完整密文 `c3`（含每层 IV），且加密流程/密钥派生方式（`sha256(3 字符)`、AES-CBC、三重加密）已知。
- 密钥空间足够小（3 字符字母数字、或已知字符集/长度）；填充方式为 PKCS7/PKCS5。
- 明文有可识别的格式（flag{...} UUID、JSON、已知前缀），可作为最终剪枝条件。
- 能承受约 10⁵–10⁶ 次 AES 解密计算（多进程/GPU 更快）。

## 利用步骤

1. 确认密文格式：每层 AES-CBC 输出为 `IV || ciphertext`，从 `c3` 开始。
2. 生成 k1 候选：字符集（如 `a-zA-Z0-9`）的所有 3 字符组合，`sha256(seg).digest()` 作为 AES key。
3. 对每个 k1 候选连续三次解密：`t1=dec(k1,c3)`、`t2=dec(k1,t1)`、`t3=dec(k1,t2)`；任一层 PKCS7 校验失败即丢弃。
4. 得到候选 `c0` 后，生成 k0 候选并做一次解密；用 UUID/flag 正则校验明文，命中即为 flag。
5. 用多进程按批次分发 k1 候选，命中后终止；记录 k0/k1 字符段。
6. 若没有输出，检查 IV 处理、密钥/密文 hex 编码、填充长度（AES 块 16 字节）是否正确。

## PoC

```python
import hashlib, itertools, re, multiprocessing as mp
from Crypto.Cipher import AES

c3_hex = "62343dfc...ef74"  # 原文完整密文
data = bytes.fromhex(c3_hex)
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
UUID_RE = re.compile(rb"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

def unpad(b):
    p = b[-1]
    if p < 1 or p > 16 or b[-p:] != bytes([p]) * p:
        raise ValueError("bad pad")
    return b[:-p]

def dec(key, blob):
    iv, ct = blob[:16], blob[16:]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))

def try_k1(seg):
    k1 = hashlib.sha256(seg.encode()).digest()
    try:
        t1 = dec(k1, data)
        t2 = dec(k1, t1)
        c0 = dec(k1, t2)
    except ValueError:
        return None
    for seg0 in ("".join(t) for t in itertools.product(ALPHABET, repeat=3)):
        k0 = hashlib.sha256(seg0.encode()).digest()
        try:
            pt = dec(k0, c0)
        except ValueError:
            continue
        if UUID_RE.match(pt):
            return seg, seg0, pt.decode()
    return None

# 多进程遍历 k1 候选；命中后输出 k1/k0/flag
```

说明：原文给出完整脚本与密文；本卡为结构化精简，未在本机复跑，也未在原文中看到最终 flag 输出，因此 confidence 标为 medium。实际密钥字符集/长度以题目为准；`unpad` 在 AES 下应限制 pad ≤16。

## 变体与关联

- **部分密钥后缀爆破**：[[crypto-aes-partial-key-suffix-bruteforce]] 已知 12 字节前缀、穷举 3 字节后缀；本卡的密钥由 3 字符口令经 sha256 派生，且叠加三重 CBC。
- **CBC 前缀/填充提示**：[[ctf-crypto-aes-cbc-prefix-padding-key-xor-hint]] 用已知 flag 前缀与 key⊕hint 逐字符恢复 key。
- **填充预言机**：[[crypto-aes-cbc-padding-oracle-certificate-service]] 用服务端两种错误响应逐字节恢复；本卡是离线暴力 + 填充合法性剪枝。
- **边界**：若密钥空间更大（≥5 字符）、密钥经过慢 KDF（PBKDF2/argon2）或密文缺少 IV/层数未知，穷举成本会急剧上升，需要改用字典/已知明文攻击/侧信道。

## 检测与防御

- 防御：不要用短口令直接 sha256 作为 AES 密钥；使用随机生成的 128/256 位密钥与 PBKDF2/Argon2 等慢 KDF 派生口令密钥。
- 防御：使用 AEAD（AES-GCM）或至少 HMAC 完整性校验，避免仅靠 PKCS7 填充判断正确性；为每层使用随机 IV。
- 检测：CTF/审计中识别 `sha256(短字符串)` 作为密钥、固定 IV、重复多层 CBC 加密等弱模式；对密文做熵与密钥空间评估。
- 响应：若真实系统使用短口令派生密钥，立即轮换密钥并迁移到强 KDF/AEAD；评估密文是否已被离线爆破。
