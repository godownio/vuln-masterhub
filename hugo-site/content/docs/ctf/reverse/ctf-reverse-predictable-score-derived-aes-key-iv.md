---
id: ctf-reverse-predictable-score-derived-aes-key-iv
title: 可预测分数派生 AES key/IV：从高分值解密硬编码密文
type: scenario
domain: ctf
path: ctf/reverse
technique: predictable-score-derived-aes-key-iv
tags:
- ctf
- reverse
- aes
- key-derivation
- game
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:07+08:00'
  notes: 已对照原文 Cheater Cheater 核对：score=6942069、key_str=str((10*score+1)^4)、key/iv 用 fromhex 与反转、AES-CBC 解 Base64 密文均一致；未实际运行。
url: /docs/ctf/reverse/ctf-reverse-predictable-score-derived-aes-key-iv/
draft: false
kb_aliases:
- 游戏分数派生密钥
- Cheater Cheater
- AES key/IV 可预测
- 高分值解密
- 硬编码密文
---

## 一句话结论

游戏把胜利条件写死为 `score >= 6942069`，胜利后用 `key_str = str(((10*score)+1)^4)` 派生 AES key 与 IV（IV 为 key_str 反转），再解密硬编码的 Base64 密文；由于高分值/胜利分数是公开且可预测的，攻击者直接代入该分数即可复现 key/IV 并解出 flag。

## 原理

- 逆向游戏逻辑可见：达到胜利分数后执行 `key_str = ((10*score)+1)^4` 的十进制字符串，`key = hexStringToByteArray(key_str)`，`iv = hexStringToByteArray(reverse(key_str))`，再用 AES-CBC 解密一段 Base64 密文。
- 密钥材料完全由 `score` 决定，而 `score` 是游戏内可达到/已显示的值（Highscore 栏就是 `6942069`），不是秘密随机数；攻击者无需玩游戏，直接代入即可。
- `key_str` 的十进制长度必须满足 AES key 与 IV 的字节长度（示例为 32 个十六进制字符 = 16 字节），否则实现会截断/报错；逆向时先确认长度与编码。
- IV 由 key_str 反转得到，进一步降低了独立性：只要知道 score，key 与 IV 同时确定。
- 这是“密钥派生自公开/可预测输入”的典型场景；同类问题包括用时间戳、用户名、关卡号、随机种子等派生密钥。

## 触发条件

- 逆向目标中存在硬编码密文与确定性密钥派生逻辑。
- 密钥派生输入（分数、关卡、时间、用户名等）可预测或可从界面/存档/配置获得。
- 加密算法与参数（AES 模式、key/IV 长度、编码）可从代码或常量识别。
- 密文使用 Base64/hex 等可提取编码。

## 利用步骤

1. 逆向/反编译目标，定位胜利条件与解密函数。
2. 提取 key/IV 派生表达式、AES 模式、密文常量。
3. 确定派生输入的取值（如 Highscore 显示 `6942069`，或从存档读取）。
4. 复现 `key_str`，按代码的编码方式转成字节；确认 key/IV 长度。
5. 用 AES-CBC 解密 Base64 密文，去 PKCS#5/7 填充，得到 flag。
6. 若解密失败，检查字节序、hex 大小写、IV 反转方向、是否使用 ECB/CTR。

## PoC

```python
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def unpad_pkcs5(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return data[:-pad]

def decrypt_flag(score: int) -> str:
    x = (10 * score + 1) ** 4
    key_str = str(x)
    key = bytes.fromhex(key_str)
    iv = bytes.fromhex(key_str[::-1])
    ct = b64decode("6Ach6HiD0JmCc1L+RwxDRzhW3sC1kS6XydgSuWVFpxVXRU8EjfuMxIMoIzMwK/ii")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return unpad_pkcs5(pt).decode()

print(decrypt_flag(6942069))
```

## 变体与关联

- 变体：key 由关卡号、用户名、时间戳、随机种子派生；可从存档、配置、界面或反编译常量获得。
- 变体：IV 固定为全零或与 key 相同，降低安全性。
- 变体：使用 ECB 模式，无需 IV，直接按块解密。
- 关联：[[ctf-reverse-png-lsb-custom-sbox-aes256-decrypt]]（逆向 AES 变体）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定密钥 ECB）、[[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]]（自定义 AES）。

## 检测与防御

- 防御：不要用公开/可预测值派生加密密钥；使用 CSPRNG 生成随机密钥，或通过 KDF 从高熵秘密派生。
- 防御：密钥与 IV 应独立随机；不要把密钥硬编码在客户端或随游戏分数变化。
- 检测：逆向中发现 `AES`、`key = f(score)`、`iv = reverse(key)`、硬编码 Base64 密文等模式。
- 响应：确认密钥可预测后，视为加密失效，轮换密钥并重新加密敏感数据。
