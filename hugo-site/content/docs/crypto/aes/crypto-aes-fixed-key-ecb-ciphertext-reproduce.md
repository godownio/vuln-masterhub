---
id: crypto-aes-fixed-key-ecb-ciphertext-reproduce
title: 二进制内固定 key/明文的 AES-128 ECB 识别与密文复现
type: scenario
domain: crypto
path: crypto/aes
technique: aes128-ecb-fixed-key-ciphertext-reproduce
tags:
- crypto
- aes
- ecb
- reverse
- ctf
- constant-key
- sbox
- xtime
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T20:04:06+08:00'
  notes: 已对照原文 pwner_LEVEL4 与 14 张图核对：KeyExpansion128/AES128_EncryptBlock/SubBytes/ShiftRows/MixColumns/AddRoundKey/xtime 指纹、key=000102...0f、pt=001122...ff、movabs 小端 0x0706050403020100/0x0F0E0D0C0B0A0908/0x7766554433221100/0xFFEEDDCCBBAA9988、密文 69c4e0d86a7b0430d8cdb78070b4c55a（FIPS-197 向量）均与原文及代码一致。未验证点：未复跑 pycryptodome 加密（向量本身标准可核）；无版本。
url: /docs/crypto/aes/crypto-aes-fixed-key-ecb-ciphertext-reproduce/
draft: false
kb_aliases:
- AES-128 ECB 识别
- 固定 key 复现
- 常量密文
- AES 逆向
---

## 一句话结论

当二进制把 16 字节 key 与 16 字节明文硬编码、只比较 AES-128 ECB 的加密结果时，不需要破解 AES：从符号名（`KeyExpansion128`/`AES128_EncryptBlock`）或 S 盒、`xtime` 指纹识别算法，按 `movabs` 小端常量还原 key/明文，本地做一次 ECB 加密即可得到固定密文并通过校验。

## 原理

- AES 是确定性分组密码：给定相同的 16 字节 key 和 16 字节明文块，输出永远相同；ECB 模式不引入 IV/nonce，逐块独立加密，因此固定 key + 固定明文 → 固定密文。
- 识别指纹：反编译中出现 `KeyExpansion128`、`AES128_EncryptBlock`、`SubBytes`、`ShiftRows`、`MixColumns`、`AddRoundKey` 等符号（未去符号时）；S 盒 256 字节常量表；`xtime` 中的 `(x << 1) ^ ((x & 0x80) ? 0x1b : 0)`（GF(2^8) 乘 2）都是强特征。
- IDA 反编译中 key/明文常以 `movabs` 立即数出现：每 16 字节拆成两个 64 位小端整数。例如 `0x0706050403020100`、`0x0F0E0D0C0B0A0908` 对应 key `00 01 02 ... 0f`；`0x7766554433221100`、`0xFFEEDDCCBBAA9988` 对应明文 `00 11 22 ... ff`。
- 把这些整数按 8 字节小端写回字节串并拼接，得到原始 key/明文；用同版本 AES 实现（pycryptodome）做一次 ECB 加密，得到程序期望的固定密文。本题即 FIPS-197 标准测试向量，密文为 `69c4e0d86a7b0430d8cdb78070b4c55a`。
- 之所以成立：程序没有随机 IV、没有对 key/明文做外部输入或派生，校验只是一个固定的“常量比较”，攻击者本地复现即可通过。

## 触发条件

- 二进制内硬编码 AES key 与明文（或可预测常量），并仅比较加密结果。
- 算法为 ECB 或使用固定 IV/nonce 的其他模式；没有每次运行随机化的盐/IV。
- 能反编译/反汇编取到常量（未加壳或可脱壳），并能识别 AES 实现。
- 攻击机有同语义的 AES 实现（标准 AES 即可；若目标魔改 S 盒/轮数则需按其实现复现）。

## 利用步骤

1. 用 `checksec`/`strings`/符号表初判；未去符号时直接看到 `KeyExpansion128`、`AES128_EncryptBlock` 等函数名。
2. 反编译 main，找到 key/明文的 `movabs` 常量与校验逻辑（如 `strcmp(got, expected)`）。
3. 将每个 64 位常量按 `to_bytes(8, "little")` 转回字节，按顺序拼接出 16 字节 key 与 16 字节明文。
4. 用 pycryptodome 执行 `AES.new(key, AES.MODE_ECB).encrypt(pt)`，得到密文 hex。
5. 将 hex 发给程序；若程序无 `setvbuf` 缓冲，可直接 `sendline`，匹配后进入 shell/执行后续命令。

## PoC

```python
from Crypto.Cipher import AES

# 从 main 的 movabs 立即数中抄出的两组 64 位常量
v5 = [0x0706050403020100, 0x0F0E0D0C0B0A0908]   # key
v6 = [0x7766554433221100, 0xFFEEDDCCBBAA9988]   # plaintext

key = b"".join(x.to_bytes(8, "little") for x in v5)
pt  = b"".join(x.to_bytes(8, "little") for x in v6)

ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
print(ct.hex())          # 69c4e0d86a7b0430d8cdb78070b4c55a（FIPS-197 测试向量）
```

```python
from pwn import *
io = remote("目标ip", 端口)
io.sendline(b"69c4e0d86a7b0430d8cdb78070b4c55a")
io.sendline(b"cat ./flag")
io.interactive()
```

## 变体与关联

- 变体：CBC/CTR/CFB 使用固定 IV/nonce 时，同样可本地复现；若 IV 随机但随密文发送，需按协议提取。
- 变体：key 由固定口令经简单 KDF 派生时，先复现 KDF；若 key 来自用户输入，则问题转为密钥可控/弱密钥。
- 变体：目标使用 AES-NI 或查表实现时，识别指纹不同（AESENC 指令、T 表），但常量与复现方法相同。
- 关联：[[code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge]]（前端 AES-CBC 参数还原与请求伪造）、[[crypto-prng-mt19937-clock-seed-wallet-key-recovery]]（另一类固定/可预测密钥材料问题）。

## 检测与防御

- 检测：逆向审计中搜索固定 key/IV、AES S 盒与 `xtime` 常量；对二进制中硬编码密钥做 secret scanning。
- 修复：不要把密钥硬编码在客户端；使用随机 IV/nonce 与认证加密（AES-GCM/ChaCha20-Poly1305）；校验值不要直接比较可离线计算的常量密文。
- 加固：对关键校验引入服务端随机挑战/会话绑定；对二进制做符号剥离与代码混淆只能提高分析成本，不能替代密钥管理。
