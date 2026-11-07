---
id: ctf-crypto-aes-cbc-prefix-padding-key-xor-hint
title: AES-CBC 自定义前置填充 + key⊕首块 hint：已知 flag{ 前缀爆破单字符恢复 key
type: scenario
domain: ctf
path: ctf/crypto
technique: aes-cbc-prepadding-key-xor-hint
aliases:
- AES-CBC 双重填充
- key 与首块异或
- hint 泄露 key
- 前置 padding
- PKCS7 二次填充
- flag 前缀爆破
tags:
- ctf
- crypto
- aes
- cbc
- padding
- key-recovery
- known-plaintext
- brute-force
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:04:57+08:00'
  notes: 已对照 91111 原文第七题核对：前置 0x0a 填充、PKCS7、hint=key⊕首块、flag{ 前缀爆破单字符及末块 0x10*16 校验均一致。PoC 未在本机复跑。
---

## 一句话结论

题目先用自定义函数把 `16-len%16` 个值等于该长度的字节**前置**到明文，再做标准 PKCS7 填充后 AES-CBC 加密；同时泄露 `hint = key ⊕ message[:16]`。由于 flag 以 `flag{` 开头，首块内容是固定的 10 字节 `\x0a` + `flag{` + 1 个未知字符，只需爆破这 1 个字符即可从 hint 还原 AES key；再用最后一块解密后应为 `\x10*16` 验证 key，随后按 CBC 逐块解密恢复完整 flag。

## 原理

- **自定义前置填充**：`tmp = 16 - len(msg) % 16`，`pad = bytes.fromhex(format(tmp,'02x') * tmp)`，返回 `pad + msg`。注意是加在明文前面而不是末尾；当 len=38 时 tmp=10，得到 `\x0a*10 + flag`，长度 48。
- **标准 PKCS7**：前置填充后再调用 `pad(message,16,'pkcs7')`，48 字节补到 64 字节，最后一块为 `\x10*16`。双重填充让首块包含 flag 的前 6 个字符，末块可作 key 校验。
- **hint 泄露**：`hint = bytes_to_long(key) ^ bytes_to_long(message[:16])`。AES-128 key 为 16 字节，首块也为 16 字节，因此 hint 是逐字节 XOR，知道首块即可直接得到 key。
- **已知前缀**：flag 格式为 `flag{...}`，首块 = `\x0a*10 + "flag{" + flag[5]`。只有第 6 个字符未知，枚举可打印字符（约 95 个）即可。
- **校验**：对每个候选 key，用 AES-ECB 解密最后一块密文 `C3`，再与 `C2` 异或得到 P3；正确 key 下 P3 必须等于 `\x10*16`。这一步同时验证 key 和填充。
- **逐块解密**：CBC 中 `P_i = D(C_i) ⊕ C_{i-1}`（C0 为 IV）。拿到 key 后可解出 Block1、Block2；Block0 已知，最后一块是填充，去掉前置填充与 PKCS7 即得 flag。
- **为什么可复用**：任何“泄露 key 与已知明文块异或”的实现都可按同样思路恢复 key；已知前缀越长，爆破空间越小。注意 hint 可能是整数异或，需按 16 字节大端对齐。

## 触发条件

- 使用 AES-CBC，key 长度与块大小一致（16 字节），且泄露 `key XOR 某个明文块` 的值。
- 该明文块有足够长的已知前缀（如 `flag{`、固定 header、JSON 开头），剩余未知字符可爆破。
- 有至少一个块可用于校验（固定 PKCS7 填充、已知末块、已知结构字段）。
- 能获得密文与 IV（或首块密文可作后续块的 IV）。

## 利用步骤

1. 解析密文为 16 字节块；确认总长度与块数（本例 4 块）。
2. 确定自定义填充规则与已知前缀，构造首块的候选明文：`b'\x0a'*10 + b'flag{' + c`。
3. 对每个候选字符 c，计算 `key = xor(hint, candidate_block)`。
4. 用该 key 解密最后一块，异或前一块密文，检查结果是否为 `\x10*16`；不匹配则换下一个 c。
5. 命中后得到 key；按 CBC 逐块解密 Block1、Block2，拼接首块已知部分，去除 PKCS7/前置填充。
6. 用 flag 格式与已知字段校验结果；若未知字符不止一个，可扩展为多字符爆破或利用语言/格式约束剪枝。

## PoC

```python
from Crypto.Cipher import AES
import string

enc = bytes.fromhex('1ce1df3812668ce0bccd86c146cc56989681e128edd0676f5d26e01abdee90c860e22a5a491f94ac5ca3ab02242740fb8c35a3b60ea737ca0d2662fba2b0e299')
hint = bytes.fromhex('32393f4e3c3c4f3e323a512a5356437d')
blocks = [enc[i:i+16] for i in range(0, 64, 16)]

for c in string.printable.strip():
    msg_block0 = b'\x0a' * 10 + b'flag{' + c.encode()
    key = bytes([h ^ m for h, m in zip(hint, msg_block0)])
    cipher = AES.new(key, AES.MODE_ECB)

    dec3 = cipher.decrypt(blocks[3])
    plain3 = bytes([d ^ x for d, x in zip(dec3, blocks[2])])
    if plain3 != b'\x10' * 16:
        continue

    dec2 = cipher.decrypt(blocks[2])
    plain2 = bytes([d ^ x for d, x in zip(dec2, blocks[1])])
    dec1 = cipher.decrypt(blocks[1])
    plain1 = bytes([d ^ x for d, x in zip(dec1, blocks[0])])
    print((b'flag{' + c.encode() + plain1 + plain2).decode())
    break
```

说明：原文答案为 `flag{IADMIN-TOP-18880101-7634567_2025}`；PoC 未在本机复跑。

## 变体与关联

- **hint 变体**：`key XOR 首块`、`key XOR 末块`、`key 的部分字节泄露`、`明文块 XOR 固定常量`；关键是找到“已知明文块 + 可爆破少量未知”的组合。
- **填充变体**：前置/后置自定义填充、双重 PKCS7、零填充、长度头 + PKCS7；校验块可能是固定填充、固定 magic 或已知 JSON 结尾。
- **CBC 变体**：IV 已知/未知（未知时首块只能恢复为 `P0 = D(C0) XOR IV`，但后续块仍可解）；CTS/PCBC 需按模式调整。
- **关联卡片**：[[crypto-aes-cbc-padding-oracle-certificate-service]]（CBC 填充预言机）、[[ctf-crypto-cdf-comments-qhalf-bit-encoding-aes]]（隐藏 key 后解 CBC）、[[ctf-crypto-aes-ecb-duplicated-char-circular-xor]]（AES 变体逆向）。
- **边界**：若 hint 不是逐字节 XOR（例如整数异或后截断/带偏移），需按实际编码还原；若未知前缀字符过多且无校验块，爆破空间不可行。

## 检测与防御

- **CTF 识别**：代码中同时出现自定义 padding、`key ^ message[:16]` 形式 hint、AES-CBC 加密，基本就是本类题。
- **防御（密码实现视角）**：不要泄露 key 与任何明文块的异或；不要用自定义填充替代标准 AEAD；AES-CBC 应配合 MAC/EtM 或直接使用 AES-GCM。
- **审计**：搜索日志/调试接口中的 `hint`、`xor`、`key ^` 字段；密钥材料不得进入日志或响应。
- **取证/验证**：保留密文、IV、hint 与填充规则；恢复 key 后用多块/多记录交叉验证，避免单块误判。
