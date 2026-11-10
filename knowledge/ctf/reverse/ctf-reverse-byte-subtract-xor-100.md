---
id: ctf-reverse-byte-subtract-xor-100
title: 字节数组逆变换：每字节减 10 再异或 100 还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: byte-array-subtract-xor-100-decrypt
aliases:
- EZAPP 解密
- 字节减 10 异或 100
- 简单异或加密逆向
- 逐字节可逆变换
tags:
- ctf
- reverse
- byte-transform
- xor
- obfuscation
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:11:17+08:00'
  notes: 已对照原文 EZAPP 解密脚本与 38 字节数组核对；(b-10)^100 首字节 12→'f'，复算结果 flag{3af85f5d603293610a9fca4813439b44} 与原文一致。未复现。
---

## 一句话结论

应用把 flag 按“加密 = `(byte ^ 100) + 10`”的逆关系逐字节变换后存成字节数组；提取该数组（本题 38 字节）后执行 `(b - 10) ^ 100` 即可还原明文 `flag{3af85f5d603293610a9fca4813439b44}`。

## 原理

- 逐字节变换是顺序无关、无状态的可逆映射：解密公式 `pt = (ct - 10) ^ 100`，等价加密为 `ct = (pt ^ 100) + 10`（字节运算按 mod 256）。
- 因为每一步只依赖当前字节，不需要密钥、IV 或位置信息；拿到整个加密数组就能还原，不能还原通常说明方向/运算顺序或字节宽度搞错。
- 常量 `10` 与 `100` 都很小，变换后仍落在 0~255 的字节范围内；这类“加减 + 异或”常用于轻量混淆，让人不能直接 `strings` 出 flag。
- 原文的 `decrypt` 函数就是 `[(b - 10) ^ 100 for b in encrypted_bytes]`，说明加密端先异或后加；本题第一个字节 `12` 经 `(12-10)^100 = 102 = 'f'`，与 flag 前缀一致，可直接验证方向。

## 触发条件

- 能从应用/二进制/配置中提取到完整的加密字节数组。
- 已知明文格式（如 `flag{`）可用于验证变换方向与常量。
- 变换是逐字节、无状态、可逆的；若存在密钥流/分组，需先恢复密钥/模式。

## 利用步骤

1. 从应用资源、逆向代码或配置中提取加密字节数组。
2. 写出候选逆变换：先减后异或、先异或后减、加/减互换，逐一尝试。
3. 用已知前缀（`flag{`、`CTF{`）验证：输出开头可打印即方向正确。
4. 按 UTF-8 解码并输出完整明文。
5. 若部分字节不可打印，检查是否按 mod 256、是否有第二层编码（Base64/hex）或字节序问题。

## PoC

```python
encrypted_bytes = [
    12, 18, 15, 13, 41, 97, 15, 12, 102, 91, 12, 91, 10, 92, 94, 97,
    96, 103, 97, 92, 95, 94, 15, 103, 12, 17, 15, 90, 102, 95, 97, 90,
    97, 103, 16, 90, 90, 35,
]

def decrypt(data):
    return bytes(((b - 10) ^ 100) & 0xFF for b in data).decode("utf-8")

print(decrypt(encrypted_bytes))
# flag{3af85f5d603293610a9fca4813439b44}
```

## 变体与关联

- **运算顺序互换**：`(b ^ 100) - 10`、`(b + 10) ^ 100`、`(b ^ 100) + 10`；用 `flag{` 前缀快速判定。
- **多位常量**：`(b - k1) ^ k2`、循环移位后异或、按索引递增的 key；用已知明文与频率分析恢复。
- **多字节密钥**：若逐字节结果不可读，尝试重复 key、RC4/滚动异或或 Base64 外层。
- 关联：[[ctf-reverse-modified-rc4-keytable-subtract-xor]]（自定义 RC4 + 加减/异或）、[[ctf-misc-firmware-eeprom-byte-transform-bruteforce-flag]]（固件字节变换枚举还原）。

## 检测与防御

- 这类逐字节变换只是混淆，不构成安全保护；密钥/常量随程序下发，逆向即可还原。
- 对真实敏感数据应使用标准加密（AES-GCM 等）与妥善管理的密钥，而不是加减/异或。
- 检测/分析侧：对二进制/应用资源中出现的高熵小数组，先试单字节 XOR/加减变换；用已知前缀验证。
