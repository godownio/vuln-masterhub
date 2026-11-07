---
id: ctf-reverse-base58-xor-key-bruteforce
title: 静态取初始密文 + Base58 解码 + 单字节 XOR 爆破还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: static-ciphertext-base58-xor-bruteforce
tags:
- ctf
- reverse
- base58
- xor
- brute-force
- ida
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:16:56+08:00'
  notes: 已对照原文与图片核对；unk_6280常量、Base58解码、单字节XOR爆破key=37均一致；已修正frontmatter domain为ctf；PoC未本机执行
url: /docs/ctf/reverse/ctf-reverse-base58-xor-key-bruteforce/
draft: false
kb_aliases:
- baseXor
- unk_6280 初始密文
- Base58 XOR 爆破
- 单字节 XOR key 37
- 不逆加密函数直接取常量
---

## 一句话结论

逆向上遇到“输入正确才输出密文、加密函数很复杂”的题目时，先判断密文是否与输入无关；若是，跳过硬啃加密函数，直接在 IDA 中找初始状态常量（如 `std::string::basic_string(&unk_6280, "22WUmJYS...")`），对该常量做 Base58 解码，再对结果爆破单字节 XOR（用 `flag{` 前缀筛选），即可得到明文 flag（文章 key=37）。

## 原理

- **密文与输入无关**：`main` 只在输入等于 `target` 时调用输出函数，输出函数的初始状态来自全局常量 `unk_6280`，输入不参与密文生成；因此不需要恢复加密算法，只要找到常量即可。
- **常量形态判断**：`"22WUmJYSXzCB4oPF3yU8StBppbXJwAMTHjfe7cWSb"` 只含 Base58 字母表（无 `0OIl`），长度较长，优先尝试 Base58 解码；解码结果看起来是经过 XOR 掩码的可读字符串。
- **单字节 XOR 爆破**：对 Base58 解码后的每个字节与候选 key（0–255）异或，筛选结果以 `flag{` 开头或全部可打印的 key；文章得到 key=37，解出 `flag{X0r_Base_Are_G00d_Br0ther}`。
- **为什么有效**：XOR 是对称且单字节的，密钥空间只有 256；已知明文前缀（`flag{`）或可打印性足以唯一确定 key。Base58 只是外层编码，不改变内层 XOR 的可爆破性。

## 触发条件

- 题目为本地逆向/CTF 逆向，二进制可静态分析（IDA/Ghidra）。
- 密文生成与输入无关，或输入只决定是否输出，全局常量保存初始密文。
- 外层是 Base58/Base64 等可逆编码，内层是单字节 XOR 或密钥空间很小的变换。
- 已知 flag 格式前缀（如 `flag{`）或可打印字符约束。

## 利用步骤

1. IDA 打开 `main`，定位输入校验与输出函数；确认输出内容不依赖输入。
2. 查找输出函数的初始状态/全局常量引用（如 `std::string::basic_string` 的第二个参数、`.data` 中的字符串）。
3. 提取常量字符串，按字符集判断 Base58/Base64 并解码。
4. 对解码结果做单字节 XOR 爆破：`for key in range(256): xor(...)`，用 `flag{` 前缀或可打印性筛选。
5. 输出明文 flag；若单字节不成立，尝试多字节重复 key（可用已知前缀推导 key 长度）。

## PoC

```python
import base58

s = "22WUmJYSXzCB4oPF3yU8StBppbXJwAMTHjfe7cWSb"
raw = base58.b58decode(s)

for key in range(256):
    out = bytes(b ^ key for b in raw)
    if out.startswith(b"flag{"):
        print(key, out.decode())
        break
# 37 b'flag{X0r_Base_Are_G00d_Br0ther}'
```

若常量不是标准 Bitcoin Base58 字母表，按题目/程序中的表替换 `base58` 实现；若 XOR 为多字节，先用 `flag{` 与密文逐字节异或推出 key 片段，再确定周期。

## 变体与关联

- **换表 Base58/Base64**：自定义字母表时先恢复表；参见 [[ctf-reverse-base64-custom-table-then-repeating-xor]] 等换表编码逆向卡。
- **多字节 XOR**：key 长度可通过已知明文前缀与密文异或的周期性判断；也可用可打印性/字符集评分爆破。
- **其他外层编码**：Base85、Base62、十六进制、压缩（zlib/gzip）可与 XOR 组合，按数据特征逐层剥离。
- **静态常量定位**：除 `std::string` 构造外，还可用 xrefs 追 `unk_6280`、`.rdata`/`.data` 中的长字符串、`memcpy` 初始化等。

## 检测与防御

- 此类为 CTF 离线逆向，不涉及目标系统防御；真实软件若用单字节 XOR/Base58 混淆敏感字符串，容易被已知明文与爆破还原，应使用标准加密/KDF 并保护密钥。
