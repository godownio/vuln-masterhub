---
id: ctf-crypto-base32-custom-alphabet-cyberchef-decode
title: Base32 自定义字母表识别与解码：从二进制取出 32 字符换表后用 CyberChef From Base32 一键还原
type: scenario
domain: ctf
path: ctf/crypto
technique: base32-custom-alphabet-table-decode
tags:
- ctf
- crypto
- base32
- custom-alphabet
- cyberchef
- encoding
- rust
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:54:59+08:00'
  notes: 已对照原文与图02/03核对：密文 N2XHD244PSVED53BHG2W7ZSVNK5W7ZSVPOTUHNUtable、From Base32 自定义 Alphabet AC-Z2-7B=、Remove non-alphabet chars、输出 flag{th1s_1s_b4by_b4se32 均与截图一致。已实际复算：按 CyberChef 区间语法展开为 ACDEFGHIJKLMNOPQRSTUVWXYZ234567B 后用 base64.b32decode 得到 b'flag{th1s_1s_b4by_b4se32'，与截图完全一致；查明原文密文去掉误粘的小写 table 后为 39 字符（非 8 的倍数），故截图输出缺右花括号。已修正卡片 PoC：字母表不能按字面 8 字符使用（原脚本会 KeyError），改为展开后的 32 字符表；明文由 this 改为 th1s 并注明截图无 }。dedup 与 Base64/B85/字符表类卡为 related 非同链（已知 Base32 表直接解码，无 oracle 恢复）。
url: /docs/ctf/crypto/ctf-crypto-base32-custom-alphabet-cyberchef-decode/
draft: false
kb_aliases:
- Base32 变表
- 自定义 base32 字母表
- From Base32 CyberChef
- base32 换表解密
- 32 字符编码表
- Rust base32 变表
---

## 一句话结论

当密文由大写字母/数字组成、长度和填充符合 Base32，但用标准 Base32 解不出明文时，多半是换了字母表：在二进制/伪代码中找到那 32 个字符的编码表（如 `AC-Z2-7B=` 一类重排；这是 CyberChef 的区间语法，展开后为 32 字符），在 CyberChef 的 From Base32 里把 Alphabet 改成该表（勾选 Remove non-alphabet chars）即可直接解码；脚本实现则用换表后的索引做位重组或先映射回标准表。

## 原理

- **Base32 的本质**：每 5 个字符（5 bit）表示 40 位，对应 5 字节输入；字符到 0-31 索引的映射由 alphabet 决定。标准表是 `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`，换表只是把索引 i 对应的字符换成自定义序列。
- **识别特征**：密文仅含自定义表内字符、长度为 8 的倍数（含 `=` 填充）、解码后无意义；反编译代码中出现 `base32::Encoding::encode`（Rust）或一张 32 字节常量表/字符串，即可确认。
- **换表来源**：题目常把表硬编码在二进制里（本例表为 `AC-Z2-7B=`，是 CyberChef 区间记法，展开为 `ACDEFGHIJKLMNOPQRSTUVWXYZ234567B` 共 32 字符）；也可能在运行时生成/异或解密，需要先提取或 hook。
- **解码方式**：CyberChef 的 From Base32 允许自定义 Alphabet，内部把每个字符映射到其在新表中的索引，再按 5 位一组重组字节；等价于先用标准表做字符替换 `translate` 再调用标准解码。
- **注意**：表必须恰好 32 个有效字符（填充符 `=` 不计入），顺序要与题目一致（有的题表是逆序/大小写混合）；若解码结果接近明文但错位，检查表是否从 0/1 起始或含填充符占位。

## 触发条件

- 密文字符集/长度符合 Base32，标准解码失败。
- 能拿到自定义 alphabet（二进制常量、伪代码、字符串、或从编码逻辑推导）。
- 需要快速还原明文（CTF/授权测试）。
- 仅用于 CTF/授权逆向。

## 利用步骤

1. 观察密文：字符集是否为大写字母+数字、长度是否为 8 的倍数、是否有 `=` 填充，初步判断 Base32。
2. 在二进制中搜索候选表：32 个连续可打印字符（常出现在 .rodata/字符串）、或反编译代码里对表的引用；确认其为编码 alphabet。
3. 用 CyberChef：`From Base32` 操作，Alphabet 填自定义表，勾选 Remove non-alphabet chars，输入密文查看 Output。
4. 或写脚本：先按自定义表把每个字符替换成标准表对应字符（`str.translate`），再 `base64.b32decode`（补 `=` 到 8 的倍数）。
5. 验证输出是否为可读明文/flag；若乱码，核对表顺序与大小写/填充处理。
6. 记录表与解码流程，复现结果。

## PoC

```text
# 输入（原文密文末尾粘了小写 "table"，会被 Remove non-alphabet chars 过滤掉）
密文: N2XHD244PSVED53BHG2W7ZSVNK5W7ZSVPOTUHNUtable
字母表: AC-Z2-7B=   # 区间记法，等价 32 字符串 ACDEFGHIJKLMNOPQRSTUVWXYZ234567B

# CyberChef
From Base32 (Alphabet: AC-Z2-7B=, Remove non-alphabet chars)
Input:  N2XHD244PSVED53BHG2W7ZSVNK5W7ZSVPOTUHNUtable
Output: flag{th1s_1s_b4by_b4se32
# 注：原文密文去掉小写 table 后为 39 字符（<8 的倍数），截图输出即 24 字节、缺右花括号；补上加密时漏掉的第 40 个字符才应得到完整 flag
```

```python
import base64

std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
# AC-Z2-7B= 按 CyberChef 区间语法展开后的 32 字符表
custom = "ACDEFGHIJKLMNOPQRSTUVWXYZ234567B"
# 建立 custom -> std 的字符映射
table = {c: std[i] for i, c in enumerate(custom)}
data = "N2XHD244PSVED53BHG2W7ZSVNK5W7ZSVPOTUHNU"   # 已去掉原文误粘的小写 table
mapped = ''.join(table[ch] for ch in data)
mapped += '=' * (-len(mapped) % 8)
print(base64.b32decode(mapped))   # b'flag{th1s_1s_b4by_b4se32'（原文密文少 1 字符，故缺右花括号）
```

## 变体与关联

- 变体：Base64 换表（已有专门卡）、Base32 表逆序/大小写混合；先确认表长度与顺序再解码。
- 变体：表在运行时解密/生成时，用调试器或 hook 在编码函数入口 dump 出 32 字节表；或在伪代码中识别位运算还原表（本例 Rust 实现用 HIBYTE/BYTE 位运算重组）。
- 变体：密文带非字母字符时，CyberChef 勾选 Remove non-alphabet chars；脚本则先过滤。
- 关联：[[ctf-crypto-custom-base64-charset-oracle-recovery]]（自定义 Base64 字符集的 oracle 恢复，适用于不知道表的情况）、[[ctf-crypto-nibble-charmap-hex-md5-sequence-openssl-salted]]（换表类编码的组合场景）。

## 检测与防御

- 检测：无（CTF 解题技巧）。
- 防御：编码不是加密，换表不能保护秘密；敏感数据用带密钥的加密与完整性校验。
- 说明：本文是 CTF 中 Base32 自定义字母表的识别与解码技巧，severity info；仅用于 CTF/授权逆向。
