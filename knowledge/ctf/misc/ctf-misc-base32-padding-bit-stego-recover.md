---
id: ctf-misc-base32-padding-bit-stego-recover
title: Base32 填充位隐写：按等号数量取末字符低位比特拼流还原隐藏数据
type: scenario
domain: ctf
path: ctf/misc
technique: base32-padding-bit-stego-recover
aliases:
- base32 隐写
- base32 填充位藏数据
- 等号位隐写 base32
- base32 steganography
tags:
- ctf
- misc
- stego
- base32
- padding
- encoding
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:20:15+08:00'
  notes: 已对照原文与截图核对：原文base32隐写小节给出等号数量→填充位映射(1→3/3→1/4→4/5→1/6→2)、提取脚本与示例flag hzuctf{base32_stegan0graphy_Y}，卡片结论/原理/PoC一致；与base64填充位卡(4字符组、低2/4bit)编码与取位规则不同，非同链，兄弟卡保留；未验证点：未用示例数据实跑脚本
---

## 一句话结论

Base32 每组 5 bit，末尾不足 40 bit 时用 `=` 补齐；规范编码器把最后一个有效字符的闲置低位写成 0，解码器会忽略它们，因此可把这些低位换成隐藏数据：按行统计 `=` 数量（1/3/4/6 个分别对应末字符低 3/1/4/2 bit），逐行取出拼成比特流，每 8 bit 还原一个字符。

## 原理

- Base32 码表为 `A-Z2-7`，每字符 5 bit；8 个字符对应 40 bit（5 字节）。不足 5 字节时用 `=` 填充到 8 字符边界：
  - 剩 1 字节（8 bit）→ 2 个有效字符（10 bit），末字符低 2 bit 闲置，补 6 个 `=`；
  - 剩 2 字节（16 bit）→ 4 个有效字符（20 bit），末字符低 4 bit 闲置，补 4 个 `=`；
  - 剩 3 字节（24 bit）→ 5 个有效字符（25 bit），末字符低 1 bit 闲置，补 3 个 `=`；
  - 剩 4 字节（32 bit）→ 7 个有效字符（35 bit），末字符低 3 bit 闲置，补 1 个 `=`。
- 标准解码只取有意义的位，忽略闲置低位；隐写者把待藏比特写入这些低位后，`b32decode` 结果不变，但文本本身携带了额外信息。
- 由于每行独立编码，`=` 数量决定每行可藏 1–4 bit；把多行 base32 文本逐行提取、按顺序拼接，即可还原任意字节串（flag）。
- 原文脚本还处理了 5 个 `=` 的情况（按 1 bit 提取）；标准 Base32 不会产生 5 个 `=`，遇到时按实际实现验证末字符位数，避免错位。

## 触发条件

- 得到多行 Base32 文本（文件或题面），常规解码结果无意义或本身就是掩码。
- 每行长度不一、末尾 `=` 数量异常（尤其出现非标准数量），符合逐行填充隐写特征。
- 已知或可猜测字符集为标准 Base32（A-Z2-7）；若换表需先映射回标准表。

## 利用步骤

1. 按行读取密文，统计每行末尾 `=` 个数，确定该行可提取位数：1→3 bit、3→1 bit、4→4 bit、6→2 bit（5→1 bit 需实测确认）。
2. 取该行最后一个非 `=` 字符，按 Base32 码表得到 5 bit 索引，取低 `offset` 位（offset 同上）。
3. 把所有行取出的比特按行序拼接，每 8 bit 转一个 ASCII 字符；若末尾不足 8 位丢弃。
4. 若出现乱码，尝试调整提取顺序（高位在前/低位在前）或跳过异常行。
5. 还原出明文/flag 后按题目格式提交。

## PoC

```python
import base64

B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
IDX = {c: i for i, c in enumerate(B32)}

def extract(lines):
    bits = ''
    for line in lines:
        line = line.strip()
        pad = line.count('=')
        if pad == 0:
            continue
        if pad == 1:   offset = 3
        elif pad == 3: offset = 1
        elif pad == 4: offset = 4
        elif pad == 6: offset = 2
        elif pad == 5: offset = 1   # 非标准，按原文脚本
        else:          continue
        ch = line[-(pad + 1)]
        v = IDX[ch]
        bits += format(v & ((1 << offset) - 1), f'0{offset}b')
    return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits) - len(bits) % 8, 8))

# print(extract(open('encrypt.txt').read().splitlines()))
```

- 原文示例：把 `hzuctf{base32_stegan0graphy_Y}` 按行写入普通文本的 Base32 编码低位，再用同样逻辑逐行提取还原。
- 与 Base64 填充位隐写的区别：Base64 按 4 字符组、取低 2/4 bit；Base32 按 8 字符组，且 `=` 数量与可藏位数对应关系不同。

## 变体与关联

- Base64 填充位隐写见 [[ctf-misc-base64-padding-bit-stego-recover]]；两者可叠加（先 base32 再 base64）。
- 若文本是自定义 Base32 字母表，先按 [[ctf-crypto-base32-custom-alphabet-cyberchef-decode]] 换表。
- 同类“忽略位藏数据”还包括 MP3 帧头 private_bit（[[ctf-misc-mp3-frame-header-private-bit-padding-stego]]）。

## 检测与防御

- CTF 技巧，非真实漏洞。出题方可随机化填充位或加校验；解题方注意 `=` 数量异常与逐行编码结构。
- 实际系统不要把隐藏信息放在编码填充位中传输，避免被隐写信道滥用；对可疑文本做规范化重编码可消除填充位差异。
