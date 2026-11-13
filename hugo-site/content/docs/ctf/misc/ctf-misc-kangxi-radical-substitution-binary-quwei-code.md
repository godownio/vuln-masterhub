---
id: ctf-misc-kangxi-radical-substitution-binary-quwei-code
title: 康熙部首替换隐写：按是否替换为康熙部首提取 0/1 比特流，7bit 区位码还原 GB2312 明文
type: scenario
domain: ctf
path: ctf/misc
technique: kangxi-radical-substitution-binary-quwei-code-stego
tags:
- ctf
- misc
- steganography
- unicode
- kangxi-radical
- quwei-code
- gb2312
- binary-encoding
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:59:06+08:00'
  notes: 已对照原文核对：康熙部首/统一汉字替换提取 0/1、332 bit、7 个 1 结束标记、308 位、7bit+0xA0 区位码 GB2312、aliyunctf{2626_5554} 均一致；无 enc.txt/unicode.txt 样本，未复跑
url: /docs/ctf/misc/ctf-misc-kangxi-radical-substitution-binary-quwei-code/
draft: false
kb_aliases:
- 康熙部首隐写
- 康熙部首 区位码
- 汉字替换隐写
- 7bit 区位码
- Bacon cipher 汉字版
- 字 隐写题
---

## 一句话结论

题目把同一段文字里部分汉字替换为 Unicode 康熙部首（不同写法但等价的汉字部件），替换与否本身构成 0/1 比特；按“是康熙部首=1、普通汉字=0”提取比特流，去掉尾部冗余 0 和 7 个 1 的结束标记后，将剩余比特按 7 位一组加上 0xA0 转成 GB2312 区位码，解码得到中文提示，再转成 `aliyunctf{...}`。

## 原理

- **康熙部首等价字**：Unicode 的 EquivalentUnifiedIdeograph 数据把康熙部首（如「⼀」「⼆」等）映射到对应的统一汉字；二者视觉相近但码位不同，适合做“同形替换”。
- **替换即比特**：若隐写要保证原文可读，可只对有对应康熙部首的字做有选择性的替换；每个可替换位置输出 1（替换为部首）或 0（保留原字），替换位置之外的字符不携带信息。
- **提取规则**：遍历文本，字符属于康熙部首集合记 1、属于普通汉字集合记 0；得到比特流后先看尾部：连续的 0 是填充/冗余，一段长度为 7 的全 1 是结束标记（对应 7 位编码中不会出现的值）。
- **7bit 分组**：结束标记前的比特数应能被 7 整除（本题 308 位）；每 7 位表示一个 0–127 的值。
- **区位码解码**：GB2312 区位码由区号、位号各加 0xA0 组成两个字节；把 7 位值加 0xA0 得到字节，两两拼成 GB2312 字符，即可还原中文消息；本题解出「阿里云夺旗赛左花括二六二六下划五五五四右花括」，即 `aliyunctf{2626_5554}`。
- **彩蛋**：区位码 2626 与 5554 分别对应「汉」「字」，呼应题目名「字」。

## 触发条件

- 拿到一段包含大量可替换汉字的文本，且部分字被替换为康熙部首、部分未替换。
- 已知或可获取康熙部首与统一汉字的等价映射表（Unicode EquivalentUnifiedIdeograph.txt）。
- 文本中存在可用于定位结束的标记/冗余模式。

## 利用步骤

1. 加载康熙部首与统一汉字的等价映射，建立两个集合。
2. 逐字符扫描文本：康熙部首记 1，有等价部首的普通汉字记 0，其余字符跳过。
3. 拼接比特流，观察尾部：去掉连续 0，定位长度为 7 的全 1 结束标记；确认标记前比特数能被 7 整除。
4. 按 7 位分组，每组值加 0xA0 转十六进制字节，拼成 GB2312 字节串并解码。
5. 将解出的中文提示（左花括/右花括/下划等）换成 ASCII 符号得到 flag；若提示是数字，按 4 位一组映射。

## PoC

```python
unicode_lines = open('unicode.txt', 'r').readlines()  # EquivalentUnifiedIdeograph.txt
hanzi, kangxi = [], []
for line in unicode_lines:
    parts = list(filter(lambda x: x, line.split()))
    kangxi.append(chr(int(parts[0], 16)))
    hanzi.append(chr(int(parts[2], 16)))

binary = []
for ch in open('enc.txt', 'r').read():
    if ch in hanzi:
        binary.append('0')
    elif ch in kangxi:
        binary.append('1')
binary = ''.join(binary)[:308]          # 去掉尾部填充与 7 个 1 的结束标记

gb = []
for i in range(0, len(binary), 7):
    gb.append(f'{int(binary[i:i+7], 2) + 0xA0:02X}')
print(bytes.fromhex(''.join(gb)).decode('GB2312'))
```

## 变体与关联

- 变体：替换集合可以是异体字、繁体/简体、全角/半角、Unicode 变体选择符等，本质都是“同形不同码位”的二值通道。
- 变体：编码可以是 Bacon 5bit、7bit 区位码、8bit ASCII；分组长度由结束标记前的比特数推断。
- 关联：多通道不可见 Unicode 隐写见 [[ctf-misc-multi-channel-invisible-unicode-gf2-sparse-matrix]]；行首尾字符隐写见 [[ctf-misc-first-last-char-line-stego]]。
- 边界：若文本没有足够多的可替换字或结束标记不明显，需要先统计频率/尝试多种分组长度。

## 检测与防御

- 本题为 CTF 隐写题；真实场景可在文本入库前做 Unicode 规范化（NFKC/NFKD），把康熙部首、变体字统一为规范汉字，消除同形替换通道。
- 检测：文本中康熙部首/异体字比例异常、同一文档内同字不同码位混用。
