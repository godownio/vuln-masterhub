---
id: crypto-classical-column-transpose-vertical-read-caesar-shift
title: 逐列竖读的换位密文 + 凯撒平移：先按列重排还原置换，再暴力 25 种移位读 flag
type: scenario
domain: crypto
path: crypto/classical
technique: classical-column-transpose-vertical-read-caesar
tags:
- crypto
- classical
- transposition
- columnar
- caesar
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:47+08:00'
  notes: 已对照原文核对：Soup or Salad 的 cipher.txt 经实测为 29 行×29 列（已按原文修正此前误写的 30×30）、hint 提示读取方向异常、exp 用双层 for 按列竖读后凯撒移位，最终 shift=15 得 ictfCaesarIsAlwaysASafeChoice，与原文一致；未设 affected_versions（CTF 题无版本）；未复跑解密但按原文数据核对尺寸与结论
url: /docs/crypto/classical/crypto-classical-column-transpose-vertical-read-caesar-shift/
draft: false
kb_aliases:
- 列换位密码
- 从上到下读
- 竖读复原
- Caesar shift 暴力
- 换位 + 替换双层
---

## 一句话结论

密文被排成 29 行 × 29 列的方阵（原文 `cipher.txt` 即 29 行、每行 29 个字母），但“正常从左到右逐行”读出来是乱码——题目 hint 提示“有些语言不是从左到右、从右到左读的”，说明真实读取顺序是**逐列（从上到下读完一列再下一列）**；按列重排得到一段仍不可读的字母流，再对 26 个凯撒位移全试一遍，前缀出现 `ictf` 即定位正确位移，余下部分按同一移位解出可读英文。

## 原理

- **换位不改变频率**：列换位只改变字符顺序，字母频率与原文完全一致；因此“看起来像随机字母但单字符频率仍像英文”是换位类的最强信号，和替换类（频率被拉平/改变）可区分。
- **读取顺序就是密钥**：密文被写成方阵，若写入时按行、读出时按列（或反之），等价于密钥为“列数 = 30”的列换位；只要试出 `列数` 与方向（逐列向上/向下），置换就唯一确定，不需要穷举密钥。
- **为什么先换位后替换**：题目的两层是“换位 + 凯撒”，谁先谁后对单表替换是可交换的（凯撒对每个字母独立作用，与位置无关），因此可以先把方阵按列重排成连续流，再统一做移位；反过来先移位再重排结果相同。
- **暴力移位的判据**：26 种移位里只有 1 种会让明文出现 `ictf{`、`flag{` 之类已知前缀与合法英文单词；用前缀匹配比“看哪个像人话”更可靠。
- **常见陷阱**：方阵的行列数必须与密文长度整除（原文 29×29=841 个字母），否则最后一行不满，逐列读取时要按实际行数补齐/跳过。

## 触发条件

- 密文以等长方阵形式给出（每行定长，或整段可被行数整除）。
- 逐行读出的文本无意义但字符分布仍像自然语言（换位特征）。
- 题面/提示暗示读取方向异常（“不是从左到右”“竖着读”“栅栏/列”）。
- 密文中含已知格式前缀（`ictf{`、`flag{`）可用于校验。

## 利用步骤

1. 统计密文行数 `row`、每行长度 `col`，确认 `row*col == len(cipher)`。
2. 按列重排：`for i in range(col): for j in range(row): out += data[j][i]`，得到连续字母流。
3. 对连续流做凯撒暴力：`for shift in range(26)`，输出 `''.join(chr((ord(c)-97-shift)%26+97) ...)`，只保留字母、非字母原样。
4. 用已知前缀（`ictf`/`flag`）与英文可读性双重判据定位正确 `shift`。
5. 截取前缀到 `}` 之间的内容，按题面要求补全 flag 格式（原文要求把 `ictf` 后面的英文消息放进 `ictf{...}`）。

## PoC

```python
data = open('cipher.txt').read().splitlines()
row, col = len(data), len(data[0])

stream = ''.join(data[j][i] for i in range(col) for j in range(row))

for shift in range(26):
    out = ''.join(
        chr((ord(c) - 97 - shift) % 26 + 97) if c.islower() else
        chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper() else c
        for c in stream
    )
    if 'ictf' in out or 'flag' in out:
        print(shift, out[:120])
```

## 变体与关联

- 变体：真实列换位带关键词密钥（按密钥字母排序决定列顺序），此时方阵要按密钥重排后再逐列读；无密钥时只能靠频率/可读性搜索列数。
- 变体：换位 + 单表替换（非凯撒）时，先换位再对替换做词频分析/已知明文攻击。
- 变体：W 型栅栏是列换位的特例（按“之”字形分配位置），见 [[ctf-crypto-base58-wrailfence-rot13]]；多字节符号换位见 [[crypto-classical-pigpen-variant-fence-column-decode]]。
- 关联：[[crypto-classical-hill-cipher-3x3-matrix-inverse-mod26]]（同为古典双层结构：矩阵替换 + 分组）。

## 检测与防御

- 这类是 CTF/教学场景，真实系统不应使用任何古典密码（列换位 + 凯撒的密钥空间 < 30!·26，穷举或频率分析即可破）。
- 若在遗留系统中遇到，检测信号是“密文长度恒定、字母频率与明文一致、无随机化 IV”；应替换为 AEAD（AES-GCM/ChaCha20-Poly1305）等带认证的现代方案。
- 教学提示：任何“换位 + 单表替换”的组合都等价于单表替换的强度，不提供真正的保密性。
