---
id: ctf-forensics-png-lsb-column-major-scan-order
title: PNG LSB 进阶隐写：行优先无结果时改用列优先 yx 扫描，短载荷用编码特征而非可打印率判定
type: scenario
domain: ctf
path: ctf/forensics
technique: png-lsb-column-major-scan-order
tags:
- forensics
- png
- lsb
- steganography
- zsteg
- scan-order
- base64
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:39+08:00'
  notes: 已对照原文核对；zsteg yx 列优先、NUL 截断后 base64 解码、短载荷用编码特征判定均一致
url: /docs/ctf/forensics/ctf-forensics-png-lsb-column-major-scan-order/
draft: false
kb_aliases:
- LSB 列优先
- zsteg yx
- 扫描顺序隐写
- 位平面隐写
- 短载荷 base64 提取
---

## 一句话结论

PNG 的 RGB 最低位确实藏了数据，但按常规行优先扫描解不出内容；把扫描顺序改成列优先（先遍历列再遍历行，`zsteg` 的 `yx`）后，从位平面提取的比特流直接拼成字节就是一段 base64，按 NUL 截断并解码即得 flag。

## 原理

- **LSB 隐写不只取决于位平面，还取决于扫描顺序**：像素按行优先读取是最常见假设，但数据可以按列优先、从右下往左上、按块蛇形等顺序嵌入。位平面相同、顺序不同，提取出的字节流完全不同。
- **本题位平面是朴素 RGB 最低位**：`zsteg` 列出的行优先 LSB 各种变体都无有意义结果，说明不是位平面组合或通道顺序问题，而是扫描顺序问题。
- **列优先含义**：`yx` 表示先遍历 y（列）再遍历 x（行），即按列读取像素的 RGB 低位，而不是按行。
- **短载荷判定陷阱**：用滑动窗口可打印率做判据时，窗口长度设大了会跨过载荷边界，短 base64 串容易被漏掉；更稳的做法是正则匹配流头部的编码特征（base64 字符集、连续十六进制）。
- **为什么最终能解**：比特流按 8 位拼字节后，开头就是 base64 字符集形态，遇到 NUL 截断，base64 解码得到闭合 flag。

## 触发条件

- PNG/BMP 等位图，常规行优先 LSB 提取无结果，但 `zsteg` 显示位平面存在非随机分布。
- 题名/提示含“进阶/顺序/列/扫描”等暗示。
- 提取出的比特流开头符合某种编码特征（base64/hex/文本）。
- 图像尺寸允许列优先遍历（宽高不相等时顺序差异更明显）。

## 利用步骤

1. 先做基础检查：`file`、`pngcheck`、`zsteg` 列出所有位平面组合，确认行优先 LSB 无结果。
2. 尝试列优先提取：`zsteg -E 'b1,rgb,lsb,yx' 1.png > bits.bin`。
3. 把比特流按 8 位拼字节，遇到 NUL 截断。
4. 用编码特征判定：检查开头是否为 base64 字符集/连续 hex，而不是用可打印率滑窗。
5. base64 解码得到 flag。
6. 若仍失败，枚举其他扫描顺序（右下→左上、块蛇形、隔行/隔列）与位平面组合（b1/b2、rgb/rgba、lsb/msb）。

## PoC

```bash
zsteg -E 'b1,rgb,lsb,yx' 1.png > bits.bin
```

```python
import base64
raw = open("bits.bin", "rb").read().split(b"\x00")[0]
print(base64.b64decode(raw).decode())
```

原文得到 `flag{lsb_is_nice}`；未在本机复跑。

## 变体与关联

- **顺序变体**：列优先、右下到左上、按块蛇形、隔行/隔列、按通道交错。
- **位平面变体**：b1/b2、RGB/RGBA、lsb/msb、通道顺序 RGB/BGR。
- **判定变体**：短载荷用正则匹配 base64/hex/flag 前缀；长载荷才用可打印率。
- **关联**：与常规 LSB 隐写、位平面分析同类；本卡强调“位平面正确但扫描顺序错误”这一常见盲区。

## 检测与防御

- 取证侧：先跑全量组合（位平面 × 通道 × 顺序），再针对短载荷用编码特征判定；不要因行优先失败就否定 LSB。
- 防护侧：图片上传/转发平台可对图像做重编码（会破坏 LSB）；敏感场景检测异常位平面分布与非常规扫描顺序载荷。
- 检测特征：LSB 位平面非随机、列优先提取出现 base64/hex 头、NUL 截断后的可解码文本。
