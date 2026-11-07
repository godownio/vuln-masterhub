---
id: ctf-misc-tupper-self-referential-formula-decode
title: Tupper 自指公式解码：大整数按 17 位列布局还原位图密码
type: scenario
domain: ctf
path: ctf/misc
technique: tupper-self-referential-formula-decode
aliases:
- Tupper 公式
- 塔珀自指公式
- 17 列位图
- 大整数位图
- 4thHHLY
- Upper Tower
tags:
- ctf
- misc
- stego
- tupper
- big-integer
- bitmap
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:38+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
---

## 一句话结论

当图片/附件给出一个超大十进制整数、且它可被 17 整除时，可将其视为 Tupper 自指公式的 `k`：对每个 `(x,y)` 取 `(k >> (17*x + y)) & 1` 还原黑白位图；本题位图读出 `password is 4thHHLY`，该密码再用于 SilentEye 解码。

## 原理

- **Tupper 自指公式**：`1/2 < floor(mod(floor(y/17)·2^(-17·floor(x)-mod(floor(y),17)), 2))` 在特定 `k` 下绘制出公式自身的图像；工程上等价于把 `k` 的二进制位按 17 列布局铺成位图，`bit = (k >> (17*x + y)) & 1`。
- **为什么除以 17**：公式以 17 行为一个“字符块”；`k` 可写成 `17 * n` 形式时，位图在垂直方向按 17 对齐，便于识别字符。题目/附件给出的大整数可被 17 整除是强提示。
- **解码**：选择 `x`/`y` 的偏移和范围（通常从 `(0,0)` 或题目提示区域开始），逐位取 `k` 的二进制位，`1` 画黑、`0` 留白；调整偏移/放大倍数即可读出文字。
- **本题**：PNG 的 b0 通道 LSB 提取出超大十进制数；可被 17 整除 → Tupper；位图显示 `password is 4thHHLY`；再用该 key 做 SilentEye 解码得到 flag。
- **边界**：`k` 的位序/偏移/行列方向可能不同（LSB-first vs MSB-first、x/y 交换）；需要按图像可读性调整。

## 触发条件

- 附件给出一个超大整数（十进制/十六进制），或从图片 LSB/文本中提取到；整数可被 17 整除。
- 题目提示“自画像/公式/Tupper/17/位图/塔珀”等。
- 有 PIL/NumPy 或任意大整数支持（Python 原生）。
- 需要从位图读出密码/提示，再进入下一层隐写。

## 利用步骤

1. 提取大整数 `k`；检查 `k % 17 == 0`，确认 Tupper 线索。
2. 选择位图范围：x 从 0 到 `k.bit_length()//17`，y 从 0 到 16；或按题目给的偏移/区域。
3. 对每个 `(x,y)` 取 `bit=(k >> (17*x+y)) & 1`，输出 `#`/空格；必要时放大/翻转。
4. 调整偏移/方向，直到读出可读文字（本题 `password is 4thHHLY`）。
5. 把读出的密码用于下一层（SilentEye/音频/压缩包），得到 flag。
6. 本题最终 `sdpcsec{get_to_the_upper_and_to_the_Tupper}`（图片 05 显示）。

## PoC

```python
from pathlib import Path
from PIL import Image

# 1) 从图片 b0 通道 LSB 提取大整数（按题目位序）
img = Image.open("1.png").convert("RGB")
bits = [str(p[2] & 1) for p in img.getdata()]   # b0 通道
k = int("".join(bits), 2)

# 2) 按 17 列布局还原位图
width = k.bit_length() // 17 + 1
for y in range(17):
    row = ""
    for x in range(width):
        row += "##" if (k >> (17 * x + y)) & 1 else "  "
    print(row.rstrip())
```

## 变体与关联

- **变体（位序/偏移）**：`17*y+x`、MSB-first、x/y 交换、从中心/指定偏移开始；按可读性尝试。
- **变体（颜色/放大）**：1 画黑/白、按 2×2 放大、反转颜色；PNG 的 LSB 提取可能有多通道/位平面。
- **变体（下一层）**：Tupper 读出的密码用于 SilentEye/DeepSound/压缩包；见 [[ctf-forensics-deepsound-audio-stego-extract]]。
- **关联卡片**：[[ctf-misc-punctuation-2bit-encoding]]（另一位图/编码）、[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 提取）、[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（大整数运算）。
- **边界**：`k` 不可被 17 整除时可能不是 Tupper；位图范围/偏移错误会得到乱码；超大整数转换注意性能。

## 检测与防御

- **CTF 识别**：超大整数 + 可被 17 整除 + “自画像/公式”提示，按 Tupper 解码。
- **数据隐写**：Tupper 只是编码，不是加密；敏感数据不要用此类可逆编码。
- **实现**：Python 大整数移位可行；位图范围按 `bit_length` 计算，避免越界/死循环。
