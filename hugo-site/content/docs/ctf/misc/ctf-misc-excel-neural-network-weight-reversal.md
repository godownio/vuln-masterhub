---
id: ctf-misc-excel-neural-network-weight-reversal
title: Excel 神经网络权重逆向：ReLU 双神经元比较对恢复目标输入字符
type: scenario
domain: ctf
path: ctf/misc
technique: excel-neural-network-weight-reversal
tags:
- misc
- excel
- neural-network
- weights
- relu
- openpyxl
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:37+08:00'
  notes: 已对照原文核对：Challenge!D8:AG8 输入、CODE(char)/127 归一化、30 输入/60 隐藏、±1 权重成对比较与 ReLU 判定、b1 行 75、前 22 位 flag 与 texsaw{n3ur4l_r3v3rs3} 均一致。未验证点：无 xlsx 附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-excel-neural-network-weight-reversal/
draft: false
kb_aliases:
- Excellent Neurons
- challenge.xlsx
- Network sheet
- CODE(char)/127
- ReLU 比较对
---

## 一句话结论

Excel 里的“神经网络”第一层对每个输入位置放了两个权重为 `+1/-1` 的神经元，分别计算 `x_i - t` 与 `t - x_i`；经过 ReLU 后，只有 `x_i == t` 时两项同时为 0，否则至少一项为正。把每对神经元的偏置反解出 `t`，再乘 127 即得 ASCII，拼出 `texsaw{n3ur4l_r3v3rs3}`。

## 原理

- **输入归一化**：`Challenge!D8:AG8` 是 30 个字符输入；下一行公式 `=IF(D8="",0,CODE(D8)/127)` 把字符转成 `CODE(char)/127`。
- **第一层结构**：30 维输入 → 60 个隐藏神经元；每个神经元只连一个输入位置，权重只有 `+1` 或 `-1`；每个位置对应两个神经元：
  - `x_i - t`：权重 `+1`，偏置 `-t`；
  - `t - x_i`：权重 `-1`，偏置 `+t`。
- **ReLU 判定**：`ReLU(x_i - t)` 与 `ReLU(t - x_i)` 在 `x_i == t` 时都为 0；只要不相等，至少有一个为正。因此这一层等价于“第 i 位是否等于目标值 t”的比较器，而不是复杂神经网络。
- **反解**：从 `Network` 表读取 W1（行 11~70、列 C~AF）和 b1（行 75、列 C~BJ）；对每个神经元找唯一非零权重，按 `w=+1 → t=-b`、`w=-1 → t=b` 恢复 t；每个位置有两个神经元，取平均；`ASCII = round(t*127)`。
- **结果**：前 22 位是 flag，第 23~30 位为 0（空白输入）；flag `texsaw{n3ur4l_r3v3rs3}`。

## 触发条件

- 拿到 `.xlsx` 工作簿，含输入区与“Network”权重/公式表。
- 第一层权重/偏置与输入位置一一对应，且存在成对的 `±1` 比较结构。
- 输入归一化公式可读（如 `CODE(char)/127`）。
- 能读取单元格公式/数值（`openpyxl` 的 `data_only=False`）。

## 利用步骤

1. 用 `openpyxl` 打开工作簿，查看 `Challenge` 与 `Network` 两张表。
2. 确认输入区、归一化公式和目标字符长度。
3. 读取第一层权重 W1 与偏置 b1；对每个神经元找唯一非零权重和对应输入位置。
4. 按 `w=+1 → t=-b`、`w=-1 → t=b` 恢复目标值；同一位置两个神经元求平均。
5. `round(t*127)` 转 ASCII；遇到 0 停止（空白输入）。
6. 拼出 flag，检查格式。

## PoC

```python
from openpyxl import load_workbook
from collections import defaultdict

wb = load_workbook("challenge.xlsx", data_only=False)
ws = wb["Network"]

b1 = [ws.cell(row=75, column=3 + i).value for i in range(60)]
targets = defaultdict(list)

for n in range(60):
    row = 11 + n
    nz = None
    for pos in range(30):
        w = ws.cell(row=row, column=3 + pos).value
        if w not in (None, 0):
            nz = (pos + 1, w)
            break
    if nz is None:
        continue
    pos, w = nz
    b = b1[n]
    t = -b if w == 1 else b if w == -1 else None
    if t is None:
        raise ValueError(w)
    targets[pos].append(t)

chars = []
for pos in range(1, 31):
    if pos not in targets:
        break
    t = sum(targets[pos]) / len(targets[pos])
    code = round(t * 127)
    if code == 0:
        break
    chars.append(chr(code))
print("".join(chars))  # texsaw{n3ur4l_r3v3rs3}
```

## 变体与关联

- **激活函数变体**：ReLU、LeakyReLU、sigmoid/tanh；比较对结构可能换成阈值/符号判断。
- **结构变体**：多层网络、权重藏在公式里、输入/输出维度不同；先找“每个输入位置对应一组神经元”的稀疏连接。
- **归一化变体**：`CODE(char)/127`、`/255`、`ord(char)-offset`；反解时对应乘回。
- **关联卡片**：[[ctf-misc-hdf5-keras-weight-ascii-hidden]]（Keras 权重隐藏 ASCII）、[[ai-security-model-extraction-weight-watermark-c2pa-seed-denoise]]（模型权重中的水印/隐藏信息）。
- **边界**：若权重被加密/混淆、或网络是真实训练模型而非比较器，不能直接反解；需要先确认结构。

## 检测与防御

- **防御**：不要把 flag/密钥编码进模型权重或 Excel 公式；模型文件应做访问控制/加密。
- **检测信号**：权重只有 `±1`、偏置成对、每个输入位置仅连两个神经元；`CODE()/127` 归一化。
- **CTF 技巧**：先看第一层稀疏结构和激活函数，再反解目标值；不要真的训练/运行模型。
