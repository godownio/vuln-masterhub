---
id: ctf-reverse-quadratic-swap-image-encryption-rounds
title: 二次多项式索引交换图像加密逆向：RGB 通道逐轮还原 + 轮数爆破
type: scenario
domain: ctf
path: ctf/reverse
technique: quadratic-swap-image-encryption-rounds
tags:
- ctf
- reverse
- image
- permutation
- pyinstaller
- brute-force
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:50+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-quadratic-swap-image-encryption-rounds/
draft: false
kb_aliases:
- 二次多项式交换
- 图像加密逆向
- RGB 通道置换
- 轮数爆破
- SRPM 2.0
- encrypt
---

## 一句话结论

当 PyInstaller 打包的图片加密器把图像补零成方阵、分离 R/G/B 通道，并在每轮按 `target=(index²+(2r+3)·index+7·(channel+1)) mod length` 交换元素时，逆向只需按相反轮序、相反索引顺序撤销交换；轮数未知（本题 3）时爆破并配合盲水印/可读性筛选。

## 原理

- **加密结构**：读取图片 → 补零成正方形 → 分离 R/G/B → 对每个通道做 `rounds` 轮元素交换，每轮对 `index` 从 0 到 `length-1` 计算 `target` 并交换 `values[index]` 与 `values[target]`。
- **可逆性**：交换是自逆的；若加密按 `round 0..R-1`、每轮 `index 0..len-1` 执行，则解密按 `round R-1..0`、每轮 `index len-1..0` 反向交换即可还原。
- **轮数未知**：轮数通常很小（本题 3）；爆破 `rounds`，对每个候选解密并用盲水印提取/图像可读性/尺寸裁剪判断。
- **补零/裁剪**：加密前把非正方形图补零成方阵；解密后按题目给的 width/height 裁剪掉填充。
- **为什么成立**：置换不丢失信息；只要索引公式、通道顺序、轮数、方向一致，逆置换就是确定性的。
- **边界**：若 `target` 计算依赖随机数/密钥，需先逆向随机源；若交换不是双射（target 可能重复），反向交换仍然可逆（按记录的顺序逆序执行）；轮数过大时爆破成本高。

## 触发条件

- 附件为 PyInstaller 打包的 Python EXE（可用 pyinstxtractor 解包、pycdc 反编译）。
- 反编译看到补零方阵、RGB 分离、`target=(index*index+... )%length` 交换循环。
- 轮数/通道顺序/尺寸可从代码或题目提示获得；轮数可能需爆破。
- 有 PIL/NumPy 与盲水印工具（如 `blind_watermark`）。

## 利用步骤

1. 用 `pyinstxtractor.py` 解包 EXE，`pycdc` 反编译 `encrypt.pyc`/`srpm_utils.pyc`。
2. 记录交换公式、轮数、通道顺序、补零/裁剪参数。
3. 实现 `swap_target(index,length,round,channel)` 与 `undo_quadratic_swaps`：按 `round` 逆序、`index` 逆序交换。
4. 对每个通道解密，合并 RGB；按 width/height 裁剪填充。
5. 轮数未知时枚举 1..N（本题 3），对每个结果做盲水印提取/视觉检查；正确轮数得到风景图。
6. 用 `blind_watermark` 提取盲水印得到 flag。

## PoC

```python
import numpy as np
from PIL import Image

def swap_target(index, length, round_index, channel_index):
    return (index * index + (2 * round_index + 3) * index + 7 * (channel_index + 1)) % length

def undo_quadratic_swaps(values, round_index, channel_index):
    restored = values.copy()
    for index in reversed(range(restored.size)):
        target = swap_target(index, restored.size, round_index, channel_index)
        restored[index], restored[target] = restored[target], restored[index]
    return restored

def decrypt_channel(channel_array, rounds, channel_index):
    current = channel_array.reshape(-1).astype(np.uint8).copy()
    for round_index in reversed(range(rounds)):
        current = undo_quadratic_swaps(current, round_index, channel_index)
    return current.reshape(channel_array.shape)

def decrypt_image(input_path, output_path, rounds, width=None, height=None):
    encrypted = Image.open(input_path).convert("RGB")
    arr = np.array(encrypted)
    channels = [decrypt_channel(arr[:, :, i], rounds, i) for i in range(3)]
    decrypted = np.stack(channels, axis=2).astype(np.uint8)
    if width and height:
        decrypted = decrypted[:height, :width, :]
    Image.fromarray(decrypted, "RGB").save(output_path)

for r in range(1, 8):
    decrypt_image("enc.png", f"dec_r{r}.png", r)
```

## 变体与关联

- **变体（轮数/公式）**：线性/二次/随机索引、按通道不同参数；按反编译公式实现逆变换。
- **变体（补零/裁剪）**：非正方形填充、边缘裁剪；尺寸信息可能在代码/题目。
- **变体（盲水印）**：`blind_watermark` 提取，或频域水印/LSB；见 [[ctf-forensics-png-lsb-column-major-scan-order]]。
- **关联卡片**：[[ctf-forensics-arnold-cat-map-inverse-parameter-brute-force]]（另一种像素置换）、[[ctf-forensics-spiral-pixel-scramble-blank-fill]]（螺旋置乱）、[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller 解包）。
- **边界**：随机化/密钥化置换需先恢复参数；轮数过大爆破慢；有损压缩破坏图像。

## 检测与防御

- **CTF 识别**：PyInstaller 图片加密器 + 二次索引交换 + 轮数未知，按逆序撤销 + 轮数爆破。
- **逆向方法**：先解包 pyc，提取公式/轮数/尺寸；实现逆变换后用盲水印/视觉验证。
- **安全**：像素置换不是加密，不能保护敏感图像；使用真正加密/水印方案。
