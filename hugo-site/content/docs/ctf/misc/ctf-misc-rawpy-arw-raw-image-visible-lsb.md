---
id: ctf-misc-rawpy-arw-raw-image-visible-lsb
title: 相机 RAW（ARW）隐写：用 rawpy 的 raw_image_visible 取原始传感器数据做 LSB 提取
type: scenario
domain: ctf
path: ctf/misc
technique: rawpy-raw-image-visible-lsb-stego
tags:
- ctf
- misc
- stego
- lsb
- rawpy
- arw
- image
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V558
  verified_at: '2026-11-12T00:49:08+08:00'
  notes: 已对照原文与图：原文 rawpy.imread('image.ARW') 用 raw_image_visible[0] 取原始传感器行，data & 0x01 拼二进制后 CyberChef From Binary(8) 还原；图02 输出中可见 L3HCTF{del1gh7ing_y0u_4lways__canon}，与卡一致（卡 PoC 用 flatten 展平并注明原文按单行演示，属合理泛化）。dedup top 候选为 PNG LSB 水印、双灰度、DCT、PNG shellcode 等，均非相机 RAW 传感器数据 LSB，new 成立。未验证点：未复跑 rawpy。
url: /docs/ctf/misc/ctf-misc-rawpy-arw-raw-image-visible-lsb/
draft: false
kb_aliases:
- ARW LSB
- RAW 图片隐写
- raw_image_visible
- rawpy LSB 提取
- 相机 RAW 最低位
- Sony ARW stego
---

## 一句话结论

CTF 给出相机 RAW 文件（如 Sony `.ARW`）做隐写时，直接 `postprocess()` 成 RGB 或按普通 PNG 解像素会丢失/改变原始数据；应使用 `rawpy.imread()` 的 `raw_image_visible` 读取未去马赛克的传感器原始像素，对像素值逐个 `& 1` 取最低位拼成二进制串，再按 8 位分组转 ASCII 即可还原隐藏的 flag。

## 原理

- **RAW 与普通图片的像素不同**：相机 RAW 保存的是传感器拜耳阵列的原始读数（常见 12/14-bit），`postprocess()` 会做去马赛克、白平衡、gamma 等处理并输出 RGB，插值会改变甚至破坏每个像素的最低位；按 PNG/JPEG 常规 LSB 思路处理 RAW 自然失败。
- **raw_image_visible 是原始数据入口**：`rawpy` 暴露 `raw_image_visible`（可见区域原始像素二维数组），它未经去马赛克与色彩处理，隐藏在水印/噪声最低位的数据保持原样。
- **LSB 还原**：对数组中的每个像素值取 `& 0x01` 得到 0/1 比特流，按 8 位一组转 ASCII/UTF-8（CyberChef 的 From Binary 即可）得到明文；按位而非按字节处理，才能读出水印类隐写。
- **为什么用 rawpy 而不是通用图像库**：Pillow/OpenCV 读取 ARW 往往只解出预览图（embedded JPEG）或直接失败，预览图经过压缩与缩放，最低位信息已被破坏；rawpy（libraw）直接解析 RAW 结构，能拿到真正的传感器数据。

## 触发条件

- 题目给出相机 RAW 文件（`.ARW`/`.CR2`/`.NEF` 等），并提示水印/隐写/LSB 方向。
- 已安装 `rawpy`（`pip install rawpy`，底层依赖 libraw）。
- 隐藏数据以最低位平面写入原始像素（水印类题目常见）。

## 利用步骤

1. 安装依赖并用 rawpy 打开 RAW：
   ```python
   import rawpy
   with rawpy.imread('image.ARW') as raw:
       data = raw.raw_image_visible
   ```
2. 对原始像素值逐位取最低位，拼成比特串：
   ```python
   bits = ''.join(str(v & 0x01) for v in data.flatten())
   ```
3. 把比特串按 8 位分组转字符（或粘贴到 CyberChef，Recipe 选 `From Binary`，Byte Length 8）。
4. 若开头/结尾有噪声，尝试偏移 0-7 位对齐，或对行/列方向重排后重试。

## PoC

原文思路代码（`data = raw.raw_image_visible[0]` 按单行演示，实战需按数组形状展平/遍历全部像素）：

```python
import rawpy

with rawpy.imread('image.ARW') as raw:
    rgb = raw.postprocess()          # 仅预览，不用于 LSB
    data = raw.raw_image_visible     # 原始传感器像素
    bits = ''.join(str(int(v) & 1) for v in data.flatten())
    print(bits)
```

得到二进制串后交给 CyberChef `From Binary`，原文据此还原出 `L3HCTF{del1gh7ing_y0u_4lways__canon}`。

## 变体与关联

- **普通图片 LSB**：PNG/BMP 等无损格式可直接按 RGB 通道最低位提取；JPEG 有损压缩会破坏 LSB，需换用其他隐写面（DCT 系数等）。
- **RAW 处理链变体**：`raw_image`（含不可见边缘）与 `raw_image_visible` 数据范围不同；也可用 dcraw/exiftool 先转 TIFF 再做常规 LSB，但转换过程可能重排像素，需验证。
- **关联**：[[ctf-forensics-lsb-watermark-timestamp-aesctr-permutation]]（LSB 水印 + 时间戳密钥的另一类题型）。
- **边界**：若隐写写入的是 postprocess 后的预览图而非传感器原始数据，则应直接对预览图做 LSB，本方法反而取不到。

## 检测与防御

- **检测**：对图像做位平面分析（bit-plane slicing），最低位平面呈现非随机结构/文字轮廓；卡方检验、RS 分析可发现 LSB 替换；RAW 文件可直接比较不同通道/位平面熵。
- **防御**：CTF 之外的场景中，敏感图像发布前重编码（有损压缩/缩放）可破坏像素级 LSB；不要把隐写当作保密手段，隐写只提供混淆。
