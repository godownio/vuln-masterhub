---
id: ctf-reverse-six-bit-block-printable-image-encoder
title: 2x3 六比特块转可打印字符：图像编码器逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: six-bit-block-printable-image-encoder
tags:
- ctf
- reverse
- image
- encoding
- bit-packing
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:09+08:00'
  notes: 已对照原文 Dust to Dust 与 img/10 核对：2x3 块 6 bit、+0x20、} 分行、~ 结尾、前 3 位上行/后 3 位下行均一致；原文 PoC 截断处由卡片补全，未实际运行。
url: /docs/ctf/reverse/ctf-reverse-six-bit-block-printable-image-encoder/
draft: false
kb_aliases:
- 六比特块编码
- 2x3 二进制块
- 可打印字符图像编码
- Dust to Dust
- 6-bit 图像还原
---

## 一句话结论

编码器把二值图按 2x3 像素块（6 bit）取值 0–63，加 `0x20` 转成可打印字符，每行用 `}` 分隔、文件以 `~` 结尾；逆向时按 `}` 拆行、字符减 32 还原 6 bit，再按“前 3 位上一行、后 3 位下一行”拼回二值图即可读出隐藏文字。

## 原理

- 2x3 块共 6 个二进制像素，恰好可表示 `0..63`；加上 `0x20` 后落在可打印 ASCII 区间 `0x20..0x5F`，便于存成文本。
- 编码按 2 行一带（band）扫描：每个字符编码当前列组的 3 个上排像素和 3 个下排像素；每带结束后输出 `}` 作为行分隔，整个文件以 `~` 结束。
- 逆向是编码的严格逆过程：`ord(ch)-0x20` 得到 6 bit；前 3 bit 属于上一行，后 3 bit 属于下一行；按字符顺序追加到两条行缓冲，遇到 `}` 把这两行写入图像。
- 6 bit 的位序可能因实现而异（MSB-first/LSB-first）；若还原出的图像是乱码，交换 6 bit 顺序、交换上下行或按列优先重排。
- 该编码不是加密，只是位打包 + 可打印化；一旦识别出 `}` 分隔与 `~` 结尾，就能直接逆推。

## 触发条件

- 附件是文本文件，行内字符集中在 `0x20..0x5F`，行尾有统一分隔符（如 `}`），文件末尾有结束符（如 `~`）。
- 题目/源码提示“2x3 块”“6 bit”“二值图”或给出 `encoder.c` 等编码器。
- 文本行数与目标图像高度成 2 倍关系，行长与宽度成 3 倍关系（或可按此推断）。
- 图像是黑白/二值图，像素只有 0/1。

## 利用步骤

1. 读取文本，确认末尾 `~`；去掉后按 `}` 拆成若干带。
2. 对每个字符 `ch` 计算 `v = ord(ch) - 0x20`，转成 6 位二进制。
3. 前 3 位追加到当前带的上行，后 3 位追加到下行；处理完该带所有字符后得到两条二值行。
4. 按带顺序把所有上行/下行拼成完整二值图；0/1 映射为黑/白。
5. 渲染成 PNG 查看隐藏文字；若图像倒置/错位，尝试交换上下行、反转位序或调整扫描顺序。

## PoC

```python
from pathlib import Path
from PIL import Image
import numpy as np

def decode_output(path="output.txt"):
    data = Path(path).read_text()
    assert data.endswith("~")
    bands = data[:-1].split("}")
    if bands and bands[-1] == "":
        bands.pop()

    rows = []
    for band in bands:
        top, bottom = [], []
        for ch in band:
            v = ord(ch) - 0x20
            bits = format(v, "06b")
            top.extend(int(b) for b in bits[:3])
            bottom.extend(int(b) for b in bits[3:])
        rows.append(top)
        rows.append(bottom)

    arr = np.array(rows, dtype=np.uint8) * 255
    Image.fromarray(arr).save("decoded.png")
    print("saved decoded.png", arr.shape)

decode_output()
```

## 变体与关联

- 变体：块尺寸改为 2x4、3x3；分隔符/结束符不同；位序 LSB-first。
- 变体：编码前对图像做翻转/旋转/取反，逆推时需相应还原。
- 变体：字符偏移不是 `0x20`，而是 `0x30` 或其他可打印基址。
- 关联：[[ctf-forensics-1bpp-qr-row-shift-frame-recovery]]（1bpp 图像行恢复）、[[ctf-misc-punctuation-2bit-encoding]]（低位打包编码）、[[ctf-reverse-pixel-low-nibble-direction-maze-bfs]]（像素低位编码）。

## 检测与防御

- 检测：文本字符集中在 `0x20..0x5F`、行尾统一 `}`、文件尾 `~`、行长与图像宽度成比例。
- 防御：该场景是 CTF 编码题，不是安全漏洞；真实系统不要把敏感数据用可打印位打包当作加密。
- 响应：若业务中出現类似编码，按“编码而非加密”处理，检查是否泄露敏感图像/数据。
