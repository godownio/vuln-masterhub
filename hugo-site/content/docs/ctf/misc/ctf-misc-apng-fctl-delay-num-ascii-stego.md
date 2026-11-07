---
id: ctf-misc-apng-fctl-delay-num-ascii-stego
title: APNG fcTL delay_num 隐写：帧延迟数值按 ASCII 编码隐藏信息
type: scenario
domain: ctf
path: ctf/misc
technique: apng-fctl-delay-num-ascii-stego
tags:
- ctf
- misc
- apng
- png
- stego
- frame-delay
- fctl
- ascii
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:18+08:00'
  notes: 已对照原文与图 60-61 核对：fcTL 26 字节布局、delay_num 偏移 20:22、116/104→'t'/'h'、第 24 帧下标 023 一致；未复跑附件。
url: /docs/ctf/misc/ctf-misc-apng-fctl-delay-num-ascii-stego/
draft: false
kb_aliases:
- APNG 帧延迟隐写
- fcTL delay_num 隐写
- APNG 时间轴隐写
- APNG 逐帧提取隐藏信息
- a_cute_dog APNG
---

## 一句话结论

APNG 在 PNG 基础上增加了 `acTL`/`fcTL`/`fdAT` 等动画块，`fcTL` 中的 `delay_num`（分子）与 `delay_den`（分母）控制每帧显示时间；把 ASCII 码写进 `delay_num`，按帧序读取所有 `fcTL` 的 `delay_num` 并转字符，即可还原隐藏字符串（本题得到 `the_24th_maybe_useful`，指向第 24 帧的后续隐写）。

## 原理

- **APNG 结构**：APNG 仍是合法 PNG，新增 `acTL`（动画控制，帧数/循环次数）、`fcTL`（帧控制）、`fdAT`（帧数据）块。每个块格式为 `length(4) + type(4) + data + crc(4)`，长度为大端 32 位。
- **fcTL 字段**：`sequence_number(4) + width(4) + height(4) + x_offset(4) + y_offset(4) + delay_num(2) + delay_den(2) + dispose_op(1) + blend_op(1)`，共 26 字节；`delay_num`/`delay_den` 为 16 位大端，显示时长约为 `delay_num / delay_den` 秒。
- **编码方式**：把每个字符的 ASCII 值直接写入某帧的 `delay_num`（如 `t`=116、`h`=104），肉眼只看到帧速变化，常规图片查看器不显示该字段；提取时遍历所有 `fcTL`，按出现顺序收集 `delay_num`，`32 <= n <= 126` 的转 `chr(n)` 即可。
- **帧号差一**：APNG 的 `fcTL` 序号与 apng 库 `frames` 列表下标可能相差 1；本题提示“第 24 个”图片，实际要分析 `frame_023.png`（下标从 0 开始），这是容易踩的坑。
- **为什么可行**：`delay_num` 对画面内容无影响，且允许任意 16 位值；出题人可把整段 ASCII 藏进时间轴，只有解析 `fcTL` 或专用工具才能看到。
- **后续链**：第 24 帧再做 LSB 隐写（内容是倒序写入的 ZIP），提取后反转字节得到压缩包，再用 `oursecret` 以第一段 flag 为密码解出第二段；这是同一题的多层设计，不属于本技巧本身。

## 触发条件

- 文件是 APNG（PNG 签名 + `acTL` 块），帧数较多，`fcTL` 的 `delay_num` 出现可打印 ASCII 范围（32–126）的非常规值。
- 常规 PNG 查看器/缩略图看不到异常，但解析块结构或使用 apng 库能看到每帧延迟。
- 题目提示“动画/帧/延迟/时间轴/第 N 帧”等关键词。

## 利用步骤

1. 确认 APNG：`file`、`pngcheck -v` 或 010 Editor 查看 `acTL`/`fcTL` 块；记录帧数与每帧 `delay_num`。
2. 写脚本按 PNG 块结构遍历：跳过 8 字节签名，循环读 `length`、`type`、`data`、`crc`；对 `fcTL` 取 `data[20:22]` 的大端 16 位值（`delay_num`）。
3. 收集所有 `delay_num`，筛选 32–126，转 ASCII 拼接；若出现乱码，检查是否漏读/多读 `fcTL`、是否把 `delay_den` 当成延迟。
4. 按提示定位目标帧（注意下标差一），用 `apng` 库逐帧导出 PNG。
5. 对目标帧继续分析（LSB、附加数据、CRC/宽高异常等）；本题从 LSB 中提取倒序 ZIP，反转字节后用 `oursecret` 解出第二段。

## PoC

```python
import struct

def extract_apng_delay_num(path):
    delays = []
    with open(path, "rb") as f:
        f.read(8)  # PNG signature
        while True:
            lb = f.read(4)
            if not lb:
                break
            length = struct.unpack(">I", lb)[0]
            ctype = f.read(4).decode("ascii", "replace")
            if ctype == "fcTL":
                data = f.read(length)
                delays.append(struct.unpack(">H", data[20:22])[0])
                f.read(4)  # crc
            elif ctype == "IEND":
                break
            else:
                f.read(length)
                f.read(4)
    text = "".join(chr(n) for n in delays if 32 <= n <= 126)
    return delays, text

delays, text = extract_apng_delay_num("a_cute_dog.png")
print(delays)
print(text)   # 期望 the_24th_maybe_useful
```

```python
from apng import APNG

im = APNG.open("a_cute_dog.png")
for i, (png, control) in enumerate(im.frames):
    png.save(f"frame_{i:03d}.png")
```

说明：PoC 为原文脚本的最小化复现，未在本机执行；原文提取出 `the_24th_maybe_useful`，并导出 `frame_023.png` 继续 LSB 分析。

## 变体与关联

- 变体（编码）：delay 的奇偶位当二进制、`delay_num`/`delay_den` 组合值、按帧序排列的十进制 ASCII、用帧数/偏移量藏位。
- 变体（载体）：GIF 的 GCE Delay（10ms 单位）、WebP/APNG 动画帧时长、视频帧时间戳/PTS。
- 变体（后续）：APNG 帧内 LSB、`fdAT` 数据块追加内容、CRC/宽高异常、`oursecret` 等隐写工具二次封装。
- 关联：[[ctf-misc-gif-frame-duration-ascii-stego]]（GIF 帧间隔 ASCII 隐写，原理同源）；[[ctf-misc-png-trailing-data-lcg-xor-base62]]（PNG 尾部数据）；[[ctf-misc-png-idat-chunk-anomaly-stego]]（IDAT 异常）；[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 扫描顺序）。
- 边界：`delay_num` 被归一化/量化、帧被重新编码、APNG 被转成 GIF/视频后时间轴信息丢失，或题目只给静帧时，该方法失效。

## 检测与防御

- 检测：APNG 的 `fcTL` 中 `delay_num` 呈可打印 ASCII 分布、与正常帧延迟明显不符；帧延迟序列可拼出有意义的字符串；后续帧存在 LSB/附加数据异常。
- 防御：CTF 场景外的正常业务无需防御；若需检测隐蔽通道，可对动画文件做块级解析、检查异常延迟分布，并对上传文件重新编码以消除原始时间轴/块结构。
