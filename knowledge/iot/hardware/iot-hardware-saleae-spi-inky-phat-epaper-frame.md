---
id: iot-hardware-saleae-spi-inky-phat-epaper-frame
title: Saleae Logic 解析 SPI 电子墨水屏：Inky pHAT 2.13 寸，按 0x24/0x26 RAM 命令重建 buf_a/buf_b 渲染图像
type: scenario
domain: iot
path: iot/hardware
technique: saleae-spi-inky-phat-epaper-frame
aliases:
- Sniff two
- Inky pHAT
- Pimoroni 电子墨水屏
- SPI 模式 0 解码
- e-paper 帧重建
- 0x24 0x26 RAM
tags:
- iot
- hardware
- saleae
- logic-analyzer
- spi
- epaper
- inky-phat
- protocol-decode
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:22:47+08:00'
  notes: 已对照原文核对：Inky pHAT接线CS=G7/CLK=G6/DIN=G5/DC=G4/RST=G3/BUSY=G2、SPI模式0/MSB first/CS低有效、DC区分命令数据、0x01开帧/0x24黑白RAM/0x26红黄RAM/0x20刷新、buf_a为0画黑/buf_b为1画红、136x250还原、多帧与垂直分辨率提醒均与正文、库代码及img10-17一致；还原flag{ec9cf27b}。未复跑原文sal。
---

## 一句话结论

逻辑分析仪抓包中按 Inky pHAT 接线（CS=G7、CLK=G6、DIN=G5、DC=G4、RST=G3、BUSY=G2）用 Saleae SPI 分析器（MOSI=DIN、Clock=CLK、Enable=CS、MSB First、CPOL=0/CPHA=0、Enable 低有效）解码；按 DC 线区分命令/数据，命令 `0x01` 开始一帧、`0x24` 选择黑白 RAM、`0x26` 选择红/黄 RAM、`0x20` 触发刷新，分别收集 `buf_a`/`buf_b`，unpackbits 后按 136×250 还原像素（buf_a 为 0 画黑、buf_b 为 1 画红）即可得到屏幕显示的 flag 图像。

## 原理

- **设备与接线**：Pimoroni Inky pHAT 2.13" e-paper 使用 SPI：`CS→G7`（片选）、`CLK→G6`、`DIN→G5`（MOSI）、`DC→G4`（数据/命令）、`RST→G3`、`BUSY→G2`。SPI 模式 0（CPOL=0、CPHA=0），MSB first，8 bit/transfer，CS 低有效。
- **Inky 库的刷新流程**：`show()` 把图像拆成 `buf_a`（黑白层）与 `buf_b`（红/黄层），`_update()` 依次发送初始化命令（0x74/0x7E/0x01/0x03/0x04/0x3A/0x3B/0x11/0x2C/0x3C/0x32/0x44/0x45），再对 `0x24`（B/W RAM）和 `0x26`（Red/Yellow RAM）分别发 `0x4E`/`0x4F` 指针命令与整帧数据，最后 `0x22`+`0x20` 触发显示，`0x10` 进入深睡。
- **DC 线的作用**：SPI 数据字节本身不区分命令/数据，Inky 用 DC 引脚：DC=0 表示命令，DC=1 表示数据。解析时必须把 DC 通道一起采样/导出，否则无法判断 0x24/0x26 后的字节是像素数据。
- **像素编码**：每字节 8 个像素，`numpy.packbits` 打包；`buf_a` 中 0 表示黑（BLACK），`buf_b` 中 1 表示红（RED），其余为白。还原时对两缓冲区 `unpackbits`，按 136×250（原文脚本尺寸）reshape 后合成 RGB。
- **多帧与分辨率**：屏幕可能连续刷新多张图（第一张不一定是 flag）；原文提醒垂直分辨率/旋转容易搞错，若最后少字符（如 `e` 看不到）需检查 height/width 与 reshape 顺序。
- **为何能拿到 flag2**：密码输入后屏幕显示的 flag 通过 SPI 明文写入 e-paper RAM，逻辑分析仪抓包即可完整重建。

## 触发条件

- 有 Saleae Logic 2 的 `.sal` 抓包，采样率足够解码 SPI（本场景约 480 kHz 时钟）。
- 知道或能从接线图推断 SPI 引脚映射与模式（0）、位序（MSB first）、CS 极性（低有效）。
- 抓包期间屏幕有刷新（输入密码后显示 flag，且可能多帧）。
- 有 Python（numpy/Pillow）用于还原图像。

## 利用步骤

1. 用 Saleae Logic 2 打开 `.sal`，按接线图确认 CS/CLK/DIN/DC 通道；本场景 MOSI=Channel 5、MISO=Channel 4、Clock=Channel 6、Enable=Channel 7。
2. 添加 `SPI` 分析器：MOSI=DIN、Clock=CLK、Enable=CS、Significant Bit=MSB First、Bits per Transfer=8、CPOL=0、CPHA=0、Enable Active Low。
3. 同时把 DC 通道作为数字通道导出（或在 CSV 中包含 DC 列）；导出 SPI 协议结果为 CSV。
4. 解析 CSV：`DC=0` 为命令，`DC=1` 为数据；命令 `0x01` 标记一帧开始，`0x24` 切到黑白缓冲，`0x26` 切到红/黄缓冲，`0x20` 表示帧结束/刷新。
5. 分别收集 `buf_a`、`buf_b` 字节；对每帧 `np.unpackbits`，按 `height×width`（原文 136×250）reshape。
6. 合成 RGB：buf_a 为 0 → 黑，buf_b 为 1 → 红，否则白；用 Pillow 显示/保存图像，读取屏幕上的 flag。
7. 若有多帧，逐帧渲染，不要看到第一张非 flag 就停止。

## PoC

Saleae SPI 配置：

```text
MOSI: 05. Channel 5 (DIN)
MISO: 04. Channel 4
Clock: 06. Channel 6 (CLK)
Enable: 07. Channel 7 (CS)
Significant Bit: Most Significant Bit First (Standard)
Bits per Transfer: 8 Bits per Transfer (Standard)
Clock State: Clock is Low when inactive (CPOL = 0)
Clock Phase: Data is Valid on Clock Leading Edge (CPHA = 0)
Enable Line: Enable line is Active Low (Standard)
```

```python
import csv, numpy as np
from PIL import Image

with open('./inky_spi.csv') as f:
    reader = csv.reader(f); next(reader)
    in_packet = in_b_w = in_y = False
    b_w, y = [], []
    frames = []
    for row in reader:
        data, dc = int(row[2], 16), int(row[3], 16)
        if dc == 0x00:              # command
            cmd = data
            if cmd == 0x01: in_packet = True
            elif cmd == 0x20:
                in_packet = False
                frames.append((b_w, y)); b_w, y = [], []
            elif cmd == 0x24: in_b_w, in_y = True, False
            elif cmd == 0x26: in_y, in_b_w = True, False
        elif in_packet:             # data
            (b_w if in_b_w else y).append(data)

def display(buf_a, buf_b):
    a = np.unpackbits(np.array(buf_a, dtype=np.uint8))[:250*136].reshape((250,136))
    b = np.unpackbits(np.array(buf_b, dtype=np.uint8))[:250*136].reshape((250,136))
    out = np.zeros((250,136,3), dtype=np.uint8)
    out[...] = 255
    out[a == 0] = (0,0,0)
    out[b == 1] = (255,0,0)
    Image.fromarray(out, 'RGB').show()

for a, b in frames:
    if a: display(a, b)
# 渲染结果：flag{ec9cf27b}
```

## 变体与关联

- 不同尺寸/型号的 Inky/e-paper：修改 width/height、颜色映射与初始化命令；先对照官方库 `_update` 的 RAM 命令。
- 若 DC 通道未导出，可用命令序列特征（0x24/0x26）猜测数据边界，但可靠性差；应始终抓 DC。
- 旋转/翻转：按库里的 rotation/v_flip/h_flip 逻辑调整 reshape 与翻转。
- 关联：[[iot-hardware-saleae-logic-uart-decode]]（UART 解码）、[[iot-hardware-saleae-i2c-cardkb-keyboard-decode]]（I2C 键盘）。

## 检测与防御

- 该场景是取证/CTF 技巧；真实设备中 e-paper 刷新数据可能包含敏感信息，应对 SPI 总线做物理防护或加密显示内容。
- 敏感显示内容不应长期留在屏幕/缓冲；设备应限制物理访问与调试接口。
- 对带有显示/键盘外设的产品做总线完整性保护，防止逻辑分析仪直接抓取明文。
