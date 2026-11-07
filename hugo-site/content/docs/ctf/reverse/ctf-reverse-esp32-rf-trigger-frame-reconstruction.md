---
id: ctf-reverse-esp32-rf-trigger-frame-reconstruction
title: ESP32-S3 RF 发射固件逆向：JPEG COM 取频道/ID，Xtensa 还原 16 字节触发帧与校验
type: scenario
domain: ctf
path: ctf/reverse
technique: esp32-rf-trigger-frame-reconstruction
tags:
- ctf
- reverse
- esp32
- xtensa
- firmware
- rf
- jpeg-comment
- checksum
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:55:50+08:00'
  notes: 已对照原文 §谁引闪了我的灯核对：JPEG COM ch18 id19、ESP32-S3 merged flash ota_0@0x10000、调试菜单 raw 示例、16 字节帧 55 01 13 01 01 00*10 6B（前15字节和低8位）、MD5 flag 均一致；未本机复跑。
url: /docs/ctf/reverse/ctf-reverse-esp32-rf-trigger-frame-reconstruction/
draft: false
kb_aliases:
- 谁引闪了我的灯
- ESP32-S3 固件逆向
- Xtensa 反汇编
- JPEG COM 注释
- SI24R1 触发帧
- RF 发射码还原
---

## 一句话结论

从 JPEG 的 COM 段读出 `ch18 id19`，再逆向 ESP32-S3 merged flash 中 `0x10000` 处的 app：字符串里的调试菜单给出 `raw 55 01 ...` 示例，Xtensa 反汇编还原出 16 字节帧格式 `55 <group> <id> 01 01 ... <checksum>`；代入 `group=1`、`id=0x13`，最后一字节为前 15 字节求和低 8 位，得到 `55 01 13 01 01 00 00 00 00 00 00 00 00 00 00 6B`。

## 原理

- JPEG 的 COM 段（marker `0xFFFE`）可以存放任意注释；案例注释为 `ch18 id19`，给出无线频道 18 与设备 ID 19。解析 JPEG 时要按 marker 长度跳过各段，不能只搜字符串。
- ESP32-S3 的 merged flash 镜像包含 bootloader、分区表和 app；案例分区表显示 `ota_0: offset 0x10000, size 0x200000`，因此 app 从 `0x10000` 开始。
- app 中的字符串保留了调试菜单与 raw payload 示例：`t / trigger`、`ch <1-21>`、`id <1-99>`、`raw 55 01 01 01 00 ... 70`，说明存在 16 字节触发帧。
- 用 Xtensa 反汇编跟踪 `trigger` 逻辑，可还原帧格式：`55 <group> <id> 01 01 00*10 <checksum>`；默认 `group=1`，`01 01` 是引闪命令字段，最后 1 字节是前 15 字节求和取低 8 位。
- 频道 `ch18` 用于配置 SI24R1 的 RF_CH 寄存器，不进入触发帧本身；帧里用的是 group/id。

## 触发条件

- 目标设备使用 ESP32/ESP32-S3 + 2.4GHz 收发芯片（如 SI24R1/NRF24L01），固件以 merged flash 形式给出。
- 能提取 JPEG 等载体的元数据/注释，获得频道、设备 ID 等参数。
- 能用 Xtensa 反汇编器（IDA/Ghidra/xtensa-objdump）分析 app，定位 trigger/raw payload 构造逻辑。
- 已有或能推出发送端的帧格式与校验算法。

## 利用步骤

1. 解析 JPEG 的 COM 段，提取 `ch<频道> id<设备ID>`；记录频道与 ID。
2. 用 `binwalk`/分区表解析 merged flash，定位 app 起始偏移（案例 `0x10000`）。
3. 在 app 中搜索调试菜单、`raw`、`trigger`、`ch`、`id` 等字符串，定位命令处理函数。
4. 反汇编 trigger 逻辑，确认帧长度、魔数、group/id 字段、命令字段与 checksum 算法。
5. 按格式构造帧：`55 <group> <id> 01 01 00...00 <sum> `；案例为 `55 01 13 01 01 00 00 00 00 00 00 00 00 00 00 6B`。
6. 若题目要求提交哈希，按题面格式（大小写、是否去空格）计算 MD5/其他哈希；案例对去空格的十六进制串做 MD5。

## PoC

```python
from pathlib import Path
from zipfile import ZipFile
import hashlib, re

with ZipFile("raw.zip") as zf:
    name = next(n for n in zf.namelist() if n.lower().endswith(".jpg"))
    jpg = zf.read(name)

comment = None
i = 0
while i < len(jpg) - 1:
    if jpg[i] == 0xFF and jpg[i + 1] not in (0x00, 0xFF):
        marker = jpg[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = int.from_bytes(jpg[i + 2:i + 4], "big")
        data = jpg[i + 4:i + 2 + length]
        if marker == 0xFE:
            comment = data.decode(errors="ignore")
            break
        i += 2 + length
    else:
        i += 1

channel, device_id = map(int, re.search(r"ch(\d+)\s+id(\d+)", comment).groups())
payload = bytes([0x55, 1, device_id, 0x01, 0x01] + [0] * 10)
payload += bytes([sum(payload) & 0xFF])
print(payload.hex(" ").upper())          # 55 01 13 01 01 00 ... 6B
print(hashlib.md5(payload.hex().encode()).hexdigest())
```

案例输出：`55 01 13 01 01 00 00 00 00 00 00 00 00 00 00 6B`，MD5 对应 flag。

## 变体与关联

- 变体：元数据可能藏在 JPEG APP1/EXIF、PNG tEXt、ID3、PDF 注释中；按格式解析而不是只 grep。
- 变体：帧校验可能是 CRC16、异或、和校验取反；以反汇编为准，不要默认和校验。
- 变体：2.4GHz 芯片可能是 NRF24L01/SI24R1/CC1101，寄存器配置与频道映射不同。
- 关联：[[ctf-reverse-unknownfirmware-1bpp-qr-row-shift-recovery]]（同场固件图像恢复）、[[ctf-forensics-openigtlink-position-trajectory-pixel-font]]（载体元数据隐写）、[[iot-industrial-mms-filewrite-firmware-upload-forensics]]（固件容器解析）。

## 检测与防御

- 防御：产品固件不要在字符串中保留调试菜单/raw payload 示例；发布前剥离符号与调试命令。
- 防御：RF 帧加入滚动码/nonce 与消息认证，防止重放和伪造；对触发命令做双向认证。
- 检测：固件中出现 `raw`/`trigger`/`ch`/`id` 调试字符串、固定魔数帧；空口出现重复的 16 字节固定帧。
- 响应：发现可伪造帧后更换协议密钥/滚动码，升级固件并限制调试接口。
