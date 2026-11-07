---
id: iot-hardware-bes2300-rom-bootloader-uart-dump
title: BES2300 智能音响固件提取：UART ROM Bootloader BE 协议 dump Flash
type: scenario
domain: iot
path: iot/hardware
technique: bes2300-rom-bootloader-uart-dump
aliases:
- BES2300 固件提取
- ROM Bootloader dump
- BE 协议
- bestool
- SiP 无外部 Flash
- UART 921600
tags:
- iot
- hardware
- uart
- rom-bootloader
- firmware
- bes2300
- bestool
- flash-dump
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:19:22+08:00'
  notes: 已对照原文与5张图核对：SiP 无独立 Flash、UART 焊盘/CH340 3.3V 接线、115200 看日志与 921600 8N1 进 ROM Bootloader、BE 包格式与 checksum=0xFF-(sum&0xFF)、Sync 帧 BE50000101EF 与应答 BE500003020001EB、FlashRead BE030508+地址/长度小端、16KB 分块、bestool issue 的 0x3C000000→0x2C000000 与日志 FLASH_BASE=0x28000000/FLASH_SIZE=0x1000000、DSA 挑战应答只有公钥，均与原文/图01-05一致。未验证点：原文称完整脚本见文末附件但 content.md 未含附件，卡片 PoC 为按协议重构且未在真机复跑；原文“整包长度=5+payload[1]”表述含糊，卡片按示例帧长解释。
---

## 一句话结论

BES2300 智能音响采用 SiP 封装、Flash 与 SoC 封在一起，无法用编程器夹取；当固件损坏反复重启、串口拿不到交互 Shell 时，可在冷启动瞬间用 UART 921600 8N1 抢占 ROM Bootloader 的监听窗口，发送 `BE 50` Sync 握手让其停留在 Bootloader，再用 `BE 03` FlashRead 按 16KB 块读取整片 Flash，得到完整固件镜像。

## 原理

- BES2300 的启动流程：上电后 ROM Bootloader 初始化串口，开启短暂监听窗口；若 Flash 中二级固件完好则跳转执行，监听结束；若 Flash 为空/损坏，或窗口期内收到合法握手包，则停留在 ROM Bootloader 命令模式，支持读写 Flash。
- 设备变砖时固件无法走完启动流程，串口没有 `login:`，但 ROM Bootloader 仍然存在；利用点是“脚本先就绪，再给设备上电”，在窗口期发送 Sync。
- BE 协议包格式：`BE | type | payload | checksum`；`checksum = 0xFF - (前面所有字节之和 & 0xFF)`；整包长度与 payload 中的长度字段相关（示例 Sync 为 6 字节，FlashRead 为 13 字节）。
- Sync：`BE 50 00 01 01 EF`；芯片应答 `BE 50 00 03 02 00 01 EB`，其中 payload 的 `02 00` 表示已锁定/停留在 Bootloader。
- FlashRead：`BE 03 05 08 <地址 4 字节小端> <长度 4 字节小端> <checksum>`；芯片返回读出的 Flash 原始数据，按 16KB 分块读取。
- 地址映射是坑：bestool 默认可能使用 `0x3C00_0000`，社区 issue 建议改为 `0x2C00_0000`；启动日志又显示 `FLASH_BASE=0x28000000`、`FLASH_SIZE=0x1000000`（16MB），需要按实际芯片/固件验证读出的数据是否合理（如 CRC/字符串/分区头）。
- 串口登录的 root 密码不是简单逆向能得到的：固件用 SN + 4 字节随机数做挑战，用户输入十六进制 DSA 签名，固件用硬编码公钥验签；私钥在厂商手中，因此无法从固件推出密码。该机制不影响 ROM Bootloader dump，但说明“拿 Shell 再 dump”这条路走不通。

## 触发条件

- 目标为 BES2300/BES 系列芯片，Flash 与 SoC SiP 封装、无独立 Flash 芯片可夹取。
- 设备能上电、UART 可访问；固件损坏/变砖，无法进入系统或没有交互 Shell。
- 能识别 UART 焊盘（VCC/GND/TX/RX），并有 3.3V USB-TTL（CH340）。
- 能控制上电时序（先启动脚本，再上电），并知道/能猜出 Flash 地址映射。

## 利用步骤

1. 拆机，找 UART 焊盘（PCB 丝印/测试点），用万用表确认 VCC/GND/TX/RX；焊接排线。
2. CH340 跳线设为 3.3V；GND 共地，TX/RX 交叉连接；串口软件 Flow control=None。
3. 先用 115200 8N1 看正常启动日志，确认芯片型号、Flash 基址/大小（如 `FLASH_BASE=0x28000000`、`FLASH_SIZE=0x1000000`）。
4. 把串口切到 921600 8N1；脚本先打开串口并准备发送 Sync，再给设备上电。
5. 发送 `BE 50 00 01 01 EF`，读取应答；若返回 `BE 50 ... 02 00 ...` 表示已进入 Bootloader。
6. 从候选地址（`0x2C000000`/`0x28000000`/`0x3C000000`）开始，按 16KB 发送 FlashRead，读取数据并校验（CRC、字符串、分区头）。
7. 循环读取整个 Flash 大小（如 16MB），拼接保存为 `firmware.bin`；用 binwalk/strings/固件分析工具验证。
8. 若读出的数据全 0/全 FF，换地址映射或检查长度/校验和；若握手失败，检查波特率、上电时序、TX/RX 交叉。

## PoC

```python
import struct
import serial

def frame(typ: int, body: bytes) -> bytes:
    pkt = bytes([0xBE, typ]) + body
    chk = 0xFF - (sum(pkt) & 0xFF)
    return pkt + bytes([chk])

def sync(ser):
    ser.write(frame(0x50, b"\x00\x01\x01"))   # BE 50 00 01 01 EF
    return ser.read(6)                         # BE 50 00 03 02 00 01 EB

def flash_read(ser, addr: int, length: int) -> bytes:
    body = b"\x05\x08" + struct.pack("<II", addr, length)
    ser.write(frame(0x03, body))
    return ser.read(length)

ser = serial.Serial("COM4", 921600, timeout=2)
print(sync(ser).hex())

addr = 0x2C000000          # 按实际芯片/日志调整：0x2C000000 / 0x28000000
size = 0x1000000           # 16MB
chunk = 0x4000             # 16KB
out = bytearray()
for off in range(0, size, chunk):
    data = flash_read(ser, addr + off, chunk)
    if len(data) != chunk:
        print("short read at", hex(off), len(data))
    out += data

open("firmware.bin", "wb").write(out)
print("saved", len(out))
```

## 变体与关联

- 变体：其他 BES 芯片/ROM Bootloader 命令字、包长/校验方式可能不同；以 bestool/社区 PoC 为准。
- 变体：Flash 地址映射不同（0x2C000000/0x28000000/0x3C000000），需按启动日志/读回数据验证。
- 变体：有独立 Flash 芯片时可直接用编程器/SOP8 夹读取；SiP 封装才需要 ROM Bootloader。
- 关联：[[code-analysis-reverse-firmware-8051-eeprom-protocol-mac]]（8051 固件/EEPROM）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件仿真）、[[code-analysis-reverse-firmware-stm32-hal-function-identification]]（固件函数识别）。

## 检测与防御

- 检测：设备上电时 UART 出现非正常 Bootloader 握手、Flash 被整片读取、调试焊盘被引出。
- 防御：量产固件关闭/限制 ROM Bootloader 串口命令、启用安全启动与 Flash 加密、封装调试口/禁用 UART、对固件做完整性校验。
- 响应：确认固件被提取后，视为固件/密钥泄露，轮换设备密钥、升级安全启动策略并评估供应链影响。
