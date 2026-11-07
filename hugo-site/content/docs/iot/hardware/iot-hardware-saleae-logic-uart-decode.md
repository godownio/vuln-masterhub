---
id: iot-hardware-saleae-logic-uart-decode
title: Saleae Logic 分析 .sal 抓包：Async Serial 解码 UART 115200 8N1 还原设备文本
type: scenario
domain: iot
path: iot/hardware
technique: saleae-logic-uart-async-serial-decode
tags:
- iot
- hardware
- saleae
- logic-analyzer
- uart
- serial
- protocol-decode
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:29+08:00'
  notes: 已对照原文与图片16/18/20核对：Async Serial 01.RX、115200 8N1、LSB first、解码文本与 flag 片段一致；PoC 为 GUI 操作要点，未复跑。
url: /docs/iot/hardware/iot-hardware-saleae-logic-uart-decode/
draft: false
kb_aliases:
- Saleae Logic 2
- .sal 文件
- Async Serial
- UART 解码
- 逻辑分析仪
- 串口调试口
---

## 一句话结论

拿到逻辑分析仪保存的 `.sal` 抓包后，在 Saleae Logic 2 中加 `Async Serial` 协议分析器，按通道（TX/RX）、波特率（常见 9600/115200）、8 数据位、无校验、1 停止位、LSB first 配置，就能把 UART 波形解码成文本/十六进制，恢复设备的启动日志、调试输出或隐藏消息。

## 原理

- **UART 波形**：UART 空闲为高，起始位拉低，随后按波特率逐位发送数据（LSB first），可选校验位和停止位（高）。逻辑分析仪以固定采样率（本例 25MHz）记录电平，软件按波特率对采样点做位判决。
- **`.sal` 文件**：Saleae Logic 2 的工程文件，包含数字通道采样、通道名、时间轴和已添加的分析器；打开后可直接看到原始波形。
- **Async Serial 分析器**：Logic 2 内置的 UART 解码器，需要选择输入通道、波特率、每帧位数、停止位、校验位、位序、是否反相；配置正确后会在协议结果表中输出每个字节/字符。
- **波特率试错**：未知波特率时，从 9600、19200、38400、57600、115200 等常见值尝试；错误波特率会得到乱码/帧错误，正确时出现可读 ASCII（如 `HTB{...}`、启动日志、`INFO:`/`WARNING:`）。
- **通道选择**：题目/设备常把 TX/RX 分别接到不同通道；先看通道名（TX/RX）或尝试每个通道。若信号反相，勾选 `Signal inversion`。
- **为什么能拿到 flag**：设备的调试串口往往明文输出启动信息、错误码、密钥/flag；逻辑分析仪抓包后解码即可。

## 触发条件

- 拿到 `.sal`/`.logicdata` 等逻辑分析仪抓包，含 UART 波形。
- 采样率足够高（至少数倍于波特率；本例 25MHz 可支持高波特率）。
- 知道或能猜出波特率/帧格式；常见 115200 8N1。
- 设备在抓包期间有串口输出（启动、调试命令、错误信息）。

## 利用步骤

1. 用 Saleae Logic 2 打开 `.sal` 文件，查看通道名（TX/RX）与采样率。
2. 点击 `+` 添加分析器，选择 `Async Serial`。
3. 选择输入通道（先试 TX/RX），设置波特率（先 115200，再 9600 等），Data Bits 8、Parity None、Stop Bits 1、LSB first、Non Inverted、Normal。
4. 观察协议结果表/终端：出现可读文本即配置正确；若乱码，调整波特率/通道/反相。
5. 复制/筛选输出，按 `HTB{...}`、`flag{...}`、`INFO:`、`WARNING:` 等关键字提取；必要时导出 CSV 做后处理。
6. 若数据是二进制协议（非 ASCII），按十六进制查看并对照设备协议文档解析。

## PoC

GUI 配置（Logic 2）：

```text
Analyzer: Async Serial
Input Channel: 01.RX（或实际 TX 通道）
Bit Rate: 115200
Bits per Frame: 8
Stop Bits: 1
Parity: None
Significant Bit: Least Significant Bit Sent First
Signal Inversion: Non Inverted
Mode: Normal
```

解码结果示例（节选）：

```text
HTB{
INFO: Communication systems are offline reference code: 547311173_
WARNING: Unauthorized subroutines detected! reference code: n37w02k_
WARNING: The satellite dish cannot sync with the swarm. reference code: c0mp20m153d}
```

提取：

```python
import re
text = open("decoded.txt", encoding="utf-8", errors="ignore").read()
m = re.search(r"HTB\{[^}]*\}", text.replace("\n", ""))
print(m.group(0) if m else "not found")
```

命令行替代（若已转换为 VCD/数字采样，可用 sigrok-cli）：

```bash
sigrok-cli -i capture.vcd -P uart:baudrate=115200:rx=D0 -A uart=rx_data
```

## 变体与关联

- **SPI/I2C/CAN**：同一逻辑分析仪可加对应协议分析器；先看通道数与波形特征（SPI 有 CS/CLK/MOSI/MISO，I2C 有 SCL/SDA）。
- **反相/开漏**：UART 经过电平转换/光耦时可能反相，勾选 Signal inversion。
- **非标准波特率**：从最小脉宽估算位宽（`baud ≈ 1 / bit_width`），或暴力枚举常见值。
- **二进制协议**：ASCII 不可读时按 hex 导出，找魔数/长度字段/校验和。
- **关联卡片**：[[iot-hardware-bes2300-rom-bootloader-uart-dump]]（UART ROM Bootloader 提取固件）；[[iot-protocol-can-replay-candump-canplayer]]（CAN 总线抓包/重放）。

## 检测与防御

- **调试口暴露**：量产设备应关闭/移除 UART 调试口，或加认证/写保护；不要通过串口输出密钥、flag、内部路径。
- **硬件安全**：对调试接口做物理防护（禁焊盘、封装内走线、熔断 eFuse）；启动日志最小化。
- **取证**：保留 `.sal` 原始文件与哈希；记录采样率、通道映射、分析器配置，保证结果可复现。
- **检测**：对设备 UART 输出做敏感信息扫描；发现明文密钥/调试命令立即整改。
