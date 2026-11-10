---
id: iot-hardware-saleae-i2c-cardkb-keyboard-decode
title: Saleae Logic 解析 I2C 键盘：CardKB 地址 0x5F，过滤空报告按字节还原输入密码
type: scenario
domain: iot
path: iot/hardware
technique: saleae-i2c-cardkb-keyboard-decode
aliases:
- Sniff one
- CardKB 键盘
- M5Stack I2C 键盘
- Saleae I2C 分析器
- 逻辑分析仪键盘解码
- I2C 0x5F
tags:
- iot
- hardware
- saleae
- logic-analyzer
- i2c
- keyboard
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
  verified_at: '2026-11-07T23:22:45+08:00'
  notes: 已对照原文核对：CardKB I2C地址0x5F、SDA/SCL对应D0/D1、Saleae I2C分析器Channel0/1配置、CSV按start/address/data/stop解析、取0x5F事务首个数据字节、过滤<=0x01空报告、还原flag{717f7532}均与正文、脚本及img07-09一致。未复跑原文sal。
---

## 一句话结论

逻辑分析仪 `.sal` 抓包中 SDA/SCL 分别接在 D0/D1 时，用 Saleae Logic 2 的 I2C 分析器（SDA=Channel 0、SCL=Channel 1）解码，把结果导出 CSV；按 `start/address/data/stop` 解析，筛出地址 `0x5F` 的读事务，取每次事务的第一个数据字节作为键码，过滤 `0x00`/`0x01` 等空报告后转 ASCII，即可还原键盘输入的密码 flag（本场景 `flag{717f7532}`）。

## 原理

- **设备与协议**：M5Stack CardKB 是 I2C 键盘，从机地址 `0x5F`；主机周期性读取按键状态，每次返回一个字节的键码（ASCII），无按键时返回 0x00 或 0x01 等空报告。
- **I2C 波形**：SDA 为数据线，SCL 为时钟线；SCL 高电平期间 SDA 变化表示 START/STOP，SCL 高电平期间 SDA 稳定为数据位。Saleae 的 I2C 分析器按此解码地址、读写位、ACK/NAK 和数据字节。
- **通道识别**：设备接线图可确认 SDA/SCL；也可看波形——恒定方波是 SCL，随数据变化的是 SDA。本场景 D0=SDA、D1=SCL。
- **CSV 结构**：Saleae 导出的协议结果含每行的 `type`（start/address/data/stop）、`address`、`data` 等字段；对每个 `start` 重置事务，记录 `address`，收集 `data`，在 `stop` 时判断地址是否为 `0x5F`。
- **空报告过滤**：主机持续轮询，绝大多数事务是“无按键”；键码 0x00/0x01 不代表输入字符（脚本用 `c > 0x01` 过滤），连续按住同一键可能重复出现，题目场景直接拼接即可得到密码。
- **为什么能出 flag**：键盘输入明文经 I2C 总线传输，逻辑分析仪抓包即可完整恢复按键序列。

## 触发条件

- 有 Saleae Logic 2 的 `.sal`（或可导入的逻辑分析仪抓包），采样率足够解码 I2C。
- 知道或能推断 I2C 地址（CardKB 为 0x5F）、SDA/SCL 通道。
- 抓包期间有键盘输入（密码通过 CardKB 输入）。
- 输入内容为 ASCII 可打印字符（flag 格式）。

## 利用步骤

1. 用 Saleae Logic 2 打开 `.sal`，查看通道波形/接线图，确定 SDA 与 SCL（本场景 D0/D1）。
2. 添加 `I2C` 分析器：SDA=Channel 0、SCL=Channel 1，勾选协议结果表/终端。
3. 将协议结果导出为 CSV（含 type/address/data 列）。
4. 用脚本按事务解析：`start` 重置；记 `address`；收集 `data`；`stop` 时若地址为 `0x5F`，取 `data[0]` 作为键码。
5. 过滤空报告（`<= 0x01`），把键码转字符并拼接，得到输入密码/flag。
6. 若存在重复/长按，按题目语义去重或保留；必要时人工核对按键序列。

## PoC

```python
import pandas as pd

raw = pd.read_csv('./keyboard.csv')
reading = False
address = None
data = []
key_data = []

for _, row in raw.iterrows():
    if row['type'] == 'start':
        reading = True
        address = None
        data = []
    if row['type'] == 'address':
        address = row['address']
    if row['type'] == 'data':
        data.append(row['data'])
    if row['type'] == 'stop':
        reading = False
        if address == '0x5F':
            key_data.append(int(data[0][2:], 16))

print(''.join(chr(c) for c in key_data if c > 0x01))
# flag{717f7532}
```

Saleae I2C 分析器配置：

```text
SDA: 00. Channel 0
SCL: 01. Channel 1
Show in protocol results table: 勾选
Stream to terminal: 勾选
```

## 变体与关联

- 其它 I2C 键盘/传感器：把地址换成目标从机地址，按数据格式解析；多字节读数需按寄存器拼接。
- I2C EEPROM/传感器读取：同样按 start/address/data/stop 解析，但需要区分读/写位与寄存器地址。
- 若只有 UART 调试口，参考 [[iot-hardware-saleae-logic-uart-decode]] 的 Async Serial 解码。
- 关联：SPI 电子墨水屏解码、其它硬件协议分析卡。

## 检测与防御

- 该场景是取证/CTF 技巧；真实产品中键盘/传感器总线应避免明文传输敏感数据，或对总线做物理防护。
- 设备设计上可使用加密键盘/安全元件，敏感输入不通过可被逻辑分析仪轻易抓取的总线明文传输。
- 对带调试/扩展接口的设备做物理访问控制与外壳防拆。
