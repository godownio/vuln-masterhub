---
id: iot-industrial-modbus-read-input-register-response-tamper
title: Modbus/TCP 读输入寄存器响应篡改：温度 >4300 时改写为 4100+value%200，让 HMI 持续显示安全值
type: scenario
domain: iot
path: iot/industrial
technique: modbus-tcp-read-input-register-response-tamper
tags:
- iot
- industrial
- modbus
- mitm
- sensor-spoofing
- plc
- scada
- safety-interlock
- response-tampering
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T07:55:34+08:00'
  notes: 已对照原文1807行与37张图核对：task_2_3 代码 Buf[7]==0x04、Buf[10]*256+Buf[9]、>4300 改写为4100+value%200 与原文逐字一致；curr_T=30004/set_T=40003/heating_S=2 与图21/22/25一致。dup-scan pair(两卡 cosine 0.9347 likely_duplicate) 按原文裁决：本卡是读响应篡改(task_2_3)，另一卡是写命令按来源屏蔽(task_3_3)，代码/触发/效果均不同，判为两个技术原子，保留两卡。原文无组件版本，未设versions。未运行文中的服务/PoC。
url: /docs/iot/industrial/iot-industrial-modbus-read-input-register-response-tamper/
draft: false
kb_aliases:
- Modbus 监听与篡改
- 温度传感器欺骗
- curr_T 篡改
- 4100+value%200
- PLC 寄存器响应改写
- Modbus MITM
---

## 一句话结论

在 Modbus/TCP 通道中间拦截 PLC 返回的“读输入寄存器”响应（功能码 `0x04`），解析当前温度寄存器 `curr_T`；当真实温度值超过 4300（43.00°C）时，把它改写为 `4100 + value % 200`，使上位机/操作员/监控员看到的温度始终落在 4100–4299 的“安全”区间，从而隐藏真实越限并阻止人工干预。

## 原理

- **Modbus/TCP 没有认证和完整性**：报文由 MBAP 头 + PDU 组成，读输入寄存器的请求/响应功能码为 `0x04`，响应里包含字节计数和每个 16 位寄存器的值。协议本身不签名、不加密，任何能坐在 PLC 与 HMI/操作站之间的人都能改响应。
- **篡改点**：中间人收到 PLC 返回的响应后，按协议解析功能码与寄存器值；文章的参考实现按自己的缓冲区布局判断 `Buf[7] == 0x04`，用 `Buf[10]*256 + Buf[9]` 取 16 位温度值（低字节在前，实际字节序按目标协议调整）。如果值大于 4300，就改写为 `4100 + value % 200`，再原样转发。
- **为什么用 `4100 + value % 200`**：阈值是 4300，直接清零或改成固定值容易与历史数据/其他传感器不一致；`value % 200` 让显示值随真实值轻微变化（4100–4299），看起来像正常波动，同时永远低于 4300 的告警线，能长期骗过只看该寄存器的 HMI/操作员。
- **为什么 HMI 会信**：上位机通常直接展示 PLC 返回的寄存器值，并把越限判断建立在同一份数据上；如果它没有独立的物理传感器、历史趋势交叉校验或第二路测量，篡改后的响应就是它看到的全部“事实”。
- **危害**：真实温度可能持续上升，但操作员/监控员看到的始终是安全值，不会触发告警或手动降温；加热丝、恒温箱等设备可能过热，形成安全问题。文章中的场景是恒温箱：`curr_T` 为输入寄存器 30004，`set_T` 为保持寄存器 40003，`heating_S` 为线圈 2。
- **前提**：攻击者位于 Modbus/TCP 可达路径（ARP 欺骗、交换机/路由器劫持、被篡改的协议插件/网关），能双向转发并改写报文；目标使用明文 Modbus/TCP，且 HMI 信任单一路径的寄存器值。

## 触发条件

- 目标使用 Modbus/TCP（默认 502 端口或自定义端口），PLC 与 HMI/操作站之间无 TLS/VPN/签名等完整性保护。
- 攻击者可中间人（同网段 ARP 欺骗、控制交换机/网关、在数据路径中植入恶意插件）。
- 上位机读取输入寄存器（功能码 `0x04`，或保持寄存器 `0x03`）并直接用于显示/告警。
- 关键寄存器地址/含义已知（如 `curr_T`=30004），且篡改后的值不会被独立的物理传感器或第二路测量交叉校验。

## 利用步骤

1. 确认 Modbus/TCP 路径与寄存器映射：读输入寄存器请求/响应、`curr_T` 地址、温度缩放（文章 4300 表示 43.00°C）。
2. 在中间人位置抓取 PLC 响应，解析 MBAP 头与 PDU：功能码、字节计数、目标寄存器值与字节序。
3. 对功能码 `0x04` 的响应，取出 `curr_T` 的 16 位值；若值 > 4300，计算 `new = 4100 + value % 200`，按原字节序写回响应。
4. 转发修改后的响应；对非目标功能码/寄存器原样转发，避免破坏其他业务。
5. 持续监控：每次读响应都重复篡改；若 HMI 有历史趋势/平均值校验，可让 `new` 随真实值变化以保持“自然”。
6. 可与其他手法组合：同时篡改 `set_T`/`heating_S` 或屏蔽自动逻辑写命令，使真实温度继续上升而界面保持安全。

## PoC

文章给出的参考实现（按其缓冲区布局，字节序按目标调整）：

```c
if (Buf[7] == 0x04) // read input register
{
    UINT16 value;
    value = Buf[10] * 256 + Buf[9];
    if (value > 4300)
    {
        value = 4100 + value % 200;
        Memcpy(Buf + 9, &value, sizeof(value));
    }
}
```

Python 伪代码（按 Modbus 标准大端解析时）：

```python
def tamper_read_input_registers(resp: bytearray, value_offset: int) -> bytearray:
    # resp[7] = function code; 0x04 = read input registers
    if len(resp) > value_offset + 1 and resp[7] == 0x04:
        value = int.from_bytes(resp[value_offset:value_offset+2], "big")
        if value > 4300:
            value = 4100 + value % 200
            resp[value_offset:value_offset+2] = value.to_bytes(2, "big")
    return resp
```

```text
# 文章中的 Modbus 报文示例（ADJUST set_T=3900）：
# 01 00 00 00 00 06 01 06 43 9c 3c 0f
# 读输入寄存器响应的功能码为 0x04，curr_T 位于输入寄存器 30004。
```

## 变体与关联

- **功能码变体**：读保持寄存器 `0x03` 也可能返回温度/设定值；写单寄存器 `0x06`、写多寄存器 `0x10` 可篡改设定值或加热开关。
- **篡改策略变体**：固定值、`min(value, 4299)`、`value - 200`、按真实值加随机抖动；目标是让显示值低于阈值且看起来自然。
- **位置变体**：在操作站侧篡改响应（只骗操作员）或在 HMI 侧篡改（骗监控）；也可在网关/协议插件中实现。
- **组合变体**：先篡改响应隐藏温度，再屏蔽 PLC 自动逻辑的写命令（见关联卡），让真实温度持续上升而无人干预。
- **关联**：[[iot-industrial-scada-snapshot-mmap-state-forgery]]（直接改 SCADA 快照的真实/观测值，属于状态文件层的同类传感器欺骗）、[[iot-industrial-s7comm-elevator-multi-db-state-forgery]]（伪造 PLC 状态触发 HMI 错误显示）、[[ctf-forensics-modbus-read-register-pdf-carve-password-hidden-text]]（Modbus 读寄存器流量的取证解析）。
- **边界**：HMI 若使用 Modbus/TLS、VPN、签名或独立物理仪表交叉校验，篡改会被发现；若 PLC 响应经过带完整性校验的网关，单纯改报文不成立。

## 检测与防御

- **协议层**：不要把明文 Modbus/TCP 暴露在不可信网络；使用 Modbus/TLS、IPsec/VPN 或串行/隔离网关；对主站/从站做 IP/MAC 白名单与端口隔离。
- **监测**：对同一寄存器的值做历史趋势与物理一致性校验（温度变化率、加热功率与温度上升的对应关系）；检测响应重复、MBAP 长度/功能码异常、同一请求出现两个不同响应（ARP 欺骗迹象）。
- **架构**：HMI 使用独立传感器/第二路测量做交叉验证；关键安全联锁不依赖单一 Modbus 通道；把安全仪表系统（SIS）与过程控制网络隔离。
- **检测**：网络中同一 502 连接出现响应被修改的迹象；`curr_T` 长期贴在阈值下方（如 4100–4299）而加热功率持续高位；操作员看到的温度与现场物理温度不一致。
