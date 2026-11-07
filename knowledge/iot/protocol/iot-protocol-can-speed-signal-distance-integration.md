---
id: iot-protocol-can-speed-signal-distance-integration
title: CAN 报文车速信号识别与路程估算：按 ID 分组找单字节变化帧，积分 36s 得行驶距离
type: scenario
domain: iot
path: iot/protocol
technique: can-speed-signal-distance-integration
aliases:
- CAN 车速信号识别
- CAN 报文按 ID 分组
- 单字节变化帧
- CAN 路程积分
- 车联网总线流量分析
tags:
- can
- can-bus
- vehicle
- forensics
- signal-mining
- speed
- distance
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:05:47+08:00'
  notes: 已对照原文与图03核对：ID=0x00000280、单字节在0x46–0x5A波动、30个速度样本按36s积分得24470m，与原文flag{24470}一致；筛选逻辑（按ID分组、单字节变化、高优先级）与原文一致。未验证点：未在本机复跑积分脚本；frontmatter无sources/source_url；原文未给组件版本。
---

## 一句话结论

在未知 CAN 总线日志中，先按仲裁 ID 分组观察各帧 payload：车速只占 1 字节且优先级较高时，找 ID 较小、只有 1 个字节在 0x50 附近波动的帧（本例 ID=0x280，0x50≈80 km/h）；把该字节按 km/h 解释，按采样间隔 Δt=36s 对速度做积分 `Σ(v_i×Δt)/3600` 得到公里数，再换算为米即 flag（本例 24470 m）。

## 原理

- **CAN 仲裁与优先级**：CAN 帧的 11 位仲裁 ID 越小优先级越高；车辆周期性广播的实时信号（车速、转速）通常由高优先级 ID 承载，而诊断/状态帧可能 ID 更大或周期不同。
- **按 ID 分组找信号**：把日志按 ID 分组后，恒定不变的 payload 多为状态位/计数器/校验；真正承载物理量的帧通常只有少数字节变化，且变化范围与物理量量程一致。
- **车速字节识别**：题目提示车速只占 1 字节、在 80 km/h 左右；观察 ID=0x280 的帧，仅某个字节在 0x46–0x5A（70–90）之间波动，与 0x50（80）吻合，因此该字节就是 km/h。
- **路程积分**：CAN 日志按固定间隔 Δt=36s 采样；第 i 个样本速度 v_i（km/h）在 Δt 内近似恒定，距离增量 `v_i × Δt / 3600` km；累加后乘 1000 得米。
- **为什么能得到整数 flag**：30 个样本的积分结果约 24.47 km，四舍五入/取整为 24470 m；题目通常要求整数距离。

## 触发条件

- 拿到包含车速信号的 CAN 日志/pcap（candump、BLF、ASC 等），且采样间隔固定或可从时间戳推算。
- 目标车辆在日志期间保持行驶（速度非零），车速信号为 1 字节且与其它信号可区分。
- 知道速度单位（km/h）与采样间隔，或可通过题目提示/量程推断。
- 日志中的 ID 与信号映射未加密/未混淆，或变化规律足够明显。

## 利用步骤

1. 用 `candump`/Wireshark/脚本解析日志，按 CAN ID 分组，统计每帧各字节的取值集合与变化次数。
2. 找高优先级（ID 较小）、payload 只有 1 个字节明显变化的帧；检查变化范围是否与车速量程（如 0x46–0x5A ≈ 70–90 km/h）吻合。
3. 确认该字节随车辆加速/减速单调变化，排除计数器/校验字节。
4. 按时间顺序提取每个样本的速度字节，换算为 km/h。
5. 用固定采样间隔 Δt 积分：`distance_km = Σ(v_i * Δt / 3600)`，再乘 1000 得米。
6. 对结果取整/按题目格式提交 flag。

## PoC

```python
speeds_hex = ["46","48","50","50","55","58","52","5A","58","58",
              "56","54","55","4F","4F","4F","4D","4D","4D","4E",
              "4E","53","56","56","59","59","51","52","4F","46"]

speeds = [int(h, 16) for h in speeds_hex]
delta_t = 36  # 秒

distance_km = sum(v * delta_t / 3600 for v in speeds)
distance_m = distance_km * 1000
print(distance_km, distance_m)
# 24.469999999999995 24469.999999999996 -> flag{24470}
```

说明：原文把 ID=0x280 的该字节识别为车速（0x50≈80 km/h），按 36s 间隔积分得到约 24470 m。实际日志需先按 ID 分组确认变化字节与时间戳；未在本机复跑。

## 变体与关联

- **CAN 日志信号挖掘**：[[iot-protocol-can-log-signal-mining]] 覆盖按 ID 估周期、定位变化字节/位、区分计数器与校验的通用方法；本卡是在已知车速信号特征下的路程积分应用。
- **CAN 干扰帧过滤**：[[ctf-forensics-can-signal-id-filter-speed-peak-frame-hash]] 用 payload 唯一率过滤干扰帧并定位真实车速 ID；本卡直接用“单字节变化 + 0x50 附近”特征识别。
- **CAN 仲裁 ID 发现**：[[iot-protocol-can-arbitration-id-discovery-spoofing]] 覆盖 ID 逆向与伪造；本卡只做被动信号分析。
- **边界**：若车速信号经过缩放/偏移（如 0.5 km/h 精度、大端/小端）、采样间隔不固定或日志缺失时间戳，需要先校准；若车辆静止或速度信号被网关过滤，本方法不成立。

## 检测与防御

- 防御：对 CAN 总线做网关隔离与入侵检测，监控异常高频/异常 ID 报文；对车速等安全关键信号做冗余校验与合理性检查。
- 检测：CAN 日志中出现非周期/异常 ID、payload 变化模式异常、车速信号与实际 GPS 速度不一致。
- 响应：隔离总线、保存日志、核对 ECU 固件与网关配置，排查是否存在报文注入/重放。
