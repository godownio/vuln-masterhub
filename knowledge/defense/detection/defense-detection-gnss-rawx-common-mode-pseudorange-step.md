---
id: defense-detection-gnss-rawx-common-mode-pseudorange-step
title: GNSS 欺骗检测：RXM-RAWX 同星座伪距共模阶跃与跨星座一致性校验
type: scenario
domain: defense
path: defense/detection
technique: gnss-rawx-common-mode-pseudorange-step-detection
aliases:
- GNSS 欺骗检测
- GPS 欺骗
- 伪距共模跳变
- RXM-RAWX
- RAIM 失效
- 跨星座一致性
tags:
- gnss
- gps
- spoofing
- detection
- u-blox
- ubx
- rawx
- raim
- drone
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:51:46+08:00'
  notes: 已对照原文核对；NAV-PVT 正常但 RAWX 同星座 6 星同步阶跃 75.0m、Galileo 连续、onset 第 37 历元一致
---

## 一句话结论

当 GNSS 接收机被欺骗时，NAV-PVT 仍可能报告 3D Fix、卫星数与精度因子正常，RAIM 也因共模偏移低于告警门限而不报警；要发现欺骗，必须下探到 RXM-RAWX 原始观测量，检测同一星座多颗卫星在同一历元出现几乎相同的伪距阶跃，并用未受影响星座的连续性作为对照。

## 原理

- RAIM（接收机自主完好性监测）基于各通道伪距残差的一致性；它擅长发现单颗卫星的异常（如多径、星历错误），但对“所有卫星同时被注入相同偏移”的共模欺骗不敏感——残差仍然一致，检验统计量不超门限。
- NAV-PVT 的位置/速度/精度因子来自接收机内部解算；欺骗信号若在物理层与合法信号同步、且偏移缓慢/幅度小，接收机可能持续输出 3D Fix、正常卫星数和 DOP。
- 欺骗信号在物理上很难做到“只改一个星座而不影响星座间几何一致性”：攻击者通常对某一星座的全部卫星注入相同的伪距增量，导致该星座所有卫星在同一历元出现相同方向的阶跃；其他星座（如 Galileo）不受影响，保持连续。
- 检测判据：逐星计算伪距增量 `delta(t) = prMes(t) - prMes(t-1)`；若同一星座多颗卫星在同一历元同时出现远大于噪声的阶跃，且各星阶跃量高度一致（散布远小于多径/钟漂的正常差异），即为共模注入的直接证据。
- 量化方法：用前若干历元（如 6 个）对每颗卫星的伪距做最小二乘外推，计算当前历元实测值与预测值之差；对同星座各星的阶跃取中位数，散布用于判断是否为共模。
- 对照方法：用未受影响星座的伪距连续性证明“不是接收机钟漂/电离层/几何变化”；钟漂会影响所有星座，几何变化不会让六条独立路径在同一秒产生几乎相同的偏移。

## 触发条件

- 目标接收机输出原始观测量（u-blox UBX `RXM-RAWX`，或其他厂商的 raw measurement 日志）；仅有 NAV-PVT/NMEA 无法做此检测。
- 攻击者能对目标星座实施欺骗（如 GPS L1），且欺骗信号与合法信号在接收机处功率/时延可控。
- 接收机未启用或无法启用抗欺骗/信号认证（如 Galileo OSNMA、GPS M-code），RAIM 门限高于共模偏移。
- 分析侧能拿到连续历元的原始伪距、载波相位、多普勒与卫星号；知道星座归属。

## 利用步骤

1. 采集 UBX 原始数据：同时记录 `NAV-PVT`（位置/定位状态）与 `RXM-RAWX`（每颗卫星的 `prMes`、`cpMes`、`doMes`、`gnssId`、`svId`、`locktime`）。
2. 建立基线：对每颗卫星取欺骗前的连续历元（如 6 个），用最小二乘拟合伪距随时间的变化，外推下一历元预测值。
3. 计算残差：`step = prMes(t) - predicted(t)`；逐历元、逐卫星记录。
4. 找共模事件：按星座分组，检查同一历元是否有多颗卫星同时出现同方向、同量级的 step；计算该组 step 的中位数与散布（如中位数 75.0 m、散布 < 0.5 m）。
5. 交叉验证：检查未受影响星座（如 Galileo）是否连续；检查接收机钟差/钟漂是否同步变化；检查卫星数、DOP、定位状态是否仍正常（正常反而说明 RAIM 不可靠）。
6. 判定 onset：共模阶跃首次出现的历元即欺骗开始；受影响星座为阶跃卫星所属星座；阶跃量取中位数作为伪距偏移估计。
7. 响应：切换备用导航源/惯导，告警并记录原始观测，必要时启用抗欺骗认证或限制自动驾驶/无人机控制指令。

## PoC

```python
import numpy as np

def step_estimate(deltas, onset, window=6):
    """对单颗卫星的前 window 个伪距增量做线性外推，返回当前历元残差"""
    hist = deltas[onset - window:onset]
    t = np.arange(len(hist))
    k, b = np.polyfit(t, hist, 1)
    predicted = k * window + b
    return deltas[onset] - predicted

# 对每个星座的每颗卫星计算 step；同一历元同星座多颗卫星
# 出现同方向、同量级 step 且散布远小于多径噪声 => 共模欺骗
```

判定示意（合成/示例数据）：

```text
epoch 36 -> 37: GPS 6 颗卫星 step = 74.975, 74.986, 75.010, 75.025, 75.017, 74.993 m
               中位数 75.0 m，散布 < 0.5 m
               GALILEO 6 颗卫星连续，无阶跃
NAV-PVT: 3D Fix, 12 sats, DOP 正常  -> RAIM/接收机未告警
```

PoC 为检测逻辑示意，不含真实数据；阈值需按接收机噪声、采样率、动态场景标定。

## 变体与关联

- 变体：只欺骗单星座（如 GPS）而保留其他星座；也可同时欺骗多星座但保持星座间几何一致（难度更高）。
- 变体：缓慢漂移式欺骗（每秒米级）比阶跃更难发现，需要长基线趋势/载波相位一致性检测；本卡针对阶跃/共模注入。
- 变体：用载波相位（`cpMes`）或多普勒（`doMes`）交叉验证伪距阶跃，排除周跳/多径。
- 关联卡片：[[iot-protocol-rtps-dds-writer-spoofing]]（无人机控制协议伪造）、[[iot-protocol-someip-sd-stopoffer-spoof-tp-command]]（工控协议伪造）。
- 边界：本方法依赖原始观测量；消费级接收机可能不输出 RAWX，或输出频率过低。抗欺骗认证（OSNMA、信号签名）是更根本的防御。

## 检测与防御

- 检测：持续采集 RXM-RAWX，按星座/卫星建立伪距、载波相位、多普勒基线；对同星座多星同步阶跃、跨星座不一致、SNR/AGC 异常、钟差突变做联合告警。
- 检测：不要只依赖 NAV-PVT 的 3D Fix、卫星数、DOP 或 RAIM 告警；这些在共模欺骗下可能全部正常。
- 防御：启用信号认证（Galileo OSNMA、GPS 信号认证/M-code）与抗欺骗天线；多源融合（GNSS+INS+视觉/激光）；对无人机控制指令做独立认证与地理围栏。
- 防御：在检测到欺骗时切换到备用导航源，限制自动起降/航线变更，记录原始 IQ/观测数据用于取证。
- 响应：隔离受影响设备、校验任务指令来源、检查是否被诱导偏离航线，更新接收机固件与抗欺骗配置。
