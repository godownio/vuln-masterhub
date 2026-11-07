---
id: iot-vehicle-gps-l1-spoofing-gps-sdr-sim-hackrf
title: 车机 GPS L1 信号欺骗：gps-sdr-sim 生成伪卫星信号经 HackRF 发射伪造定位
type: scenario
domain: iot
path: iot/vehicle
technique: vehicle-gps-l1-spoofing-sdr
tags:
- iot
- vehicle
- automotive
- gps
- gnss
- spoofing
- sdr
- hackrf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:43:01+08:00'
  notes: 已对照原文与图片36/38/40/43核对：gps-sdr-sim RINEX/坐标参数、HackRF 1575.42MHz/2.6Msps、PortaPack GPS Simulator 一致；PoC 未复跑。
url: /docs/iot/vehicle/iot-vehicle-gps-l1-spoofing-gps-sdr-sim-hackrf/
draft: false
kb_aliases:
- GPS 欺骗
- gps-sdr-sim
- HackRF GPS 发射
- L1 1575.42MHz
- 车机定位伪造
- GNSS 信号伪造
---

## 一句话结论

民用 GPS L1（1575.42MHz）信号无加密、无认证且功率弱，攻击者用 `gps-sdr-sim` 按公开星历和目标经纬度生成基带采样，再经 HackRF 以 2.6Msps 发射，就能让车机/导航接收机解算出攻击者指定的位置（静态坐标或动态轨迹），实现定位欺骗。

## 原理

- **GPS 定位依赖伪距**：接收机需要至少 4 颗卫星，通过信号传播时延计算伪距 `r = C × t`，再解算三维位置与钟差。攻击者只要伪造出与目标位置一致的伪距/星历信号，接收机就会输出错误坐标。
- **民用 L1 无认证**：L1 民用信号未加密，格式公开（C/A 码、导航电文），接收机无法从信号层区分真实卫星与伪造信号；军用 L2 加密，但车机通常只用民用 L1。
- **信号弱、易被覆盖**：GPS 信号到达地面功率极低，攻击者用 SDR 在近距离发射同频伪造信号即可压制/替代真实信号；转发式欺骗则延时重放真实信号，实现更隐蔽的漂移。
- **工具链**：`gps-sdr-sim` 读取 RINEX 星历（如 `brdc0010.22n`）与目标经纬度/轨迹 CSV，生成 8-bit 基带样本 `gpssim.bin`；`hackrf_transfer` 以 `-f 1575420000`（L1 频率）、`-s 2600000`（采样率）、`-x 40`（增益）发射。
- **为什么车机会中招**：车机导航/GNSS 模块只做信号解算，不与网络时间、惯性导航或地图匹配做强一致性校验；伪造信号强度足够时会被直接采纳。

## 触发条件

- 攻击者在目标车辆附近，具备 HackRF/BladeRF 等 SDR 发射能力与相应频段天线。
- 车机/导航使用民用 GPS L1，且未启用信号认证、INS 融合或异常检测。
- 能获取对应时段的公开 RINEX 星历（如广播星历文件）。
- 在合法授权范围内测试；发射功率需遵守当地无线电法规。

## 利用步骤

1. 准备 SDR 与天线，确认可发射 1575.42MHz；下载 `gps-sdr-sim` 并编译。
2. 获取目标时段的 RINEX 广播星历（如 `brdc0010.22n`）。
3. 生成静态位置样本：`./gps-sdr -e brdc0010.22n -l <lat>,<lon> -b 8`；或生成动态轨迹：`./gps-sdr-sim -e brdc3540.14n -u circle.csv -b 8`。
4. 用 HackRF 发射：`hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 40`。
5. 观察车机导航定位是否跳到指定坐标/轨迹；记录发射前后坐标与时间作为证据。
6. 测试结束停止发射，确认车机定位恢复；如造成导航/远程控制状态异常，按应急流程处理。

## PoC

```bash
git clone https://github.com/osqzss/gps-sdr-sim.git
cd gps-sdr-sim
gcc gpssim.c -lm -O3 -o gps-sdr

# 静态位置（示例坐标）
./gps-sdr -e brdc0010.22n -l 29.6562801500,91.1257504400 -b 8

# 动态轨迹
./gps-sdr-sim -e brdc3540.14n -u circle.csv -b 8

# HackRF 发射 L1
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 40
```

说明：原文用 HackRF One + PortaPack 的 GPS Simulator 功能复现，发射后地图定位点发生变化；参数 `-x 40` 为示例增益，实际需按法规与距离调整。本库未复跑。

## 变体与关联

- 变体：转发式欺骗——先接收真实卫星信号再延时转发，隐蔽性更高、实现难度更大。
- 变体：动态轨迹可让定位沿攻击者规划的路线移动，影响导航、车队调度或基于位置的远程控制策略。
- 变体：SDR 换成 BladeRF/USRP；采样率与增益按设备调整。
- 关联：[[defense-detection-gnss-rawx-common-mode-pseudorange-step]]（GNSS 欺骗检测：伪距共模跳变）、[[iot-vehicle-bluetooth-hid-keyboard-spoofing]]、[[iot-vehicle-camera-debug-console-20000-unauth]]（同属车机攻击面）。
- 限制：需要物理接近与合法频谱授权；现代车机若启用 GNSS+INS 融合、RTK 或信号监测，欺骗难度显著上升。

## 检测与防御

- 检测：定位坐标突变/漂移但车速与 IMU 数据不一致；卫星数量、信号强度异常（单一恒定强度、突然增加卫星）；卫星授时与网络时间偏差。
- 防御：GNSS + INS 融合与地图匹配；使用多星座/多频接收机；启用信号认证（如 Galileo OSNMA）或军用加密信号；监测 C/N0 与伪距一致性。
- 加固：对基于定位的远程控制/计费/调度逻辑增加二次校验，不把 GPS 坐标作为唯一信任源。
- 响应：定位异常时切换惯性导航、提示驾驶员，并记录频谱/信号异常用于溯源。
