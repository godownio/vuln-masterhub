---
id: iot-protocol-can-bisection-replay-bit-fuzz
title: CAN 功能帧定位：candump 录制后用 canplayer 二分重放收窄到单帧，再用 cansend/ SavvyCAN 位级 fuzz 找出控制字段
type: scenario
domain: iot
path: iot/protocol
technique: can-bisection-replay-bit-fuzz
tags:
- can
- can-bus
- vehicle
- icsim
- can-utils
- savvycan
- replay
- fuzzing
- reverse-engineering
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V464
  verified_at: '2026-11-10T15:12:14+08:00'
  notes: 已通读原文并逐张核对全部 11 张图：图04 ICSim 仪表与 controls 控制器；图05 candump -l 日志格式；图07-09 SavvyCAN Connection→Add New Device Connection→SocketCAN vcan0；图10-11 Fuzzing Window（0x244、字节3=bb/4=2、位扫描、Interframe Timing 10ms）并观察 MPH 仪表变化；正文明确 candump 录制→canplayer 二分重放→cansend 单帧→SavvyCAN fuzz 的流程。未验证点：原文为入门教程，无实际二分命中记录或 fuzz 前后对照数据，PoC 为 can-utils 标准命令组合、未本机复跑；frontmatter 无 sources/source_url；affected_versions 为空符合原文（CAN 通用协议，无版本）。
url: /docs/iot/protocol/iot-protocol-can-bisection-replay-bit-fuzz/
draft: false
kb_aliases:
- CAN 二分法重放
- candump canplayer 二分
- CAN 功能帧定位
- cansend 单帧验证
- SavvyCAN fuzz
- ICSim 虚拟 CAN
---

## 一句话结论

在 CAN 总线上不知道哪个报文控制某功能时，用 `candump -l` 录下操作该功能期间的完整流量，把日志一分为二用 `canplayer` 分别重放，观察仪表/执行器是否复现动作，保留命中的一半继续二分，直到剩几帧时改用 `cansend` 单帧发送 `ID#DATA` 验证；随后用 SavvyCAN 的 Fuzzing Window 对目标 ID 的字节/位做定向 fuzz，即可从“能触发功能”进一步定位到具体控制位/字节。

## 原理

- **CAN 是广播、无认证的确定性总线**：所有节点看到所有帧，接收方按仲裁 ID 过滤；同样的 ID+数据在同一状态下会产生同样的执行结果，因此录制的合法帧可以重放（CAN 本身没有新鲜性/防重放）。
- **二分法的前提**：操作某个功能（加速、开门、转向）期间录到的日志中，至少有一帧是该功能的触发/状态帧；把日志按时间对半切，重放其中一半，若功能复现则目标帧在这一半，否则在另一半，重复 log2(N) 次即可把范围缩到个位数帧。
- **canplayer 负责批量重放**：`canplayer -I <log>` 按日志中的时间戳/顺序回放；ICSim 的仪表与车模会随重放动作变化，提供可视化判定信号。
- **cansend 负责单帧验证**：`cansend vcan0 <ID>#<DATA>` 发送单帧，用于确认“这一帧就是控制帧”，并可手工改数据观察字段含义。
- **SavvyCAN 位级 fuzz**：在 Fuzzing Window 里选择目标 ID（如 `0x244`）、数据字节数与位掩码，按设定间隔连续发送变异帧；ICSim 仪表的变化能指示哪一位/哪一字节对应车速等信号（本案例只 fuzz 最后一个/指定字节，观察 MPH 变化）。
- **为什么有效**：不需要逆向 ECU 固件或 DBC 文件，纯黑盒地用“录制—重放—二分—单帧—fuzz”把 CAN 日志变成功能帧与字段映射；对 ICSim 这类模拟器零风险，对真实车辆台架则需隔离环境。

## 触发条件

- 能访问目标 CAN 总线（真实车辆的 OBD-II/网关，或 Linux `vcan`/SocketCAN 虚拟总线 + ICSim 模拟器）。
- 已安装 `can-utils`（candump/canplayer/cansend/cansniffer/cangen）与可选的 SavvyCAN；对虚拟总线执行过 `setup_vcan.sh` 并启动 `icsim vcan0`、`controls vcan0`。
- 操作功能时能观察到明确的反馈（仪表数值、车门/转向灯状态、执行器动作），用于判断重放是否命中。
- 重放/发送不会对真实车辆造成危险（台架/模拟器/授权测试）。

## 利用步骤

1. 初始化虚拟总线：`./setup_vcan.sh`，启动模拟器 `./icsim vcan0` 与控制器 `./controls vcan0`。
2. 开始录制：`candump -l vcan0`（生成 `candump-<时间>.log`）；在控制器上执行一次目标动作（如加速），停止录制。
3. 把日志按行对半切，分别用 `canplayer -I half1.log`、`canplayer -I half2.log` 重放，观察 ICSim 仪表是否出现该动作；保留命中的一半。
4. 对命中的一半继续二分，直到剩几帧；用 `cansend vcan0 <ID>#<DATA>` 逐帧发送验证，确认控制帧。
5. 若知道 ID 但不知道字段：打开 SavvyCAN，Connection → Add New Device Connection → QT SerialBus Devices (SocketCAN)，设备 `vcan0`；打开 RE Tools → Fuzzing Window。
6. 在 Fuzzing Window 选择目标 ID（如 `0x244`）、Data Bytes、位扫描方式（Sequential/Sweep/Random），勾选要 fuzz 的字节/位，设置 Interframe Timing（如 10ms）与 Burst Rate，Start Fuzzing，观察仪表变化定位控制位。
7. 记录“ID+字节+位→功能”的映射，用于后续伪造/重放/安全评估报告。

## PoC

```bash
# 1) 虚拟 CAN 与 ICSim
./setup_vcan.sh
./icsim vcan0 &
./controls vcan0 &

# 2) 录制
candump -l vcan0           # 操作一次加速后 Ctrl-C

# 3) 二分重放（对日志按行切半）
canplayer -I candump-<time>.log.part1
canplayer -I candump-<time>.log.part2

# 4) 单帧验证
cansend vcan0 244#0000000BB2000000   # 示例，ID/数据按实际日志替换

# 5) 观察差异
cansniffer -c vcan0
```

本卡无本机执行记录；命令为 can-utils 标准用法，ICSim 环境搭建与 SavvyCAN 连接步骤按原文与工具官方文档。

## 变体与关联

- 与本项目既有 CAN 卡的侧重点：
  - `iot-protocol-can-replay-candump-canplayer`：整段日志重放（本卡在其上加二分定位）。
  - `iot-protocol-can-arbitration-id-discovery-spoofing`：在线 `candump`/`cansniffer` 观察 + `cansend` 伪造 ID（本卡用离线日志二分 + SavvyCAN fuzz）。
  - `iot-protocol-can-log-signal-mining`：统计日志变化定位信号（本卡用主动重放/fuzz 验证）。
- 工具变体：`cangen` 生成随机流量、`cansequence` 递增负载、`cansniffer` 观察变化；SavvyCAN 还可加载 DBC、图形化信号。
- 协议扩展：CAN-FD、ISO-TP（多帧重组）、UDS 诊断服务；真实车辆上还需考虑网关过滤、诊断会话与安全访问。

## 检测与防御

- 车辆/总线侧：部署 CAN IDS/网关白名单与频率基线，检测异常 ID、异常周期、重放与 fuzz 特征；对关键控制帧使用 SecOC/消息认证（若平台支持）；网关隔离 OBD 与关键域。
- 测试侧：只在隔离台架/虚拟总线（vcan+ICSim）做重放与 fuzz；真实车辆需授权并确保不会触发危险动作。
- 取证：保留 candump 日志、SavvyCAN 工程与 fuzz 配置，记录每次重放的 ID/数据/时间，便于复现与报告。
- 注意：CAN 无认证是协议层事实，防御重点在网关分段、入侵检测与整车信息安全流程，而不是单点补丁。
