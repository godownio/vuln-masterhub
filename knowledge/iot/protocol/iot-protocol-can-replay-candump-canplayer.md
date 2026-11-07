---
id: iot-protocol-can-replay-candump-canplayer
title: CAN 总线重放攻击：candump 记录合法帧 + canplayer 回放
type: scenario
domain: iot
path: iot/protocol
technique: can-replay-candump-canplayer
aliases:
- CAN 重放
- CAN Replay Attack
- candump -l
- canplayer
- 车辆重放
- ICSim 重放
tags:
- iot
- automotive
- can-bus
- replay
- can-utils
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:10:09+08:00'
  notes: 已对照原文与7张图核对：candump -l 记录、canplayer -I candump-2026-03-13_221006.log 回放及回放后仪表盘仍显示加速状态与原文/图07一致；'开门状态帧回放'为原文推测性表述，卡片已保留'可能'措辞。未验证点：原文为 ICSim 虚拟总线实验，未做实车验证；原文未标记受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

CAN 总线没有消息新鲜性/防重放机制：用 `candump -l` 记录合法 ECU 的 CAN 帧，再用 `canplayer -I <log>` 原样回放，仪表/执行器会再次执行加速、开门、转向等动作；记录到“开门状态”的帧在回放时可能让车辆误认为车主正在开门。

## 原理

- CAN 帧只有 CRC 传输校验，没有时间戳、nonce、计数器或 MAC；接收方只检查 ID/CRC/长度，不会区分“新帧”和“录制的旧帧”。
- 攻击者只需被动监听（不注入）记录一段合法流量，之后在任意时间重放；无需知道数据含义或 checksum 算法，因为帧本身是合法的。
- 示例：`candump -l vcan0` 记录日志；关闭控制器后 `canplayer -I candump-...log` 回放，仪表盘仍显示之前记录的加速/车门状态，证明重放有效。
- 重放可全量回放，也可按 ID/时间裁剪；真实车辆上可重放开门、解锁、灯光、车速等状态帧，具体效果取决于 ECU 是否要求计数器/挑战。
- 若目标有滚动计数器/时间戳校验，直接重放会失败；需要逆向计数器或结合伪造/中继。

## 触发条件

- 能接入 CAN 总线并被动监听（OBD-II、网关、调试口、虚拟 vcan0）。
- 目标 ECU 接受无计数器/无时间戳的 CAN 帧，或重放窗口足够宽。
- 能记录并回放 CAN 日志（can-utils/canplayer 或专用工具）。
- 重放的帧对应的功能没有额外的会话/认证保护。

## 利用步骤

1. 接入总线，确认接口与波特率（如 `ip link set can0 up type can bitrate 500000`）。
2. `candump -l can0` 开始记录；触发目标功能（开门、加速、转向、解锁等），让合法帧进入日志。
3. 停止记录，分析日志中的 ID/数据/时间戳；可按 ID 过滤或裁剪出目标帧。
4. 关闭合法控制器/停止触发，执行 `canplayer -I <log>` 回放；观察仪表/执行器是否响应。
5. 若全量回放噪声太大，构造只含目标 ID 的日志/脚本，按需调整发送间隔。
6. 若目标有计数器/校验，先逆向计数规则，或改用伪造/中继；测试后恢复车辆状态。

## PoC

```bash
# 记录
candump -l vcan0
# 触发加速/开门/转向后停止记录，得到 candump-2026-03-13_221006.log

# 回放
canplayer -I candump-2026-03-13_221006.log

# 只回放某个 ID（可先过滤日志或用脚本发送）
candump vcan0,244:7FF -l
canplayer -I <filtered.log>
```

## 变体与关联

- 变体：按 ID/时间窗口裁剪日志，只重放目标功能帧。
- 变体：修改回放间隔/顺序，绕过简单的时间窗口检测。
- 变体：有滚动计数器时，结合逆向/中间人实时转发（中继）而非离线重放。
- 关联：[[iot-protocol-can-arbitration-id-discovery-spoofing]]（CAN 伪造/ID 发现）、[[iot-protocol-uds-routinecontrol-can-injection-takeover]]（UDS 停发 + 注入）、[[iot-protocol-ble-smart-bulb-att-write-replay]]（BLE 重放）。

## 检测与防御

- 检测：CAN IDS 检测重复帧/异常周期/相同数据反复出现、同一帧在短时间内多次出现。
- 防御：SecOC/MAC、滚动计数器/时间戳、接收方维护重放窗口、网关白名单/速率限制。
- 响应：确认重放后隔离总线，审计异常帧，升级 ECU 认证与 IDS 规则。
