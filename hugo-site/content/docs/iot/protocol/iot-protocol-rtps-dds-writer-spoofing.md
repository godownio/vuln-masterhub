---
id: iot-protocol-rtps-dds-writer-spoofing
title: RTPS/DDS writer 身份无认证伪造：克隆 guidPrefix/entityId/SN 下发伪造控制指令
type: scenario
domain: iot
path: iot/protocol
technique: rtps-dds-writer-identity-spoofing
tags:
- rtps
- dds
- udp
- ics
- drone
- protocol
- spoofing
- no-authentication
- cdr
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:51:31+08:00'
  notes: 已对照原文核对；RTPS DATA CDR_LE 24 字节载荷、guidPrefix/entityId/SN 伪造与 domain42/17900、CRC 判据一致
url: /docs/iot/protocol/iot-protocol-rtps-dds-writer-spoofing/
draft: false
kb_aliases:
- RTPS writer 伪造
- DDS 无认证
- GuidPrefix 冒充
- entityId 伪造
- 无人机云台指令伪造
- RTPS DATA 子消息
---

## 一句话结论

RTPS/DDS 的 writer 身份由 `guidPrefix`（12 字节）+ `entityId`（4 字节）自声明，协议层没有认证或授权；攻击者只要嗅探到合法 writer 的 GUID 与当前序列号，就能伪造 RTPS DATA 子消息、携带合法 CRC 的 CDR 载荷和更大的 SN，让订阅端把伪造的云台/控制指令当成合法 writer 的最新命令执行。

## 原理

- RTPS（Real-Time Publish-Subscribe）是 DDS 的线上协议，通常跑在 UDP 上。每个 writer 由 `guidPrefix`（participant 标识）与 `entityId`（writer 端点标识）唯一命名；这两个字段完全由发送方在报文里填写，接收端只按它们做匹配，没有签名、证书或挑战应答。
- DATA 子消息的 `serializedData` 是 CDR 封装（常见 `00 01 00 00` = CDR_LE）加业务载荷；本例载荷为 24 字节：`seq(u32)|mode(u32)|pan(f32)|tilt(f32)|duration(u32)|crc32(u32)`，全部小端，`crc32 = zlib.crc32(payload[:20])`。
- 接收端通常按 writer GUID 维护状态，并以序列号（SN）判断新旧；同一 GUID 下更大的 SN 会被当作更新数据。攻击者嗅探到合法 writer 的 GUID 与最后 SN 后，构造 SN 更大的 DATA，即可覆盖/抢先下发控制指令。
- 合法 writer 的行为特征：entityId 恒定、每帧 CRC 正确、SN 单调递增；HEARTBEAT 子消息会声明该 writer 已发送的 SN 范围，可用于交叉验证。
- 伪造者的常见破绽（也是检测点）：entityId 在连续 DATA 帧间随机切换；目的端口落在错误 domain（如 domain-7 的 9150 而非 domain-42 的 17900）；CRC 校验失败；用他人 guidPrefix 但 SN 与 HEARTBEAT 不一致。
- 本例抓包中，合法 writer（`aabbccddeeff10203040` / entity `000003c2`）在 6 帧上保持身份、CRC、SN 连续性三重一致；伪造流使用 `deadc0de001337420042`、`1234123456789abcdef0` 等前缀，entityId 随机变化，并混入坏 CRC 与错误 domain 端口。
- DDS Security 规范提供认证、访问控制与加密插件，但默认未启用；未启用时，协议层无法区分合法 writer 与伪造 writer。

## 触发条件

- 攻击者能嗅探/预测目标 DDS 域内的 RTPS 流量（同一二层网络、可镜像端口或可路由到 UDP 端口）。
- 目标未启用 DDS Security（或无签名/加密），writer 身份仅靠 guidPrefix/entityId 匹配。
- 攻击者知道或能嗅探到合法 writer 的 guidPrefix、entityId 与当前 SN；知道业务载荷结构与 CRC 算法。
- 目标接收端按“同 GUID 更大 SN 获胜”处理数据，且没有额外的应用层鉴权/白名单。
- 能向目标 domain 的 RTPS 端口发包（如 domain 42 的 17900）。

## 利用步骤

1. 抓包识别 RTPS 流量：UDP 端口按 `7400 + 250*domainId + offset` 计算（domain 42 的 participant 端口为 17900）。
2. 解析 DATA 子消息：跳过 20 字节 RTPS 头，按子消息 ID/长度遍历；取 `serializedData` 的 CDR 封装与 24 字节业务载荷。
3. 记录合法 writer：`guidPrefix`、`entityId`、最后 SN、HEARTBEAT 声明的 SN 范围、CRC 算法。
4. 构造伪造载荷：设置目标 `seq`（大于合法 SN）、`mode`、`pan`、`tilt`、`duration`，计算 `crc32(payload[:20])`。
5. 构造 RTPS DATA：使用合法 writer 的 guidPrefix/entityId，填入 CDR 封装与载荷，发送到目标 domain 端口。
6. 观察接收端是否接受：云台/控制状态是否按伪造值变化；必要时重放/提高 SN，或等待 HEARTBEAT 周期后再发。
7. 注意：真实环境中 RELIABLE 读者可能通过 HEARTBEAT/ACKNACK 发现不一致；BEST_EFFORT 或缺少完整性校验的读者更容易被覆盖。

## PoC

```python
import struct, zlib, socket

seq, mode, pan, tilt, duration = 106, 7, -0.145, -0.5475, 1605
body = struct.pack('<IIffI', seq, mode, pan, tilt, duration)
crc = zlib.crc32(body) & 0xffffffff
payload = body + struct.pack('<I', crc)          # 24 字节业务载荷
serialized = b'\x00\x01\x00\x00' + payload       # CDR_LE 封装
# 再按 RTPS 头 + DATA 子消息格式封装，guidPrefix/entityId 使用嗅探到的合法 writer
```

RTPS DATA 子消息的关键字段（示意）：

```text
RTPS header: "RTPS" | version | vendorId | guidPrefix(12)
DATA submessage: id=0x15 | flags | octetsToNextHeader | extraFlags | octetsToInlineQos | readerId(4) | writerId(4) | writerSN(8) | serializedData
```

PoC 未在本机执行；真实注入需要按目标 DDS 实现的 RTPS 版本、子消息标志与 QoS 调整，且可能被 DDS Security 或 RELIABLE 机制阻断。

## 变体与关联

- 变体：伪造 HEARTBEAT/ACKNACK 子消息干扰合法 writer 的状态机，或先发送 StopOffer/Dispose 让订阅端丢弃合法数据，再冒充 writer 下发指令。
- 变体：若目标使用 DDS Security 但只启用加密未启用认证，仍需验证是否能重放/伪造；不要假定加密等于身份可信。
- 变体：同一“身份自声明 + 无认证”问题也出现在 SOME/IP-SD、MMS、Modbus 等工控协议，可利用方式类似。
- 关联卡片：[[iot-protocol-someip-sd-stopoffer-spoof-tp-command]]（SOME/IP-SD 伪造 StopOffer 并冒充服务下发指令）、[[iot-protocol-hartip-command9-quadrant-covert-channel]]（工控协议隐蔽信道）。
- 注意：本例来自 CTF 抓包分析，验证了伪造 writer 帧的存在与识别方法，未在真实无人机/工控网络执行注入；实际可用性取决于 QoS、DDS 实现与安全插件。

## 检测与防御

- 防御：启用 DDS Security 的认证、访问控制与加密插件；为 writer 配置权限白名单，拒绝未授权 GUID。
- 防御：在应用层对控制指令做签名/序列号+时间戳校验，不单纯依赖 RTPS SN；对云台/执行器指令增加独立的命令认证。
- 防御：网络分段与 ACL，限制谁能向 DDS domain 端口发包；关闭不必要的 DDS 域发现/多播。
- 检测：同一 GUID 的 entityId 突变、CRC 失败、SN 跳跃、HEARTBEAT 声明的 SN 范围与 DATA 不一致、目的端口与 domain 不匹配；对合法 writer 建立行为基线（GUID/entityId/端口/SN 连续性）。
- 检测：抓包侧解析 RTPS DATA，按 writer GUID 聚合，标记“身份相同但 entityId 变化”“SN 超出 HEARTBEAT 窗口”“CRC 错误”的帧。
- 响应：隔离受影响的 DDS 网段，重置控制设备状态，检查是否有伪造指令被执行，启用 DDS Security 并轮换相关凭据。
