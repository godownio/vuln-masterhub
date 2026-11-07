---
id: iot-protocol-someip-sd-stopoffer-spoof-tp-command
title: SOME/IP-SD 无认证：伪造 StopOffer 下线制动服务，再冒充服务分片下发加密制动指令
type: scenario
domain: iot
path: iot/protocol
technique: someip-sd-stopoffer-spoof-tp-command
tags:
- ics
- automotive
- someip
- service-discovery
- stopoffer
- spoofing
- someip-tp
- brake-command
- zlib
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:17+08:00'
  notes: 对照工控230：0x327a、TTL 15→0 StopOffer、203.0.113.66:30507、42 段 TP、Offer entry 派生 keystream、FULL_BRAKE 参数一致；未复跑
url: /docs/iot/protocol/iot-protocol-someip-sd-stopoffer-spoof-tp-command/
draft: false
kb_aliases:
- SOME/IP 服务发现伪造
- StopOffer TTL=0 攻击
- SOME/IP-TP 分片制动指令
- 车载以太网 0x327a
- Offer 报文重放
- SD 记录派生密钥
---

## 一句话结论

SOME/IP-SD 没有认证机制，攻击者冒用制动 ECU 的 IP/端口重放其 Offer 报文并把 TTL 改为 0 伪造成 StopOffer，让接收方认为制动服务已下线；随后以另一地址冒充该服务，用 SOME/IP-TP 分 42 段发送一条用 SD 记录派生密钥加密的合法制动指令，实现无升级窗口的远程制动。

## 原理

- **SD 无认证**：SOME/IP 服务发现（SD）通过 OfferService/StopOfferService 条目通告服务可用性，StopOffer 用 TTL=0 表示服务下线。协议本身没有消息认证或来源校验，接收方只按报文内容更新服务状态。
- **伪造下线**：攻击者在 t≈10.65s 冒用制动 ECU（10.77.0.20）的源 IP 和端口 30507，把 ECU 自己发出的 Offer 报文原样重放，仅将 TTL 从 15 改为 0。接收方认为 0x327a 制动服务已 StopOffer，此后不再期待该服务；这制造了一个“服务空窗”，为冒充者让路。
- **冒充服务**：t≈11.25–11.67s，攻击者以 203.0.113.66:30507 冒充已下线的 0x327a 服务，用 SOME/IP-TP（MessageType 0x22）把一条加密制动指令拆成 42 段发送。TP 头包含 offset 与段标志，接收方按 offset 重组出 1202 字节载荷。
- **密钥来自 SD 记录本身**：`keystream = sha256(ServiceID 0x327a 的 16 字节 Offer entry)`，原文条目为 `01000010327a00090300000f0000000b`。用该 32 字节摘要与重组载荷循环异或，得到 `78 da` 开头的 zlib 流；解压后 1191 字节明文。必须使用 TTL 非 0 的真实 Offer entry 派生密钥——用伪造的 StopOffer entry 解不开，这一“解不开”反过来验证了伪造报文与真实报文的差分。
- **指令解析**：明文中的坐标字段是决定性判据。穷举对齐方式与端序后，只有一个候选同时满足“落在合法经纬度范围”和“1e-7 尺度整数末位为 0”（生成器统一用度×10^7 编码）两条约束；车辆自身 POSI 值也满足该特征。解出的指令是在 (30.355555, 45.899999) 执行 FULL_BRAKE、压力 87.5、持续 2500ms。
- 整条链之所以成立，是“服务发现可伪造 + 服务身份不绑定源地址 + 应用层密钥可从公开 SD 记录推导 + TP 分片可重组”四个缺陷叠加，而不是某一条加密被破解。

## 触发条件

- 车载网络可达 SOME/IP-SD 组播/单播流量，攻击者能发送伪造源 IP 的 UDP 报文（或位于同一二层网络可 ARP 欺骗/直接注入）。
- 接收方信任 SD 报文且不校验 Offer/StopOffer 的源地址、序列号与签名。
- 目标服务使用 SD 记录中的字段派生应用层密钥，且该派生方式可离线复现。
- 加密指令格式（坐标、压力、时长）可被逆向或枚举；接收方不校验指令来源/新鲜度。

## 利用步骤

1. 抓取车载以太网流量，识别制动 ECU 的 Offer 报文、服务 ID 0x327a、端口 30507 与 SD 条目结构。
2. 复制 ECU 的真实 Offer 报文，定位 TTL 字段并改为 0，以 ECU 的 IP/端口为源发送 StopOffer。
3. 等待接收方将 0x327a 标记为下线；随后以攻击者地址冒充该服务。
4. 用真实 Offer entry 的 16 字节做 SHA-256 得到 keystream，与构造好的加密指令循环异或并 zlib 压缩，得到 1202 字节载荷。
5. 按 SOME/IP-TP 格式切分为 42 段（offset、more-segments 标志、MessageType 0x22）依次发送。
6. 接收方重组、解密、解压并执行制动指令；用坐标合法性（经纬度范围、1e-7 末位 0）校验解析是否正确。

## PoC

```python
import hashlib, zlib, struct

# 1) 用真实 Offer entry 派生 keystream
offer_entry = bytes.fromhex("01000010327a00090300000f0000000b")
ks = hashlib.sha256(offer_entry).digest()

# 2) 构造明文指令并压缩（示意字段：lat, lon, pressure, duration）
plain = struct.pack(">iI", 30355555, 45899999) + struct.pack(">H", 8750) + struct.pack(">H", 2500)
comp = zlib.compress(plain)                     # 以 78 da 开头

# 3) 循环异或得到 1202 字节密文（实际需填充到协议长度）
ct = bytes(b ^ ks[i % 32] for i, b in enumerate(comp))

# 4) SOME/IP-TP 分片（伪代码）
SEG = 1392  # 每段可承载的 TP 数据长度，按抓包实际值调整
for off in range(0, len(ct), SEG):
    chunk = ct[off:off + SEG]
    more = 1 if off + SEG < len(ct) else 0
    tp_header = struct.pack(">I", (off << 4) | more)   # offset + more flag 的示意编码
    send_someip_tp(service=0x327A, method=0x0001, payload=tp_header + chunk)
```

```text
# StopOffer 伪造（示意）：复制真实 Offer，仅把 TTL 15 -> 0
src=10.77.0.20:30507 -> dst=<SD 接收方>:30490
entry: service=0x327a instance=0x0009 major=0x03 ttl=0x000000
```

## 变体与关联

- 变体：不伪造 StopOffer，直接抢注同 ServiceID/InstanceID 的 Offer（服务冲突/最后写入者胜出）；或用 TTL 递减/重放制造服务抖动。
- 变体：TP 分片可换成单包 UDP 分片、IP 分片或更大 MTU；密钥派生可换成 SD 选项字段、诊断 DID、固定常量。
- 关联：[[iot-protocol-hartip-command9-quadrant-covert-channel]]（同为工控协议字段隐写/伪造）、车联网服务发现认证缺失的通用问题。
- 边界：需要网络可达并能伪造源地址；接收方若实现 SD 认证、源地址绑定、序列号/新鲜度校验或应用层签名，链路失效；不同车型的 SOME/IP 布局与 TP 参数不同。

## 检测与防御

- 检测：同一 ECU 在无关机流程时出现 TTL=0 的 StopOffer；Offer/StopOffer 的源 IP、端口、序列号异常；服务下线后短时间内出现不同源地址的同 ServiceID 流量；SOME/IP-TP 大量分片且 MessageType=0x22；制动指令来源与合法 ECU 不符。
- 修复：为 SOME/IP-SD 增加消息认证（如 AUTOSAR SecOC/TLS/签名）并绑定源地址；接收方校验 Offer/StopOffer 的序列号、新鲜度与 ECU 身份；应用层指令加签名/防重放。
- 加固：车载网络分段与入侵检测；SD 白名单（固定 ECU/端口/ServiceID）；TP 重组限制与异常分片告警；制动等安全关键指令要求多因子/网关校验。
