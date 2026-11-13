---
id: defense-detection-asyncrat-ping-heartbeat-replay-verify
title: AsyncRAT C2 心跳包重放主动验证：MsgPack Ping 报文按高低版本分别发包，JARM/JA3S 指纹仅作辅助
type: scenario
domain: defense
path: defense/detection
technique: asyncrat-ping-heartbeat-replay-verify
tags:
- defense
- detection
- c2
- asyncrat
- msgpack
- heartbeat
- jarm
- ja3s
- threat-hunting
- active-probe
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:11:34+08:00'
  notes: 已对照原文与图6/图8/图9核对：客户端 KeepAlivePacket 的 Packet=Ping+GetActiveWindowTitle、服务端 ping_Tick 的 This is a ping!、高版本 gzip 需分版本发包、工具输出 TLS命中+心跳回显+JARM不符仍判 found 均属实。未验证点：原文未给报文 hex，PoC 为伪代码，未实际向任何目标重放。
url: /docs/defense/detection/defense-detection-asyncrat-ping-heartbeat-replay-verify/
draft: false
kb_aliases:
- AsyncRAT 心跳包
- MsgPack Ping 重放
- AsyncRAT 主动探测
- This is a ping!
- 心跳包回显
- AsyncRAT 服务端确认
---

## 一句话结论

AsyncRAT 用 MsgPack 明文消息保活：客户端发 `Packet=Ping`（`Message` 为当前活动窗口标题），服务端定时向所有在线客户端回 `Packet=Ping`、`Message="This is a ping!"`；把对应版本的心跳报文重放给可疑 C2，收到协议级正确回显即可确认是 AsyncRAT 服务端。高版本对流量做 gzip，高低版本心跳包不能通用，必须分版本分别发包；JARM/JA3S 指纹随版本漂移，只能当辅助旁证，不能单独定案。

## 原理

- **协议层心跳**：AsyncRAT 的消息统一用 MsgPack 序列化，`ForcePathObject("Packet")` 标记消息类型。Ping 是保活/在线判定消息，比 TLS 证书等被动指纹更贴近应用协议本身。
- **客户端侧代码行为**：`KeepAlivePacket` 构造 `MsgPack`，写 `Packet="Ping"`、`Message=Methods.GetActiveWindowTitle()`，`Send(msgpack.Encode2Bytes())` 后置 `ActivatePong=true`——即客户端定期上报“我在线 + 当前窗口标题”。
- **服务端侧代码行为**：`ping_Tick` 在存在在线客户端时构造 `Packet="Ping"`、`Message="This is a ping!"` 的报文，向所有客户端 `client.Send`——这是服务端主动下发的固定心跳。
- **重放为什么能确认家族**：报文结构与字段组合是该家族实现私有的；向可疑 host:port 重放心跳报文后，只有真正的 AsyncRAT 服务端会按协议解析并返回匹配的回显（探测工具输出“心跳包回显”），无关服务通常不响应或返回错误/乱码。相比证书改名，协议行为更难伪装。
- **高低版本差异**：高版本 AsyncRAT 对流量做了 gzip 压缩，低版本不压缩；同一份心跳包在高低版本间不通用，探测时必须准备两套报文分别验证，否则会把高版本服务误判为“非 AsyncRAT”。
- **JARM/JA3S 只是辅助**：TLS 服务端实现随版本变化，JARM/JA3S 指纹在高低版本间不一致。工具的实测输出即为例证：TLS 握手命中 `AsyncRAT` 字样且心跳包回显成功，但 JARM 检测显示“不为 AsyncRAT Server”，最终仍判定 `AsyncRAT Server found`——说明指纹匹配不上不能排除，指纹只是加分项。
- **与被动测绘配合**：先靠默认证书测绘缩小候选范围（改证书名会漏），再用心跳重放逐端口确认在线与身份，同时剔除测绘数据中大量已下线资产。

## 触发条件

- 可疑服务端口开放且确为 AsyncRAT 服务端（任一版本，含改证书名的部署）；
- 探测方能直接连接目标端口（网络可达，且处于授权范围内）；
- 已从对应版本的源码或流量样本中提取到心跳报文的字段结构与压缩方式；
- 若版本未知，需要同时准备低版本与高版本两套探测报文。

## 利用步骤

1. 从已知样本/源码提取心跳行为：定位客户端 `KeepAlivePacket` 与服务端 `ping_Tick`，确认 `Packet=Ping`、`Message` 字段取值（窗口标题 / `This is a ping!`）以及是否 gzip 压缩。
2. 按低版本（明文）与高版本（gzip）分别构造探测报文。
3. 连接可疑 `host:port`，发送对应版本的心跳报文，读取响应。
4. 若收到结构化正确回显 → 判定为 AsyncRAT 服务端；可同时检查 TLS 握手中是否出现 `AsyncRAT` 字样做交叉确认。
5. 计算 JARM/JA3S 并与已知版本指纹比对：一致可加强结论，不一致不能排除（以协议回显为准）。
6. 批量场景：对测绘候选列表逐端口探测，筛出真正在线的服务，记录版本线索，输出 IOC 供封禁与拓线。

## PoC

```python
# 伪代码：心跳探测思路（原文未给出报文 hex，需按目标版本从源码/样本提取）
# 低版本: 明文 MsgPack；高版本: 按该版本约定先压缩
def probe(host, port, packet_bytes):
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(packet_bytes)
    resp = s.recv(4096)
    s.close()
    # AsyncRAT 服务端会按协议回显 Ping 心跳
    return resp

# packet_bytes 需包含 Packet="Ping" 及对应 Message 字段
# 判定: 回显中出现预期字段/结构 -> AsyncRAT Server found
```

```text
# 工具实测输出（文章示例，目标为改证书名也可发现）
[+] 'AsyncRAT' found in TLS handshake.
[+] 心跳包回显
[-] JARM检测 不为 AsyncRAT Server
[+] AsyncRAT Server found
```

探测工具与报文细节来自文章配套脚本，本文未复现；报文格式以目标对应版本源码/流量为准。

## 变体与关联

- 变体：不确定版本时先发明文包、无回显再发 gzip 包；或按 TTL/响应时序区分版本。
- 变体：心跳回显之外还可结合客户端上线包、窗口标题上报等消息做二次确认。
- 关联：[[defense-detection-asyncrat-default-tls-cert-c2-mapping]]——先用默认证书测绘找候选，再用本卡心跳重放确认在线，二者构成“被动找 + 主动验”的完整链路。
- 关联：[[defense-detection-sliver-default-tls-jarm-31337]]（JARM 测绘思路）、[[defense-detection-asyncrat-download-chain-traffic-triage]]（JA3S/证书 hex 流量侧研判）。
- 边界：服务端不在线、端口被防火墙过滤时无回显；协议被魔改或二次封装后字段不匹配；JARM/JA3S 随版本/配置漂移，只能辅助；主动探测第三方资产需授权。

## 检测与防御

- 检测（防御方/狩猎）：监控内网出站连接中出现 AsyncRAT 心跳特征（固定间隔、MsgPack 结构、`This is a ping!` 等字符串），并结合 TLS 证书/JA3S 交叉确认。
- 检测（情报侧）：用高低版本两套心跳包对测绘候选做主动验证，避免只靠证书导致改名资产漏检、历史下线条目误报。
- 防御（攻击面治理）：授权测试部署 AsyncRAT 时避免默认协议特征直接暴露在公网；企业侧对已知 C2 IP/证书/JA3S 做封禁与告警。
- 注意：主动探测与重放仅限授权范围；不要把对第三方服务的扫描结果用于非防御目的。
