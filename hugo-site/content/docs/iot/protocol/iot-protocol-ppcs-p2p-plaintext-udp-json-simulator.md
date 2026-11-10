---
id: iot-protocol-ppcs-p2p-plaintext-udp-json-simulator
title: PPCS P2P 明文 UDP 控制协议逆向与模拟：PPP/DRW 包头 + JSON 指令自构造（含明文 pwd）
type: scenario
domain: iot
path: iot/protocol
technique: ppcs-p2p-plaintext-protocol-simulator
tags:
- iot
- camera
- ppcs
- p2p
- udp
- protocol-reverse
- json
- plaintext
- replay
- simulator
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V341-fix
  verified_at: '2026-11-08T21:01:55+08:00'
  notes: V341 核对指出两处并已修正：1) PoC build() 的 pkt_len 改为 len(drw)+len(body)（含 DRW 头 4 字节，示例 0x0214=DRW4+JSON528），步骤4 同步说明；2) 原理中 PPP flag 列表删去误混入的 DRW 常量 0xD1，改为抓包示例 0xD0 与 SDK 注释 0x00/0x01/0xE0/0xE1。主会话按 V341 结论修正后转 verified；其余核对项不变。
url: /docs/iot/protocol/iot-protocol-ppcs-p2p-plaintext-udp-json-simulator/
draft: false
kb_aliases:
- PPCS 协议逆向
- libPPCS_API.so
- PPP_Header DRW_Header
- 摄像头 UDP JSON 控制协议
- 明文 P2P 指令模拟
- 摄像头协议仿真客户端
---

## 一句话结论

摄像头 APP 与设备之间的 PPCS P2P 控制面是明文 UDP + JSON：抓包可识别 `PPP_Header`（`0xf1`/flag/pkt_len）与 `DRW_Header`（`0xd1`/flag/seq_id）两层包头，按 `pkt_len` 切分即得到 JSON 指令；逆向 `libPPCS_API.so` 后可复现设备发现、握手与心跳，用 Python 自构造 `LoginDev`、`GetDevStream`、`DownloadFile` 等任意指令，而指令中明文携带的 `pwd` 使抓到流量的人可以直接重放或接管会话。

## 原理

- 分层：APP 的 Java 层只负责拼 JSON 指令，具体的编码、UDP 发包/收包、ACK 与重传、设备发现和心跳由 Native 库 `libPPCS_API.so`（C++）完成；逆向该库即可还原完整状态机。
- 封包结构（由 SDK 注释与抓包还原）：外层 `PPP_Header` = 1 字节固定 `0xf1` + 1 字节 flag（抓包示例为 `0xD0`，SDK 注释枚举为 `0x00/0x01/0xE0/0xE1`）+ 2 字节大端 `pkt_len`；内层 `DRW_Header` = 1 字节固定 `0xd1`（这是 DRW 层的固定常量，不是 PPP flag）+ 1 字节 flag + 2 字节 `seq_id`；其后是 JSON。`pkt_len` 统计的是 DRW 头 + JSON 的长度，不包含 4 字节 PPP 头。示例抓包的 536 字节 UDP Data 以 `f1 d0 02 14 d1 01 00 04 ...` 开头，`0x0214=532` 恰为 536-4，即 DRW(4)+JSON(528)，可与头部字段对上。
- 可靠性：UDP 之上由应用层 ACK 与重传保证可靠；因此客户端必须处理 ACK、序号递增和超时重传，不能只发一个裸 UDP 包。
- 为什么容易被攻击：控制面没有 TLS/应用层加密或签名，JSON 可读、`pwd` 每条指令明文携带；UDP 无连接，第三方只要能同网段嗅探或做中间人，就能读到口令并重放/篡改指令，也可以自己实现客户端与设备直接建立会话。
- P2P 架构：客户端与设备分别向 P2P 服务器注册公网地址，服务器交换双方地址后由两端 NAT 打洞直连；服务器对「谁可以查询某个设备地址」缺少强身份校验，知道设备序列号即可尝试建立连接（序列号空间较大，枚举不现实，但泄露的序列号可直接利用）。
- 附带信息泄露：设备信息查询的响应 JSON 中可见 `wifiSsid`、`wifiPwd` 等配置字段（图示为明文返回），查询接口本身也会泄露网络配置。

## 触发条件

- 能抓取 APP 与设备之间的 UDP 流量（同一 Wi-Fi/热点、交换机镜像、ARP/DNS 中间人等），或能直接访问设备的 P2P 控制端口。
- 知道设备地址或序列号用于寻址。
- 设备固件/协议未启用加密；需要登录的指令，其 `pwd` 可从明文流量中获得，或在设备不校验会话时直接下发。
- 自写客户端需还原 flag、seq、ACK 与心跳逻辑，具体常量以目标版本抓包为准。

## 利用步骤

1. Wireshark 过滤 UDP，按首字节 `0xf1` 与内层 `0xd1` 定位包头，按 `pkt_len` 切分出 JSON payload。
2. 观察 App→设备与设备→App 的端口对（示例 `23567` ↔ `18006`）、心跳周期、flag 变化、`seq_id` 递增与 ACK 报文。
3. 用 IDA/Ghidra 载入 `libPPCS_API.so`，按端口、`LoginDev` 等字符串定位发送/接收、心跳线程与设备发现函数，还原状态机与各 flag 常量。
4. Python 用 socket 实现封包：`PPP(0xf1,flag,len) + DRW(0xd1,flag,seq) + JSON`，其中 `len = 4 + len(JSON)`（DRW 头 4 字节 + JSON）；先发 `GetDevInfo`，解析响应与 ACK，确认封装正确。
5. 读取响应中的设备信息（版本、IP、Wi-Fi 配置等），再按需发送 `LoginDev`、`GetDevStream`、`DownloadFile` 等指令；若设备不校验会话，可逐条尝试。
6. 以此为投递工具，配合任意文件下载、Wi-Fi 配网注入等场景完成完整利用。

## PoC

Python 发包骨架（概念，flag/seq 以抓包校准）：

```python
import json, socket

DEV_IP, DEV_PORT = "192.168.100.1", 18006
PPP_CONST, PPP_FLAG = 0xF1, 0xD0   # 图中示例：外层 flag=0xD0
DRW_CONST, DRW_FLAG = 0xD1, 0x01   # 图中示例：内层 flag=0x01

def build(payload: dict, seq: int = 1) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode()
    drw = bytes([DRW_CONST, DRW_FLAG]) + (seq & 0xFFFF).to_bytes(2, "big")
    pkt_len = len(drw) + len(body)   # 含 DRW 头：示例 0x0214 = DRW(4) + JSON(528)
    ppp = bytes([PPP_CONST, PPP_FLAG]) + pkt_len.to_bytes(2, "big")
    return ppp + drw + body

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(build({"cmd": "GetDevInfo"}), (DEV_IP, DEV_PORT))
data, addr = s.recvfrom(65535)
print(addr, data[:64])
```

说明：示例常量取自截图中的协议注释与抓包样例；不同固件/会话阶段的 flag 可能不同，需先抓一次合法交互对齐，并按 ACK/重传逻辑维持会话。本卡未在真机复跑，故 confidence 记为 medium。

## 变体与关联

- 变体：只嗅探不发包——明文流量中直接获得 `pwd`、设备信息、网络配置与媒体数据。
- 变体：UDP 源地址可伪造，若设备以源 IP/端口作为会话标识，可尝试会话劫持或向既有会话注入指令。
- 变体：其他采用「自定义头 + JSON」的 IoT P2P SDK（不同厂商的 P2P 库）可套用同一分析方法：抓包定界、反汇编找状态机、自写客户端。
- 关联：[[iot-camera-app-login-result-hook-bypass]]（利用同一协议绕过登录判定）、[[iot-protocol-camera-downloadfile-arbitrary-file-read-mtd-mount]]（用模拟客户端下发 DownloadFile）、[[iot-camera-wifi-psk-shell-injection-jffs2-persistence]]（配网字段注入）、[[rtsp-weakauth-unauth-surveillance-view]]（摄像头另一控制面的未授权取流）。
- 边界：固件升级引入 TLS/DTLS 或每会话密钥、P2P 强制中继且加密时，明文重放失效；若 AAC/ACK 与 flag 未完全还原，自构造包会被设备丢弃。

## 检测与防御

- 防御：控制面改用 TLS/DTLS 或应用层加密 + HMAC，`pwd` 不明文传输；会话使用一次性令牌与序号窗口，防重放。
- 防御：P2P 服务器校验设备身份与客户端授权，不向仅知道序列号的第三方返回设备地址；设备端限制并发会话并记录异常客户端。
- 检测：UDP 会话中出现 `f1/d1` 魔法字节与固定长度的自定义头、异常 ACK/重传风暴；同一设备出现多客户端会话；明文流量中出现 `cmd`/`pwd` 等 JSON 关键字。
- 加固：协议混淆不能替代加密；把 P2P 控制端口收敛到必要网络，禁用不必要的设备发现与调试指令。
