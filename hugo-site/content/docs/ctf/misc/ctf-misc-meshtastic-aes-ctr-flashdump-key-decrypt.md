---
id: ctf-misc-meshtastic-aes-ctr-flashdump-key-decrypt
title: Meshtastic 报文解密：16 字节包头解析、AES256-CTR 的 IV=packetID+0+NodeID+0，从 flash dump 取私有 channel PSK 解出明文
type: scenario
domain: ctf
path: ctf/misc
technique: meshtastic-packet-aes-ctr-flashdump-key-decrypt
tags:
- ctf
- misc
- meshtastic
- lora
- aes-ctr
- flash-dump
- protocol-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V550
  verified_at: '2026-11-11T22:50:31+08:00'
  notes: 已对照原文与全部23张图核对：图17 Meshtastic Layer1 包头表（0x00 dest/0x04 sender/0x08 packetID/0x0C flags/0x0D channel hash/0x0E 2B padding/0x10 payload）；图18 文档明确 AES256-CTR、nonce=node+packet number；图19 Channels.cpp defaultpsk=d4f1bb3a20290759f0bcffabcf4e6901；图20 Crypto.kt genNonce= id 4B LE+4×00+from 4B LE+4×00；图21 flash 0x8000 分区表；图22 flash dump 中 Buddies 信道 32 字节 PSK cef8db8e8e6017fd6dcca21db8a1476d451480acd7f4f9f769a763f528c011f7；图23 CyberChef AES-CTR 配置。已按任务做复算：用卡内 key/IV/ct 实跑 AES-256-CTR 得到明文 '\x08\x01\x12Talright alright. the key is rwctf{No_h0p_th1s_tim3_c831bcad725935ba25c0a3708e49c0c8}'，与图23 可见片段 '...T alright. the key is...' 一致，证明 packetID→IV 构造（8899c20200000000c4c06dfa00000000）与 flash key 均正确，PoC 代码可直接运行。修正一处表述：flash 中 PSK 与信道名的位置关系由 '紧随其后' 改为 '邻近（示例中 PSK 紧邻信道名前）'。dedup：候选为固件 AES-ECB、部分密钥爆破、Godot PCK AES-CFB、SHA256-CTR KEYMAT、Pyarmor AES-CTR、EM-RAT 等不同载体/协议，无同链；dup-scan.json 未涉及本卡。原文未标注软件版本，affected_versions 保持空。未验证点：无原始 WAV 附件，未重跑 gr-lora 解调；明文已复算。
url: /docs/ctf/misc/ctf-misc-meshtastic-aes-ctr-flashdump-key-decrypt/
draft: false
kb_aliases:
- Meshtastic 解密
- Meshtastic AES256-CTR
- Meshtastic 包结构
- genNonce
- channel PSK
- flash dump channel key
- LongRange2
---

## 一句话结论

Meshtastic 的 LoRa 载荷是 16 字节包头（目的 NodeID、发送 NodeID、packet ID、flags、channel hash、padding）+ protobuf 数据，数据用 AES256-CTR 加密，IV 由 `packetID 小端 4 字节 + 00000000 + 发送 NodeID 小端 4 字节 + 00000000` 组成；先用固件默认公共信道 PSK 尝试，失败则从设备 flash dump 中找到自定义 channel（如 `Buddies`）的 16/32 字节 PSK，再用 AES-CTR 解密载荷得到明文。

## 原理

- **包结构**：Meshtastic Layer 1（Unreliable Zero Hop Messaging）包头固定 16 字节：`0x00` 4 字节目的 NodeID（广播为 `0xFFFFFFFF`）、`0x04` 4 字节发送方 NodeID、`0x08` 4 字节 packet ID、`0x0C` 1 字节 flags、`0x0D` 1 字节 channel hash（解密提示）、`0x0E` 2 字节内存对齐 padding、`0x10` 起为 protobuf 数据（最大 237 字节）。多字节字段均为小端。
- **加密方式**：Meshtastic 文档明确使用 AES256-CTR（128/256 位密钥，密钥属于 Channel 配置），只加密 SubPacket payload 层，路由头保持明文，以便节点为不同密钥的信道转发。每个 16 字节块使用递增 COUNTER，首个块 COUNTER=0。
- **IV/nonce 构造**：固件 `Crypto.kt` 的 `genNonce(from, id)` 生成 16 字节：`id` 的 4 字节小端 + 4 个 0x00 + `from`（发送 NodeID）的 4 字节小端 + 4 个 0x00。即 IV = `packetID || 00000000 || senderNodeID || 00000000`。拿到包头字段即可算出 IV，无需其他状态。
- **密钥来源**：固件 `Channels.cpp` 内置公共信道 `defaultpsk`（16 字节：`d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01`，AES128）；如果题目/设备使用了自定义信道，公钥 PSK 解不开，需要从 flash dump 的 channel 配置里找。示例中 flash 分区表在 `0x8000`，应用分区里可搜索信道名（如 `Buddies`）与邻近的 16/32 字节 PSK（示例中 PSK 紧邻信道名前）（示例 32 字节：`cef8db8e...28c011f7`）。
- **为什么可行**：LoRa 空口只提供链路层，Meshtastic 的应用层加密完全依赖共享 PSK；拿到设备固件/flash 或默认密钥即可离线解密所有同信道报文。CTR 模式无完整性校验，密钥正确即可直接得到 protobuf 明文字节。

## 触发条件

- 已通过 LoRa 解调（如 gr-lora）拿到 Meshtastic 报文的十六进制字节流，能分离出 16 字节包头与 payload。
- 手上有设备 flash dump（题目附件）或知道目标使用的 channel PSK；公共信道可用固件默认 PSK。
- 报文长度较短、COUNTER 从 0 开始，IV 可由包头的 packet ID 与发送 NodeID 直接构造。

## 利用步骤

1. 从解调输出中按包结构切分：前 16 字节为包头，按偏移解析目的 NodeID（4）、发送 NodeID（4）、packet ID（4）、flags（1）、channel hash（1）、padding（2），其后为密文 payload。
2. 构造 IV：把 packet ID 按小端写成 4 字节，接 4 个 0x00，再接发送 NodeID 的小端 4 字节，再接 4 个 0x00。
3. 先试默认公共信道 PSK（`d4f1bb3a20290759f0bcffabcf4e6901`）；若输出不可读，说明是自定义信道。
4. 分析 flash dump：在 `0x8000` 处解析分区表定位应用分区；在应用分区搜索信道名/`channels` protobuf 结构，提取该 channel 的 PSK（16 或 32 字节）。示例在 `Buddies` 信道附近找到 32 字节 key。
5. 用 AES-CTR（密钥为 PSK，初始计数器块为 IV）解密密文，得到 protobuf/文本明文；按需再用 protobuf 定义解析字段。

## PoC

以示例报文为例（dest=`ffffffff`、sender=`c4c06dfa`、packetID=`8899c202`、flags=`03`、channel hash=`04`、padding=`a792`）：

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter

key = bytes.fromhex("cef8db8e8e6017fd6dcca21db8a1476d451480acd7f4f9f769a763f528c011f7")  # flash dump 中 Buddies 信道 PSK
iv  = bytes.fromhex("8899c20200000000c4c06dfa00000000")  # packetID LE + 00000000 + sender LE + 00000000
ct  = bytes.fromhex(
    "5001502e35d73ab793c3e9ad6acc9da6a4955bc56b8054e9989d76f5355cf286"
    "8b90bffae321d51077be4e1774fc074f63a4c0af6ba38f33a829b0784bdadbcc"
    "738b16e930e741c48f4d6c0cab012e5605122dce40eaeb7b"
)

ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
pt = AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ct)
print(pt)   # 明文（原文输出含 "es someth...T alright. the key is nu..."）
```

CyberChef 等价配置：`AES Decrypt`，Key=`cef8db8e...28c011f7`（Hex），IV=`8899c20200000000c4c06dfa00000000`（Hex），Mode=`CTR`，Input=payload 十六进制。

默认公共信道 PSK（AES128）：

```text
d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01
```

## 变体与关联

- 变体：不同信道使用不同 PSK，包头 channel hash（1 字节）可提示用哪把 key；多信道设备需逐个尝试 dump 中的 key。
- 变体：若只有抓包没有 flash dump，可先试固件默认 PSK 与常见默认口令派生的 key；若目标是私有信道且无 dump，只能暴力/社会工程获取 key。
- 变体：COUNTER 从 0 起始，长报文跨块时按 32 位计数器递增；实现时注意不要用错 nonce/计数器端序。
- 关联：[[ctf-misc-lora-gr-lora-signal-decoding]]（前置的 LoRa 信号解调步骤）、[[ctf-forensics-openssh-session-key-memory-sshenc-pcap-decrypt]]（同类"从内存/flash 取密钥解流量"思路）。
- 边界：CTR 无认证，密钥错误时输出乱码，需用 protobuf 结构/文本可读性判断；flash dump 中可能存在多份信道配置（旧版本/多 slots），要按信道名与 hash 对齐。

## 检测与防御

- 设备安全：对 flash 开启读保护/加密存储，避免 PSK 被 dump；不要把公共默认 PSK 当作安全边界。
- 协议安全：Meshtastic 信道加密依赖共享密钥，任何拿到密钥的人都能解密；敏感通信应使用私有信道并定期轮换 PSK，必要时在上层再做端到端加密。
- 检测：射频侧可被动收集 LoRa 报文；防守方可监测使用默认 PSK 的报文（默认密钥可解密即说明未改默认配置）。
