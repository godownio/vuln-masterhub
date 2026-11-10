---
id: defense-forensics-dinodasrat-udp-variant-traffic-decrypt
title: DinodasRAT Linux UDP 变体流量解密：独立内置 key + UDP 二次封装，QQ-TEA/qq_crypt 还原心跳设备信息
type: scenario
domain: defense
path: defense/forensics
technique: dinodasrat-udp-variant-traffic-decrypt
tags:
- dinodasrat
- linux
- udp
- traffic-decrypt
- tea
- qq-crypt
- forensics
- malware
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T19:11:02+08:00'
  notes: 已对照原文及 28 张图核对：UDP 样本 key A1A118AA10F0FA160671B308AAAF31A1、0x30+小端长度帧、GetSessionId/MakeOneBuf 二次封装、qq_decipher 解密结构、Ubuntu 22.04.2 LTS 解密明文均与原文代码/截图 25-27 一致；TCP key 与帧结构引用既有卡无误。PoC 为简化伪代码（省略 hex 解码/uint32 转换），不影响理解。dedup 与 TCP C2 卡仅 related（不同变体 key/封装），new 合理。原文未给版本，已 clear；dup-scan(2026-11-08)早于建卡未覆盖。
url: /docs/defense/forensics/defense-forensics-dinodasrat-udp-variant-traffic-decrypt/
draft: false
kb_aliases:
- DinodasRAT UDP 解密
- DinodasRAT UDP key
- A1A118AA10F0FA160671B308AAAF31A1
- MakeOneBuf UDP 封装
- QQ-TEA 心跳解密
---

## 一句话结论

DinodasRAT Linux 的 UDP 变体（MD5 8138f1af1dc51cde924aa2360f12d650）与 TCP 变体使用同一套 QQ-TEA（qq_crypt）心跳加密结构和 0x30 帧头，但内置独立 16 字节 key `A1A118AA10F0FA160671B308AAAF31A1`，且在 UDP 发送前对加密数据做二次封装（MakeOneBuf/会话 ID 组包）；从 UDP 会话中剥掉外层封装后，用该 key 即可解出设备心跳明文（如 `Linux_20240318_ff7fa52fa55a9bd71ea45ad8f1bc5ed3_83049_V10 Ubuntu 22.04.2 LTS 64 root 2 10`）。

## 原理

- DinodasRAT 通信载荷由 `MacKControlBuf` 调用 `qq_cryptqq` 完成加密/解密：内部是 TEA 变体（16 轮、delta 0x9E3779B9、初值 0xE3779B90）加外层前一块 XOR 链与 QQ 风格填充（首字节低 3 位参与填充长度，尾部 7 字节 0，见 pidgin-libqq 的 qq_crypt.c）。
- 心跳/上报帧结构为 `0x30 || 4 字节小端长度 || 加密载荷`；解密后为 `padding 控制字节 + 随机填充 + 指令字段 + 设备 ID 长度 + 数据长度 + 设备 ID + 数据`。TCP 变体直接按此结构收发。
- UDP 变体在发送侧先 `GetSessionId` 取会话标识，再把加密数据交给 `MakeOneBuf` 做二次组包（按会话/长度字段封装）后 `udpsend` 发出；因此 UDP 抓包里内层仍是同一套 0x30 帧，只是外面多了 UDP 封装层，剥离外层后按 TCP 相同结构解密。
- 两个样本的 key 均硬编码在 .rodata，且不同：TCP 变体 `A101A8EAC010FB120671F318ACA061AF`，UDP 变体 `A1A118AA10F0FA160671B308AAAF31A1`。key 不做交换，因此抓到 UDP 流量即可离线解密。
- 原文用同一份 Go 解密实现（common.go 的 Decrypt_out + main.go 切换 key）分别验证两类样本：UDP 样例取自 any.run 沙箱 2024-03-19 的抓包，解密后得到 Ubuntu 22.04.2 LTS 主机信息。

## 触发条件

- 捕获到 DinodasRAT Linux UDP 变体与 C2 之间的 UDP 会话（原文样本外联 `update.centos-yum.com:443` 的 UDP 流量）；
- 能从样本 .rodata 提取 16 字节 key（或已知 UDP 变体 key）；
- 能识别 UDP 报文中二次封装的内层 0x30 帧（首字节 0x30 + 小端长度 + 载荷）。

## 利用步骤

1. 从 PCAP 中筛出目标主机的 UDP 会话，排除 DNS 等噪声；关注向固定域名/IP 的周期性短报文。
2. 识别内层帧：载荷中出现 `0x30` 开头、随后 4 字节小端长度且与剩余长度匹配的段；记录外层封装字段以便切分。
3. 提取加密载荷，按 `qq_decipher`（TEA 变体，16 轮，sum 初值 0xE3779B90、每轮减 0x9E3779B9）+ 前块 XOR 链解密；填充长度为 `2 + (plain[0] & 7)`。
4. 按明文结构解析：指令字段（4 字节小端 + 0x00）、设备 ID 长度、数据长度、设备 ID 与系统信息。
5. 若解不开，确认样本是 TCP 还是 UDP 变体，切换对应 key；同一实现（Decrypt_out）可直接复用。
6. 批量解密全部心跳，提取设备 ID、系统版本、用户、CPU 等作为受害主机画像与同源聚类依据。

## PoC

```go
// 关键参数（原文 main.go 节选）
// TCP 样本 decd6b94792a22119e1b5a1ed99e8961:
// key = A101A8EAC010FB120671F318ACA061AF
// UDP 样本 8138f1af1dc51cde924aa2360f12d650:
key := "A1A118AA10F0FA160671B308AAAF31A1"

// 解密前校验：首字节 0x30，4 字节小端长度与载荷长度一致
if plain[0] == 0x30 {
    n := binary.LittleEndian.Uint32(plain[1:5])
    if int(n) == len(plain[5:]) {
        dec := common.Decrypt_out(common.BytesToUint32Slice(plain[5:]), key)
        fmt.Println(string(dec))
    }
}
```

原文 UDP 实测解密结果：`Linux_20240318_ff7fa52fa55a9bd71ea45ad8f1bc5ed3_83049_V10 Ubuntu 22.04.2 LTS 64 root 2 10`。

## 变体与关联

- 关联：[[pentest-c2-dinodasrat-linux-c2-protocol-fake-controller]]（同族 TCP 变体协议与伪控制端，已覆盖 QQ-TEA 细节、0x30 帧与 24 类指令；本卡补充 UDP 变体的独立 key 与二次封装）。
- 变体：样本可通过 Trans_mode 指令切换 TCP/UDP；不同样本/版本的 key 与设备 ID 格式可能变化，需从 .rodata 提取。
- 变体：外层封装字段（会话 ID/长度）如变化，按实际 PCAP 调整切分。

## 检测与防御

- 检测：同一主机周期性向固定外部地址发送 UDP 短报文；载荷内层出现 0x30 + 小端长度结构；解密后设备 ID 形如 `Linux_<日期>_<32hex>_<数字>_V10`。
- 防御：限制内网主机对未知外部 UDP 服务的出站；结合 C2 域名（update.centos-yum.com、security-microsoft.net）做阻断与回溯。
- 取证：保留 PCAP，按上述 key/算法离线还原心跳与指令；设备 ID 可用于同源聚类与影响面统计。
