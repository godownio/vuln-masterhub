---
id: defense-detection-quasar-rat-tls-traffic-fingerprint
title: Quasar RAT v1.4.0+ 加密流量识别：TLS1.2 固定套件、默认证书 CN/hex、25 秒 1 字节 00 心跳与 ACK>>SYN
type: scenario
domain: defense
path: defense/detection
technique: quasar-rat-tls-traffic-fingerprint
aliases:
- Quasar RAT 流量检测
- Quaser RAT
- ET MALWARE Observed Malicious SSL Cert (Quasar CnC)
- Quasar Server CA
- KEEP_ALIVE 25 秒
- ACK 多于 SYN
- AsyncRAT 同源证书
tags:
- detection
- quasar-rat
- tls
- traffic-analysis
- suricata
- certificate
- keepalive
- c2
- threat-hunting
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V494
  verified_at: '2026-11-11T00:36:38+08:00'
  notes: 已对照原文与16张图片核对：v1.4.0 changelog 的 Protobuf/TLS1.2（图01）、ServerHello TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030)（图02）、证书 CN=Quasar Server CA（图03/04）、证书固定 hex 0f39393939313233313233353935395a 与 99991231235959Z（图05）、KEEP_ALIVE_INTERVAL/TIME 0x61A8=25s（图07）、25 秒间隔与 1 字节 00 载荷（图08/09）、Keep-Alive/ACK 标志位均 ACK（图10-12）、ET 两条规则 fast.log（图15）均与卡片一致。卡片为单一检测特征组合场景，颗粒度合适；与 Quasar 配置解密卡、AsyncRAT 证书/心跳卡为不同技术面，非重复；无 sources/文章ID；原文未给“受影响版本”区间（仅版本演进），已 --clear。未验证点：固定套件依赖 Win10/.NET 运行时，非绝对指纹。
---

## 一句话结论

Quasar RAT v1.4.0 起把通信改为 TLS 1.2 + Protobuf 后，内容特征基本不可见，但仍可组合几类被动特征识别：未指定套件时 .NET/Windows 在常见 Win10 版本上固定协商 `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`；默认配置证书 CN 为 `Quasar Server CA`，且证书中带固定 hex 串 `0f 39 39 39 39 31 32 33 31 32 33 35 39 35 39 5a`（AsyncRAT 默认证书也有，提示同源）；无任务时约 25 秒一次 Keep-Alive（`0x61A8` 毫秒）且载荷为单字节 `00`；TCP Keep-Alive 使 ACK 包远多于 SYN，加上“上行数据远大于下行”可作组合弱特征。ET 规则 `ET MALWARE Observed Malicious SSL Cert (Quasar CnC)` 与 `Generic AsyncRAT Style SSL Cert` 可直接命中默认证书。

## 原理

- **TLS 1.2 + Protobuf 让内容匹配失效**：Quasar 使用 .NET `SslStream` 做安全套接字，消息用 Protobuf 序列化；链路加密后看不到命令字段，因此只能依赖 TLS 握手/证书、TCP 行为与流量统计等元数据。
- **加密套件相对固定**：代码不指定 cipher suite，选择由 .NET Framework/Core 与操作系统加密库决定；在 Windows 10 专业版/家庭版/教育版/企业版等常规版本上，测试均选择 `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`。这可以作为“像 .NET RAT”的弱指纹，但不同 OS/补丁/运行时可能变化。
- **默认证书特征**：使用 Quasar 自带配置时，证书 CN 为 `Quasar Server CA`；证书字节中包含固定序列 `0f 39 39 39 39 31 32 33 31 32 33 35 39 35 39 5a`——对应 ASN.1 时间串 `99991231235959Z` 一类默认值。该 hex 在 AsyncRAT 默认证书中同样存在，可作为家族同源/默认配置线索。攻击者改 CN/重新生成证书即可规避，因此证书特征只对默认配置有效。
- **25 秒 Keep-Alive 与 1 字节载荷**：配置中 `KEEP_ALIVE_INTERVAL`/`KEEP_ALIVE_TIME` 均为 `0x000061A8`（25000ms=25 秒）；空闲时客户端按该间隔发送心跳，抓包可见单字节载荷 `00`。这是应用层心跳，和 TCP Keep-Alive 不同，但两者都造成周期性小包。
- **ACK 远多于 SYN**：Quasar 用 Keep-Alive 维持连接，Windows 上 Keep-Alive/Keep-Alive ACK 包的 TCP 标志位均为 ACK；长时间会话中 ACK 数量远大于 SYN（SYN 只在建连时出现）。这是统计型弱特征，需要与基线比较。
- **上行远大于下行**：服务端指令精简、客户端回传（系统信息/文件/屏幕等）数据量大；上行/下行比例可作为组合特征。
- **检测分工**：强特征（默认证书 CN/hex、固定套件）可写成 Suricata/ET 规则；心跳周期、ACK/SYN 比例、上下行比例适合多维度统计模型/威胁狩猎，不宜单独定案。

## 触发条件

- 目标运行 Quasar RAT v1.4.0 及以上（TLS1.2+Protobuf），且使用默认/未定制的证书与套件配置。
- 能在网络侧看到 TLS 握手与证书（不需要解密），或具备端点侧流量/EDR 数据。
- 流量未被代理完全改写（TLS 中间盒可能改变套件/证书特征）；默认证书未替换。
- 有足够的观察窗口统计 Keep-Alive 周期、ACK/SYN 比例与上下行数据量。

## 利用步骤

> 以下为防御方检测/研判步骤。

1. **发现可疑 TLS 会话**：按外联 IP/域名、非浏览器进程或威胁情报筛选 TLS 1.2 会话，记录五元组与时间。
2. **看 ServerHello 套件**：过滤 `tls.handshake.type == 2`，检查是否选中 `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`；结合 JA3/JA3S 与证书做指纹。
3. **看证书**：在 Certificate 消息中检查 CN 是否为 `Quasar Server CA`，搜索固定 hex `0f39393939313233313233353935395a`；默认证书可直接命中 ET 规则。
4. **看心跳**：统计同一连接上的小包间隔，是否约 25 秒一次、载荷是否单字节 `00`；区分 TCP Keep-Alive 与应用层心跳。
5. **看 TCP 统计**：统计 ACK 与 SYN 数量比、上行/下行字节比；与同网段正常业务基线对比。
6. **组合研判**：默认证书/套件 + 25 秒心跳 + ACK>>SYN + 上行远大于下行，再结合威胁情报确认 C2；必要时用样本配置解密（另见 Quasar 配置解密卡）核对 C2 地址。
7. **处置**：封禁 C2、隔离主机、提取样本与内存，排查持久化与横向。

## PoC

Wireshark/tshark 过滤与检查：

```text
# ServerHello 与证书
tls.handshake.type == 2 || tls.handshake.type == 11
# 固定证书 hex（在证书字节中搜索）
frame contains 0f:39:39:39:39:31:32:33:31:32:33:35:39:35:39:5a
# 25 秒心跳（按会话观察）
tcp.stream == <n> && tcp.len == 1
```

Suricata/ET 告警示例（默认证书）：

```text
ET MALWARE Observed Malicious SSL Cert (Quasar CnC)
ET MALWARE Generic AsyncRAT Style SSL Cert
```

## 变体与关联

- **自定义证书/套件**：攻击者重新生成证书、指定 cipher suite 或改用 TLS 1.3 后，证书/套件特征失效；需转向 JA3S、心跳周期、流量统计与主机侧行为。
- **同源家族**：AsyncRAT 默认证书包含相同 hex，ET 规则以 “AsyncRAT Style SSL Cert” 匹配；Quasar 与 AsyncRAT 的流量特征可互相参考。
- **传输变体**：Quasar 旧版本可能使用明文/其他协议；新版本可能换 Protobuf 版本或增加压缩。
- **关联卡**：Quasar RAT 配置 AES-256 解密、AsyncRAT 默认证书测绘、AsyncRAT 心跳重放验证、TLS 指纹/JA3 检测、加密 C2 流量统计狩猎。
- **边界**：只有默认配置才带固定 CN/hex；心跳间隔可配置；ACK/SYN 与上下行比例受业务影响大，必须组合判断。

## 检测与防御

- **规则**：部署 ET `Observed Malicious SSL Cert (Quasar CnC)` 与 `Generic AsyncRAT Style SSL Cert`；补充自定义规则匹配固定证书 hex/CN 与异常套件组合。
- **威胁狩猎**：建立“周期性小包 + ACK/SYN 比例异常 + 上行远大于下行”的统计基线，对新增外联做排序；结合 JA3/JA3S 与证书指纹。
- **端点**：监控 .NET 进程（尤其从 `%AppData%`/`%Temp%` 启动）发起的长连接 TLS；结合 Quasar 配置解密提取 C2 后封禁。
- **网络**：出站白名单/代理记录 SNI 与证书；对默认证书 C2 直接阻断；对加密流量做 TLS 指纹与元数据检测。
- **响应**：隔离主机、提取样本与内存、排查持久化（启动项/计划任务）与横向移动；轮换可能泄露的凭据。
