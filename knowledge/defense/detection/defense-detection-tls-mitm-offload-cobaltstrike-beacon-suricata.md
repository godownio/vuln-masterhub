---
id: defense-detection-tls-mitm-offload-cobaltstrike-beacon-suricata
title: TLS 中间人卸载解密 HTTPS C2 流量后由 Suricata/ET 规则检出 Cobalt Strike Beacon
type: scenario
domain: defense
path: defense/detection
technique: tls-mitm-offload-c2-nids-detection
aliases:
- PolarProxy TLS 卸载
- HTTPS C2 解密检测
- 加密流量 NIDS 盲区
- Beacon 明文检出
- MitM pcap
tags:
- tls
- 中间人
- PolarProxy
- 流量解密
- pcap
- suricata
- cobalt-strike
- c2
- malleable-c2
- 检测
- 根证书
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:54:10+08:00'
  notes: 已对照原文核对；certutil安装根CA、PolarProxy --httpconnect 8080 解密输出pcap、全局代理127.0.0.1:8080、解密后明文GET /jquery-3.3.1.min.js、Suricata命中ET MALWARE Cobalt Strike告警与未解密pcap零告警的对照实验与图01-08及正文一致；dedup_review对比beacon_keys(需TeamServer私钥离线取证)与mTLS InsecureSkipVerify(红队针对客户端缺陷)成立，本卡为防御方下发根CA做实时TLS卸载交NIDS批量检测，不需服务端私钥、非篡改或取证，非同一利用链；confidence为high对照实验完整；非DoS崩溃或仅资源耗尽、非未打通理论链；非组件漏洞、原文仅工具版本号CS 4.5与PolarProxy 1.0.2.0无受影响版本区间，省略affected_versions；未验证点：PoC命令为最小化示意未执行
---

## 一句话结论

对 HTTPS C2 流量做 TLS 中间人卸载、解密成明文 pcap 后交给 NIDS，就能让原本对加密通道"零告警"的 Suricata 用现成规则检出 Cobalt Strike Beacon 的 Malleable C2 通信；不依赖主机侧特征或样本免杀情况，是补齐加密流量检测盲区的通用路径。

## 原理

- NIDS 的规则引擎（如 Suricata 的 HTTP 解析、ET/ETPRO 规则）依赖明文 HTTP 字段：请求方法、URI、Host、Header、固定 Cookie/参数等。TLS 加密后链路上只剩 ClientHello/Server Hello 与 `Application Data`，这些字段不可见，因此 `ET MALWARE Cobalt Strike Malleable C2 Query Custom Profile`、`Cobalt Strike Beacon Activity (GET)` 一类规则全部失效——默认配置下 beacon 上线不产生任何告警。
- MitM 代理（PolarProxy）在客户端信任其自签根 CA 后，分别与客户端、C2 服务端建立两条 TLS 连接：对客户端伪装成服务器、对服务器伪装成客户端，在中间得到明文 HTTP，再按原始 TCP 流重新封装输出为 pcap 或 JSON 日志。
- 输出的 pcap 里 HTTP 请求恢复为明文（原文解密后可见 `GET /jquery-3.3.1.min.js HTTP/1.1` 等 Malleable C2 的 jquery 伪装请求），Suricata 的 HTTP 解析与规则匹配即可命中，产生大量 Cobalt Strike 相关告警；未解密的原始 pcap 只有 TLSv1.3 Application Data，规则无字段可匹配，故零告警。原文用同一套规则对两份 pcap 做对照实验验证了这一点。
- 本质是"把加密检测问题转化为明文检测问题"：用可控的证书信任与流量牵引，换回规则引擎的全部可见性。

## 触发条件

- 能让被监控客户端信任 MitM 根证书（企业可统一下发 CA；实验机可 `certutil -addstore "Root"`）。
- 能把客户端出站流量导向透明代理（全局代理、虚拟网卡、网关镜像或专职中间人服务器）。
- 目标 C2 未做证书固定/证书校验（beacon 默认信任系统根、无 pinning），否则 MitM 握手失败（原文日志可见 `decrypt_fail_errorcode 0x80131620` 一类对部分域名的解密失败）。
- 具备明文侧检测能力（Suricata + ET/ETPRO 规则或自定义规则、Zeek、Wireshark）。

## 利用步骤

1. 在生产监控点（或实验用受控终端）安装 PolarProxy 根证书，使客户端信任其签发的叶证书。
2. 启动 PolarProxy 监听 HTTP CONNECT 并输出解密 pcap：`PolarProxy.exe --httpconnect 8080 -x polarproxy.cer -w decrypted_https.pcap`。
3. 将客户端流量牵引到该监听（实验用系统全局代理 127.0.0.1:8080；企业方案用透明代理/虚拟网卡把流量导出到 Suricata/Zeek，而非落 pcap）。
4. 触发 Cobalt Strike HTTPS Beacon 上线（原文用 CS 二开工具生成原始样本、未免杀）。
5. 结束抓包，对解密 pcap 跑 `suricata -r decrypted_https.pcap`，查看 `fast.log`/`eve.json`；再对未解密的 `https_8443.pcapng` 跑同一套规则作对照。
6. 对照结果：解密后大量 `ET MALWARE Cobalt Strike ...` 告警，未解密零告警，证明检出能力来自 TLS 卸载。

## PoC

```text
# 1) 信任 MitM 根 CA
certutil -addstore "Root" .\polarproxy.cer

# 2) 启动 TLS 卸载并输出明文 pcap
PolarProxy.exe --httpconnect 8080 -x polarproxy.cer -w decrypted_https.pcap

# 3) 设置全局代理 127.0.0.1:8080，让 beacon 流量经过代理后上线

# 4) 解密后可见明文请求（Wireshark/tshark）
GET /jquery-3.3.1.min.js HTTP/1.1

# 5) 规则侧验证（最小化命令，未执行）
suricata -r decrypted_https.pcap     # fast.log 命中 ET MALWARE Cobalt Strike Malleable C2 ...
suricata -r https_8443.pcapng        # 未解密：无告警（对照）
```

## 变体与关联

- 变体：企业级应自建中间人代理集群，把解密流实时喂给 Suricata/Zeek/SIEM，而非像实验那样起在受控终端并输出 pcap。
- 变体：不解密也可做有限检测——JA3/JA3S TLS 客户端指纹、证书/SNI/NetFlow 行为特征（`defense-detection-ja3-tls-fingerprint-suricata`），但看不见 URI/载荷，粒度低。
- 变体：取证侧另有"提取 beacon_keys 私钥解元数据得 Raw Key，再还原 C2 命令"的离线解密路径（`defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt`），与本场景的实时 MitM 卸载不同。
- 关联：红队侧 `pentest-c2-mtls-insecureskipverify-client-cert-mitm` 利用客户端 `InsecureSkipVerify` + 提取客户端证书让 mitmproxy 拦截 mTLS C2，是同一 MitM 思路的攻击面；本场景是防御检测面。
- 关联：C2 侧可用 Malleable C2 伪装（伪装 10086 商城流量、随机路径）、域前置、DoH/IP 直连前置代理等方式让特征消失，与检测方案构成对抗。

## 检测与防御

- 落地：根 CA 私钥严格管控、只在受控网络范围下发，避免成为新的信任风险；代理做高可用与旁路，防止单点导致业务中断。
- 落地：规则库持续更新（ET MALWARE Cobalt Strike 系列），并把解密后的 HTTP 日志接入 SIEM 做关联（同域名周期心跳、固定 jquery URI、异常 UA）。
- 局限与对抗：证书固定/pinning、双向 mTLS、TLS 1.3、非 HTTP 的自定义加密协议会令 MitM 解密失败；需保留"解密失败"日志并回退到 JA3/证书/流量行为等不解密手段，形成多层检测。
- 局限：TLS 卸载涉及明文处理与员工隐私/合规，需明确授权范围、最小化留存、对敏感业务（网银、医疗等）做白名单排除；高吞吐下注意解密性能与 pcap 存储成本。
