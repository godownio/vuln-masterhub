---
id: defense-detection-jarm-active-tls-fingerprint-algorithm
title: JARM 主动 TLS 指纹的计算结构：10 组 ClientHello 探测 + 62 位模糊哈希（前 30 位套件/版本映射，后 32 位 ALPN+扩展 SHA256）
type: scenario
domain: defense
path: defense/detection
technique: jarm-active-tls-fingerprint-algorithm
tags:
- defense
- detection
- jarm
- tls
- fingerprint
- fuzzy-hash
- c2
- threat-hunting
- fofa
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V542
  verified_at: '2026-11-11T20:39:05+08:00'
  notes: 已对照原文全文与 33 张图片逐张核对（08.gif 取首帧，26.bin/31.bin 实为 PNG）：img17 的 10 组探测配置（TLS1.2 forward/reverse/top_half/bottom_half/middle_out、TLS1.1 middle_out、TLS1.3 forward/reverse/invalid/middle_out）、img18 的 queue/while/超时填 |||、img19 choose_grease、img22/25 的 jarm_hash（cipher_bytes/version_byte 前30位 + ALPN+扩展 SHA256 前32位）、img28 cipher_bytes 源码、img29 version_byte 源码、img30 的 sha256[0:32] 均与卡内一致；PoC 示例的 weibo.com/111.13.225.75/JARM 27d27d... 与 img23 的 -v 输出逐字一致。核对时修正两处不准确表述：① cipher_bytes 未命中并非返回 00（源码 count 从 1 开始、返回 count 的两位十六进制，未命中返回列表长度+1；仅空串返回 00）；② socket TIMEOUT 时源码将 10 段全置 ||| 并中止，非逐段。另将组件示例替换为截图原值 c02b|0303|h2|ff01-0000-0001-000b-0010-0017。JA3/JA3s 跳过判断：JA3 五字段拼接+MD5 与 GREASE 剔除已由 defense-detection-ja3-tls-fingerprint-suricata 覆盖，成立；JA3s 三字段+MD5 仅在 JA3 卡变体中提及、JA4S 是不同算法，属轻微覆盖缺口，已在 verify.json notes 记录。未验证点：未实际运行 jarm.py 对目标扫描；原文无软件版本，未设 affected_versions。
url: /docs/defense/detection/defense-detection-jarm-active-tls-fingerprint-algorithm/
draft: false
kb_aliases:
- JARM 62 位
- JARM 模糊哈希
- jarm.py
- cipher_bytes
- version_byte
- JARM 十次扫描
- 主动 TLS 指纹
---

## 一句话结论

JARM 主动向目标发送 10 组不同 TLS 配置的 ClientHello，按 ServerHello 的选中套件、TLS 版本、ALPN 与扩展列表计算 62 位模糊哈希：前 30 位是 10 次探测各 3 位的套件/版本映射（`cipher_bytes`+`version_byte`），后 32 位是 ALPN 与扩展串 SHA256 的前 32 个十六进制字符；该指纹反映服务端 TLS 实现/配置，可用于 C2 与资产测绘，但必须与证书、端口和行为联合研判。

## 原理

- **主动探测**：JA3/JA3s 是被动解析单个 ClientHello/ServerHello；JARM 主动向目标发送特制 ClientHello，是被动指纹的补充，更像扫描器。
- **10 组探测配置**：`jarm.py` 预置 10 组 `[目标, 端口, TLS 版本, 套件列表, 套件顺序, GREASE, ALPN, Version 扩展支持, 扩展顺序]`：TLS1.2 forward / reverse / top_half / bottom_half / middle_out，TLS1.1 middle_out，TLS1.3 forward / reverse / middle_out / invalid。某次探测无有效 ServerHello 时该段为 `|||`；socket 超时（`TIMEOUT`）时代码会把 10 段全部置为 `|||` 并中止本轮。
- **组件格式**：`read_packet` 把每个 ServerHello 提取为 `选中Cipher|TLS版本|ALPN|扩展列表`（如 `c02b|0303|h2|ff01-0000-0001-000b-0010-0017,`），10 段再以逗号拼接成 `jarm_raw`。
- **62 位结构**：`jarm_hash` 中，对每段 `components[0]` 调 `cipher_bytes`、`components[1]` 调 `version_byte`，结果直接追加到 `fuzzy_hash`；10 段 × (2 位 + 1 位) = 前 30 位。同时把 `components[2]`（ALPN）与 `components[3]`（扩展）连续拼成 `alpns_and_ext`，整体做 SHA256 取前 32 个十六进制字符，追加为后 32 位。全部为空时返回 62 个 0。
- **前 30 位的私有映射**：`cipher_bytes` 在一份固定的套件字节列表中按十六进制串匹配目标返回的套件，命中时返回其序号（`count` 从 1 开始）的两字节十六进制（不足补 0），为空返回 `00`；未命中时源码不单独处理，返回列表长度 +1 的十六进制。`version_byte` 取版本字符串第 4 个字符（如 `0303` 的末位 `3`）作为下标，映射到 `abcdef` 中的一个字符（为空返回 `0`）。这不是标准哈希，而是 JARM 作者定义的模糊映射，目的是让不同套件/版本的组合落成稳定短码。
- **GREASE 处理**：`choose_grease` 随机挑选一个 GREASE 值放入探测包，模拟真实浏览器的可扩展性行为，避免服务端对无 GREASE 客户端给出异常响应；这使 JARM 在部分中间盒/服务端上更接近真实流量。
- **为什么可用于识别**：JARM 输入是服务端 TLS 栈对 10 组固定握手的响应，主流 TLS 实现（OpenSSL、Schannel、Go、Cobalt Strike 的 TLS 栈等）在这些维度上组合不同，因此同一实现/版本趋于稳定，不同实现可区分；但它是概率性指纹，配置变更、版本升级、前置 CDN/反向代理都会改变结果。

## 触发条件

- 能直接访问目标 TLS 服务端口（默认 443，可指定其他端口）。
- 目标对 10 组探测有可解析的 ServerHello 响应，且中间网络不对 TLS 握手做拦截/改写。
- 使用 jarm.py（或兼容实现）并具备授权，仅用于资产排查、威胁狩猎与防守方自查。
- 有已知实现/版本的 JARM 基线或空间测绘平台（FOFA/Shodan/Censys 等）可交叉比对。

## 利用步骤

1. 准备目标列表（每行一个域名/IP，可用逗号指定端口），运行 `python3 jarm.py -i targets.txt -p 443`。
2. 加 `-v` 查看 10 次探测的原始 components（`Cipher|Version|ALPN|Extensions`），确认哪些探测超时或返回空。
3. 按 62 位结构解读：前 30 位为套件/版本映射短码，后 32 位为 ALPN+扩展的 SHA256 前缀；同一服务端多次扫描应稳定（除非负载均衡到不同 TLS 栈）。
4. 与已知指纹库比对：把 62 位值作为 IOC/signature，在空间测绘平台检索（如 `jarm="<62位值>"`），再结合证书字段、端口、HTTP 行为缩小到具体产品。
5. 对命中资产重新采集并记录版本/时间，避免用旧指纹定性；必要时用 JA3/JA3s/JA4 与证书链交叉验证。

## PoC

```bash
# 单目标或列表扫描，-v 输出未哈希前的 10 组 components
python3 jarm.py -i targets.txt -p 443 -v

# 示例输出（截断）：
# Domain: weibo.com
# Resolved IP: 111.13.225.75
# JARM: 27d27d27d29d27d1dc27d27d27d27d53193801a5eb3e94385fd853d5812962
# Scan 1: c02b|0303|h2|ff01-0000-0001-000b-0010-0017,
# ...
# Scan 10: c02b|0303|h2|ff01-0000-0001-000b-0010-0017
```

```text
# 空间测绘语法示例（值需按目标重新采集，不能直接套用旧指纹）
jarm="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
```

```text
# 62 位结构示意
[前 30 位] = 10 段 × (2 位 cipher_bytes + 1 位 version_byte)
[后 32 位] = SHA256(收敛后的 ALPN 串 + 扩展串)[:32]
# 全部探测为空 => "00000000000000000000000000000000000000000000000000000000000000"
```

## 变体与关联

- 变体：TLS 1.3 支持不足或中间盒拦截时，部分探测返回空，前 30 位出现 `00`/`0`，指纹仍可能稳定，但区分度下降。
- 变体：`-P socks5://host:port` 通过代理探测，或 `-j` 输出 ndjson 便于批量入库。
- 变体：同一域名解析到多台不同 TLS 栈的服务器（负载均衡/CDN）时，多次扫描可能得到不同 JARM，需要按 IP 分别采集。
- 关联：[[defense-detection-cobaltstrike-default-jarm-cert-fofa]]（CS 默认 JARM + 证书 + FOFA 测绘）、[[defense-detection-sliver-default-tls-jarm-31337]]（Sliver 的 JARM/证书指纹）、[[defense-detection-ja3-tls-fingerprint-suricata]]（被动 JA3 客户端指纹）、[[defense-detection-ja4-tls-client-fingerprint-modular]] 与 [[defense-detection-ja4s-tls-server-fingerprint]]（JA4 系列）。
- 边界：JARM 不是唯一标识，正常服务与 C2 可能碰撞；修改 TLS 库/配置、使用 CDN/重定向器即可改变；空间测绘结果含蜜罐与误报。

## 检测与防御

- 检测（防守方视角）：单一来源在短时间内对同一目标发起 10 组不同 TLS 配置的握手，特征接近 JARM 扫描；可对短时间内版本/套件组合跳跃的 TLS 握手告警。
- 检测：监控 `jarm.py` 默认套件顺序与 GREASE 特征，以及空间测绘平台对自家资产的扫描。
- 防御：不要用单一 JARM 指纹定性；结合证书、端口、HTTP 行为、被动 JA3/JA4 与主机侧证据。
- 加固（C2 运营方视角）：更换 TLS 实现/版本、调整套件与扩展顺序、使用 CDN/重定向器可改变 JARM；但这只是提高测绘成本，不能替代流量层伪装与证书管理。
- 资产自查：定期用本方法采集本单位服务的 JARM 基线，发现异常变化时排查是否被替换/前置了未知 TLS 栈。
