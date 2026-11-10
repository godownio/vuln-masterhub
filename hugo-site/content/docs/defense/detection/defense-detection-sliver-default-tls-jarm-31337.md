---
id: defense-detection-sliver-default-tls-jarm-31337
title: Sliver C2 网络指纹检测：默认 31337、TLS 证书 CN=operators/multiplayer 与 JARM 空间测绘
type: scenario
domain: defense
path: defense/detection
technique: sliver-default-tls-jarm-network-detection
tags:
- defense
- detection
- sliver
- c2
- jarm
- tls
- certificate
- threat-hunting
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:08:15+08:00'
  notes: 已对照原文与图片核对：默认 31337（sliver shell 连接 localhost:31337）、默认证书 CN=operators/multiplayer、JARM 示例 3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910 与 FOFA 查询命中 443 服务器截图一致。未验证点：JARM/证书指纹随 Sliver 版本与配置漂移，卡片已标 confidence medium；未在真实环境重算 JARM；affected_versions 已 --clear。
url: /docs/defense/detection/defense-detection-sliver-default-tls-jarm-31337/
draft: false
kb_aliases:
- Sliver JARM
- Sliver 31337
- CN=operators
- CN=multiplayer
- Sliver C2 服务器发现
- JARM 指纹测绘
---

## 一句话结论

Sliver 默认监听 31337，默认 TLS 证书使用 `CN=operators`（多人模式另有 `CN=multiplayer`）的组合；其 TLS 服务端实现有相对稳定的 JARM 指纹（文章示例为 `3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910`），可用 JARM 在 Shodan/Censys/FOFA 等空间测绘中反向发现 Sliver C2 服务器，并结合 DNS/HTTP(S) 异常做流量侧检测。

## 原理

- **默认监听端口**：Sliver 服务端默认在 31337 上监听（The `sliver` shell 连接 localhost:31337 的默认配置），未改端口时对外扫描可命中该特征。
- **默认 TLS 证书**：Sliver 默认生成的 TLS 证书使用 `CN=operators`；开启 multiplayer 时组合使用 `CN=operators` 与 `CN=multiplayer`。证书 Subject/Issuer CN 是可直接在 TLS 握手/证书透明度/空间测绘中查询的字符串。
- **JARM 指纹**：JARM 主动向 TLS 服务端发送多组特制 ClientHello，按服务端返回的 TLS 版本、密码套件、扩展顺序等计算 62 字符哈希。不同 TLS 实现/配置产生不同指纹；Sliver 的默认 TLS 栈产生文章示例中的 JARM。由于 JARM 不依赖证书，即使攻击者更换域名/IP 仍可能被同一指纹关联。
- **空间测绘反查**：Shodan/Censys/FOFA 支持按 JARM 指纹或证书 CN 搜索历史/当前资产；文章示例用 FOFA 搜索 `"JARM: 3fd2..."` 命中一台 443 端口、伪装为博客的服务器，说明 C2 可以藏在正常 CDN/静态站点外观下。
- **流量侧补充**：Sliver 支持 HTTP(S)、DNS、TLS、TCP 等协议；同一域名/IP 的异常 DNS 查询、HTTP(S) 心跳（固定间隔、小请求/大响应、URI 形态）可作为内部检测信号；TLS 流量可做 JA3/JA3S/JARM 指纹与证书 CN 检查。
- **边界**：默认值都可修改——端口、证书 CN、TLS 配置、使用合法证书或 CDN 都可使上述指纹失效；JARM 也可能随 Sliver 版本/编译选项变化。因此指纹只用于“疑似/情报”，需要与主机侧行为交叉确认。

## 触发条件

- 分析者可访问互联网测绘平台（Shodan/Censys/FOFA）或有内部 TLS 元数据/流量镜像。
- 目标使用未修改默认端口/证书的 Sliver 服务端，或其 JARM 与已知 Sliver 指纹一致。
- 能采集/解密（或读取元数据）可疑 TLS 流量，或能关联 DNS 查询日志。
- 有授权：测绘与扫描仅限授权范围，避免误扫第三方资产。

## 检测步骤

1. 资产测绘：按证书 CN 查询
   ```text
   ssl.cert.subject.cn:"operators"
   ssl.cert.subject.cn:"multiplayer"
   ```
   按 JARM 查询（示例指纹）：
   ```text
   "JARM: 3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910"
   ```
2. 内部流量：监控出站到 31337 端口的连接；对可疑 TLS 服务器提取证书 CN 并计算 JARM，与已知 Sliver 指纹比对。
3. 对命中资产做被动确认：证书自签名/异常有效期、仅 443/31337、HTTP 响应伪装为正常站点但无真实业务内容、与已知恶意 IP/域名关联。
4. DNS/HTTP 侧：检查异常域名（DGA、短期注册、与证书 CN 不匹配）、固定周期心跳、请求/响应大小异常。
5. 与端点侧告警（PowerShell 子进程、令牌错位、注入）做时间线关联，确认 C2 与受害主机。

## PoC

```bash
# 对可疑 TLS 服务计算 JARM（需安装 jarm）
python3 jarm.py <suspected-host> -p 443
# 与文章示例 Sliver JARM 比较：
# 3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910

# 用 openssl 读取证书 CN
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer
```

```text
# 空间测绘查询语法（按平台）
ssl.cert.subject.cn:"operators"
"JARM: 3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910"
```

说明：JARM 示例值与证书 CN 取自文章；指纹随版本/配置可能不同，查询结果需人工确认。

## 变体与关联

- **变体：DNS 监听**：Sliver 的 DNS 协议监听在 UDP/53，需结合 DNS 隧道检测与异常域名分析。
- **变体：自定义证书/端口**：攻击者使用 Let's Encrypt 或 CDN 证书后，证书 CN 判据失效，但 JARM/JA3 与流量行为仍可辅助识别。
- **变体：WireGuard 通道**：新版 Sliver 可走 WireGuard（UDP），端口/协议指纹不同，见 [[pentest-c2-sliver-wireguard-udp53-egress-bypass-socks-pivot]]。
- **关联**：CobaltStrike 的 JA3/checksum8 流量识别见 [[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]；JA3 指纹的 Suricata 检测见 [[defense-detection-ja3-tls-fingerprint-suricata]]。
- **边界**：默认指纹被修改、使用域前置/CDN、或 JARM 随版本漂移时，单靠网络指纹不能定性。

## 检测与防御

- **检测**：证书 CN=operators/multiplayer、31337 出站、JARM 与 Sliver 已知指纹匹配、异常 DNS/HTTP(S) 心跳；与端点行为关联。
- **防御**：出站默认拒绝，仅放行必要端口；对 31337 等非常用端口告警；部署 TLS 检查与威胁情报（JARM/JA3/证书）比对；封禁已知 C2 资产。
- **响应**：确认 C2 后封禁域名/IP/证书，排查内部主机外联记录，结合端点检测定位植入体与横向路径。
