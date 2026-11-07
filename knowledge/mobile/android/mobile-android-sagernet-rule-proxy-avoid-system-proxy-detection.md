---
id: mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection
title: SagerNet 规则代理：禁用 IPv6/远程 DNS 后按域名/IP 分流，规避系统代理检测
type: scenario
domain: mobile
path: mobile/android
technique: sagernet-rule-proxy-avoid-system-proxy-detection
aliases:
- SagerNet
- 系统代理检测
- 规则代理
- 远程 DNS
- IPv6 路由
- 抓包代理
tags:
- android
- proxy
- burp
- sagernet
- mitm
- anti-detection
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:20:11+08:00'
  notes: 已对照原文与截图核对：SagerNet 手动 HTTP 代理、IPv6 路由禁用、远程 DNS 改可用地址（正文 tls://114.114.114.114，截图 tls://dns.google）、路由分流、改动后重连均一致。未验证点：未实测代理分流效果；远程 DNS 两处取值不一致已在卡中并列说明。
---

## 一句话结论

直接设置 Android 系统代理容易被应用检测且会引入大量无关流量；用 SagerNet 手动添加 HTTP 代理、禁用 IPv6 路由、把远程 DNS 改成可用地址，再在“路由”里按域名/IP 配置直连或代理，可只让目标流量进 Burp 并降低被检测概率。

## 原理

- **系统代理检测**：应用可读取 `ProxySelector`/系统属性/网络配置判断是否走代理；系统代理还会把设备上所有应用的流量都送进代理，产生大量噪声。
- **SagerNet 模式**：SagerNet 是 Android 上的代理客户端，通过 VPNService 在本地建立代理入口；手动添加 HTTP 代理指向 Burp/Charles，再按路由规则决定哪些流量走代理、哪些直连。
- **两个常见坑**：IPv6 路由未禁用时，应用可能走 IPv6 绕过代理；远程 DNS 默认地址在部分网络不可用，需要改成 `tls://114.114.114.114` 或 `tls://dns.google` 等可用 DNS。
- **生效方式**：修改配置/路由后需要重连代理；VPN 图标出现后，Burp 只看到被规则匹配的流量。
- **与透明代理对比**：iptables DNAT 更隐蔽但需要 root；SagerNet 是应用层 VPN，配置简单、可按应用/域名分流，但仍可能被检测 VPN/代理。

## 触发条件

- Android 设备能安装 SagerNet（或同类 VPN 代理客户端）。
- Burp/Charles 与手机网络可达（同一局域网或公网）。
- 已安装代理 CA 并解决证书信任（见关联卡）。
- 目标应用未使用更强的代理/VPN 检测或 native 网络栈。

## 利用步骤

1. 安装 SagerNet，手动添加一个 HTTP 代理，填写 Burp/Charles 的 IP:端口。
2. 进入设置，把 `IPv6 路由` 设为禁用，避免应用走 IPv6 绕过代理。
3. 把 `远程 DNS` 改成可用地址（如 `tls://114.114.114.114` 或 `tls://dns.google`）。
4. 在“路由”里配置规则：目标域名/IP 走代理，其余直连；需要抓所有流量时再改为全局。
5. 选中配置并启动；确认 VPN 图标/连接状态。
6. 每次修改路由/配置后重连代理；用 Burp 观察是否只出现目标流量。
7. 若应用仍检测代理，结合证书信任、root 隐藏、透明代理等方案。

## PoC

```text
SagerNet → 手动输入 → HTTP → 填 Burp IP:8080
设置 → IPv6 路由：禁用
设置 → 远程 DNS：tls://114.114.114.114
路由 → 添加目标域名/IP → 代理；其余 → 直连
启动 → 重连 → Burp 抓包
```

## 变体与关联

- **客户端变体**：SagerNet、Clash、Shadowrocket、Surfboard、VPN Hotspot；核心是 VPNService + 规则分流。
- **透明代理变体**：root 后用 iptables DNAT 80/443 到 Burp，应用层看不到代理；需阻断 UDP 443/QUIC。
- **检测变体**：应用检测 VPN/代理、`ProxySelector`、网络接口、DNS；需要 Hook/隐藏或透明代理。
- **关联卡片**：[[mobile-android-anti-detection-root-emulator-proxy]]（iptables 透明代理 + 反检测）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（证书信任）、[[mobile-android-android16-certificate-trust-alwaystrustusercerts]]（Android 16 证书）。
- **边界**：VPNService 本身可被检测；QUIC/UDP 可能绕过 HTTP 代理；目标使用 native 网络栈/pinning 时仍需额外处理。

## 检测与防御

- **防御**：应用检测 VPN/代理/网络接口、使用证书 pinning/Play Integrity；敏感流量走 mTLS。
- **检测信号**：设备存在 VPN 图标/SagerNet 配置；`ProxySelector` 返回非直连；DNS 解析走远程 DoT。
- **测试建议**：先用浏览器验证代理和证书，再测目标；修改路由后务必重连；只代理目标流量以减少噪声。
