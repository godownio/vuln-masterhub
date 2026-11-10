---
id: mobile-android-windows-hotspot-netch-tun-reqable-transparent-proxy
title: Windows 热点 + Netch TUN 网卡共享 + Reqable SOCKS 透明代理：连接设备无感抓包、规避 APP 代理/VPN 检测并兼作 WiFi 近源流量嗅探
type: scenario
domain: mobile
path: mobile/android
technique: windows-hotspot-netch-tun-reqable-transparent-proxy
tags:
- android
- proxy
- transparent-proxy
- netch
- reqable
- socks5
- hotspot
- ics
- traffic-analysis
- anti-detection
- mitm
- wifi
- near-source
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V323
  verified_at: '2026-11-08T16:26:06+08:00'
  notes: 已对照 content.md 与 12 个图片/动图核对：img01 虚拟机桥接、img02/03 Reqable 监听 192.168.100.204:9000 且 SSL 全部绕行、img04-06 Netch 添加 SOCKS 服务器与 Bypass LAN 模式、img07/10 aioCloud(WireGuard Tunnel) 虚拟网卡与 ICS 共享给 本地连接*10(Microsoft Wi-Fi Direct Virtual Adapter)、img08 cp.cloudflare.com 代理检测请求、img09 Windows 热点开关；GIF11/12 经 worker 抽帧记录显示目标 192.168.100.201 经热点访问微信域名与 Reqable+Burp 二级代理拦截，与卡内描述一致。原子性：单一 Windows 热点+TUN+Reqable 透明代理配置技术（设备侧无代理配置），合格；不是漏洞利用卡，但为可复用的 APP/WiFi 近源流量分析手法，未违反排除条件。路径 mobile/android 与既有 APP 抓包/代理反检测卡同族，合理。未验证点：未本地复现，GIF 抽帧证据来自 worker 记录；原文无受影响版本，未设 affected_versions。dedup 候选 SagerNet 规则代理/mTLS 抓包/SOCKS 穿透均非同链。
url: /docs/mobile/android/mobile-android-windows-hotspot-netch-tun-reqable-transparent-proxy/
draft: false
kb_aliases:
- 透明代理抓包
- Netch Bypass LAN
- 热点共享 TUN 网卡
- Reqable SOCKS5 抓包
- APP 代理检测绕过
- 无感抓包
- WiFi 近源流量嗅探
- 二级代理 Burp
---

## 一句话结论

在 Windows 上开启移动热点后，把 Netch 启动时创建的 TUN/WireGuard 虚拟网卡通过系统“共享”功能共享给热点对应的 `Microsoft Wi-Fi Direct Virtual Adapter`，并让 Netch 以 `Bypass LAN` 模式把流量转发到 Reqable 的 SOCKS5 监听端口；连接热点的设备不需要任何代理配置，流量就会透明地经过抓包器，APP 读取系统代理/VPN 状态的检测逻辑看不到代理，HTTP 流量可嗅探和篡改，安装证书后还可经二级代理交给 Burp 拦截 HTTPS。

## 原理

- **透明代理与显式代理的区别**：显式代理需要客户端配置代理地址，APP 可通过系统代理设置、`ProxySelector`、VPN 接口等判断流量是否被劫持；透明代理在网络层完成转发，客户端仍以为自己在直接上网，因而代理对应用“不可见”。本文的实现不需要 Root 手机、不需要软路由，也不需要购买兼容 Linux 的 USB 无线网卡。
- **Netch 的角色**：Netch 是 Windows 上的代理客户端，支持 SOCKS5/Shadowsocks/VMess/WireGuard 等服务器类型。启动后会创建一个名为 `aioCloud` 的 WireGuard/TUN 虚拟网卡，并按模式把流量导入该网卡，再转发到上游服务器。示例中 Netch 版本为 1.9.7，服务器填 Reqable 的 `192.168.100.204:9000`，模式选 `[3] Bypass LAN`。
- **Reqable 的角色**：Reqable 启动“API 抓包”后在本机网卡上监听 SOCKS5/HTTP 代理（示例 `192.168.100.204:9000`）。把 SSL 功能设为“全部绕行”后，未安装证书的设备访问 HTTPS 时按隧道透传，不会因为证书不受信任而断网，同时 HTTP 明文请求可以被记录和修改。
- **网卡共享（ICS）如何把热点流量送进 TUN**：Windows 网络适配器属性的“共享”页可以把一个网卡的连接共享给另一个网卡。把 Netch 的 `aioCloud (WireGuard Tunnel)` 共享给热点使用的 `本地连接* N (Microsoft Wi-Fi Direct Virtual Adapter)` 后，连接热点的设备发出的数据包被主机 NAT 并从 TUN 网卡转发，形成 `设备 → 热点虚拟适配器 → aioCloud TUN → Netch → SOCKS5(Reqable)` 的链路。设备侧看到的只是一个普通 WiFi 网关。
- **为什么能规避 APP 检测**：设备上没有设置系统代理，也没有建立 VPN 接口，APP 检查代理配置或 VPN 状态时拿不到异常；流量在主机侧被透明转发，应用层协议栈仍按直连处理。
- **为什么默认只能看 HTTP**：没有在设备上安装 Reqable 的 CA 证书时，Reqable 对 HTTPS 只能看到 `CONNECT` 隧道和目标域名/IP，无法解密内容；HTTP 是明文，可以直接查看、修改。安装证书并开启 SSL 解密后即可查看 HTTPS；再把 Reqable 配成二级代理指向 Burp，就能用 Burp 做拦截和改包。
- **副作用**：开启共享后，运行热点的笔记本自身流量也会被 Netch 接管并出现在抓包器里，因此主机应尽量减少网络使用，避免噪声和带宽占用。

## 触发条件

- 一台具备移动热点能力的 Windows 10/11 PC（笔记本一般自带；台式机需支持 Wi-Fi Direct 的无线网卡或 USB 无线网卡）。
- 安装 Netch 与 Reqable；可选使用 VMware 中的 Windows 10 虚拟机并把网络适配器设为桥接模式（DHCP 获取不到地址时配同网段静态 IP）。
- 目标设备连接该热点，且不需要在设备上安装任何代理配置；这正是规避代理检测的关键。
- 默认仅能查看/修改 HTTP；要解密 HTTPS，需要在设备上安装并信任 Reqable CA，且目标 APP 未使用证书固定或固定可被绕过。
- 仅限授权测试；开放热点给他人设备接入属于近源攻击行为，需在授权范围内进行。

## 利用步骤

1. 准备 Windows 抓包环境：虚拟机网络适配器改为桥接模式；安装 Reqable 与 BurpSuite。
2. 启动 Reqable 的“API 抓包”，记录监听地址与端口（示例 `192.168.100.204:9000`）；弹出安装证书时先跳过，随后把 SSL 功能设为“全部绕行”，保证未装证书的设备仍能正常上网且 HTTP 可被抓取。
3. 打开 Netch，添加 `[SOCKS]` 服务器，地址/端口填 Reqable 的监听地址与端口，版本选 5；模式选择 `[3] Bypass LAN`，启动后系统会出现新的 `aioCloud` TUN 虚拟网卡。
4. 验证代理链路：Reqable 中应出现 Netch 发出的代理可用性检测 HTTP 请求（示例为访问 `http://cp.cloudflare.com/`）。
5. 开启 Windows 移动热点（或用 Connectify 等工具），进入“网络连接”，把 `aioCloud` 网卡共享给 `本地连接* N (Microsoft Wi-Fi Direct Virtual Adapter)`。
6. 让目标设备连接热点。设备无需设置代理即可上网；Reqable 中可以看到该设备（示例 `192.168.100.201`）的请求，包括域名、IP、端口和 HTTP 明文内容，例如微信的 `szsstshort.weixin.qq.com`、`mmbiz.qpic.cn`、`wx.qlogo.cn` 等请求。
7. 需要拦截改包时：在设备安装 Reqable CA 并开启 SSL 解密，或把 Reqable 作为二级代理指向 Burp，由 Burp 进行 `Intercept`、重放和修改 HTTP 请求/响应。
8. 近源场景下可把该热点作为钓鱼 WiFi：目标连入后其 HTTP 流量透明经过攻击者，可篡改页面/下载内容；配合无线层面的断网攻击可促使目标重新连接攻击者热点。

## PoC

本场景为配置型利用，无漏洞 PoC。关键配置参数：

```text
Reqable 监听：192.168.100.204:9000（SOCKS5/HTTP，SSL 全部绕行）
Netch 服务器：[SOCKS][NONE] 192.168.100.204:9000
Netch 模式：[3] Bypass LAN
Netch 虚拟网卡：aioCloud (WireGuard Tunnel)
ICS 共享：aioCloud → 本地连接* N (Microsoft Wi-Fi Direct Virtual Adapter)
```

链路示意：

```text
目标设备 --WiFi--> Windows 热点适配器 --ICS/NAT--> aioCloud TUN --Netch--> SOCKS5(Reqable) --> 互联网/二级代理(Burp)
```

设备侧不需要设置代理，因此在 APP 的代理/VPN 检测视角中仍是直连网络。

## 变体与关联

- **替代实现**：已 Root 的 Android 设备用 `iptables` DNAT 80/443 到代理端口；软路由上做透明转发；Kali + 兼容 Linux 的 USB 无线网卡充当路由。本卡是门槛最低的 Windows 热点方案。
- **HTTPS 变体**：在设备安装 CA 后由 Reqable 解密；或用 r0capture/objection 等导出客户端证书与绕过证书固定，再把流量交给 Burp。
- **关联卡片**：[[mobile-android-anti-detection-root-emulator-proxy]]（Android 侧 iptables 透明代理 + 阻断 QUIC 防代理检测，本卡是其 Windows 免 Root 版本）；[[mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection]]（Android 端 VPN 规则代理，本卡在热点侧实现且设备无感）；[[mobile-android-mtls-r0capture-client-cert-export]]（mTLS 客户端证书导出）；[[pentest-recon-mobile-app-traffic-shadow-asset]]（用抓到的 APP 流量发现影子资产）；[[iot-vehicle-wifi-evil-twin-auto-reconnect-mitm]]（WiFi 邪恶双胞胎入口）。
- **边界**：Windows 热点/ICS 驱动不稳定或热点无法共享 TUN 网卡时链路不成立；设备启用证书固定且无法绕过时 HTTPS 不可读；仅 HTTP 场景可读可改；主机自身流量会被代理，影响隐蔽性。

## 检测与防御

- **应用侧**：不要只依赖系统代理/VPN 状态检测；使用证书固定（pinning）、TLS 双向认证和请求签名，防止中间人解密与改包；重要接口增加完整性校验。
- **终端侧**：企业设备不要自动连接开放/未知 SSID；启用 802.1X 企业 WiFi 与 MDM 策略；检测网关/BSSID 变化和异常证书颁发者。
- **无线侧**：监控同名 SSID/异常 BSSID 的仿冒热点、异常 DHCP 网关和 ARP 行为；对员工进行钓鱼 WiFi 意识培训。
- **流量侧**：HSTS/HTTPS 优先，监控 TLS 证书链异常、HTTP 明文降级和响应内容被篡改的迹象；对高安全场景强制走企业 VPN 并校验服务端证书。
- **红队自检**：确认授权范围与热点使用时段，避免把无关设备流量纳入抓包；抓包结束后关闭共享并清理证书。
