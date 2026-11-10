---
id: iot-vehicle-wifi-evil-twin-auto-reconnect-mitm
title: 车机 WiFi 热点同名同密码仿冒：克隆 SSID+PSK+BSSID 后车机自动重连，形成中间人入口
type: scenario
domain: iot
path: iot/vehicle
technique: wifi-evil-twin-ssid-psk-bssid-clone-auto-reconnect
tags:
- iot
- vehicle
- wifi
- evil-twin
- rogue-ap
- mitm
- wireless
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:59:32+08:00'
  notes: 已对照原文核对：车机热点 WPA3-Personal 5GHz（图 02/06/10）、iPhone 热点同名同密码仿冒（图 12 热点设置、图 13 设备名 deny 与图 11 车机热点 ESSID 一致）、断开原热点后车机自动重连且 MAC 校验通过（原文文字+图 12/13）。卡正文已诚实区分：原文仅实测 SSID+PSK 同名自动重连，BSSID 克隆需软 AP（手机热点无法改 MAC），危害边界止于二层接入/中间人位置，medium 置信与证据强度匹配。skipped 4 项（mdk3 DoS 未打通且属 DoS 类、Ripple20 探测无响应、WPA3 爆破未命中、Fluxion 无自身实操）排除均合理。dedup 候选（蓝牙 HID、PMKID、deauth 爆破、ADB）均不同链；dup-scan 无涉及 pair。
url: /docs/iot/vehicle/iot-vehicle-wifi-evil-twin-auto-reconnect-mitm/
draft: false
kb_aliases:
- 车机 WiFi 钓鱼
- 仿冒热点同名同密码
- 克隆 BSSID 钓鱼
- 车机热点自动重连
- 个人热点伪装车机热点
---

## 一句话结论

车机的 WiFi 客户端按“SSID + 预共享密钥 + AP 的 BSSID（MAC）”记忆已配网热点，而不校验 AP 身份来源；攻击者用手机热点或软 AP 起一个 SSID、密码与之完全相同且克隆了原 AP MAC 的仿冒热点，车机在原热点不可达时就会自动连上该仿冒热点，攻击者由此获得车机二层接入与流量中间人位置。

## 原理

- 家用/车机 WiFi 客户端保存的是网络配置档（profile）：SSID 字符串、PSK、以及可选的 BSSID/MAC 绑定。重连时它按配置档做被动/主动扫描匹配，匹配成功即发起四次握手并自动关联，全程没有“这个 AP 是不是原来那个”的可信证明。
- WPA2/WPA3-Personal 的四次握手只能证明“双方知道同一个 PSK”，无法证明对方就是原 AP；攻击者从车机热点名与密码（常贴在前台设置页、简单可猜、或被车主共享）得到 PSK 后，与车机之间同样能完成合法握手。
- 部分实现把 MAC 绑定当作防仿冒手段，但 BSSID 只是明文可读的二层标识，攻击者可在软 AP 配置里随意设置 `bssid`/`ssid`，克隆成本为零，因此“校验 MAC”并不构成认证。
- 车机作为客户端往往开启“自动加入/优先连接已知网络”，当原热点关闭或信号被压制时，它会主动扫描并连到同名同 PSK 的仿冒 AP，攻击者在关联后即可拿到车机的 IP 层入口。
- 该位置的价值在于：车机与手机 App/云端之间的本地同步流量、车机内部服务端口、OTA/诊断相关请求都会经过攻击者的 AP，可用于流量嗅探、DNS 劫持、伪造升级源与端口探测。

## 触发条件

- 车机以 WiFi 客户端方式连接外部热点（手机热点/随车热点），并保存了该网络配置档且开启自动重连。
- 攻击者已知或可猜出该热点的 SSID 与密码（设置页可见、默认口令、车主共享），并能读取原 AP 的 BSSID。
- 攻击者能在车机附近起一个可自定义 SSID/PSK/BSSID 的 AP（手机个人热点在 SSID/密码上即可满足，BSSID 克隆需要支持修改 MAC 的软 AP）。
- 原热点在攻击窗口内不可达或信号弱于仿冒 AP，使车机选择仿冒 AP。

## 利用步骤

1. 在车机设置页或通过车机界面读取当前连接热点的 SSID、安全类型与密码；用 `airodump-ng` 一类工具记录该热点的 BSSID 与信道。
2. 准备仿冒 AP：用手机开个人热点，把热点名称与密码改成与原热点完全一致（手机热点无法改 BSSID，仅能验证“同名同密码是否会被自动连接”）；需要克隆 MAC 时改用支持设置 BSSID 的软 AP。
3. 关闭或干扰原热点（关闭原手机热点/让原热点信号更弱），使车机失去当前关联。
4. 观察车机是否自动扫描并关联仿冒 AP；关联成功后在其 DHCP 池里看到车机租约，说明车机已成为仿冒 AP 的客户端。
5. 在仿冒 AP 网关上做流量转发与抓包（tcpdump/ mitmproxy），并对车机侧开放端口做探测，确认可触达的本地服务。
6. 若需持续化，配合 DNS 劫持或伪造同名升级/同步服务响应，观察车机是否发起明文请求。

## PoC

软 AP 侧关键配置（hostapd，值取自目标热点，仅用于授权测试）：

```ini
interface=wlan0
driver=nl80211
ssid=<车机热点同名 SSID>
hw_mode=g
channel=<原热点信道>
wpa=2
wpa_passphrase=<与原热点相同的密码>
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
bssid=<原热点 BSSID，需网卡支持改 MAC>
```

手机热点替代方案（用于验证自动重连，无法覆盖 BSSID 绑定）：

```text
个人热点名称 = <车机热点同名 SSID>
无线局域网密码 = <与原热点相同的密码>
关闭原热点 → 车机断开 → 观察是否自动连上该热点
```

验证车机已接入：

```bash
# 在仿冒 AP 所在主机上
ip neigh | grep -i <车机网卡 OUI 前缀>
tcpdump -i wlan0 -n host <车机 IP>
```

## 变体与关联

- 变体：不改 BSSID、只改 SSID+PSK，用于验证车机是否仅凭 SSID/PSK 匹配；若车机仍自动连接，说明 MAC 绑定未真正生效。
- 变体：用 captive portal（Fluxion 类）在同名热点上弹认证页骗取更高价值凭据（云账号、车主账号）。
- 变体：配合解除认证帧把车机从原热点打下来，缩短等待其自动重连的时间窗。
- 关联：车机蓝牙外围欺骗见 [[iot-vehicle-bluetooth-hid-keyboard-spoofing]]；车机本地调试端口暴露见 [[iot-vehicle-camera-debug-console-20000-unauth]]；OTA 握手密钥问题见 [[iot-vehicle-ota-handshake-session-key-aes-cbc-zero-iv]]。
- 边界：车机若强制校验 AP 证书（WPA-Enterprise/EAP-TLS）、或关闭自动重连并要求用户确认新网络，则本场景不成立。原文只演示到“断开原网络后自动连接仿冒热点且 MAC 校验通过”，未抓取或展示车机流量，故危害以二层接入/中间人位置为主，confidence 标 medium。

## 检测与防御

- 检测：车机侧记录同 SSID 但 BSSID 变化的重连事件并告警；对“同名热点同时出现两个 BSSID”做无线侧扫描告警；网关上出现陌生 DHCP 客户端或异常 DNS 请求。
- 防御：车机连接热点时校验 BSSID 绑定并在 BSSID 变化时要求用户确认；优先使用 WPA3-SAE 并启用 PMF（802.11w）降低降级与解认证攻击面；关闭无条件自动重连。
- 加固：避免使用默认/可猜的热点口令，不在车机界面明文展示热点密码；对车机本地服务做认证，不依赖“内网即可信”；敏感同步流量强制 TLS 并校验证书。
