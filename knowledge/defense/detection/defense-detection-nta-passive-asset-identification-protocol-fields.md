---
id: defense-detection-nta-passive-asset-identification-protocol-fields
title: 全流量 NTA 被动资产识别：从 DHCP Host Name、NBNS 注册、Kerberos AS-REQ/TGS-REP、LDAP 与 HTTP UA 提取 IP/MAC/主机名/域用户/设备型号
type: scenario
domain: defense
path: defense/detection
technique: nta-passive-asset-identification-protocol-fields
aliases:
- 被动资产识别
- NTA 资产识别
- 流量资产画像
- DHCP Host Name 识别
- NBNS 主机名
- Kerberos 用户名提取
- User-Agent 资产识别
tags:
- nta
- traffic-analysis
- asset-identification
- passive-recon
- dhcp
- nbns
- kerberos
- ldap
- user-agent
- wireshark
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:47:15+08:00'
  notes: 已对照原文全文与全部12图核对：DHCP Request Option12 jeremiahs-MBP/Option50 172.16.1.38/Apple_04:a5:7b（图01/02）、NBNS Registration JEREMIAHS-MBP<00> 与 DESKTOP-HVKYP4S（图03-05）、Kerberos AS-REQ cname rene.mccollum/realm PCAPWORKSHOP.NET/HostAddress DESKTOP-HSJD5R8<20> 与 TGS-REP sname PCAPWORKSHOP-DC.pcapworkshop.net（图06-08）、LDAP DN CN=Rene McCollum,CN=Users,DC=pcapworkshop,DC=net（图09）、Edge UA Windows NT 10.0 与 Android 13 Pixel 4a (5G)（图10-12）均一致；MAC 最近一跳与 UA Reduction 边界与原文一致。tshark 字段名按 Wireshark 常见字段整理、未在样本 pcap 上复跑（卡片已注明）。与 Kerberos 攻击向（AS-REP 破解/用户枚举）及 HTTP2/3 指纹卡场景不同，dedup new 成立。非组件漏洞，无版本设置。frontmatter 无 sources/source_url/文章ID。
---

## 一句话结论

全流量分析产品做“被动资产识别”时，不需要主动扫描：在镜像/分光流量中解析 DHCP Option 12 的 Host Name、NBNS Name Registration 的 NetBIOS 名、Kerberos AS-REQ 的 cname/realm 与 TGS-REP 的 sname、LDAP searchRequest 的 DN，以及明文 HTTP 的 User-Agent，即可把 IP、MAC、主机名、域环境、域用户名、操作系统/设备型号关联成资产画像；多协议字段互相印证可提高准确度，但也受加密普及、UA 伪造和复杂网络 MAC 跳变限制。

## 原理

- **被动识别的定位**：主动识别（Nmap/资产扫描）准确但会产生流量、可能触发告警；被动识别只监听流量，适合不能干扰业务的环境与持续监控，代价是依赖协议明文与流量覆盖，精确度和全面性较差。二者常结合使用。
- **DHCP Request（UDP 67/68，0.0.0.0 → 255.255.255.255）**：报文中 `Option 50 Requested IP Address` 给出期望 IP，`Option 12 Host Name` 给出客户端主机名，链路层源 MAC 给出客户端 MAC（前 3 字节可查 OUI 推断厂商）。示例：MAC `Apple_04:a5:7b` + Host Name `jeremiahs-MBP` 可推断为 Apple MacBook Pro 类设备。
- **MAC 的边界**：抓到的 MAC 是“流量传输链路中最近一跳”的地址，跨路由/交换的复杂网络中常是网关、路由器或安全设备的 MAC，而非终端自身；不能只凭 MAC OUI 下结论，要结合主机名、IP 段与网络拓扑交叉判断。
- **NBNS（UDP 137）**：NetBIOS Name Registration 广播声明 `<NetBIOS名><00>`，类型为 Workstation/Redirector（`NB` 0x20）；据此可取 Windows 主机名（如 `DESKTOP-HVKYP4S`）。Name Query/Release 同样带名称，可用于同一主机的持续观测。
- **Kerberos（TCP/UDP 88）**：AS-REQ 的 `cname` 是请求票据的域用户名（如 `rene.mccollum`），`realm` 是域（如 `PCAPWORKSHOP.NET`），`addresses`/HostAddress 常带客户端 NetBIOS 主机名（如 `DESKTOP-HSJD5R8<20>`）；TGS-REP 的 `sname` 是服务 SPN（如 `PCAPWORKSHOP-DC.pcapworkshop.net`），可定位域控主机名与域。由此可把“客户端 IP ↔ 域用户名 ↔ 主机名 ↔ 域控/域”关联起来。
- **LDAP（TCP 389）**：明文 LDAP 的 searchRequest 中常见 `CN=Rene McCollum,CN=Users,DC=pcapworkshop,DC=net` 形式的 DN，可补充用户全名与组织单元信息；LDAPS/StartTLS 后不可见。
- **HTTP User-Agent**：UA 可给出浏览器/内核版本与操作系统：`Windows NT 5.1`=XP、`6.0`=Vista、`6.1`=7、`6.2`=8、`6.3`=8.1、`10.0`=10 或 11；Chrome/Edge/Firefox 已把 Windows 版本固定在 `NT 10.0`（UA Reduction），无法区分 10/11；Android UA 可能带设备型号（如 `Android 13; Pixel 4a (5G)`）。HTTPS 普及与 UA 伪造使该来源可靠性下降，只适合做平台级粗分类。
- **关联入库**：把各协议抽取的字段以 IP/MAC/主机名为键写入数据库并建索引，单实体聚合展示；同一实体在 DHCP 与 NBNS 中出现相同主机名/MAC 时可提升置信度，冲突时标记待人工核验。

## 触发条件

- 具备流量镜像/分光/TAP 或 NTA 采集能力，能看到目标网段的南北向/东西向流量。
- 流量中存在明文协议：DHCP、NBNS、Kerberos（用户名/域名字段通常明文可见）、明文 LDAP、HTTP。
- 终端未完全使用加密替代（LDAPS、HTTPS、DoH 等会隐藏相应字段）。
- 分析者能按 IP/MAC/主机名做关联存储与索引。

## 利用步骤

1. 在采集流量上按协议过滤，先建立“IP ↔ MAC ↔ 主机名”基础表。
2. DHCP：过滤 DHCP Request，提取 `Option 12 Host Name`、`Option 50 Requested IP Address` 与源 MAC/OUI。
3. NBNS：过滤 UDP 137 的 Name Registration，提取 `<00>` NetBIOS 名（Workstation/Redirector 类型）。
4. Kerberos：过滤 AS-REQ/TGS-REP，提取 `cname`、`realm`、`sname`、`addresses` 中的 NetBIOS 主机名，得到域用户与域控信息。
5. LDAP：在明文 LDAP searchRequest 中提取 DN（`CN=用户全名,CN=Users,DC=...`）。
6. HTTP：解析 User-Agent，按 Windows NT 版本表/Android 型号做 OS 与设备粗分类；对 UA Reduction 后的 `NT 10.0` 不下 10/11 结论。
7. 以主机名/MAC/IP 为键合并多协议观测，生成资产画像；对冲突项（MAC 属网关、主机名重复）人工核验。
8. 持续监控时对新出现的资产/协议字段变化做增量告警。

## PoC

```bash
# DHCP Request 中的主机名、请求 IP 与源 MAC
tshark -r capture.pcap -Y "dhcp.option.dhcp == 3" -T fields \
  -e ip.src -e eth.src -e dhcp.option.hostname -e dhcp.option.requested_ip_address

# NBNS 名称注册（NetBIOS 主机名）
tshark -r capture.pcap -Y "nbns" -T fields -e ip.src -e eth.src -e nbns.name

# Kerberos AS-REQ 的域用户名与域；TGS-REP 的服务名/域控主机名
tshark -r capture.pcap -Y "kerberos.msg_type == 10" -T fields \
  -e ip.src -e kerberos.CNameString -e kerberos.realm
tshark -r capture.pcap -Y "kerberos.msg_type == 13" -T fields \
  -e ip.src -e kerberos.SNameString -e kerberos.realm

# 明文 LDAP searchRequest 的 DN
tshark -r capture.pcap -Y "ldap" -T fields -e ip.src -e ldap.dn

# HTTP User-Agent
tshark -r capture.pcap -Y "http.user_agent" -T fields -e ip.src -e http.user_agent
```

```text
Wireshark 过滤示例：
dhcp                         # DHCP 报文
nbns                         # NetBIOS Name Service
kerberos                     # 或 kerberos.CNameString contains "rene"
ldap                         # 明文 LDAP
http.user_agent              # 含 UA 的 HTTP 请求
```

说明：以上为按原文分析整理的结构化提取方法，字段名随 Wireshark/tshark 版本可能略有差异，未在本文样本上复跑；实际使用需按 pcap 调整。

## 变体与关联

- **协议变体**：LLMNR/mDNS 可提供主机名；SMB 协商可提供主机名/域；TLS SNI/证书可提供域名；HTTP/2/HTTP3 客户端指纹可提供客户端栈特征（见 [[pentest-recon-http2-client-fingerprint]]、[[pentest-recon-http3-server-settings-fingerprint]]）。
- **主动补充**：Nmap 存活/端口/服务识别与被动画像互补；主动扫描会产生特征流量，需授权。
- **攻防两用**：同样的流量字段也是攻击者被动侦察（无扫描器落地）的信息来源；防守方可用这些字段做资产清点与告警定位，攻击方可在镜像/中间人位置收集。
- **边界**：HTTPS/LDAPS/DoH 隐藏 UA/DN；UA 可伪造；NBNS/LLMNR 在较新 Windows 中常被禁用；复杂网络 MAC 非终端；DHCP 主机名可被终端自定义。

## 检测与防御

- **资产侧**：建立被动资产基线，定期核对新出现的 MAC/主机名/域账号；对未知设备接入、主机名突变、UA 与历史画像不一致告警。
- **隐私与合规**：被动采集用户名、主机名、设备型号涉及个人信息，需授权、最小化与访问审计。
- **降低暴露**：关闭不必要的 NBNS/LLMNR；使用 LDAPS/HTTPS/DoH；DHCP 主机名避免包含使用者姓名/设备型号等敏感信息；网络分段限制流量可见面。
- **采集侧**：镜像流量只给必要的分析平台，采集口访问受控；对 NTA 数据库中的用户/资产信息做脱敏与保留期限管理。
