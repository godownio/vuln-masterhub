---
id: defense-detection-nmap-scan-et-snort-signatures
title: nmap 五类扫描的流量特征与 ET/Snort 检测规则：SYN/ACK 窗口常量、NSE UA、sqlspider URI、OS 探测 CCCC 填充
type: scenario
domain: defense
path: defense/detection
technique: nmap-scan-signature-et-snort-detection
aliases:
- nmap 扫描特征
- ET SCAN NMAP
- emerging-scan.rules
- Nmap Scripting Engine UA
- sqlspider
- nmap OS 探测 CCCC
- ET SCAN NMAP -sS
- ET SCAN NMAP -sA
tags:
- defense
- detection
- ids
- snort
- suricata
- emerging-threats
- nmap
- port-scan
- recon
- wireshark
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V535
  verified_at: '2026-11-11T17:36:36+08:00'
  notes: '已对照原文全文与14张截图(img_small)核对：图01 nmap 7.92 -sS；图02 SYN包Win=1024 Len=0；图03 DF位Not set(fragbits:!D)；图04/05/06/07 窗口1024、flags SYN+保留位未置、Ack=0；图08 -sA扫描；图09 ACK置位/窗口1024；图10 --script=vuln；图11 Follow TCP Stream中User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)；图12 NSE代码postdata= "'' OR sqlspider"；图13 nmap -O -p 80；图14 UDP目标端口39472(≥10000) Len=300且Data为连续0x43。卡中五类规则、字段解释、threshold语义与原文一致，PoC规则与原文基本一致(标注简化版)。文章为检测规则分析非组件漏洞，未设affected_versions正确；nmap 7.92为实验环境版本而非受影响版本。dedup top候选为Suricata缓冲区语法/CS beacon/ja4t指纹/nmap LDAP探测等，均非同链；dup-scan无涉及pair。卡片以ET emerging-scan.rules为主线聚合五类nmap特征，主题单一，保留verified。未实际部署IDS或执行扫描。'
---

## 一句话结论

nmap 的默认扫描在报文层留下了稳定且跨版本保留的常量特征：SYN 扫描是 `flags:S` + `dsize:0` + `ack:0` + 固定 `window`（1024/2048/3072/4096）且不带 DF 位；ACK 扫描是 `flags:A` + 固定窗口；NSE 脚本请求带 `User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine`；SQL 注入脚本把参数改成 `' OR sqlspider`；OS 探测发往高端口（≥10000）的 UDP 包 payload 为 300 字节的连续 `C`（0x43）。Emerging Threats 的 `emerging-scan.rules` 即用这些常量做告警。

## 原理

- **Snort/ET 规则结构**：规则由规则头（动作、协议、源/目的 IP 与端口、方向）和括号内规则选项组成；选项如 `flags`、`dsize`、`ack`、`window`、`fragbits`、`content`、`threshold` 描述要匹配的报文特征。`msg` 只是告警文案，`classtype:attempted-recon` 标记为侦察行为。
- **SYN 扫描（`nmap -sS`）**：nmap 构造裸 SYN 包探测端口，不完成握手。默认实现下这些包 payload 长度为 0（`dsize:0`）、ACK 号为 0、SYN 置位且保留位未置（`flags:S,12`）、不分片（`fragbits:!D`），且 TCP 窗口大小是固定常量（不同版本/平台为 1024/2048/3072/4096 之一）。正常业务主机的 SYN 包窗口值随系统与连接变化，批量出现同一常量窗口的零载荷 SYN 即是扫描特征。
- **ACK 扫描（`nmap -sA`）**：只置 ACK 标志（`flags:A,12`）、`dsize:0`、窗口固定 1024/3072，用于判断防火墙状态；单独看 ACK 包误报高，所以规则叠加窗口与零载荷条件降低误报。
- **NSE User-Agent**：nmap 脚本引擎通过 HTTP 发起探测时，默认 `User-Agent` 为 `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`。规则用 `content:"User-Agent|3a| Mozilla/5.0 (compatible|3b| Nmap Scripting Engine"`（`|3a|`=冒号，`|3b|`=分号）+ `http_header` + `nocase` + `fast_pattern` 在头部做快速匹配。
- **SQL 注入脚本**：`http-sql-injection.nse` 会把每个参数值替换为 `' OR sqlspider` 触发报错，然后检查响应体是否包含 `invalid query`、`sql syntax`、`odbc drivers error` 等错误串；因此请求 URI 中出现 ` OR sqlspider` 是脚本专属特征（规则 `content:" OR sqlspider"; http_uri`）。
- **OS 探测**：`nmap -O` 会向目标 ≥10000 的 UDP 端口发送探测包，其中一类 payload 为固定长度 300 字节、内容为连续 `C`（0x43）的填充，用于触发目标协议栈响应。该特征极强，误报极低。
- **为什么默认扫描总能被识别**：这些常量来自 nmap 的默认实现而非随机化；只要不修改源码/参数，跨版本仍保留。要绕过 IDS 需自行改源码去除窗口、UA、CCCC 等特征后重编译，或改用其他扫描器。

## 触发条件

- 目标网络部署了 Snort/Suricata + ET `emerging-scan.rules`（或等价自写规则），能看到扫描流量。
- 攻击者使用 nmap 默认参数（如 `-sS`、`-sA`、`--script=vuln`、`-O`）进行扫描，未做特征修改。
- 流量未被加密隧道/代理掩盖，IDS 位于扫描路径上。

## 利用步骤

（防守方验证/复现视角。）

1. 在测试网段用 nmap 对靶机执行 `nmap -sS <target>`、`nmap -sA <target>`、`nmap --script=vuln <target>`、`nmap -O -p 80 <target>`。
2. 用 Wireshark 过滤 `ip.src_host == <扫描机IP>`，逐类核对：SYN 包的 `Flags`、`Window`、`Acknowledgment number`、IP `Flags` 的 DF 位；HTTP 请求的 `User-Agent`；SQLi 脚本请求 URI 中的 ` OR sqlspider`；UDP 包 `Data` 是否为 300 字节 `CCCC...`。
3. 对照 ET 规则逐条匹配（见 PoC），确认告警触发与阈值行为（`threshold: type both, track by_dst, count 1, seconds 60` 表示 60 秒内同目的地址只告警一次）。
4. 观察不同 nmap 版本/参数下哪些特征变化（窗口 1024/2048/3072/4096、ACK 扫描窗口），据此调整规则。

## PoC

ET `emerging-scan.rules` 中的代表性规则（检测用，省略 reference/metadata 字段的简化版）：

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 1024"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:1024; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2009582;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 2048"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000537;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (1)"; fragbits:!D; dsize:0; flags:A,12; window:1024; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000538;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN Nmap Scripting Engine User-Agent Detected"; flow:to_server,established; content:"User-Agent|3a| Mozilla/5.0 (compatible|3b| Nmap Scripting Engine"; fast_pattern:38,20; http_header; nocase; classtype:web-application-attack; sid:2009358;)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET SCAN NMAP SQL Spider Scan"; flow:established,to_server; content:"GET"; http_method; content:" OR sqlspider"; http_uri; classtype:web-application-attack; sid:2013778;)
alert udp $EXTERNAL_NET 10000: -> $HOME_NET 10000: (msg:"ET SCAN NMAP OS Detection Probe"; dsize:300; content:"CCCCCCCCCCCCCCCCCCCC"; fast_pattern:only; classtype:attempted-recon; sid:2018489;)
```

最小验证（Wireshark 显示过滤器）：

```text
tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.len==0 && tcp.window_size_value==1024
tcp.flags.ack==1 && tcp.flags.syn==0 && tcp.len==0 && tcp.window_size_value==1024
http.user_agent contains "Nmap Scripting Engine"
http.request.uri contains " OR sqlspider"
udp.length == 308 && udp contains 43:43:43:43:43:43:43:43
```

## 变体与关联

- **窗口常量变体**：SYN 扫描还有 2048/3072/4096 窗口的姐妹规则；ACK 扫描有 3072 窗口；不同 nmap 版本/OS 可能落在不同常量，宜同时部署。
- **脚本特征变体**：NSE 的 HTTP User-Agent 可被 `--script-args http.useragent=...` 覆盖；SQLi 脚本参数串可改脚本；OS 探测的 CCCC 填充也可靠改源码去除。
- **规避思路**：修改 nmap 源码去除固定窗口、UA、填充特征后重编译；使用 masscan/ZMap 等替代（JA4T 类被动指纹仍可识别，见 [[defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint]]、[[defense-detection-ja4t-greynoise-syn-block-scanner]]）；走代理/VPN 掩盖源 IP，但报文常量不变。
- **规则工程**：Suricata 规则的 `fast_pattern` 与缓冲区选择见 [[defense-detection-suricata-buffer-order-fast-pattern-rule]]。

## 检测与防御

- **部署规则**：启用 ET `emerging-scan.rules` 或按上表自写规则；SYN/ACK 类规则加 `threshold`/`suppress` 控制告警量，避免正常业务零载荷 SYN 造成误报。
- **组合判据降低误报**：单一 ACK 包很常见，需叠加 `dsize:0` + 固定窗口；SYN 类叠加 `ack:0`、`fragbits:!D`、窗口常量；HTTP 类叠加 `http_header`/`http_uri` 缓冲区和 `nocase`。
- **补充行为检测**：单源在短时间内对多端口/多主机发起大量零载荷 SYN、NSE UA 请求、`sqlspider` URI、UDP CCCC 探测，按源 IP 做频率阈值；对 OS 探测可监控高端口 UDP 300 字节填充。
- **防御**：IDS/IPS 前置并在边界阻断扫描源；对关键资产做扫描告警与封禁；不要仅依赖固定特征（可被改源码绕过），结合连接频率、端口分布、JA4T 指纹与威胁情报综合判定。
