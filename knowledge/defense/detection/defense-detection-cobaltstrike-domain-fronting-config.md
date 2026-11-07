---
id: defense-detection-cobaltstrike-domain-fronting-config
title: CobaltStrike 域前置 C2 配置识别：Host 头与请求域名不一致
type: scenario
domain: defense
path: defense/detection
technique: cobaltstrike-domain-fronting-config-detection
aliases:
- CobaltStrike 域前置
- Domain Fronting 检测
- Host 头与 SNI 不一致
- douyin.com 伪装 C2
- coze.site Host
- CS 配置提取
tags:
- cobaltstrike
- c2
- domain-fronting
- host-header
- malleable-c2
- detection
- threat-hunting
- tls
- dllhost
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:48:01+08:00'
  notes: 已对照原文与图24-26核对：C2 https://www.douyin.com:443/goofy/...jquery-3.3.1.min.js、URL 列表含 code.coze.cn/www.bytedance.com 同路径、HostHeader yzf4c3q35g.coze.site、HttpPostUri jquery-3.3.2、UA IE11、Malleable 去头尾/Base64 URL-safe/XOR、PublickeyMd5 baf6...、NtMapViewOfSection、dllhost.exe 注入链、YARA 规则与 443 Established 连接均与截图/配置表一致。原文无组件版本区间，未设 affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

CobaltStrike 域前置把 C2 URL 放在 `www.douyin.com`、`www.bytedance.com`、`code.coze.cn` 等高信誉域名上，但在 HTTP `Host` 头里写攻击者控制的 `yzf4c3q35g.coze.site`；TLS/SNI 与 HTTP Host 不一致、同一伪装 URI 路径出现在多个无关域名、结合 `NtMapViewOfSection` 注入与 `dllhost.exe` 子进程等 Beacon 配置字段，可以在流量与主机侧同时识别。

## 原理

- **域前置基本模型**：客户端与 CDN/前置域名（如 douyin.com）建立 TLS，SNI 写前置域名以通过审查/信誉检查；HTTP `Host` 头（或 HTTP/2 `:authority`）写真实 C2 域名（coze.site），CDN 按 Host 转发到攻击者源站。外部看到的是与高信誉域名通信，实际控制端在攻击者域名。
- **示例配置字段**：C2 地址 `https://www.douyin.com:443/goofy/slardar/fe/sdk/plugins/jquery-3.3.1.min.js`；URL 列表还包括 `code.coze.cn` 与 `www.bytedance.com` 的同路径；`Host: yzf4c3q35g.coze.site`；UA 伪装 IE11 `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko`；`HttpPostUri` 为 `jquery-3.3.2.min.js`；`DnsStrategy round-robin`。
- **Malleable 指令**：`Remove 1522 bytes from the end`、`Remove 84 bytes from the beginning`、`Remove 3931 bytes from the beginning`、`Base64 URL-safe decode`、`XOR mask w/ random key`，说明 Beacon 对 HTTP 载荷做去头/去尾/解码/XOR，流量特征与普通 jQuery 请求不同；可用配置解析器提取。
- **主机侧配置**：`ProcinjectAllocationmethod NtMapViewOfSection`、`ProcinjectExecute ntdll:RtlUserThreadStart,CreateThread,NtQueueApcThread-s,CreateRemoteThread,RtlCreateUserThread`、`SpawntoX64 %windir%\sysnative\dllhost.exe`、`SpawntoX86 %windir%\syswow64\dllhost.exe`、`bUsesCookies True`、`bCFGCaution False`、`bProcinjectStartrwx False`、`bProcinjectUserwx False`、`WatermarkHash`、`PublicKey`/`PublickeyMd5`（`baf6bff3774ed74ce89b3a918b245303`）。
- **为什么能检测**：
  - 正常 CDN 访问的 SNI 与 Host 通常一致；SNI=www.douyin.com 而 Host=*.coze.site 是典型域前置信号。
  - 同一 URI 路径出现在多个不相关的高信誉域名上，且路径伪装成静态 JS（jquery-3.3.x.min.js），但请求方法/大小/响应不符合静态资源特征。
  - 进程侧：`dllhost.exe` 作为异常子进程、`NtMapViewOfSection`/远程线程注入、读取伪装 `.db/.log` 文件后执行内存 shellcode。
- **边界**：部分 CDN 已禁用域前置或要求 Host 与 SNI 一致；企业可能无法解密 TLS，只能依赖 JA3/SNI/Host 元数据；攻击者可改用 CDN 重定向、域前置到自有域名或 DNS 隧道，需要结合其他检测。

## 触发条件

- 网络侧可获取 TLS SNI、HTTP Host/`:authority`、请求路径、UA、响应大小等元数据（代理、防火墙、NDR、Zeek/Suricata、CDN 日志）。
- 主机侧有 EDR/Sysmon 可观察 `dllhost.exe` 子进程、`NtMapViewOfSection`、远程线程、异常文件读取与内存执行。
- 已知/可提取 Beacon 配置（CS 配置解析器、YARA、沙箱报告），用于比对 PublicKey/Watermark/URI/UA 等字段。
- 目标未对全部流量做 TLS 解密，但 SNI/Host 元数据仍可用。

## 利用步骤

1. 从样本/沙箱/内存中提取 CobaltStrike 配置（PublicKey、PublickeyMd5、WatermarkHash、C2 URL、HttpPostUri、UA、Malleable 指令、注入方式）。
2. 在代理/NDR 日志中检索 C2 URL 的域名与路径（示例 `/goofy/slardar/fe/sdk/plugins/jquery-3.3.1.min.js`），统计 SNI 与 HTTP Host 是否一致。
3. 标记 SNI 为高信誉域名（douyin/bytedance/coze）但 Host 为陌生子域（`*.coze.site`）的会话；检查同路径是否出现在多个无关域名。
4. 检查 HTTP 方法/请求体/响应大小是否符合静态 JS 资源；对 POST URI（`jquery-3.3.2.min.js`）尤其可疑。
5. 主机侧关联：`dllhost.exe` 异常启动、`NtMapViewOfSection`/`CreateRemoteThread`/`NtQueueApcThread` 注入、读取 `data_*.db`/`error.log` 后 `VirtualAlloc`+`CreateThread`。
6. 用配置字段（PublicKeyMd5、WatermarkHash、URI、UA）写入检测规则/YARA/IDS，封禁 C2 域名与 Host。

## PoC

原文提取的配置要点（节选）：

```text
家族: CobaltStrike    通信协议: HTTPS
C2: https://www.douyin.com:443/goofy/slardar/fe/sdk/plugins/jquery-3.3.1.min.js
URL: www.douyin.com/goofy/slardar/fe/sdk/plugins/jquery-3.3.1.min.js
     code.coze.cn/goofy/slardar/fe/sdk/plugins/jquery-3.3.1.min.js
     www.bytedance.com/goofy/slardar/fe/sdk/plugins/jquery-3.3.1.min.js
HostHeader: Host: yzf4c3q35g.coze.site
HttpPostUri: /goofy/slardar/fe/sdk/plugins/jquery-3.3.2.min.js
请求头: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
ProcinjectAllocationmethod: NtMapViewOfSection
SpawntoX64: %windir%\sysnative\dllhost.exe
Malleable: Remove 1522 bytes from the end, Remove 84 bytes from the beginning,
           Remove 3931 bytes from the beginning, Base64 URL-safe decode, XOR mask w/ random key
PublickeyMd5: baf6bff3774ed74ce89b3a918b245303
```

检测逻辑示意（伪代码）：

```text
if tls.sni in {www.douyin.com, www.bytedance.com, code.coze.cn}
   and http.host endswith ".coze.site":
       alert "possible domain fronting"
if http.uri == "/goofy/slardar/fe/sdk/plugins/jquery-3.3.*.min.js"
   and http.method == POST:
       alert "CobaltStrike fronting URI"
if process.parent == dllhost.exe and process.injects(NtMapViewOfSection):
       alert "Beacon injection pattern"
```

原文流量验证：`ConsoleA... DESKTOP-SQ1HR... 52906 www.douyin.com 443 TCP Established`，说明主机与伪装的 douyin.com 建立了 443 连接；沙箱命中多条 CobaltStrike YARA 规则（`CobaltStrike_C2_Encoded_XOR_Config_Indicator`、`cobaltstrike_beacon_strings`、`Windows_Trojan_CobaltStrike_f0b627fc`）。

## 变体与关联

- **Malleable C2 伪装**：伪装成 10086 商城流量等；见 [[pentest-c2-cs-malleable-10086-traffic-masquerade]]。
- **其他前置域名**：CloudFront/Azure/Fastly 等 CDN；检测核心仍是 SNI 与 Host 不一致。
- **无 TLS 解密**：用 JA3/JA4、SNI、Host、包长/时序、URI 路径做启发式；结合 DNS 查询与响应 IP 信誉。
- **绕过演进**：攻击者可能让 Host 与 SNI 一致、使用自有域名或 CDN 重定向；需要结合主机侧注入行为与配置字段。
- **关联**：分片 shellcode 加载见 [[code-analysis-dynamic-debugging-split-shellcode-file-loader-xor]]；双阶段持久化见 [[pentest-persistence-two-stage-self-copy-scheduled-task-programdata]]；臭名昭著的 CS 配置检测可与沙箱 YARA 联动。
- **防御/检测**：TLS 检查/SNI-Host 关联、代理日志、DNS 信誉、EDR 注入检测、YARA/IDS 规则、封禁 C2 与前置 Host。

## 检测与防御

- **网络检测**：SNI 与 HTTP Host/`:authority` 不一致；同一伪装 URI 路径跨多个无关域名；POST 到 `.js` 静态资源路径；UA 与请求特征不匹配；JA3/JA4 与已知 CS 配置比对。
- **主机检测**：`dllhost.exe` 异常子进程、`NtMapViewOfSection`/`CreateRemoteThread`/`NtQueueApcThread` 注入、进程读取 `data_*.db`/`error.log` 后执行内存 shellcode。
- **配置检测**：用 CS 配置解析器/YARA 提取 PublicKeyMd5、WatermarkHash、URI、UA、Malleable 指令，建立组织内 IOC 库。
- **防御**：TLS 检查与出站域名白名单；限制 CDN 前置/未知子域；EDR 阻断异常注入；封禁 C2 域名与 Host；对高信誉域名上的异常路径做告警。
- **应急**：隔离主机、提取 shellcode 与配置、封禁 C2、排查同批次样本与计划任务。
