---
id: defense-detection-blacknet-http-c2-heartbeat-traffic
title: BlackNET 僵尸网络 HTTP(S) C2 通信识别：check_panel/connection/getCommand/receive 路径与 URL-safe Base64 心跳
type: scenario
domain: defense
path: defense/detection
technique: blacknet-http-c2-heartbeat-detection
aliases:
- BlackNET 流量识别
- BlackNET C2 检测
- getCommand.php 心跳
- receive.php CleanCommands
- 僵尸网络 HTTP 心跳
- URL-safe Base64 C2
tags:
- detection
- c2
- blacknet
- botnet
- http
- heartbeat
- base64
- network
- threat-hunting
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:30:58+08:00'
  notes: 已对照原文与全部 30 图核对：图01/06 面板、02 Builder（BN URL /192.168.65.129/blacknet、Victim ID HacKed、Splitter |BN|）、03 面板 PHP（check_panel.php/connection.php/getCommand.php 等）、06 Bot 列表 victim HacKed_DEA8B705/192.168.65.128、图26 ENB/DEB 实现（Base64→去=→+换-/换_；反向补=）、图27 POST /blacknet/connection.php（Content-Length 275、data=SGFj...|BN|...）、图28 同一秒 getCommand.php?id=SGFjS2VkX0RFQThCNzA1 与 receive.php?command=UGluZ2Vk&vicID=... 成对，长度 270/302 与 287/277，与卡内完全一致；图29/30 为 HTTPS 加密流量，符合卡内 HTTPS 变体判断。UA Mozilla/5.0 ... Chrome/80.0.3987.149 与原文抓包一致；Ping/Pinged Base64 解码正确。未验证点：原文为 192.168.65.128/129 实验环境，未复现；frontmatter 无 sources/source_url；BlackNET 开源框架无受影响版本，未设 affected_versions。kb show 存在；dedup top1 为自身，其余候选（Suo5 tunnel、gate.php beacon、Linux polling agent、HTML comment C2 等）协议/路径/编码不同，非同链；dup-scan.json 无本篇 pair。
---

## 一句话结论

BlackNET 远控木马用固定的一组 PHP 路径与 C&C 通信：上线前 `check_panel.php` 探活、`connection.php` 上报主机信息，之后高频轮询 `getCommand.php?id=<URL-safe Base64 victimID>` 取指令，执行后向 `receive.php?command=<Base64>` 回执（无指令时为 `Ping`/`Pinged`，还有 `CleanCommands`）。请求参数使用 URL-safe Base64（`+`→`-`、`/`→`_`），无心跳间隔，因此流量中会出现大量相同长度、成对交替的 HTTP 请求；按路径、参数编码和心跳节律即可识别 BlackNET 感染与提取 Victim ID。

## 原理

- **固定协议路径**：木马运行后依次请求 `/blacknet/check_panel.php`（校验 C&C 存活）、`/blacknet/connection.php`（POST 系统基本信息）、循环 `GET /blacknet/getCommand.php?id=<b64(victimID)>` 获取指令；执行完指令后请求 `/blacknet/receive.php?command=<b64(command)>&vicID=<b64(victimID)>` 回执。
- **URL-safe Base64**：`ENB` 先把 UTF-8 字符串做标准 Base64，去掉 `=` 填充，再把 `+` 替换为 `-`、`/` 替换为 `_`；`DEB` 反向替换、按长度补 `=` 后 Base64 解码。因此 URL 里的 `id`/`command` 是 `A-Za-z0-9-_` 字符集、无 `=` 的 Base64。
- **心跳特征**：未收到指令时 `getCommand.php` 返回 `Ping`（Base64 `UGluZw`），木马回执 `receive.php?command=UGluZ2Vk...`（`Pinged`）；由于代码未设置请求间隔，这两个请求会以很高频率交替出现，且载荷长度固定。原文抓包中同一秒内出现多组 `getCommand.php?...`（270/302 字节）与 `receive.php?command=UGluZ2Vk...`（287/277 字节）请求。
- **指令回执**：不同指令执行后会带 `receive.php?command=CleanCommands`（或 `DeleteScript`、`Offline`、`Uninstall` 等）；截图/文件/密码/日志类指令还会通过 `upload.php`、`post.php`、`remoteshell.php` 上传结果或执行 shell。
- **HTTPS 变体**：加密后看不到路径与参数，但证书/域名、请求频率、固定长度心跳、JA3/UA 与 C&C 基础设施仍可作为检测面；HTTP 明文则可以直接解码参数。
- **为什么可检测**：BlackNET 是开源项目、协议固定且缺少随机化；默认 User-Agent 为 `Mozilla/5.0 ... Chrome/80.0.3987.149 Safari/537.36`（可在 builder 中改），路径名 PHP 固定，心跳无抖动，这些组合在正常业务流量中很少同时出现。

## 触发条件

- 可获取 HTTP 代理日志、pcap 或 IDS/NDR 流量；明文 HTTP 最佳，HTTPS 需依赖 SNI/证书/时序/指纹。
- 目标主机或出口存在访问 `/blacknet/` 前缀 PHP 路径的请求，或 `getCommand.php?id=`、`receive.php?command=` 等参数。
- 请求参数符合无填充 URL-safe Base64 特征；`id` 解码后通常为 `HacKed_<ID>` 形式（prefix 可被 builder 修改）。
- 出现高频、固定长度、`getCommand`/`receive` 成对交替的心跳。
- 主机侧同时有可疑 .NET 进程、`Client.exe`/`watcher.exe`、`Windows Update Assistant` 文件描述等（可作为关联证据）。

## 利用步骤

1. 在代理/NDR 中筛选 HTTP 请求 URI，匹配 `/blacknet/`、`check_panel.php`、`connection.php`、`getCommand.php`、`receive.php`、`upload.php`、`post.php`、`remoteshell.php`。
2. 提取 `getCommand.php` 的 `id` 参数，按 URL-safe Base64 解码（`-`→`+`、`_`→`/`、补 `=`），得到 Victim ID；它可与面板中的 Bot 列表对应。
3. 提取 `receive.php?command=` 参数并解码，观察是否为 `Ping`/`Pinged`/`CleanCommands`/`DeleteScript`/`Offline` 等 BlackNET 指令回执。
4. 统计请求时间序列：同一源 IP 对同一 C&C 的 `getCommand` 与 `receive` 频率、载荷长度、间隔是否固定；BlackNET 默认无 sleep，表现为高频、等长、成对。
5. 关联 `connection.php` POST 的上报内容（Base64 解码后以 `|BN|` 分隔的主机名、OS、CPU、内存、版本等），确认受控主机画像。
6. 对 HTTPS：用 SNI/证书、JA3、UA、请求节奏与已知 BlackNET C&C 情报匹配；必要时在端点侧抓取进程网络行为。
7. 输出 IOC：C&C 域名/IP、URI 路径、UA、Victim ID、心跳周期，交给封禁与主机排查。

## PoC

tshark 提取 HTTP 请求：

```bash
tshark -r blacknet.pcap -Y 'http.request.uri contains "/blacknet/"' \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri -e http.user_agent
```

URL-safe Base64 解码：

```python
import base64

def b64url_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)

print(b64url_decode('SGFjS2VkX0RFQThCNzA1'))  # b'HacKed_DEA8B705'
print(b64url_decode('UGluZw'))                 # b'Ping'
print(b64url_decode('UGluZ2Vk'))               # b'Pinged'
```

典型心跳（原文抓包）：

```text
GET /blacknet/getCommand.php?id=SGFjS2VkX0RFQThCNzA1 HTTP/1.1
GET /blacknet/receive.php?command=UGluZ2Vk&vicID=SGFjS2VkX0RFQThCNzA1 HTTP/1.1
```

同一秒内重复出现，长度分别约 270/302 与 287/277 字节。

## 变体与关联

- 配置变体：builder 可修改 BN URL 路径前缀、Victim ID、Splitter、User-Agent；路径不一定为 `/blacknet/`，但 PHP 文件名与参数名通常保留。
- 加密变体：AES Encryption 只加密配置里的 C&C 地址（见 BlackNET 配置解密卡），不改变上线后的 HTTP 协议与 Base64 参数。
- HTTPS 变体：载荷加密后无法直接解码，需靠证书/SNI/时序/指纹与端点遥测。
- 关联：其它 C2 心跳检测（Merlin、Cobalt Strike beacon）可用相同思路：固定 URI、固定长度、无抖动心跳、编码参数；BlackNET 的判别点是 PHP 路径组合与 URL-safe Base64 参数。
- 边界：原文为实验环境（192.168.65.129/128）复现；真实样本可能改路径/UA/间隔，需结合多个特征而非单一 IOC。

## 检测与防御

- 网络检测：IDS/Suricata 规则匹配 `/blacknet/` 下 PHP 路径、`getCommand.php?id=`、`receive.php?command=`、无填充 URL-safe Base64 参数；对高频等长 `getCommand`/`receive` 成对请求做 beacon 评分。
- 主机检测：排查 `Client.exe`/`watcher.exe`、文件描述 `Windows Update Assistant`、`%TEMP%` 下 `xmrig.exe`、`Passwords.txt`/`CookiesCh.sqlite` 等 BlackNET 产物；检查启动项/计划任务与服务。
- 防御：封禁 C&C、阻断 `/blacknet/` 路径与相关 UA；对出站 HTTP 做域名/路径白名单；对 .NET 无签名/可疑进程做 EDR 告警。
- 响应：解码 Victim ID 与 connection.php 上报信息确定受影响主机；隔离主机、重置凭据、检查横向与数据外带；用相同 IOC 在全网回溯。
