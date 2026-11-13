---
id: ctf-forensics-webshell-generated-backdoor-base64-zip-in-http-stream
title: WebShell 流量取证：由 ViewMore.php 写出的 d00r.php 后门 + POST 中 base64 加密 ZIP 与同流密码还原攻击者写入文件
type: scenario
domain: ctf
path: ctf/forensics
technique: webshell-traffic-generated-backdoor-encrypted-zip-in-stream
aliases:
- 陇剑杯 ez_web
- ViewMore.php d00r.php
- d00r.php 后门流量
- base64 加密 zip 流量
- WebShell 流量取证
- 内网 IP 从 ip a 回显提取
tags:
- ctf
- forensics
- pcap
- webshell
- traffic-analysis
- base64
- zip
- php
- cve
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:49:35+08:00'
  notes: 已对照原文与36图核对：图22 tcp contains d00r.php 命中最早的 ViewMore.php POST、图23 file_put_contents('d00r.php',base64_decode(...))、图24 ip a 回显 ens33 192.168.162.130/ens38 192.168.101.132（CTF 答案取内网 192.168.101.132）、图25 file_put_contents('k3y_f1le',base64_decode('UEsDBBQ...'))。注意：实际 img26 是 cat /passwd 的 POST/响应流，并非 WinHex 查看加密 ZIP 的截图；加密 ZIP 与同流密码仅原文文字描述，未在截图中复现（卡片按原文如实描述）。dedup top（xor/gzip、冰蝎、SM4、哥斯拉等加密马流量卡）非同一条链。未设 affected_versions。未在本环境复现。
---

## 一句话结论

当 pcap 中只有一个已存在的后门（如 `d00r.php`）在执行命令时，先用 `tcp contains "d00r.php"` 找全所有出现位置，往前回推生成它的请求（`ViewMore.php` 中 `file_put_contents('d00r.php', base64_decode('PD9waHAg...'))`）即可确认“服务器自带后门文件”其实是攻击者生成的；再在 `d00r.php` 的 POST 流量里取 `file_put_contents('k3y_f1le', base64_decode('UEsDBBQ...'))` 的 base64 内容，解码后是**加密 ZIP**，密码藏在同一条 HTTP 流中，解压即得攻击者写入的 key/flag。`ip a` 类命令的回显还能直接给出服务器内网 IP。

## 原理

- **后门文件是生成物**：Wireshark 过滤 `tcp contains "d00r.php"` 会同时命中后续对 `d00r.php` 的 GET/POST 和一个更早的 `POST /e/public/ViewClick/ViewMore.php`。该请求体是 `a=file_put_contents('d00r.php', base64_decode('PD9waHAgZXZhbCg...'));`，即 ViewMore.php 被利用把 base64 解码后的 PHP 后门写到 Web 目录——`d00r.php` 不是服务器自带，`ViewMore.php` 才是被利用的入口/自带文件。
- **命令回显直接泄露资产**：`d00r.php` 后续 POST 里有 `cmd=system('cat /passwd');`、`cmd=system('ip a');` 等；`ip a` 回显中 `ens33 192.168.162.130`（公网侧）与 `ens38 192.168.101.132`（内网侧）可直接读出内网 IP。
- **base64 载荷不一定是明文**：`file_put_contents('k3y_f1le', base64_decode('UEsDBBQ...'))` 的 base64 解码结果以 `50 4B 03 04`（`PK\x03\x04`）开头，是 ZIP 而非文本；看文件头/丢进 WinHex 可识别。ZIP 带密码时，密码通常由同一 C2 会话的参数/Cookie 传入（同一条 HTTP 流里可见），用 `unzip -P` 或归档工具解开即可得到 key。
- **为什么这条链成立**：WebShell 的命令与文件写入都在 HTTP 明文里，`file_put_contents` 的 base64 参数是可逆编码而非加密；攻击者把二进制（加密 ZIP）塞进 base64 以减少特殊字符，但流量侧完整保留，只要按流号回推生成链就能还原。

## 触发条件

- 已获得包含 Web 入侵过程的 pcap（HTTP 明文或可解密）。
- 存在一个执行命令的后门文件，且其写入/生成请求也在同一份流量中。
- 攻击者用 base64 传输二进制/加密 ZIP，密码在同会话流量中传递（或可从上下文推断）。

## 利用步骤

1. 过滤 `tcp contains "d00r.php"`，记录所有命中：后续 GET/POST 是命令执行，最早的一条 `POST ViewMore.php` 是后门生成。
2. 追踪 `ViewMore.php` 的 HTTP 流，读 `file_put_contents('d00r.php', base64_decode(...))`，确认生成者与被写入内容。
3. 追踪 `d00r.php` 的 POST 流，找 `cmd=system('ip a')` 等命令回显，记录内网 IP；找 `file_put_contents('k3y_f1le', base64_decode('...'))`。
4. 把 base64 解码结果保存为文件，用 `file`/WinHex 确认是 ZIP（`PK\x03\x04`）；在同一条 HTTP 流里找密码参数。
5. 解压 ZIP 得到攻击者写入的 key/flag（本例 key 为 UUID 形式）。

## PoC

```text
Wireshark 过滤器：
  tcp contains "d00r.php"

生成请求（示意）：
  POST /e/public/ViewClick/ViewMore.php HTTP/1.1
  a=file_put_contents('d00r.php', base64_decode('PD9waHAgZXZhbCg...'));

命令执行（示意）：
  POST /e/public/ViewClick/d00r.php HTTP/1.1
  cmd=system('ip a');
  # ens33 inet 192.168.162.130 / ens38 inet 192.168.101.132

写加密文件（示意）：
  POST /e/public/ViewClick/d00r.php HTTP/1.1
  cmd=file_put_contents('k3y_f1le', base64_decode('UEsDBBQAAAA...'));

# 解码后：
# file k3y_f1le -> Zip archive data, encrypted
# unzip -P <同流中的密码> k3y_f1le
```

## 变体与关联

- **后门生成方式**：`file_put_contents` 可换成 `fwrite`/`move_uploaded_file`/SQL `INTO OUTFILE`；用 `tcp contains "<后门名>"` 前推生成请求的方法通用。
- **编码层**：base64 可再叠加 gzip/zip/异或；先看 magic（`PK`、`1F 8B`、`MZ`）再决定解码路径。类似手法见 `[[ctf-forensics-antsword-rot13-reverse-encoder-traffic-decode]]`（蚁剑编码器）与 `[[defense-forensics-webshell-local-replay-eval-to-printf-traffic-decrypt]]`（本地重放解密）。
- **内网 IP**：`ip a`/`ifconfig`/`systeminfo` 回显是流量取证里最快的内网资产线索。
- 关联：`[[ctf-forensics-antsword-connection-key-request-param-attacker-marker]]`（同一 writeup 的蚁剑连接密钥/留存值）、`[[defense-forensics-chopper-aspx-webshell-base64-traffic-decode]]`（中国菜刀 base64 流量）。

## 检测与防御

- **检测**：HTTP 请求体中出现 `file_put_contents`、`base64_decode`、`$_POST[...]`、`eval`、`system`、`INTO OUTFILE` 组合；Web 目录出现新的 `.php` 文件（尤其体积异常或内容以 base64 形式传输）；同一 URI 先写入后立即被访问。
- **防御**：修复 ViewMore.php 等可控写入点；上传目录禁止 PHP 执行；Web 进程最小权限；对出站流量与内网横向做监测。
- **响应**：按流量时间线定位生成请求，删除后门与写入文件，检查同入口是否还有其他 `d00r*.php`，并轮换在流量中出现过的凭据。
