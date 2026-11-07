---
id: ctf-forensics-tls-keylog-pcap-decrypt
title: TLS keylog 解密 pcap：从流量中提取 SSLKEYLOGFILE 并导入 Wireshark 还原 HTTP
type: scenario
domain: ctf
path: ctf/forensics
technique: tls-keylog-pcap-decrypt
aliases:
- TLS keylog 解密
- SSLKEYLOGFILE
- (Pre)-Master-Secret log
- 5sLk3y.log
- Wireshark 解密 TLS
- pcap TLS 明文
tags:
- ctf
- forensics
- tls
- pcap
- wireshark
- sslkeylogfile
- traffic-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:33+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
---

## 一句话结论

TLS 本身不能被“破解”，但如果 pcap 里同时带出了会话密钥日志（SSLKEYLOGFILE，常见文件名如 `5sLk3y.log`），把该日志导入 Wireshark/tshark 的 `(Pre)-Master-Secret log` 选项，就能解密对应会话，把 TLS 流量还原成明文 HTTP，再按普通 HTTP 取证流程提取上传的 Base64 图片、二维码等内容。

## 原理

- **TLS 密钥日志格式**：浏览器/客户端在设置 `SSLKEYLOGFILE` 环境变量后，会把每个会话的密钥材料写到文本文件。TLS 1.2 常见行是 `CLIENT_RANDOM <client_random_hex> <master_secret_hex>`；TLS 1.3 则是 `CLIENT_HANDSHAKE_TRAFFIC_SECRET`、`SERVER_HANDSHAKE_TRAFFIC_SECRET`、`CLIENT_TRAFFIC_SECRET_0`、`SERVER_TRAFFIC_SECRET_0` 等，均带 `client_random`。
- **解密条件**：Wireshark 用 `client_random` 匹配会话，用日志中的密钥派生会话密钥；因此需要抓到完整握手（至少 ClientHello/ServerHello）和对应的密钥日志，且日志与会话属于同一连接。
- **导入方式**：Wireshark → 编辑 → 首选项 → Protocols → TLS → `(Pre)-Master-Secret log filename` 选择日志文件；或 tshark `-o tls.keylog_file:keylog.log`（旧版本为 `ssl.keylog_file`）。
- **为什么能还原 HTTP**：解密后 Wireshark 会把应用数据重新解析为 HTTP/2、HTTP/1.1 等；若原流量是 HTTPS 上传，过滤 `http` 即可看到请求行、Header 和 Body，和明文抓包一样。
- **密钥日志可能就在 pcap 里**：题目/实战中密钥日志可能通过 SMB/HTTP 传输，或被放在同一目录；先从 pcap 导出对象/跟踪 TCP 流，找到 `.log` 文件，再导入。
- **边界**：TLS 1.3 的早期数据（0-RTT）、会话恢复、QUIC 等需要额外密钥/支持；若抓包缺少握手或日志不匹配，解密失败；密钥日志本身是敏感材料，拿到即可解密历史流量。

## 触发条件

- 抓到 TLS 流量（HTTPS、SMTPS、自定义 TLS 等），且 pcap 中包含完整握手。
- 能获得对应会话的 SSLKEYLOGFILE/密钥日志（pcap 内传输、主机文件、备份、终端环境变量、浏览器配置等）。
- 密钥日志中的 `client_random` 与 pcap 会话匹配；时间/连接未被截断。
- Wireshark/tshark 版本支持 TLS 1.2/1.3 密钥日志（现代版本均支持）。
- 目标应用数据是 HTTP 或可被 Wireshark 识别的协议，便于后续提取。

## 利用步骤

1. 用 Wireshark 打开 pcap，先过滤 `tls`/`ssl` 确认有握手与应用数据；记录服务器 IP、端口、SNI。
2. 在 pcap 中找密钥日志：`File → Export Objects → HTTP/SMB`，或对可疑 TCP 流 `Follow → TCP Stream`，搜索 `CLIENT_RANDOM`、`CLIENT_HANDSHAKE_TRAFFIC_SECRET`、`SERVER_TRAFFIC_SECRET_0` 等关键字；也可 `binwalk`/`foremost` 分离。
3. 把密钥日志保存为 `.log` 文件（保持原始文本，不要改行）。
4. Wireshark 首选项 → Protocols → TLS → `(Pre)-Master-Secret log filename` 指向该文件；或 tshark 加 `-o tls.keylog_file:keylog.log`。
5. 重新过滤 `http`/`http2`，确认原本的 TLS 流量已解密；查看请求行、Header、Body。
6. 对上传内容做进一步处理：Base64 解码图片、解压 ZIP、QR 扫码、提取表单字段；按 HTTP 对象导出保存证据。
7. 若解密失败：核对 `client_random`、握手是否完整、日志是否属于该会话、Wireshark 版本与 TLS 1.3 密钥类型。

## PoC

```bash
# 1) 从 pcap 导出 HTTP 对象（可能包含 keylog 文件）
tshark -r capture.pcapng --export-objects http,exported

# 2) 或在流量中搜索 keylog 行
tshark -r capture.pcapng -Y 'tcp contains "CLIENT_RANDOM"' -T fields -e tcp.payload

# 3) 用 keylog 解密并只看 HTTP
tshark -r capture.pcapng -o tls.keylog_file:keylog.log -Y http \
  -T fields -e http.request.method -e http.request.uri -e http.file_data

# 4) Wireshark GUI：Preferences -> Protocols -> TLS
#    (Pre)-Master-Secret log filename = keylog.log
```

Base64 图片还原：

```python
import base64
body = open("upload.b64", "rb").read().strip()
open("upload.png", "wb").write(base64.b64decode(body))
```

然后用二维码/图片工具扫描；若上传体是 `data:image/png;base64,...`，先去掉前缀再解码。

## 变体与关联

- **RSA 私钥解密**：没有 keylog 但有服务器 RSA 私钥时，Wireshark 可解 TLS_RSA_* 套件；TLS 1.3/ECDHE 不适用。
- **会话恢复/0-RTT**：需要额外密钥或完整握手；0-RTT 数据可能无法解密。
- **QUIC/HTTP3**：使用 `tls.keylog_file` 同样可解 QUIC，但需 Wireshark 支持。
- **密钥日志来源**：浏览器 `SSLKEYLOGFILE`、curl `--keylogfile`、Java/Go 客户端自定义 keylog、恶意软件窃取的 keylog；取证时同时检查环境变量与用户目录。
- **关联卡片**：[[ctf-forensics-tls-rsa-cert-match-tshark-jwt-body-mismatch]]（RSA 私钥解密 TLS）；[[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]（RDP 证书解密 TLS 并还原输入）。

## 检测与防御

- **保护密钥日志**：SSLKEYLOGFILE 是“明文钥匙”，应按密钥材料管理；生产环境禁止开启，调试后立即删除/轮换。
- **终端检测**：监控 `SSLKEYLOGFILE` 环境变量、浏览器启动参数、异常 keylog 文件写入；恶意软件可能窃取该文件解密流量。
- **流量侧**：TLS 1.3、ECDHE、证书固定不能阻止持有 keylog 的本地攻击者；应结合端点防护与最小权限。
- **取证规范**：拿到 keylog 后先备份哈希，按敏感数据保管；解密结果可能包含口令、Cookie、个人信息，注意合规。
