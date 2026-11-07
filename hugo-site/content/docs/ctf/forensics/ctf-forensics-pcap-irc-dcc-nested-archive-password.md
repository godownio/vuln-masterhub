---
id: ctf-forensics-pcap-irc-dcc-nested-archive-password
title: PCAP 中 IRC DCC 传输加密 7z：Base64 口令 + 嵌套 pcap 追踪 TCP 流
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-irc-dcc-nested-archive-password
tags:
- ctf
- forensics
- pcap
- irc
- dcc
- base64
- 7z
- nested-pcap
- traffic-analysis
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/ctf/forensics/ctf-forensics-pcap-irc-dcc-nested-archive-password/
draft: false
kb_aliases:
- IRC DCC SEND
- pcap 压缩包密码
- Base64 口令
- 嵌套 pcap
- tshark irc
- CTF 流量取证
---

## 一句话结论

当 pcap 里同时出现 IRC 与 COTP/HTTP 等多种协议时，先做协议分层统计，再单独提取 IRC 会话：`PRIVMSG` 中往往带 Base64 口令，`DCC SEND` 给出文件名、十进制 IP、端口和字节数；按端口/流导出 DCC 传输的加密 7z，用解出的口令解压，里面还有一层 pcap，继续追踪 TCP 流即可得到最终内容。

## 原理

- **IRC DCC 是带外文件传输**：DCC SEND 消息格式为 `DCC SEND <filename> <ip_decimal> <port> <size>`，文件名和 IP/端口/大小都在 IRC 消息里；真正的文件数据走一条独立的 TCP 连接，因此只看 IRC 协议字段看不到文件内容，需要按端口或流号导出。
- **口令藏在聊天消息里**：对端常用 `PRIVMSG` 发一句“password on it”，随后跟一个 Base64 字符串；Base64 解码即压缩包密码。题目不会把明文密码直接放在聊天里，但编码方式通常很弱。
- **协议分层统计缩小范围**：`tshark -z io,phs` 列出各协议帧数/字节数；HTTP、TLS、IRC、COTP、SMB 混杂时，先判断哪个协议承载了文件或口令，再针对性过滤。
- **嵌套 pcap**：解压后的 7z 里可能不是最终答案，而是第二层 pcap；二层流量通常很小，直接 `Follow TCP Stream` 就能看到明文 flag/命令输出。
- **为什么成立**：网络取证的本质是“按协议字段切片 + 重组”；DCC 把控制信息（文件名/端口）和数据通道分离，正好给出可编程的提取锚点；Base64 只是编码，不提供任何机密性。

## 触发条件

- 拿到包含 IRC 流量的 pcap/pcapng，且存在 DCC SEND 或其它带外传输。
- 聊天消息中出现 Base64/十六进制字符串或“password”提示。
- DCC 传输的是压缩包（7z/zip/rar），且压缩包有密码。
- 解压后得到嵌套 pcap 或其它容器，需要继续分析。

## 利用步骤

1. 看协议分层：`tshark -r capture.pcapng -q -z io,phs`，确认 IRC、COTP、HTTP、TLS 等分布。
2. 提取 IRC 请求/响应：`tshark -r capture.pcapng -Y "irc" -T fields -e irc.request -e irc.response`。
3. 在输出中找 `PRIVMSG` 的 Base64 字符串，解码得到压缩包口令；同时记录 `DCC SEND` 的文件名、IP、端口、大小。
4. 按端口定位数据流：`tshark -r capture.pcapng -Y "tcp.port==<port>" -T fields -e tcp.stream`，再用 `-z follow,tcp,raw,<stream>` 或 Wireshark 的 Follow TCP Stream 导出原始字节。
5. 把导出的字节按 DCC 的 size 截断，保存为 7z/zip；用第 3 步口令解压。
6. 若解压出嵌套 pcap，重复“协议统计 → 过滤 → Follow TCP Stream”；二层流量通常直接暴露 flag。
7. 交叉验证文件头（`7z` 为 `37 7A BC AF 27 1C`，pcap 为 `D4 C3 B2 A1`/`A1 B2 C3 D4`）和大小，避免把 TCP 重传/填充算进文件。

## PoC

```bash
# 1) 协议分层
tshark -r capture.pcapng -q -z io,phs

# 2) IRC 消息（找 Base64 口令与 DCC SEND）
tshark -r capture.pcapng -Y "irc" -T fields -e irc.request -e irc.response

# 3) 按 DCC 端口导出原始 TCP 载荷
tshark -r capture.pcapng -Y "tcp.port==35289" -T fields -e tcp.payload \
  | tr -d ':' | xxd -r -p > Flag.7z

# 4) Base64 解码口令（示例）
python -c "import base64; print(base64.b64decode('TWFyaW9SdWxlejE5ODU=').decode())"

# 5) 解压并继续分析嵌套 pcap
7z x Flag.7z -p<password>
tshark -r 1.pcapng -q -z io,phs
```

说明：DCC 的端口/流号以实际抓包为准；若 TCP 载荷含重传，按 DCC 声明的 size 截断并去重。

## 变体与关联

- 变体：DCC 换成 HTTP 下载、FTP、SMB 或 SMB2 命名管道；控制信息可能在邮件、HTTP 头或另一条 TCP 流中。
- 变体：口令用 Base32/ROT13/十六进制编码，或放在文件名、IRC 主题、WHOIS 字段里。
- 变体：压缩包使用 ZipCrypto/AES 真加密，需要已知明文攻击或爆破；本卡只适用于口令泄露。
- 关联：[[ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb]]（另一种 pcap 口令 + AES ZIP 链）；[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（从 pcap 中恢复密钥）；[[ctf-forensics-pcap-shell-history-base64-nc-image-exfil]]（pcap 中还原外传数据）。

## 检测与防御

- 检测：企业网络中出现 IRC 出站、DCC SEND、非标准高位端口的大流量 TCP；IRC 消息含长 Base64 串。
- 检测：DCC 传输的文件头与扩展名不一致（如 `.7z` 实际为 PE/脚本）；压缩包在终端落地后很快被解压执行。
- 防御：默认阻断 IRC/DCC 出站；对文件传输做内容检测与沙箱；禁止终端从聊天工具接收并执行压缩包。
- 防御：邮件/IM 网关对 Base64 长串和“password”上下文做告警；对解压后的嵌套容器继续扫描，而不是只看第一层。
