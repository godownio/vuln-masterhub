---
id: defense-forensics-winrm-ntlm-traffic-decrypt-soap-command
title: WinRM 流量解密与命令还原：明文口令解 NTLM 会话，提取 SOAP stdout Base64
type: scenario
domain: defense
path: defense/forensics
technique: winrm-ntlm-traffic-decrypt-soap-command
tags:
- forensics
- traffic-analysis
- winrm
- ntlm
- soap
- lateral-movement
- incident-response
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:23:24+08:00'
  notes: 已对照原文与图06/07/08核对：5985 WinRM、/wsman POST、NTLMSSP NEGOTIATE/CHALLENGE/AUTH、decrypt-winrm 解出 rsp:Stream Name="stdout" Base64、解码后 Mimikatz 输出与 NTLM 3d83254b... 均与原文一致；PoC 未本机复跑；原文未标注组件版本。
url: /docs/defense/forensics/defense-forensics-winrm-ntlm-traffic-decrypt-soap-command/
draft: false
kb_aliases:
- WinRM 流量解密
- decrypt-winrm
- WinRM SOAP 命令还原
- 5985 NTLM 解密
- rsp:Stream stdout Base64
---

## 一句话结论

WinRM over HTTP（5985）外层是 HTTP、内部是 SOAP，认证使用 NTLM/SPNEGO，认证后的 WSMan 消息用 NTLM 会话密钥加密；只要掌握该账号的明文口令（或 NT Hash），用 decrypt-winrm 重新推导会话密钥即可解密流量，解出 `rsp:Stream Name="stdout"` 里的 Base64 分片并拼接，还原攻击者执行的命令与输出。

## 原理

- WinRM over HTTP 的请求路径通常是 `/wsman`，HTTP 层承载 `NTLMSSP_NEGOTIATE` → `NTLMSSP_CHALLENGE` → `NTLMSSP_AUTH` 的 Negotiate 认证；认证完成后，WSMan SOAP 消息体在 SPNEGO/NTLM 会话密钥保护下传输（Wireshark 中表现为加密的 WSMan 负载或无法直接解析的二进制）。
- NTLM 会话密钥由用户口令派生的 NT Hash、ServerChallenge 与 NTProofStr 计算得到；知道明文口令即可离线重建该密钥，从而解密双向的 WSMan 消息。
- 解密后的 SOAP 中，命令输出以 `<rsp:Stream Name="stdout" CommandId="...">` 分片返回，内容是 Base64；按顺序解码并拼接即得到完整 stdout。`dir`、`mimikatz` 等命令及其结果都能还原。
- 为什么可行：WinRM 的加密只保护传输层消息，不改变 NTLM 认证握手中已暴露的挑战/响应；凭据一旦泄露，历史流量即可被解密。工具 `decrypt-winrm` 封装了密钥推导与消息解密。
- 若 WinRM 走 HTTPS（5986），还需要 TLS 私钥/会话密钥；若使用 Kerberos 认证，则需要 Kerberos 会话密钥，不能用明文口令直接解。

## 触发条件

- pcap 中包含 5985 端口的 WinRM 流量，且有完整的 NTLMSSP 认证（NEGOTIATE/CHALLENGE/AUTH）。
- 掌握该账号的明文口令或 NT Hash；或能从其他证据（如 NetNTLMv2 破解、Mimikatz）取得。
- 工具支持对应的 WinRM/WSMan 加密方式（NTLM）；HTTP 未做额外应用层封装。
- 攻击者通过 WinRM 执行过命令且输出被返回。

## 利用步骤

1. Wireshark 过滤 `tcp.port == 5985` 或 `http`，确认存在 `/wsman` POST 与 NTLMSSP 认证序列。
2. 导出该会话的 pcap（或直接使用原始包），记录用户名/域名。
3. 用已知明文口令运行解密工具：
   ```bash
   python winrm_decrypt_fixed.py 1-pth.pcapng -p '<password>'
   ```
4. 在输出中查找解密后的 SOAP `rsp:Stream Name="stdout"` 节点；提取其 Base64 文本。
5. 按 `CommandId` 分组、按顺序 Base64 解码并拼接，得到命令输出；结合 `dir`、`whoami`、`mimikatz` 等关键字还原攻击者行为。
6. 若输出被分片或压缩，先拼接再解码；若有多条命令，按 CommandId/时间排序。

## PoC

```bash
# 1) 解密 WinRM 流量（明文口令）
python winrm_decrypt_fixed.py 1-pth.pcapng -p 'pass@word1'

# 2) 从解密结果中提取 stdout Base64 并解码
python - <<'PY'
import base64, re
text = open("decrypted.xml", encoding="utf-8", errors="ignore").read()
chunks = re.findall(r'<rsp:Stream Name="stdout"[^>]*>([^<]+)</rsp:Stream>', text)
print(base64.b64decode("".join(chunks)).decode("utf-8", "replace"))
PY
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权取证与应急响应。

## 变体与关联

- 变体（NT Hash）：没有明文口令时，可用 NT Hash 代替口令参与 NTLM 会话密钥推导；具体参数看工具支持。
- 变体（HTTPS 5986）：需要服务器 TLS 私钥或 SSLKEYLOGFILE；先解 TLS，再按 WSMan 层处理。
- 变体（Kerberos）：WinRM 使用 Kerberos 时需从 ccache/keytab 或流量中的 Kerberos 会话密钥解密。
- 关联：[[defense-forensics-smb3-session-key-wireshark-decrypt]]（同套 NTLM 凭据解 SMB3）；[[pentest-ad-ntlmv2-smb-pcap-hashcat-crack]]（前置：从 SMB 流量破解口令）；[[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]（同一攻击链的 RDP 阶段）。
- 边界：WinRM 使用证书认证、HTTPS 且无私钥、Kerberos 且无会话密钥、或流量中缺少完整 NTLM 握手时，本方法不成立。

## 检测与防御

- 检测：5985/5986 端口出现 `/wsman` POST、NTLMSSP 认证后紧跟加密 WSMan 消息；同一账号在异常时间/来源使用 WinRM；解密后出现 `mimikatz`、`cmd.exe`、`powershell`、`net user` 等命令。
- 防御：限制 WinRM 仅允许受信任管理主机访问，普通终端之间不开放 5985/5986；启用 WinRM 日志与 PowerShell 转录；对高权限账号启用 Credential Guard/Protected Users。
- 加固：优先使用 Kerberos 与 HTTPS，并保护证书私钥；监控 WinRM 服务端 `Microsoft-Windows-WinRM/Operational` 日志；限制 pcap 访问权限。
