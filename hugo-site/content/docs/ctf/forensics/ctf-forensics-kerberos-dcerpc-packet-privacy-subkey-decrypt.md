---
id: ctf-forensics-kerberos-dcerpc-packet-privacy-subkey-decrypt
title: Kerberos keytab + GSSAPI subkey 手动解密 DCE/RPC Packet Privacy 分片，提取计划任务 XML
type: scenario
domain: ctf
path: ctf/forensics
technique: kerberos-dcerpc-packet-privacy-subkey-fragment-reassembly
tags:
- ctf
- forensics
- pcap
- kerberos
- dcerpc
- gssapi
- subkey
- fragment-reassembly
- wireshark
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:26:36+08:00'
  notes: 已对照原文与图06-09/15核对：keytab 生成/导入、AP-REP 学到的 subkey 6c729591...、tcp.stream=5 分片重组、GSSWrapToken RRC/EC、AES256-CTS INITIATOR_SEAL、去 EC+16、UTF-16LE task XML 均与原文脚本一致。PoC 未本机复跑；原文未标注组件版本。
url: /docs/ctf/forensics/ctf-forensics-kerberos-dcerpc-packet-privacy-subkey-decrypt/
draft: false
kb_aliases:
- kerberos.file keytab
- encAPRepPart_subkey
- GSSWrapToken
- DCE/RPC 分片重组
- Packet Privacy
- SchRpcRegisterTask 大包解密
- AES256-CTS RPC 解密
---

## 一句话结论

当 DCE/RPC 使用 Kerberos Packet Privacy 且请求跨大量 TCP 分片时，Wireshark 往往无法自动重组解密；用 keytab 让 Wireshark 学习 `encAPRepPart_subkey`，再按 TCP seq 重组 payload、解析 DCE/RPC PDU、用该 subkey 解开 GSSAPI wrap token，即可还原任务 XML 与被外带的数据。

## 原理

- **keytab 解密 Kerberos**：keytab 由账户口令（或 AES key）生成，包含 `principal@REALM` 的长期密钥。Wireshark 配置 `kerberos.file` 指向 keytab 后，能解密 AS-REP/TGS-REP，并从 AP-REP 的 `encAPRepPart` 中学习会话 subkey（keytype 18 对应 AES256-CTS-HMAC-SHA1-96）。
- **DCE/RPC Packet Privacy**：RPC PDU 的 stub 被 GSSAPI/Kerberos 封装，PDU 头包含 `frag_len`、`auth_len`、`call_id`、`flags`；尾部是 GSS wrap token，包含 `RRC`（右旋字节数）与 `EC`（加密填充长度）。解密时先把 auth 部分与加密 stub 拼接、按 `RRC+EC` 反向旋转，再用 subkey 以 `INITIATOR_SEAL` key usage 做 AES256-CTS 解密，最后去掉 `EC+16` 字节。
- **分片重组**：大请求（如带完整任务 XML 的 `SchRpcRegisterTask`）被拆成多个 TCP 段，Wireshark 的 DCE/RPC 重组/解密可能只处理单帧而失败。需要按 `tcp.seq` 排序并拼接 payload，再从流中找到 PDU 起始魔数（如 `05 00 00 01 10 00 00 00 ...`），逐段解析直到 `flags & 0x02`（最后分片）。
- **为什么 keytab 足够**：Kerberos 的会话 subkey 由 AP-REQ/AP-REP 协商，keytab 提供长期密钥后 Wireshark 能推导出 subkey；拿到 subkey 就能离线解开所有同会话的 Packet Privacy stub，不需要目标主机在线。
- **数据位置**：解出的 stub 是 UTF-16LE 的任务 XML，`<Description>` 中通常是 Base64 外带数据；再按外层的加密逻辑（如 AES-CBC + Base64）还原文件。

## 触发条件

- pcap 中存在 Kerberos 认证的 DCE/RPC 流量，且启用了 Packet Privacy（auth_len > 0、GSS wrap token）。
- 能获得目标账户的 keytab（由口令、AES key 或 hash 生成），或已知长期密钥。
- 关键请求跨多个 TCP 分片，Wireshark 自动解密/重组失败或只显示部分 stub。
- 有 `tshark` 与 Python（`minikerberos`、`impacket`、`pycryptodome` 等）环境。

## 利用步骤

1. 用已知口令/密钥生成 keytab（`ktutil`、`Create-KeyTab.ps1` 或 impacket 工具），确认 principal 与 realm 正确。
2. 在 Wireshark 配置 `kerberos.file: <keytab>`、`kerberos.decrypt: TRUE`；找到 AP-REP，记录 `Learnt encAPRepPart_subkey keytype 18` 的 keyvalue。
3. 用 `tshark` 按 `tcp.stream`、源 IP、帧范围导出 `frame.number`、`tcp.seq`、`tcp.payload`。
4. 按 seq 排序并重组为连续字节流；从流中定位 DCE/RPC PDU 起始，循环读取 `frag_len`、`auth_len`、`call_id`、`flags`，提取加密 stub 与 auth trailer。
5. 用 subkey 解开每个分片的 GSS wrap token，拼接明文 stub；按 UTF-16LE 解码，截取 `<Task>...</Task>` XML。
6. 从 XML 取 `<Description>`，Base64 解码；若仍是密文，按任务中的 AES-CBC 逻辑（外层 Base64、前 16 字节 IV、固定 key）继续解密。

## PoC

```python
import subprocess, re
from pathlib import Path
from minikerberos.protocol.encryption import Key, Enctype, _AES256CTS
from minikerberos.gssapi.gssapi import GSSWrapToken, GSSAPI_AES, KG_USAGE

pcap = "capture.pcapng"
subkey_hex = "<从 AP-REP 学到的 subkey>"
key = Key(Enctype.AES256, bytes.fromhex(subkey_hex))
gss = GSSAPI_AES(key, _AES256CTS, None)

out = subprocess.check_output([
    "tshark", "-r", pcap,
    "-Y", "tcp.stream==5 && ip.src==192.168.1.10 && tcp.len>0 && frame.number>=881 && frame.number<=2572",
    "-T", "fields", "-e", "frame.number", "-e", "tcp.seq", "-e", "tcp.payload",
], text=True, encoding="utf-8")

segments = []
for line in out.strip().splitlines():
    parts = line.split("\t")
    if len(parts) < 3 or not parts[2]:
        continue
    segments.append((int(parts[1]), bytes.fromhex(parts[2].replace(":", ""))))
segments.sort()

stream = bytearray()
base_seq = segments[0][0]
for seq, data in segments:
    off = seq - base_seq
    if off + len(data) <= len(stream):
        continue
    if off < len(stream):
        data = data[len(stream) - off:]
        off = len(stream)
    stream.extend(data)
s = bytes(stream)

start = s.find(bytes.fromhex("05000001100000009c10440002000000"))
parts, pos = [], start
while pos + 24 <= len(s):
    frag_len = int.from_bytes(s[pos + 8:pos + 10], "little")
    auth_len = int.from_bytes(s[pos + 10:pos + 12], "little")
    call_id = int.from_bytes(s[pos + 12:pos + 16], "little")
    flags = s[pos + 3]
    if call_id != 2:
        break
    frag = s[pos:pos + frag_len]
    stub_len = frag_len - 24 - 8 - auth_len
    enc_stub = frag[24:24 + stub_len]
    auth = frag[24 + stub_len + 8:24 + stub_len + 8 + auth_len]

    t = GSSWrapToken.from_bytes(auth)
    rotated = auth[16:] + enc_stub
    cipher = gss.unrotate(rotated, t.RRC + t.EC)
    plain = _AES256CTS().decrypt(key, KG_USAGE.INITIATOR_SEAL.value, cipher)
    parts.append(plain[:-(t.EC + 16)])

    pos += frag_len
    if flags & 0x02:
        break

full = b"".join(parts)
idx = full.find(b"<\x00T\x00a\x00s\x00k\x00")
xml = full[idx:].decode("utf-16le", errors="ignore")
xml = xml[:xml.find("</Task>") + 7]
print(re.search(r"<Description>(.*?)</Description>", xml, re.S).group(1))
```

```text
# 解出的 Description 若为 Base64，解码即得外带文件；
# 若为 AES-CBC 密文：外层 Base64 → 前 16 字节 IV → AES-CBC 解密 → 再 Base64 解码。
```

## 变体与关联

- 认证变体：NTLMSSP 保护的 RPC 可直接用 `ntlmssp.nt_password` 解密，见 [[ctf-forensics-task-scheduler-rpc-description-exfil]]。
- 加密类型变体：AES128-CTS（etype 17）、RC4-HMAC（etype 23）的 key usage 与解密函数不同；按 AP-REP 的 keytype 选择实现。
- 重组变体：Wireshark 能自动重组时可直接导出 `dcerpc.decrypted_stub_data`；只有大包/跨多段时才需要手工脚本。
- 关联：[[pentest-ad-kerberos-asrep-etype18-pcap-crack]]（从 pcap 破解 Kerberos 凭据）、[[ctf-forensics-task-scheduler-rpc-description-exfil]]（任务 Description 数据通道）。

## 检测与防御

- 检测：Kerberos 认证后的 DCE/RPC Packet Privacy 流量中出现超大 `SchRpcRegisterTask` 请求；同一会话中 AP-REP 后紧跟大量分片 RPC；任务 XML 的 Description 为长 Base64。
- 防御：限制 Task Scheduler RPC 的远程访问；使用 Kerberos AES 并保护 keytab（keytab 等同于账户长期密钥，泄露后可离线解密全部会话）；对计划任务创建/修改做审计与告警。
- 加固：keytab 文件权限最小化、定期轮换账户口令；敏感主机禁用 NTLM；监控异常任务 Description 与任务 XML 内容。
