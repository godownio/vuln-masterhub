---
id: defense-forensics-smb3-session-key-wireshark-decrypt
title: SMB3 加密流量解密：NTLM Hash + NTProofStr + Encrypted Session Key 推导 Random Session Key
type: scenario
domain: defense
path: defense/forensics
technique: smb3-random-session-key-wireshark-decrypt
aliases:
- SMB3 流量解密
- Encrypted SMB3 还原
- Random Session Key 计算
- SMB3 Session Key
- NTLM 会话密钥推导
tags:
- forensics
- traffic-analysis
- smb
- smb3
- ntlm
- session-key
- wireshark
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:23:22+08:00'
  notes: 已对照原文与图09/10/11/13核对：NTLM Hash 3d83254b...、NTProofStr 4103e8d84572fa74f220ecc20be704c1、Encrypted Session Key 7433d4ac87cdff2d38b2e8a5840b919d、Session ID 5500000000480000、Session Key 3252507a61756f507132585748475953、解密后 svcctl/CreateServiceW 均与原文一致。已修正 PoC 中 tshark 过滤：smb2.cmd==0x0e 实为 QUERY_DIRECTORY，不是 svcctl，改为 dcerpc。PoC 未本机复跑；原文未标注组件版本。
---

## 一句话结论

SMB3 会话加密后 Wireshark 只显示 `Encrypted SMB3`，但只要抓包里有完整的 NTLMSSP 认证，并且拿到该用户的 NTLM Hash，就能用 `NTProofStr` 与 `Encrypted Session Key` 推导出 Random Session Key；把 Session ID 和 Session Key 填入 Wireshark 的 SMB2 解密配置，即可还原加密的文件操作、svcctl 远程服务调用等攻击行为。

## 原理

- SMB3 在 SMB2 基础上增加会话级加密；加密后 SMB2 头的 `Flags` 标记加密，Wireshark 显示 `Encrypted SMB3`，后续命令、路径、参数都不可见。
- SMB3 的加密/签名密钥由 NTLM 会话密钥经 SP800-108 KDF 派生，而 NTLM 会话密钥可从认证流量与用户 NT Hash 还原：
  - `ResponseKeyNT = HMAC_MD5(NT_Hash, UTF-16LE(uppercase(username) + domain))`
  - `SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)`
  - `RandomSessionKey = RC4(SessionBaseKey, EncryptedSessionKey)`（协商了 key exchange 时；否则会话密钥直接来自认证）
- 其中 `NTProofStr` 与 `Encrypted Session Key` 都在 `NTLMSSP_AUTH` 消息里，`NT_Hash` 可从 Mimikatz/secretsdump 获得，或由明文口令计算 `MD4(UTF-16LE(password))`。
- Wireshark 的 SMB2 协议首选项接受 `Session ID` + `Session Key`（Random Session Key），内部再按 SMB3 规范派生加密/签名密钥，从而解密该会话。Session ID 不是算出来的，而是从 SMB2 Session Setup Response 中读取。
- 为什么可行：SMB3 加密保护的是传输内容，不改变 NTLM 认证握手中已暴露的挑战/响应；一旦 NT Hash 泄露，会话密钥就可离线重建，加密不再提供保密性。

## 触发条件

- pcap 中包含 SMB2/SMB3 协商、NTLMSSP_CHALLENGE/AUTH，以及后续 Encrypted SMB3 流量。
- 能获得该用户的 NTLM Hash（Mimikatz、secretsdump、SAM/NTDS 导出）或明文口令。
- 知道对应会话的 Session ID；抓包中 Session Setup Response 可见。
- Wireshark 版本支持 SMB2 解密配置；若使用 Kerberos 认证，则需要 Kerberos 会话密钥而非 NTLM Hash。

## 利用步骤

1. Wireshark 过滤 `smb2`，找到 `Session Setup Request, NTLMSSP_AUTH`；记录用户名、域名。
2. 在 CHALLENGE 包记录 `NTLM Server Challenge`；在 AUTH 包记录 `NTProofStr`、`Encrypted Session Key`（Wireshark 字段通常为 `ntlmssp.ntlmsesskey` / `ntlmssp.auth.ntresponse` 相关）。
3. 取得该用户的 NTLM Hash（如 Mimikatz `sekurlsa::logonpasswords` 输出中的 `NTLM` 字段）。
4. 用工具计算 Random Session Key，例如：
   ```bash
   python randomSessionKeyNTLM.py -u administrator --domain= \
     -n <NTLM_Hash> -p <NTProofStr> -k <EncryptedSessionKey>
   ```
5. 从 Session Setup Response 读取 `Session ID`（如 `5500000000480000`）。
6. Wireshark → 编辑 → 首选项 → Protocols → SMB2 → 新增一行 `Session ID` + `Session Key`；确定后原本的 `Encrypted SMB3` 会变成 `Decrypted SMB3`。
7. 过滤 `smb2.filename`、`svcctl`、`dcerpc` 等，查看攻击者的 Tree Connect、文件读写、服务创建命令。

## PoC

```bash
# 1) 计算 Random Session Key（参数来自 NTLMSSP_AUTH）
python randomSessionKeyNTLM.py -u administrator --domain= \
  -n 3d83254b53697355ef7498b535e7ab29 \
  -p 4103e8d84572fa74f220ecc20be704c1 \
  -k 7433d4ac87cdff2d38b2e8a5840b919d

# 2) Wireshark SMB2 解密配置示例
# Session ID : 5500000000480000
# Session Key: 3252507a61756f507132585748475953

# 3) 验证：过滤解密后的 svcctl / CreateServiceW（DCE/RPC over SMB2）
tshark -r 1.pcapng -Y "dcerpc" -V
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权取证与应急响应。

## 变体与关联

- 变体（明文口令）：先算 `NT_Hash = MD4(UTF-16LE(password))`，再走同一流程；原文先用 NetNTLMv2 破解得到口令，再用 Mimikatz 得到 Hash。
- 变体（Kerberos）：SMB3 使用 Kerberos 时需从 ccache/keytab 或流量中的 Kerberos 会话密钥推导，不能直接用 NTLM Hash。
- 变体（仅签名）：若会话只启用 SMB 签名未加密，则内容本就可见，无需解密。
- 关联：[[pentest-ad-ntlmv2-smb-pcap-hashcat-crack]]（前置：从 SMB 流量破解口令）；[[defense-forensics-winrm-ntlm-traffic-decrypt-soap-command]]（同套 NTLM 凭据解 WinRM）；[[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]（解密后从 SMB 导出 RDP 证书）；[[pentest-ad-lsass-minidump-pypykatz-offline]]（获取 NTLM Hash 的另一路径）。
- 边界：缺少 NTProofStr/Encrypted Session Key、没有 NT Hash、Session ID 不匹配、SMB3 使用 Kerberos 或 QUIC 传输时，本方法不成立或需换材料。

## 检测与防御

- 检测：SMB 流量中出现 NTLMSSP_AUTH 后紧跟大量 Encrypted SMB3；同一账号在异常时间/来源进行 SMB 会话；解密后出现 `svcctl`、`CreateServiceW`、`net user`、`IPC$` 等横向移动特征。
- 防御：优先使用 Kerberos 并禁用 NTLM；启用 SMB 签名与加密；保护 NT Hash（Credential Guard、LSASS 保护、限制管理员登录普通终端）。
- 加固：限制 pcap/流量镜像的访问权限；高权限账号使用托管服务账户/长随机口令；定期轮换可能已泄露的凭据；对 SMB 服务创建行为做审计告警。
