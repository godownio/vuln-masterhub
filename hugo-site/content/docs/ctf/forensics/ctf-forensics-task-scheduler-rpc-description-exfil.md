---
id: ctf-forensics-task-scheduler-rpc-description-exfil
title: Task Scheduler RPC 流量提取计划任务：Description 字段承载 Base64 外带文件
type: scenario
domain: ctf
path: ctf/forensics
technique: task-scheduler-rpc-description-base64-exfil-extraction
tags:
- ctf
- forensics
- pcap
- wireshark
- dcerpc
- task-scheduler
- exfiltration
- base64
- ntlmssp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:26:33+08:00'
  notes: 已对照原文与图01-05核对：DCE/RPC auth3 NTLMSSP 用户 wire.com\kanna.seto、SchRpcRegisterTask/RetrieveTask opnum、DownloadByPs/DownloadByCom 把文件 Base64 写入 Description、1MB 限制、frame42/759 的 task XML 与 hint.zip 均与原文一致。PoC 未本机复跑；原文未标注组件版本。
url: /docs/ctf/forensics/ctf-forensics-task-scheduler-rpc-description-exfil/
draft: false
kb_aliases:
- SchRpcRegisterTask
- SchRpcRetrieveTask
- 计划任务 Description 外带
- DownloadByPs
- Task Scheduler RPC 取证
- task XML 提取
- NTLMSSP 解密 DCE/RPC
---

## 一句话结论

攻击者通过 Task Scheduler RPC 注册计划任务，把目标文件字节 Base64 后写进任务的 `Description` 字段；防守方在 pcap 中用 NTLMSSP 口令解密 DCE/RPC，提取 `SchRpcRegisterTask`/`SchRpcRetrieveTask` 的 decrypted stub，按 UTF-16LE 解析任务 XML，再 Base64 解码 `Description`，即可还原被外带的文件。

## 原理

- **Task Scheduler RPC 接口**：Windows 通过 `Taskschd` 服务的 DCE/RPC 接口远程管理计划任务，常见 opnum 为 `SchRpcRegisterTask`(1，创建/覆盖任务)、`SchRpcRetrieveTask`(2，取回任务 XML)、`SchRpcDelete`(13)、`SchRpcRename`(14)、`SchRpcEnableTask`(19)。注册和取回请求都携带完整的任务 XML。
- **Description 是可控字符串**：任务 XML 的 `RegistrationInfo/Description` 可以存放任意文本；攻击者的 PowerShell 脚本（如 `DownloadByPs`）读取目标文件字节、Base64 编码后写入 `$task.Description`，再用 `Set-ScheduledTask` 保存；另一个变体 `DownloadByCom` 写入 `$definition.RegistrationInfo.Description` 后调用 `RegisterTaskDefinition`。文件超过约 1 MB 时脚本会返回 “File is too large”，即单任务 Description 可承载约 1 MB 数据。
- **取回与还原**：客户端随后调用 `SchRpcRetrieveTask` 取回任务 XML，从 `Description` 取 Base64 字符串解码即可得到原始文件。整个过程不依赖文件共享或 HTTP，数据藏在合法的计划任务元数据里。
- **流量解密**：RPC bind 的 auth3 使用 NTLMSSP 时，只要知道账户口令（可从同一 pcap 的 NetNTLMv2 破解，或直接配置 `ntlmssp.nt_password`），Wireshark 就能解密 `dcerpc.decrypted_stub_data`；`tshark` 导出该字段后用 `xxd -r -p` 还原二进制，再按 UTF-16LE 解码得到 XML。
- **为什么可取证**：任务 XML 以明文 UTF-16LE 存在于 RPC stub 中（在认证/加密层被解开后），`Description` 的 Base64 内容具有明显特征（长串 `A-Za-z0-9+/=`），便于从流量中定位。

## 触发条件

- pcap 中存在 Task Scheduler Service 的 DCE/RPC 流量（bind 上下文为 `TaskSchedulerService V1.0`）。
- RPC 使用 NTLMSSP 认证，且攻击者/取证者知道对应账户口令，或能从同一 pcap 的 NetNTLMv2 响应离线破解出口令。
- 任务 XML 的 `Description` 含 Base64 数据；若数据还被 AES 等二次加密，需要额外的密钥（见关联卡片）。
- 抓包覆盖了 `SchRpcRegisterTask` 或 `SchRpcRetrieveTask` 的完整请求。

## 利用步骤

1. 在 Wireshark 中过滤 `dcerpc`，找到 `Bind: call_id` 与 `Auth3`，确认 NTLMSSP 用户（如 `DOMAIN\user`）。
2. 从同一 pcap 提取 NetNTLMv2 响应并离线破解，或直接把已知口令配置到 Wireshark：`Preferences → Protocols → NTLMSSP → NT Password`。
3. 定位 `SchRpcRegisterTask`(opnum 1) 或 `SchRpcRetrieveTask`(opnum 2) 的请求/响应，确认 `dcerpc.decrypted_stub_data` 已可读。
4. 用 `tshark` 导出指定帧的 stub 并还原为二进制，按 UTF-16LE 解码，截取 `<Task>...</Task>` XML。
5. 从 XML 中取 `<Description>` 文本，Base64 解码得到外带文件；若内容仍是密文，按任务中的加密逻辑继续解密。

## PoC

```bash
# 1) 用已知口令解密 NTLMSSP，并导出指定帧的 RPC stub
tshark -o "ntlmssp.nt_password:<password>" -r capture.pcapng \
  -Y "frame.number==42" -T fields -e dcerpc.decrypted_stub_data | xxd -r -p > stub.bin

# 2) 按 UTF-16LE 查看任务 XML
iconv -f UTF-16LE -t UTF-8 stub.bin | sed -n 's:.*<Description>\(.*\)</Description>.*:\1:p'
```

```powershell
# 攻击侧写入 Description 的核心逻辑（示意）
$bytes = Get-Content -Path $target_file -Encoding Byte
$b64   = [Convert]::ToBase64String($bytes)
$task  = Get-ScheduledTask -TaskName $taskname
$task.Description = $b64
Set-ScheduledTask $task
```

```text
# 取证侧：Description 是一段长 Base64，解码后即为文件字节
# 若任务 XML 中 Description 为空但 URI 异常，也要检查 URI/任务名等其它可控字段
```

## 变体与关联

- 存储字段变体：除 `Description` 外，任务名、`URI`、`Author`、`RegistrationInfo` 其它文本字段也可能被用作低带宽数据通道。
- 加密变体：Description 可先 AES-CBC 加密再 Base64，外层 Base64 解码后前 16 字节为 IV；需要密钥才能还原。
- 认证变体：RPC 也可用 Kerberos Packet Privacy 保护，此时 Wireshark 需要 keytab 和 subkey，见 [[ctf-forensics-kerberos-dcerpc-packet-privacy-subkey-decrypt]]。
- 关联：[[pentest-persistence-windows-task-com-handler]]（计划任务 COM handler 持久化）、[[pentest-persistence-signed-gpu-masquerade-hidden-scheduled-task-system]]（隐藏计划任务）；本卡侧重流量取证与 Description 数据通道。

## 检测与防御

- 检测：Task Scheduler RPC 中出现超长 `Description`（尤其 Base64 字符集）、任务 XML 的 `Description` 与任务用途明显不符、短时间大量 `SchRpcRegisterTask`/`SchRpcRetrieveTask` 调用。
- 检测：同一账户的 NTLMSSP 认证后紧跟计划任务 RPC；任务创建者与任务名/路径不匹配；任务 XML 含可疑 PowerShell 或下载逻辑。
- 防御：限制普通用户远程调用 Task Scheduler RPC（防火墙/服务权限）；对计划任务创建与修改做审计（事件 4698/4702 及 Taskschd 操作日志）；EDR 监控 `Set-ScheduledTask`、`RegisterTaskDefinition` 与异常 Description 写入。
- 加固：任务描述字段长度/字符集限制；敏感主机禁止 NTLM，改用 Kerberos 并保护 keytab；定期清理无用计划任务。
