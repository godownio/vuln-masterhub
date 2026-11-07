---
id: ctf-forensics-windows-sam-system-offline-ntlm-mask-crack
title: Windows 镜像离线 SAM/SYSTEM 蜂巢提取 NTLM 并掩码爆破：6 位纯数字口令秒破
type: scenario
domain: ctf
path: ctf/forensics
technique: offline-sam-ntlm-mask-crack
aliases:
- mimikatz lsadump::sam
- SAM SYSTEM 离线提取
- hashcat -m 1000
- NTLM 掩码爆破
- 数字口令爆破
tags:
- ctf
- forensics
- windows
- sam
- system
- ntlm
- hashcat
- mimikatz
- credential-access
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:53:17+08:00'
  notes: 已对照原文与图片 04 核对；mimikatz lsadump::sam 离线蜂巢、hashcat -m 1000 掩码 6 位数字、260919 恢复一致
---

## 一句话结论

拿到 Windows 镜像或导出的 `SAM`/`SYSTEM` 蜂巢后，用 mimikatz `lsadump::sam` 解出本地账户 NT 哈希，再用 hashcat `-m 1000` 的掩码模式爆破纯数字口令，6 位口令在单机上数秒即可恢复明文。

## 原理

- **SAM 存 NT 哈希，SYSTEM 存 BootKey**：Windows 本地账户的口令不会以明文保存，SAM 蜂巢中保存的是 NT 哈希（MD4(UTF-16LE(password))）；解密 SAM 需要 SYSTEM 蜂巢中的 BootKey。
- **mimikatz 可离线组合两个蜂巢**：`lsadump::sam /sam:<SAM> /system:<SYSTEM>` 读取离线文件，用 BootKey 解出各账户的 RID、用户名和 NT 哈希，不要求当前系统就是镜像来源。
- **NT 哈希可直接用于爆破**：hashcat `-m 1000` 针对 NT 哈希；掩码攻击 `?d?d?d?d?d?d` 只枚举 6 位数字（100 万候选），现代 GPU 每秒数亿次，秒级完成。
- **为什么成立**：很多 CTF 镜像/取证样本使用弱口令（纯数字、短口令），且哈希可离线无限次尝试；没有在线锁定、速率限制或审计。
- **取证意义**：离线分析不需要启动镜像，不会改动证据；同样的流程也适用于从备份、快照或磁盘镜像导出的蜂巢。

## 触发条件

- 已获得 Windows 镜像或 `SAM`、`SYSTEM` 蜂巢文件（如火眼等取证工具导出）。
- 目标本地账户使用弱口令，且口令空间可被字典或掩码覆盖。
- 攻击者可在本地运行 mimikatz 与 hashcat（有足够 GPU/CPU 算力）。
- 镜像未启用会影响离线提取的强保护（如仅云端账户、无本地口令）。

## 利用步骤

1. 从镜像中定位并导出 `Windows/System32/config/SAM` 与 `SYSTEM`（或取证工具导出的同名文件）。
2. 用 mimikatz 离线读取蜂巢，输出各账户 NT 哈希：
   `lsadump::sam /sam:"...\SAM" /system:"...\SYSTEM"`。
3. 记录目标账户的 NT 哈希（32 位十六进制）。
4. 根据口令线索选择攻击模式：已知纯数字/长度用掩码（`-a 3`），未知用字典（`-a 0`）。
5. 运行 hashcat 爆破，得到明文后用于镜像内账户登录或验证其他系统是否复用。

## PoC

```bash
# 1) 离线提取 SAM 中的 NT 哈希（示意路径）
mimikatz.exe "lsadump::sam /sam:\evidence\SAM /system:\evidence\SYSTEM" exit

# 2) 6 位纯数字掩码爆破（NT 哈希模式）
hashcat.exe -m 1000 -a 3 <ntlm_hash> "?d?d?d?d?d?d"
```

原文实测：哈希 `bb552c1772ea2b18fcb8abd75fba66e5` 经 `-m 1000 -a 3 '?d?d?d?d?d?d'` 在数秒内恢复为 `260919`。

## 变体与关联

- **口令空间变体**：纯数字、生日/年份、手机号后 8 位、常见弱口令字典；可先用 `--increment` 从短到长枚举。
- **蜂巢来源变体**：物理磁盘镜像、虚拟机快照、VSS 卷影副本、`reg save` 导出的实时蜂巢、取证工具（火眼等）导出的文件。
- **账户变体**：本地管理员、普通用户、服务账户；域控环境可进一步导出 `NTDS.dit`。
- **关联卡片**：[[web-generic-file-inclusion-windows-sam-ntlm-crack]]（Web LFI 读 SAM 后破解）、[[pentest-privilege-escalation-edr-bypass-reg-export-bootkey-hashdump]]（在线 HashDump 与 EDR 绕过）。
- **边界**：强口令/长口令会使爆破不可行；仅有 SAM 没有 SYSTEM 时无法解出 BootKey；Windows Hello/微软账户登录的本地缓存口令可能为空或不可用。

## 检测与防御

- **取证侧**：对镜像中的 SAM/SYSTEM 做只读副本与哈希校验，记录提取时间与工具版本，保证证据链。
- **防御侧**：启用 LAPS 使用随机长口令；禁用/限制本地账户；开启 BitLocker/TPM 防止离线磁盘读取；监控蜂巢文件被复制/导出。
- **口令策略**：禁止纯数字、短口令和常见弱口令；定期轮换；不同系统不复用。
- **检测信号**：镜像分析环境中出现 mimikatz/hashcat；生产主机上 SAM/SYSTEM 被 `reg save`/复制；异常离线爆破产生的登录尝试（若哈希被用于在线验证）。
