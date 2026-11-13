---
id: ctf-forensics-vmware-vmx-encrypted-vm-dictionary-crack
title: VMware 加密虚拟机 vmx 字典爆破：pyvmx-cracker 解加密 VM，encryptedVM.guid 残留行导致失败的修复
type: scenario
domain: ctf
path: ctf/forensics
technique: vmware-encrypted-vmx-pyvmx-cracker-dictionary
tags:
- forensics
- vmware
- vmx
- encryption
- password-cracking
- dictionary
- ctf
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V624
  verified_at: '2026-11-12T22:17:01+08:00'
  notes: 已对照12623原文win-1题核对：vmx加密虚拟机、pyvmx-cracker、encryptedVM.guid=""残留行导致解密失败需删除、rockyou字典跑出密码somewhere，均与原文一致；卡片原子、与VBox VDI/LUKS及BitLocker卡非同链。未验证点：win-1关键截图为未下载外链图（本地仅前61图），pyvmx-cracker实际命令参数未由截图二次确认，利用步骤中脚本名与PoC略有差异。
url: /docs/ctf/forensics/ctf-forensics-vmware-vmx-encrypted-vm-dictionary-crack/
draft: false
kb_aliases:
- vmx 加密虚拟机破解
- pyvmx-cracker
- encryptedVM.guid
- VMware 虚拟机密码爆破
- 加密 VM 取证
---

## 一句话结论

拿到加密的 VMware 虚拟机（vmx + vmdk）时，可用 pyvmx-cracker 解析 vmx 中的 keySafe/密钥派生字段，用 rockyou 等字典做离线密码爆破；若 vmx 中存在 `encryptedVM.guid = ""` 这类工具不认识的加密残留行会导致解析/解密失败，删除该行后即可跑出密码并正常启动虚拟机取证。

## 原理

- **VMware 加密 VM 的密钥保存结构**：加密虚拟机把用户口令经 KDF 派生出的密钥用 keySafe 结构保存在 vmx 配置里；pyvmx-cracker 读取 vmx 的 keySafe（encryptedKey、salt、迭代次数等），对字典中的每个候选口令执行相同 KDF 并比对解密结果，命中即得到启动密码。
- **encryptedVM.guid 的影响**：加密后的 vmx 会写入 `encryptedVM.guid` 标记；部分版本的 pyvmx-cracker/解析库对空值或未知 guid 处理不当（报错或解析失败），删掉该行让工具按旧格式解析即可。
- **为什么可行**：密码爆破是纯离线的（无需启动虚拟机），成本只取决于字典与 KDF 迭代次数；题目/取证场景常用 rockyou 或赛事提供字典。
- **边界**：强随机长密码字典无法覆盖；不同 VMware 版本加密格式（encryption.keySafe 字段布局）差异可能需换工具版本；删除 guid 行只影响工具解析，不影响密钥本身。

## 触发条件

- 已获得加密的 VMware 虚拟机文件（.vmx 中含加密配置，通常配套 .vmdk/.nvram 等）。
- 能运行 pyvmx-cracker（Python3）并有合适字典（如 rockyou.txt）。
- 授权取证/CTF 环境。

## 利用步骤

1. 打开 .vmx 确认存在加密字段（keySafe/encryptedVM），并记下虚拟磁盘文件。
2. 删除 vmx 中 `encryptedVM.guid = ""` 行（若存在且工具报错）。
3. 运行 `python3 pyvmx-cracker -v <vm>.vmx -d rockyou.txt`，等待命中密码。
4. 用得到的密码在 VMware 中正常开机，进入系统继续取证（浏览器历史、文档、聊天记录等）。

## PoC

```bash
# 1) 查看 vmx 加密配置
grep -iE "encrypt|keySafe" <vm>.vmx

# 2) 删除导致解析失败的残留行
sed -i '/encryptedVM.guid/d' <vm>.vmx

# 3) 字典爆破
python3 pyvmx-cracker.py -v <vm>.vmx -d /usr/share/wordlists/rockyou.txt
```

## 变体与关联

- 变体：VirtualBox 加密 VDI 转 LUKS/keystore 后字典破解（见 [[ctf-forensics-vbox-vdi-keystore-luks-dictionary-crack]]）；BitLocker/TrueCrypt 类全盘加密的内存密钥提取（见 [[ctf-forensics-bitlocker-fvek-memory-dislocker-mount]]、[[ctf-forensics-truecrypt-memory-key-mount]]）。
- 边界：若 vmx 密码与 vmdk 解密密钥分离（企业密钥库），爆破 vmx 口令后仍需密码解磁盘。

## 检测与防御

- 取证侧：先备份 vmx/vmdk 原始文件再修改；记录字典与工具版本保证可复现。
- 防护侧：加密 VM 使用高强度随机口令、口令不与业务口令复用；加密虚拟机文件访问需最小权限与审计。
