---
id: ctf-forensics-office-doc-password-office2john-hashcat
title: 加密 Office 文档离线破解：office2john 提取校验哈希后字典/掩码爆破
type: scenario
domain: ctf
path: ctf/forensics
technique: office2john-hashcat-crack
tags:
- ctf
- forensics
- office
- docx
- password
- office2john
- hashcat
- john
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:53:20+08:00'
  notes: 已对照原文核对；office2john 提取哈希、hashcat 按前缀选模式、纯小写口令 nanjing 一致；原文未给具体模式
url: /docs/ctf/forensics/ctf-forensics-office-doc-password-office2john-hashcat/
draft: false
kb_aliases:
- office2john
- Word 文档密码破解
- Office 加密文档
- docx hash
- hashcat Office 模式
---

## 一句话结论

对加密的 `.docx/.xlsx/.pptx` 文档，用 `office2john.py` 提取 Office 加密校验哈希，再按哈希前缀选择 hashcat 模式做字典或掩码爆破，即可离线恢复打开密码；CTF 中常见纯小写单词口令可在短时间内命中。

## 原理

- **Office 加密文档保存的是口令校验值**：现代 Office 使用 AES 加密文档内容，密钥由用户口令派生；文档内保存 salt、加密算法参数和口令校验哈希，验证口令只需重算校验值，不需要解密全文。
- **office2john 把文档转成可爆破哈希**：脚本解析 OOXML 包中的 `EncryptionInfo`/`EncryptedPackage`，输出 John/Hashcat 兼容的 `$office$*...` 哈希行。
- **hashcat 按格式选模式**：`$office$*2007*`、`*2010*`、`*2013*` 等前缀对应不同 hashcat 模式（如 2013 为 `-m 9600`）；模式选错会显示“no hashes loaded”或永远跑不出。
- **为什么成立**：口令校验是确定性的离线计算，攻击者可以无限次尝试；弱口令/单词口令在字典或掩码空间内，GPU 可高速枚举。
- **CTF 常见线索**：题目提示“密码为纯小写字母”“与图片/邮箱/地名相关”，可据此选择字典、规则或掩码。

## 触发条件

- 获得加密的 Office 文档（`.docx/.xlsx/.pptx` 等）。
- 文档使用口令加密，且口令强度较低或可从题目线索推导。
- 分析环境有 Python（运行 office2john）、hashcat/john 与可用算力。
- 允许离线爆破（不触发在线锁定/审计）。

## 利用步骤

1. 确认文档确实加密：打开时提示输入密码；用 `file`/解压工具查看 OOXML 内是否有 `EncryptionInfo`。
2. 运行 office2john 提取哈希并保存：
   `python office2john.py word.docx > word.hash`。
3. 查看哈希前缀（`$office$*2013*...` 等），选择对应 hashcat 模式；不确定时先用 `hashcat --example-hashes | grep -i office` 对照。
4. 根据线索选择攻击方式：字典（`-a 0` + 词表）、规则（`-r`）、掩码（`-a 3`，如纯小写 `?l?l?l?l?l?l`）。
5. 命中后得到明文口令，打开文档；若文档内还有二级加密/隐写，继续按题目线索分析。

## PoC

```bash
# 1) 提取 Office 加密文档的校验哈希
py -3.11 office2john.py word.docx > word.hash

# 2) 按哈希前缀选择模式后爆破（示例：2013 格式，字典攻击）
hashcat.exe -m 9600 -a 0 word.hash rockyou.txt

# 或纯小写字母掩码（按题目提示调整长度）
hashcat.exe -m 9600 -a 3 word.hash "?l?l?l?l?l?l?l?l"
```

原文实测：对加密的 `word.docx` 运行 office2john 后用 hashcat 爆破，得到口令 `nanjing`（原文未展示具体 hashcat 模式与命令，模式需按哈希前缀确认）。

## 变体与关联

- **文档格式变体**：`.docx/.xlsx/.pptx`、旧版 `.doc/.xls/.ppt`、带宏的 `.docm`；不同格式/版本对应不同哈希前缀与模式。
- **口令线索变体**：纯小写单词、地名、人名、日期、键盘模式；可用规则引擎（`best64.rule`）扩展字典。
- **工具变体**：office2john + john、msoffcrypto-tool 验证、hashcat 掩码/组合攻击。
- **关联卡片**：[[ctf-forensics-windows-sam-system-offline-ntlm-mask-crack]]（同类离线哈希爆破）、[[ctf-forensics-wsl-ext4-vhdx-offline-inspect]]（同一镜像中的文档/配置取证）。
- **边界**：强口令/长随机口令爆破不可行；文档使用证书/IRM 权限管理而非口令加密时，office2john 可能无法提取可用哈希；模式选错会失败。

## 检测与防御

- **取证侧**：保留原始文档哈希，复制副本后爆破；记录使用的词表、规则、模式与耗时，保证结论可复现。
- **防御侧**：使用长随机口令或证书加密；敏感文档放入受 IRM/DLP 管理的仓库；不要把口令与文档放在同一镜像/同一目录。
- **检测信号**：文档目录出现 `*.hash`/hashcat 会话文件；分析机上运行 office2john/hashcat；文档被大量尝试打开失败（若在线场景）。
