---
id: ctf-forensics-windows-sticky-notes-snt-memory-openssl-aes
title: Windows 便签取证：volatility filescan 提取 .snt 文件 + 磁盘找密钥文件 + OpenSSL Salted AES 解密
type: scenario
domain: ctf
path: ctf/forensics
technique: windows-sticky-notes-snt-memory-dump-openssl-aes-decrypt
aliases:
- Sticky Notes 取证
- .snt 内存提取
- 便签内存取证
- Salted__ 解密
- openssl aes-256-cbc 取证
tags:
- forensics
- windows
- volatility
- sticky-notes
- memory
- openssl
- aes
- ctf
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V624
  verified_at: '2026-11-12T22:17:03+08:00'
  notes: 已对照12623原文baby_forensics_3题核对：volatility pslist/filescan找.snt、导出后放回Win7便签路径、U2FsdGVkX1(OpenSSL Salted)密文、R-Studio按时间找密钥文件i4ak3y=qwerasdf、解密得flag，均与原文一致；卡片原子、与filescan壁纸/BitLocker卡非同链。未验证点：本篇关键截图为未下载外链图；原文只写openssl的aes加密，aes-256-cbc为按Salted__格式的合理推断，未由截图确认。
---

## 一句话结论

Windows 内存镜像取证时，先 `pslist` 看是否有便签进程（StickyNotes），再用 `filescan` 按 `.snt` 后缀找便签数据文件并 dump，放回用户 `AppData\Local\Microsoft\Sticky Notes\` 路径即可读取内容；若内容形如 `U2FsdGVkX1...` 的 base64（OpenSSL `Salted__` 格式 AES），需在磁盘镜像中按时间线找同机存放的密钥文件，再用 `openssl aes-256-cbc -d` 解密得到明文 flag。

## 原理

- **便签存储位置**：Windows 便签（Sticky Notes）把内容存在用户目录 `%APPDATA%\Microsoft\Sticky Notes\StickyNotes.snt`（Win7）等路径；文件随进程加载/保存进入内存页，可被 Volatility 的 filescan 以文件对象形式扫描到。
- **内存提取**：volatility `filescan` 列出内存中的文件对象（含物理偏移），`dumpfiles -Q <offset> -D out` 导出内容；把 dump 出的 .snt 放回原相对路径的同版本系统即可被便签程序打开。
- **为何要密钥**：新版便签/部分题目对内容做加密；`U2FsdGVkX1` 是 OpenSSL `Salted__` 的 base64 前缀，表示使用 `openssl enc -aes-256-cbc -salt` 类格式加密，口令由人工输入，无法从密文直接恢复。
- **密钥来自同机**：出题/真实场景常把密钥明文写在磁盘某文件（如命名为 `i4ak3y` 的文本）；用磁盘取证工具（R-Studio/挂载）按修改时间排序找可疑文件，读取后作为 `-pass pass:` 参数解密。
- **完整链**：内存镜像给内容（.snt），磁盘镜像给密钥，两者交叉还原明文，这是典型的"内存+磁盘双镜像"取证思路。

## 触发条件

- 有 Windows 内存镜像（可用对应 Volatility2 profile 解析）与（可选）同机磁盘镜像。
- 便签进程或 .snt 文件对象在内存中可被扫描到；密文为 OpenSSL Salted 格式且密钥在磁盘可寻。
- 授权取证/CTF 环境。

## 利用步骤

1. `vol.py -f mem.raw --profile=Win7SP1x64 pslist` 找便签进程（如 StikyNot.exe），确认目标方向。
2. `vol.py -f mem.raw --profile=Win7SP1x64 filescan | findstr /i ".snt"` 找 .snt 文件对象与物理偏移。
3. `vol.py ... dumpfiles -Q <offset> -D ./out` 导出文件。
4. 将导出文件重命名/放回 `%APPDATA%\Microsoft\Sticky Notes\` 对应路径，打开便签程序读取密文。
5. 用 R-Studio/挂载磁盘镜像，按修改时间排序找密钥文件（如 `i4ak3y` 内容 `qwerasdf`）。
6. `openssl enc -d -aes-256-cbc -a -in note.b64 -pass pass:qwerasdf` 得到明文（或先 base64 解码再解密）。

## PoC

```bash
# 内存侧：找便签文件并导出
vol.py -f mem.raw --profile=Win7SP1x64 filescan | grep -i "\.snt"
vol.py -f mem.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007d1234a0 -D ./out

# 密文特征
# U2FsdGVkX195MCsw0ANs6/Vkjibq89YlmnDdY/dCNKRkixvAP6+B5ImXr2VIqBSp94qfIcjQhDxPgr9G4u++pA==

# 磁盘侧找到密钥后解密
echo 'U2FsdGVkX1...' | base64 -d > note.bin
openssl enc -d -aes-256-cbc -in note.bin -pass pass:<key_file_content>
```

## 变体与关联

- 变体：密钥藏在浏览器密码库/文本文件/图片元数据；用 john/hashcat 爆破弱口令；便签内容直接在内存字符串中搜索（无需完整文件）。
- 关联：[[ctf-forensics-bitlocker-fvek-memory-dislocker-mount]]（内存镜像提取全盘加密密钥）、[[ctf-forensics-linux-memory-rc4-encrypted-file-source-key-recovery]]（内存中找源码密钥解同机加密文件，思路一致）。
- 边界：便签程序版本与 .snt 格式绑定，放回不同版本系统可能无法解析；Salted AES 若密钥长度/摘要算法不符会解密失败。

## 检测与防御

- 取证侧：保留原始镜像与导出文件哈希，记录工具版本与 profile 来源保证可复现。
- 防护侧：便签中不放敏感信息；加密密钥不与密文同机存放；终端启用磁盘加密与访问审计。
