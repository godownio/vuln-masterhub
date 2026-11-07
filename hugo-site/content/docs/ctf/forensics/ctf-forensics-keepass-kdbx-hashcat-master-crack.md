---
id: ctf-forensics-keepass-kdbx-hashcat-master-crack
title: KeePass kdbx 密码库离线爆破：hashcat -m 13400 恢复主密码并读取横向凭据
type: scenario
domain: ctf
path: ctf/forensics
technique: keepass-kdbx-hashcat-master-password
tags:
- forensics
- keepass
- kdbx
- hashcat
- password-cracking
- credential-access
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:33:22+08:00'
  notes: 已对照原文题10与图53-54核对：hashcat -m 13400 1 rockyou.txt --show 得到 Cutiepie14（原文正文写作 cutiepie14），KeePass 中 Heisen-9-WS-6 条目用户 Werni、密码 Quantum1!，另有 Billy、Cog-Backup；与各类 NTLM/Office/SSH 离线爆破卡为不同哈希类型。未验证点：未在本机复跑 hashcat。
url: /docs/ctf/forensics/ctf-forensics-keepass-kdbx-hashcat-master-crack/
draft: false
kb_aliases:
- KeePass 主密码爆破
- kdbx 离线破解
- hashcat 13400
- keepass2john
- 密码库取证
- KeePass 凭据提取
---

## 一句话结论

拿到目标主机上的 KeePass `.kdbx` 密码库后，用 `keepass2john` 提取主密码校验哈希，`hashcat -m 13400` 配合字典/掩码离线爆破出主密码（文章用 rockyou.txt 得到 `cutiepie14`），再用 KeePass 打开数据库即可读出保存的 RDP/本地账号口令（本例 `Werni:Quantum1!`），为横向移动补上凭据。

## 原理

- KeePass 2 的 `.kdbx` 用主密码（可选 keyfile/Windows 账户）经 AES-KDF 或 Argon2 派生加密密钥，数据库内容整体加密；验证哈希来自头部与密钥派生结果。
- `keepass2john` 从 kdbx 提取可被 hashcat 识别的哈希；hashcat 模式 `13400` 对应 KeePass 1/2（AES）的主密码校验，可用字典、规则或掩码离线猜测主密码。爆破在本地进行，不触发目标锁定。
- 主密码一旦恢复，KeePass 客户端即可解密数据库并展示所有条目（标题、用户名、密码、URL、备注），攻击者常在其中找到本地管理员、RDP、服务账号等凭据（本例 `Heisen-9-WS-6` 条目的 `Werni:Quantum1!`，另有 Billy、Cog-Backup 条目）。
- 该技术常接在主机取证之后：triage 镜像中发现 `.kdbx` → 离线爆破 → 用其中凭据登录其他主机或服务，形成“文件获取 → 凭据恢复 → 横向”的完整链路。

## 触发条件

- 已获得 `.kdbx` 文件（主机镜像、用户目录、共享盘、备份等）。
- 主密码强度不足以抵抗字典/掩码爆破；数据库未额外绑定 keyfile/Windows 账户，或已同时获得对应因素。
- 本地有 hashcat 与足够算力；KeePass 版本/模式与 hashcat 支持的模式匹配。

## 利用步骤

1. 定位 `.kdbx` 文件（常见于用户 Documents、桌面、云盘同步目录、运维共享）。
2. 提取哈希：`keepass2john acquired.kdbx > kdbx.hash`（或使用 `keepass2john.py`）。
3. 查看哈希格式与本机算力，选择字典/规则/掩码；先跑 rockyou.txt：
   `hashcat -m 13400 kdbx.hash rockyou.txt`
4. 用 `--show` 查看已恢复的主密码（文章命令：`hashcat -m 13400 1 rockyou.txt --show`，结果为 `cutiepie14`，截图显示 `Cutiepie14`，大小写以实际为准）。
5. 用主密码在 KeePass 中打开数据库，导出/查看条目，收集用户名、密码、URL、备注。
6. 用收集到的凭据登录目标主机/服务，验证是否可横向；对同一密码在其他系统的复用做撞库测试。

## PoC

```bash
# 1) 从 kdbx 提取 hashcat 可识别的哈希
keepass2john acquired.kdbx > kdbx.hash

# 2) 字典爆破（文章使用 -m 13400 与 rockyou.txt）
hashcat -m 13400 kdbx.hash rockyou.txt

# 3) 查看已恢复的主密码
hashcat -m 13400 kdbx.hash rockyou.txt --show
```

```text
# 文章结果：主密码 cutiepie14（hashcat 输出截图为 Cutiepie14）
# KeePass 打开后条目：Heisen-9-WS-6 -> Werni / Quantum1!（另有 Billy、Cog-Backup）
```

## 变体与关联

- 变体：KeePass 1（`.kdb`）与 KeePass 2（`.kdbx`）模式不同，按 hashcat 支持的编号选择；若数据库启用 Argon2 KDF，爆破成本显著上升。
- 变体：同时存在 keyfile 时，需要“keyfile + 主密码”组合，hashcat 有对应模式；也可从主机上直接找 keyfile。
- 关联：[[ctf-forensics-office-doc-password-office2john-hashcat]]（Office 文档哈希提取与离线破解同类流程）；[[defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction]]（在本例中，kdbx 是同一入侵链的凭据来源）。
- 边界：CTF 环境主密码在 rockyou.txt 中；真实环境若主密码强或启用 Argon2+keyfile，离线爆破可能不可行。

## 检测与防御

- 检测：主机/共享盘出现 `.kdbx` 被复制或外带；EDR 发现 `keepass2john`/`hashcat` 在取证主机运行；KeePass 数据库被异常程序读取。
- 修复/加固：KeePass 主密码使用高强度随机值并定期轮换；启用 Argon2 KDF 与 keyfile/Windows 账户绑定；不要把 `.kdbx` 放在可被批量收集的共享目录或备份中。
- 响应：一旦 kdbx 泄露，视为其中全部凭据失陷，立即轮换并排查复用；对相关账号启用 MFA 与会话审计。
