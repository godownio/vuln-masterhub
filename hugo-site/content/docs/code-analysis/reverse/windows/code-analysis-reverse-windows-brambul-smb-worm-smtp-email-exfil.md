---
id: code-analysis-reverse-windows-brambul-smb-worm-smtp-email-exfil
title: Brambul（HIDDEN COBRA）SMB 蠕虫样本分析：动态 API 解析、SYSTEM 分支自启与信息收集、随机 IP 445 弱口令爆破、HELO SMTP 邮件外发
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: brambul-smb-worm-smtp-email-exfil
tags:
- malware-analysis
- windows
- worm
- smb
- brute-force
- smtp
- email-exfil
- hidden-cobra
- reverse-engineering
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V511
  verified_at: '2026-11-11T04:58:48+08:00'
  notes: 已通读原文 13417 并逐张核对全部 11 张图：01 US-CERT Alert TA18-149A（HIDDEN COBRA – Joanap Backdoor Trojan and Brambul SMB Worm）、02 Brambul 描述（32 位 SMB 蠕虫、内置口令字典、随机 IP、SMTP 外发 IP/主机名/用户名/口令）、03 动态拼接 Netapi32.dll/Mpr.dll 与 WNetAddConnection2A/WNetCancelConnection2A/NetApiBufferFree/NetUseEnum 并 GetProcAddress、04 dnsapi.dll/LoadLibraryA/GetProcAddress 调 DnsQuery_A(gmail.com)、05 GetUserNameA 与 SYSTEM 比较及自启/获取 IP/Subject 分支、06 RegOpenKeyExA(HKLM, SOFTWARE\Microsoft\Windows\CurrentVersion\Run) 与 RegSetValueExA(ValueName=Windows Update)、07 反汇编同见 ValueName Windows Update 与样本路径缓存、08 SYSTEM 分支 sub_401BA0/401B30/401040 与 GetVersion 的 WinXP/Win2003/WinVista/WinNt/Win2000 分支、09 rand() 生成 IPv4、段 <20/>240/=127 改 210、htons(445)、10 内置弱口令字典（password/123456/654321/pass/test1234/admin/root/!@#$/passwd/angel/BUMBLE/asdf 系列/连续数字/web/mail 系列）、11 SMTP 无认证 HELO gmail.com/MAIL FROM:johnS203@yahoo.com/RCPT TO:whiat1001@gmail.com，均与卡一致。样本元数据 57344 字节与 MD5/SHA1/CRC32 与原文完全一致。原文 US-CERT 图提到端口 139/445，正文与样本代码为 445，卡按原文描述。dedup
    报告 recommendation=new（related=0），SMB 爆破/邮件外传候选均非同链。样本分析非漏洞组件，无 CVE/affected_versions；图片均未超 1200 长边无需缩放，无读取失败。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-brambul-smb-worm-smtp-email-exfil/
draft: false
kb_aliases:
- Brambul
- HIDDEN COBRA Brambul
- US-CERT TA18-149A
- SMB 邮件蠕虫
- Brambul Server Message Block Worm
---

## 一句话结论

Brambul（美国 DHS/FBI 归因 HIDDEN COBRA，US-CERT 警报 TA18-149A）是一个 32 位 Windows SMB 蠕虫：样本运行后动态拼接并解析 `Netapi32.dll`/`Mpr.dll` 的网络 API，先对 `gmail.com` 做 DNS 查询；随后按当前用户名分流——用户名为 `SYSTEM` 时写 `Run` 键自启、收集系统版本与 IP 并通过无认证 HELO SMTP 把受害者信息发到固定邮箱；非 SYSTEM 时随机生成 IP、用内置弱口令字典对 445 端口做 SMB 爆破，成功后把受害者用户名/口令/IP/主机名同样以邮件外发。

## 原理

- **动态 API 解析**：样本不直接导入敏感网络 API，而是在运行时把 `Netapi32.dll`、`Mpr.dll` 与函数名片段拼接（`sprintf`/`LoadLibraryA`/`GetProcAddress`），解析 `WNetAddConnection2A`、`WNetCancelConnection2A`、`NetUseEnum`、`NetApiBufferFree` 等用于建立/枚举/清理网络连接的函数，降低静态导入表特征。
- **连通性探测**：调用 `DnsQuery_A` 查询 `gmail.com`，确认网络可用并获取解析环境，为后续 SMTP/SMB 操作做准备。
- **按用户名分流**：`GetUserNameA` 取当前用户名并与 `SYSTEM` 比较：
  - **SYSTEM 分支**：创建自启动（`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`，值名 `Windows Update`，数据为当前样本路径）；收集 IP 与系统版本（`GetVersion` 区分 WinXP/2003/Vista/WinNT/Win2000），拼出邮件主题。
  - **非 SYSTEM 分支**：进入 SMB 爆破传播流程。
- **随机 IP + SMB 爆破**：用 `rand()` 逐段生成 IPv4（`(base + rand()) % 0xFF`），跳过 `127` 段、把 `<20` 或 `>240` 的段改为 `210`，用 `htons(445)` 构造 SMB 端口；内置密码字典（`password`、`123456`、`654321`、`pass`、`test1234`、`admin`、`root`、`!@#$%`、`passwd`、`angel`、`BUMBLE`、`asdf`/`asdfg`/`asdfgh`、连续数字、`web`/`mail`/`web123`/`mail1234` 等）对随机主机尝试 SMB 认证/未授权访问。
- **SMTP 邮件外发**：直接以 socket 发送 SMTP 命令，`HELO gmail.com` → `MAIL FROM johnS203@yahoo.com` → `RCPT TO whiat1001@gmail.com` → `DATA`，不使用身份认证（HELO 普通 SMTP 可匿名投递，常见于垃圾邮件）；正文包含被攻陷主机的 IP、主机名，以及爆破成功获得的用户名/口令。
- **传播/外发闭环**：蠕虫用弱口令在局域网/随机地址上横向，成功后再次走邮件外发通道，把凭据与主机信息回传给攻击者；这也解释了 HIDDEN COBRA 利用 Brambul 作为“初始访问+凭据收集”组件的用途（与 Joanap 后门同批披露）。
- **样本元数据**：大小 57344 字节；MD5 `86B4E50393E52F0F649DE6756B6F5F36`；SHA1 `19E0FAD9CE41A118C0238D866E3DE5C227A724EC`；CRC32 `45839045`。

## 触发条件

- 32 位 Windows 主机执行该样本（通常由投放器/其他恶意软件释放，文件名为长十六进制串）。
- 主机可访问 DNS、TCP 445（SMB）与 SMTP 出站端口；样本在 SYSTEM 权限下与普通用户权限下走不同分支。
- 网络中存在使用内置弱口令字典的 SMB 账户/共享（否则爆破失败，但 SYSTEM 分支的自启与信息收集仍会发生）。
- 分析场景，非漏洞利用。

## 利用步骤（分析步骤）

1. 记录样本哈希与大小，使用 IDA/Ghidra 加载，先看字符串：`Netapi32.dll`、`Mpr.dll`、`WNetAddConnection2A`、`NetUseEnum`、`gmail.com`、`johnS203@yahoo.com`、`whiat1001@gmail.com`、`Windows Update`、密码字典。
2. 定位 `LoadLibraryA`/`GetProcAddress` 组合，还原动态解析的网络 API 列表。
3. 跟进 `DnsQuery_A("gmail.com")` 与 `GetUserNameA`/`strcmp("SYSTEM")` 分支。
4. SYSTEM 分支：分析 `RegOpenKeyExA`/`RegSetValueExA` 写入的 Run 键与值名，以及 `GetVersion` 分支生成的系统版本字符串。
5. 非 SYSTEM 分支：分析 `rand()` 生成 IP 的算法（跳过 127/保留段、`htons(445)`）与密码字典表，确认 SMB 连接/枚举/清理 API 的调用顺序。
6. 分析 socket 发送的 SMTP 命令序列（HELO/MAIL FROM/RCPT TO/DATA）与邮件正文拼接逻辑（IP、主机名、用户名/口令）。
7. 在隔离环境动态验证：注册表自启、DNS 查询、445 扫描与 SMTP 外发；抓包比对 IOC。

## PoC

无 PoC（样本分析卡）。可用于检测的行为/IOC 摘要：

```text
文件：57344 字节，MD5 86B4E50393E52F0F649DE6756B6F5F36，SHA1 19E0FAD9CE41A118C0238D866E3DE5C227A724EC
自启动：HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows Update = <样本路径>
DNS：DnsQuery_A("gmail.com")
邮件：HELO gmail.com / MAIL FROM johnS203@yahoo.com / RCPT TO whiat1001@gmail.com（无认证）
网络：随机 IPv4 的 TCP 445 连接 + 内置弱口令字典尝试
```

## 变体与关联

- **同批 HIDDEN COBRA 组件**：Joanap 后门（TA18-149A 同时披露）；Brambul 负责 SMB 传播与凭据收集，Joanap 负责远程控制。
- **同类蠕虫传播**：`pentest-c2-removable-drive-worm-nodrives-shortcut-infection`（可移动盘蠕虫）、`pentest-persistence-self-copy-multipath-runkey-zoneidentifier`（Run 键多路径自复制）。
- **SMB 弱口令横向**：`pentest-ad-domain-admin-targeted-bruteforce-wmiexec`、`smb-weak-password-local-admin-seimpersonate-machine-account-credential-harvest`。
- **邮件外发通道**：`defense-forensics-snake-keylogger-stealer-collection-exfil-channels`（SMTP/FTP/Telegram 外传）、`pentest-c2-grandoreiro-outlook-harvesting-spam-secman-mapi`（批量邮件）。
- **变体**：更换邮箱/发件人、改用其他 SMTP 端口或 EHLO+AUTH、扩展密码字典、加入更多系统信息字段。

## 检测与防御

- **主机检测**：Run 键值名 `Windows Update` 指向非系统路径/长十六进制文件名；进程动态加载 `Netapi32.dll`/`Mpr.dll` 并调用 `WNetAddConnection2A`/`NetUseEnum`；短时间对大量随机外部 IP 发起 445 连接；非邮件进程向外部 SMTP 端口发送 `HELO`/`MAIL FROM`。
- **网络检测**：出站 TCP 445 扫描/爆破行为、DNS 查询 `gmail.com` 与 SMTP 外发组合；邮件 IoC `johnS203@yahoo.com`、`whiat1001@gmail.com`；对随机公网 IP 的 445 连接做告警与阻断。
- **防御**：禁止终端到互联网的 445 出站；关闭 SMBv1、禁用不必要的 SMB 共享；使用强口令并禁用默认/弱口令账户；限制终端直接外发 SMTP（仅允许邮件网关）；监控 Run 键与异常自启动；部署 EDR 对蠕虫行为链告警。
- **响应**：隔离主机，删除 Run 键与样本，排查同网段被爆破成功的主机与凭据泄露，重置相关口令并检查外发邮件记录。
