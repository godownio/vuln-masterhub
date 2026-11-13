---
id: defense-incident-response-ransomware-family-fingerprint-triage
title: 勒索事件家族指纹归因与解密渠道选择：按加密后缀/勒索信/释放路径比对，再用 ID Ransomware 与厂商解密库匹配
type: scenario
domain: defense
path: defense/incident-response
technique: ransomware-family-fingerprint-triage
tags:
- ransomware
- incident-response
- triage
- detection
- forensic
- file-artifacts
- decryptor
- windows
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V653
  verified_at: '2026-11-13T05:32:31+08:00'
  notes: 已对照原文《勒索病毒简易浅析》全文与38张图核对：家族速查表逐行比对原文与截图（STOP .litar文件列表图09，原文正文误写.litrar；RYUK .RYK图11；Buran勒索信图13；Phobos [ID]{mail}.phobos+info.hta图17；WannaCry图18/38；GlobeImposter auchentoshan图19；MedusaLocker图20；LockBit 2.0 Restore-My-Files.txt图21；BlackBasta谈判门户图22；LockBit 3.0 aGrhEtcUe.README.txt与黑底白边B壁纸图23/24；xollam FILE RECOVERY.txt图25/26；babyk How To Restore Your Files图27；babyk/.Astra同族关系有图37 Emsisoft AstraLocker decryptor原文佐证）。已将STOP后缀改为截图可见的.litar并标注原文写法；DataRecovery.txt非本文来源已标注属LockBit 3另一变种(关联卡)；WannaCry URL表述按原文收窄；babyk/.Astra来源指向图37。搜索引擎/解密工具页面(图28-37)与正文链接一致。confidence=medium合适：原文为综述，家族列表不完整且未做样本/解密验证，卡内已注明需ID Ransomware与样本哈希复核。dedup=new，与LockBit3单家族识别、具体家族解密取证卡均非同链；dup-scan无本篇pair。未验证点：未实际提交在线引擎、未执行任何勒索/解密样本；无受影响版本信息，未设versions。
url: /docs/defense/incident-response/defense-incident-response-ransomware-family-fingerprint-triage/
draft: false
kb_aliases:
- 勒索病毒家族识别
- 勒索信指纹
- 加密后缀速查
- ID Ransomware
- NoMoreRansom
- 勒索解密工具选择
---

## 一句话结论

勒索事件处置的第一步是归因而非支付：按加密文件的新增后缀规则、勒索信文件名与关键词、联系邮箱/Tor 站点、样本释放目录和传播入口（RDP 爆破、SMB、MS17-010、Weblogic/Tomcat/JBoss 漏洞等）比对家族指纹，再用 ID Ransomware、360/腾讯/奇安信勒索搜索引擎交叉确认家族，最后到 NoMoreRansom、Emsisoft、卡巴斯基、瑞星、Avast、腾讯哈勃查找对应免费解密器；不同家族的加密方案（基础运算、单对称、RSA/ECC、RSA+对称混合）决定了在无私钥时是否存在可解密路径。

## 原理

- **指纹来自加密器实现与运营习惯**：同一家族的不同变种会保留稳定的文件系统痕迹——后缀命名规则（固定后缀、随机字母后缀、`[ID]{邮箱}` 结构、随机串+邮箱+扩展名）、勒索信文件名与正文关键词、联系邮箱、样本释放目录（`%appdata%\local`、`%appdata%\Roaming`、Windows 目录、Startup）、服务名（如 WannaCry 的 `mssecsvc2.0`）等；变种通常只改其中一部分，因此需要组合多个特征判断。
- **加密方案决定可解密性**：
  - 基础运算加密（XOR、加减）没有密钥管理，可通过已知明文、文件头碰撞或暴力枚举逆出密钥，历史样本常有解密器。
  - 单对称加密（AES/DES/3DES/RC4/Salsa20/TEA）若密钥在本地残留、由弱随机数生成或算法实现有缺陷，可被恢复；否则需要从样本或内存取证拿密钥。
  - 非对称/混合加密（RSA、ECC；或 GandCrab 式 RSA+Salsa20：作者 RSA 公钥加密第一层 Salsa20 的 key/IV，程序生成的 RSA 私钥被第一层 Salsa20 加密，第二层 Salsa20 加密磁盘文件）在没有作者私钥时不可直接解密，只能依赖厂商获取的私钥、执法行动或实现缺陷；被加密文件中保存的是被作者公钥封装的密钥材料，而不是明文密钥。
- **为什么必须先归因再解密**：各厂商解密器按家族与密钥方案发布，家族判断错误或对不匹配样本强行解密可能导致文件永久损坏；部分变种（如 Satan 的 evopro、新版 STOP）暂无公开解密器。

## 触发条件

- Windows/Linux 主机或共享目录出现大量文件被改名、无法打开，或桌面壁纸/弹窗出现勒索信息；
- 存在勒索信文本/HTML、异常后缀、联系邮箱或 Tor 谈判站点；
- 需要判断是否可以免费解密、是否值得尝试备份恢复，以及攻击入口（RDP 3389、SMB 445、Web 漏洞、钓鱼附件等）；
- 有权限读取加密文件样本、勒索信与主机日志（应急响应或授权取证场景）。

## 利用步骤

1. **隔离现场**：断网/禁用网卡，停止共享，保留勒索信、样本与日志；不要先删除文件或重装。
2. **抽样看后缀**：记录原始扩展名与新增后缀模式（固定如 `.ryk`/`.phobos`/`.babyk`；随机字母如 LockBit 3 的 9 位随机串；带邮箱/ID 如 `[ID]{mail}.phobos`、`{ID}_{mail}.后缀`）。
3. **找勒索信与关键词**：如 `RyukReadMe.html/.txt`、`info.txt`/`info.hta`、`FILE RECOVERY.txt`、`How To Restore Your Files.txt`、`aGrhEtcUe.README.txt`、`RECOVER_INSTRUCTIONS.html`、`Restore-My-Files.txt`，以及 `!!!ALL YOUR FILES ARE ENCRYPTED !!!`、`maze` 等正文关键词（`DataRecovery.txt` 属 LockBit 3 另一变种，见关联卡，非本文来源）。
4. **看释放路径与传播入口**：`%appdata%\local\<随机>`（STOP）、`%appdata%\Roaming`（Scarab）、Windows 目录与服务 `mssecsvc2.0`（WannaCry）、Startup（Paradise）；入口多为 RDP 弱口令/爆破（Satan、Matrix、Phobos、MedusaLocker、LockBit、xollam）、SMB/MS17-010（WannaCry、Satan）、JBoss/Tomcat/Weblogic 等 Web 组件漏洞（Satan、Buran）、钓鱼邮件与挂马（Maze、Buran、Sacrab）。
5. **在线交叉归因**：把勒索信/加密样本/后缀提交到 ID Ransomware（id-ransomware.malwarehunterteam.com）、360（lesuobingdu.360.cn）、腾讯（guanjia.qq.com/pr/ls）、奇安信（lesuobingdu.qianxin.com），核对家族与解密可能性；不要只凭后缀下结论（后缀可被仿冒，同名家族也有多个构建）。
6. **匹配解密器**：到 NoMoreRansom、Emsisoft、卡巴斯基 noransom、瑞星、Avast、腾讯哈勃查询对应家族工具；先在副本上验证，再处理原件；部分工具只支持历史变种。
7. **记录与升级**：把家族、样本哈希、加密时间窗、入口线索写入事件记录；无免费解密器时评估离线备份恢复，不建议直接支付赎金。

## PoC

原文给出的家族指纹速查（示例，非全集，后缀列表以原文缩写为准；实际以 ID Ransomware/样本哈希复核）：

| 家族 | 常见后缀/文件特征 | 勒索信/关键词 | 其他痕迹 |
|---|---|---|---|
| STOP | `.TRO` `.djvu` `.puma` `.pumas` `.pumax` `.djvuq` `.litar`（原文写作 `.litrar`）… | 带付款说明文本 | 释放于 `%appdata%\local\<随机名称>`；捆绑破解软件/KMS |
| Satan | `.evopro` `.sick`… | — | 永恒之蓝/RDP 爆破/JBoss/Tomcat/Weblogic 漏洞传播 |
| RYUK | `.ryk` | `RyukReadMe.html`/`.txt` | RSA+AES；垃圾邮件/漏洞包/Trickbot |
| MAZE | 不规则 | 关键词 `maze` | 垃圾邮件、挂马 |
| Buran | 不规则 | `!!!ALL YOUR FILES ARE ENCRYPTED !!!` | RIG Exploit Kit、CVE-2018-8174；RaaS |
| Scarab | `.krab` `.Sacrab` `.bomber` `.Crash`… | — | 释放于 `%appdata%\Roaming`；Necurs/RDP |
| Matrix | `.GRHAN` `.PRCP` `.SPCT` `.PEDANT`… | — | RDP 爆破；显示加密进度 |
| Paradise | `{ID}_{邮箱}.特定后缀` | 勒索弹窗 | 自身释放到 Startup |
| Phobos | `.Banta` `.phobos` `.actin` `.PISCA` `.caleb`… | `info.txt`/`info.hta` | RDP 弱口令；RSA+AES |
| WannaCry | `.wncry` | — | MS17-010；服务 `mssecsvc2.0`；启动时连接一个不存在的 URL（杀开关域名） |
| GlobeImposter | `auchentoshan`、十二生肖+`4444` | — | 释放于 `%appdata%`/`%localappdata%`；RDP 爆破 |
| MedusaLocker | `.ReadTheInstructions` `.READINSTRUCTIONS` | `RECOVER_INSTRUCTIONS.html`/`INSTRUCTIONS.html` | RDP 弱口令 |
| LockBit 3 | 9 位随机字母后缀（如 `.AGRHETCUE`） | `aGrhEtcUe.README.txt`；黑底白边 B 图标/壁纸 | AES-256+RSA-2048；PSExec 横向；RDP |
| BlackBasta | — | 谈判聊天门户 | RSA+ChaCha20；僵尸网络；Windows/ESXi |
| xollam（Mallox 变种） | `.xollam` | `FILE RECOVERY.txt` | RDP 爆破/弱口令/邮件/漏洞 |
| babyk | `.babyk`（同族另有 `.Astra`） | `How To Restore Your Files.txt` | 社交工程/恶意邮件附件 |

快速枚举现场后缀与勒索信（只读排查）：

```powershell
# 按目录统计异常后缀（抽样）
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
  Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 30

# 搜索常见勒索信文件名
'*RECOVER*','*RECOVERY*','*README*','info.hta','Restore-My-Files.txt','DataRecovery.txt' |
  ForEach-Object { Get-ChildItem -Path C:\ -Recurse -Filter $_ -ErrorAction SilentlyContinue }
```

说明：以上家族与后缀按原文整理，原文列表本身不完整且变种会改后缀；`babyk`/`.Astra` 的同族关系来自原文图 37 的 Emsisoft AstraLocker decryptor 描述（"The extension '.Astra' or '.babyk' is appended to files"）。归因结论必须结合勒索信正文、样本哈希与在线引擎结果，不能只靠单一后缀。

## 变体与关联

- 关联：[[defense-detection-lockbit3-encrypted-file-artifacts]]（LockBit 3 文件名结构、图标与勒索信的现场识别细化）。
- 关联：[[defense-incident-response-ransomware-pre-encryption-cleanup]]（加密前清日志、停服务、删备份的行为与处置顺序）。
- 关联：[[defense-forensics-chinese-ransomware-rsa-wrapped-aes-cfb-cbc-dual-branch]]、[[defense-forensics-bianlian-ransomware-hardcoded-aes-cbc-offset-decrypt]]、[[defense-forensics-homuwitch-pbkdf2-aes-cbc-deflate-decrypt]]（具体家族的解密与取证实现）。
- 变体：Web 服务器加密勒索（利用 CMS 已知漏洞投放）没有统一指纹，按 Web 日志与文件时间线归因；MBR 勒索以启动中断和屏幕索款为特征，不加密个人文件。
- 边界：同家族不同构建的后缀/勒索信会变化，新型变种可能无解密器；支付赎金不保证解密且可能二次勒索。

## 检测与防御

- 事前：关闭/限制 RDP 3389、SMB 445 等暴露面，强口令与多因素；及时打 MS17-010 与 Web 组件补丁；离线/异介质备份并演练恢复；EDR 监控批量改名、熵骤升与日志清除。
- 事中：隔离主机与共享、冻结备份；保留勒索信与样本；按上述流程归因后再决定解密或恢复；不要自行重命名/修改加密文件。
- 事后：复盘入口（RDP 弱口令、漏洞、钓鱼），排查同网段其他主机，更新检测规则；对已确认家族补充样本哈希与 IoC。
