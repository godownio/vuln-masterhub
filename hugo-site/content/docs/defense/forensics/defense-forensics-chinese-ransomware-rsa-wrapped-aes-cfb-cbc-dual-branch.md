---
id: defense-forensics-chinese-ransomware-rsa-wrapped-aes-cfb-cbc-dual-branch
title: 中文勒索软件加密方案取证：RSA 封装随机口令 + 按 50MB 分流 AES-CFB/CBC（固定盐 11223344），密钥日志 libadvpack.dll 与 ._locked 结构
type: scenario
domain: defense
path: defense/forensics
technique: ransomware-rsa-wrapped-aes-cfb-cbc-dual-branch-forensics
tags:
- forensics
- ransomware
- malware-analysis
- rsa
- aes-cfb
- aes-cbc
- pbkdf2
- key-recovery
- incident-response
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T16:51:51+08:00'
  notes: 已对照原文与图13-22核对：string_5+LOCK+string_6经内置RSA公钥加密(图14/16)、WritePasswlog双重Base64写c:\temp\libadvpack.dll(图14/17，已修正卡内方法名拼写)、>50MB CFB随机盐PBKDF2 50000(图20)、<=50MB CBC盐{1,2,3,4}PBKDF2 1000(图19/21)、._locked、重要資訊.txt与收款碼.jpg(图22/24)均一致；原文写盐值11223344而截图代码为字节{1,2,3,4}，卡内已注明。与CryptNet/HomuWitch/BianLian同RSA+AES但密钥载体与分支不同，非同链。原文无受影响版本。
url: /docs/defense/forensics/defense-forensics-chinese-ransomware-rsa-wrapped-aes-cfb-cbc-dual-branch/
draft: false
kb_aliases:
- ._locked 勒索软件
- libadvpack.dll 密钥日志
- 支付宝收款码勒索
- RSA 封装随机口令
- AES CFB CBC 按大小分流
- 中文信息勒索软件
---

## 一句话结论

该中文勒索样本用“255 个随机字符 + LOCK + 硬盘序列号”作为口令，用内置 RSA 公钥加密后 Base64 写入 `c:\temp\libadvpack.dll`（文本），再按文件大小分流：大于 50MB 用 AES-256-CFB（随机盐、PBKDF2 50000 次），小于等于 50MB 用 AES-256-CBC（固定盐 `{1,2,3,4}`、PBKDF2 1000 次），输出 `<原名>._locked` 后删除原文件。取证关键是确认密钥只以 RSA 密文存在——没有攻击者私钥时无法解密，固定盐分支也不构成弱点。

## 原理

- **混合加密把“解密权”交给攻击者**：文件密钥不是硬编码，而是运行期随机生成（`string_5` 随机串 + `"LOCK"` + 硬盘序列号 `string_6`），随后用样本内置的 RSA 公钥加密。受害者手里只有 RSA 密文，AES 口令明文从未落盘；RSA 私钥只在攻击者手中，因此不存在“从样本中提取密钥直接解密”的路径。
- **按大小分流是性能设计，不是安全差异**：
  - >50MB：`Rfc2898DeriveBytes(password, randomSalt, 50000)` 派生 256 位 key 与 IV，`CipherMode.CFB` 流式加密；随机盐先写入输出文件头部（代码中 `fileStream.Write(array, 0, array.Length)` 在 CryptoStream 之前），因此大文件密文头部可提取盐用于格式识别。
  - ≤50MB：`salt = {1,2,3,4}`，`Rfc2898DeriveBytes(password, salt, 1000)`，`CipherMode.CBC`。盐固定且迭代次数低，但口令仍来自未知随机串并经 RSA 封装，所以固定盐只降低派生成本，不降低口令熵；除非随机数生成器可预测或同一口令被复用，否则不能据此解密。
- **文件格式**：输出文件名在原名后追加 `._locked`（`FileStream(inputFile + "_locked", FileMode.Create)`），加密完成后删除原始文件；加密范围覆盖桌面、下载、文档、图片目录及 469 种扩展名，说明样本以“用户可感知损失”为目标。
- **勒索与收款链路**：桌面写入繁体中文 `重要資訊.txt`（2000 元、Tutanota 邮箱、24 小时解锁期限），并把内置 Base64 图片还原为 `收款碼.jpg`（支付宝收款码）；同时向攻击者邮箱发送磁盘序列号、计算机名、加密文件数量与 RSA 密文串。
- **取证价值**：`c:\temp\libadvpack.dll` 是每台主机独立的 RSA 密文（Base64），可用于关联同一攻击者/同一私钥下的多台受害者；密文文件头部的盐、文件大小分支与扩展名可辅助确认家族/变种。

## 触发条件

- Windows 主机执行了该样本（C++ 加载器解密并调用 .NET 勒索模块）；
- 主机上出现 `._locked` 后缀文件、原文件被删除，桌面出现 `重要資訊.txt`/`收款碼.jpg`；
- `c:\temp\libadvpack.dll` 存在（Base64 文本，内容为 RSA 加密的口令串）。
- 密钥恢复的前提（本案不满足）：样本内置 RSA 私钥、随机数生成器可预测/种子可复现、或口令在多个样本间复用且已知。

## 取证/恢复步骤

1. 隔离主机并做内存/磁盘镜像；保留 `c:\temp\libadvpack.dll`、勒索信、收款码图片与样本本身（样本可能在 `%TEMP%`/启动目录）；
2. 用 Detect It Easy 确认外层加载器与内层 .NET 模块，按多阶段解密流程 dump 出 .NET 载荷，de4dot/.NET Reactor Slayer 脱壳；
3. 在 `StartAction()`/`encryptDirectory()` 中确认：随机口令拼接规则（255 随机字符 + `LOCK` + 硬盘序列号）、RSA 公钥、`WritePasswlog` 写入路径、AES 模式与 PBKDF2 参数、`._locked` 命名规则；
4. 对大文件检查密文头部是否有随机盐（CFB 分支），对小文件确认 CBC 分支无盐存储；用文件大小（字节数/1048576 与 50 比较）分类，统计可恢复面；
5. 恢复评估：如果没有攻击者 RSA 私钥，AES 口令不可得，不能解密；不要尝试对 AES 密文暴力破解 255 字符随机串；保留样本与 `libadvpack.dll` 作为报案/厂商溯源材料；
6. 若拿到私钥（执法/厂商渠道），用 RSA 解出 Base64 内容→UTF-8 口令→按分支 PBKDF2 派生 key/IV→CFB/CBC 解密 `._locked` 文件。

## PoC

无独立 PoC（原文未提供解密工具，样本本身不含私钥）。关键逻辑形态：

```csharp
string text = string_5 + "LOCK" + string_6;          // 随机串 + 硬盘序列号
byte[] bytes = Convert.FromBase64String(<内置RSA公钥>);
string enc = Encrypts.RsaEncrypt(text, Encoding.Default.GetString(bytes));
WritePasswlog(Convert.ToBase64String(Encoding.UTF8.GetBytes(enc))); // c:\temp\libadvpack.dll
// >50MB: Rfc2898DeriveBytes(password, randomSalt, 50000) + CipherMode.CFB
// <=50MB: salt={1,2,3,4}; Rfc2898DeriveBytes(password, salt, 1000) + CipherMode.CBC
```

## 变体与关联

- 同族判断：`._locked` 后缀、`libadvpack.dll` 日志、支付宝收款码与繁体勒索信可作为行为指纹；
- 若随机串由弱 PRNG（如 `new Random()` 以时间为种子）生成，可在已知大致运行时间窗内枚举种子重建口令——本案原文未分析 PRNG，不能假定可利用；
- 与库内 BianLian（硬编码 KEY/IV + 偏移恢复）、HomuWitch（硬编码口令 + 文件头 salt + PBKDF2）、PyInstaller（内嵌 RSA 私钥）对比：本案属于“RSA 公钥封装 + 无私钥不可恢复”，恢复结论应明确为不可行；
- 固定盐（原文记作 11223344，截图代码实为字节 `{1,2,3,4}`）与低迭代次数可作为同类变种识别特征。

## 检测与防御

- 监控大批量文件重命名为 `._locked` 且原文件被删除、桌面突然出现 `重要資訊.txt`/`收款碼.jpg`、`c:\temp\libadvpack.dll` 被创建等行为组合；
- 阻止/告警可疑进程枚举并终止 `360tray.exe`、`360sd.exe`、`360rps.exe`、`360rp.exe` 等安全软件进程；
- 备份与离线副本是最有效的恢复手段；对关键主机限制本地管理员权限、禁用不必要的宏/可执行附件；
- 邮件侧拦截发往 Tutanota 等匿名邮箱的异常外联（样本会向攻击者邮箱发送主机信息与加密结果）。
