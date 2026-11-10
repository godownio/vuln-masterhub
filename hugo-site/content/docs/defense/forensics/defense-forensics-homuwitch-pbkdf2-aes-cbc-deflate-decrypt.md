---
id: defense-forensics-homuwitch-pbkdf2-aes-cbc-deflate-decrypt
title: HomuWitch 勒索加密格式与免赎金解密：硬编码口令 + 文件头 16B salt 经 PBKDF2(10000) 派生 AES-256-CBC 密钥，DEFLATE 压缩
type: scenario
domain: defense
path: defense/forensics
technique: homuwitch-ransomware-pbkdf2-aes-cbc-deflate-decrypt
tags:
- forensics
- ransomware
- homuwitch
- pbkdf2
- rfc2898
- aes-cbc
- deflate
- decryption
- key-recovery
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V461
  verified_at: '2026-11-10T14:06:53+08:00'
  notes: 已对照原文与 27 张图片核对：16B salt 写文件头、Rfc2898DeriveBytes(口令, salt, 10000) 派生 32B key+16B IV、DEFLATE+AES-256-CBC、.homuencrypted/55MB/后缀列表、互斥体、%APPDATA%\HMW\User.ini=BFX0、C2 与 alive_status_send/getLocalization 路径、CyberChef 样例 key/IV/密文均与原文一致；PoC 与原文 DecryptFile 等价。未验证点：未实际运行样本复算密文（依赖原文样例）。dup-scan.json 早于建卡且无涉及本篇 pair。
url: /docs/defense/forensics/defense-forensics-homuwitch-pbkdf2-aes-cbc-deflate-decrypt/
draft: false
kb_aliases:
- HomuWitch
- HomuCrypt
- .homuencrypted 解密
- oralcumshot1998
- Rfc2898DeriveBytes 勒索
- 勒索软件对称加密设计缺陷
---

## 一句话结论

HomuWitch 勒索软件的加密文件格式为“前 16 字节随机 salt + AES-256-CBC 密文（明文先经 C# DEFLATE 压缩）”，AES 的 key/IV 由 `Rfc2898DeriveBytes`（PBKDF2-HMAC-SHA1，10000 次迭代）从**样本内置的固定口令** `oralcumshot1998` 派生；样本自身还带有 `DecryptFile` 解密函数和密码输入框，因此拿到加密文件与样本后无需支付赎金即可批量还原原始文件。

## 原理

- **加密流程**（`EncryptFile(input, output)`）：`password = Program.password`（字符串常量，原文各样本均为 `oralcumshot1998`）；随机生成 16 字节 `salt` 写入输出文件最前面；`new Rfc2898DeriveBytes(passwordBytes, salt, 10000)` 依次 `GetBytes(32)` 得 AES-256 key、`GetBytes(16)` 得 CBC IV；随后 `CryptoStream(AES encrypt)` 包住 `DeflateStream(Compress)`，即先 DEFLATE 压缩原始文件内容再 AES-CBC 加密写盘。
- **文件格式**：`[16 字节 salt][AES-256-CBC 密文]`，没有 magic、长度字段或每文件密钥封装；salt 唯一的随机性来源，且与密文一起存放，等于明文给出 KDF 参数。
- **解密即逆过程**（`DecryptFile`）：从输入文件读前 16 字节作 salt，用同一内置口令按同样参数派生 key/IV，`CryptoStream(AES decrypt)` 包住 `DeflateStream(Decompress)` 输出原文；`CryptAllFolders` 在解密分支调用 `HomuCrypt.DecryptFile(text, 去掉 .homuencrypted 后缀的路径)` 后删除密文。
- **为什么可不付赎金**：对称加密的密钥完全由“样本内硬编码口令 + 文件内 salt”决定，既没有每受害者密钥，也没有 RSA/非对称封装；从样本或全网公开报告中取得该口令即可离线解密。原文认为这属于设计缺陷而非严格意义的“漏洞”。
- **C# DEFLATE 兼容性**：原文指出用其他语言复现 C# `DeflateStream` 压缩曾失败，最终直接调用 C# 代码处理 DEFLATE；手动验证时用 CyberChef 的 `Derive PBKDF2 key`（SHA1、384-bit、10000 次、salt 取文件头 16 字节）再 `AES Decrypt`（CBC、key 前 32 字节、IV 后 16 字节）可得到 DEFLATE 数据。

## 触发条件

- 取得 `.homuencrypted` 加密文件以及对应 HomuWitch 样本（用于提取内置口令；原文样本口令均为 `oralcumshot1998`）。
- 明确的加解密参数：PBKDF2-HMAC-SHA1、10000 次迭代、48 字节输出（32 字节 key + 16 字节 IV）、AES-256-CBC、C# DEFLATE。
- 仅用于授权的事件响应与取证恢复。

## 利用步骤

1. 在受害主机上按 `.homuencrypted` 后缀收集加密文件，并保留原始样本（注意先做镜像/只读保全）。
2. 从样本字符串/反编译代码中提取 `Program.password`（原文各样本为 `oralcumshot1998`）。
3. 对每个文件读前 16 字节作 salt，用 `Rfc2898DeriveBytes(password, salt, 10000)` 得到 32 字节 key 与 16 字节 IV。
4. AES-256-CBC 解密剩余数据，再经 DEFLATE 解压即得明文；可用样本自带 UI 的 “File decryptor” 输入口令直接解密，或按原文用 C# 写批量工具（对文件列表逐条 `DecryptFile` 并把密文重命名为 `.bak`）。
5. 抽样校验文件头/内容是否恢复（原文用已知文本 `61 61...0D 0A 62...` 与 CyberChef 结果比对），确认后批量处理并留存哈希清单。

## PoC

原文给出的 C# 解密核心（与样本 `DecryptFile` 等价）：

```csharp
public static void DecryptFile(string inputFilePath, string outputFilePath)
{
    string password = "oralcumshot1998";
    using (FileStream fs = new FileStream(inputFilePath, FileMode.Open))
    using (FileStream outFs = new FileStream(outputFilePath, FileMode.Create))
    using (Aes aes = Aes.Create())
    {
        byte[] pwd = Encoding.UTF8.GetBytes(password);
        byte[] salt = new byte[16];
        fs.Read(salt, 0, salt.Length);                       // 文件头 16 字节
        var kdf = new Rfc2898DeriveBytes(pwd, salt, 10000);
        byte[] key = kdf.GetBytes(32);
        byte[] iv  = kdf.GetBytes(16);
        using (var dec = aes.CreateDecryptor(key, iv))
        using (var cs = new CryptoStream(fs, dec, CryptoStreamMode.Read))
        using (var ds = new DeflateStream(cs, CompressionMode.Decompress))
        {
            ds.CopyTo(outFs);
        }
    }
}
```

原文验证样例：salt `BF 74 17 D5 2F 80 6A 19 D0 F4 1F 43 EF 85 77 C6` + 口令 `oralcumshot1998` → key `37ee...1595`、IV `8b5e...d470`，AES 解密得 `4b4c84035eae24380000`，即 C# DEFLATE 数据。

## 变体与关联

- **同类可解勒索**：样本自身携带私钥/固定密钥的实现错误，如 [[defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery]]（内嵌 RSA 私钥 + AES-ECB）、[[defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery]]（CryptoAPI 密钥/IV 恢复）；本卡是“硬编码口令 + 每文件 salt 的对称派生”，不需要非对称私钥。
- **样本行为与 IOC（取证线索）**：互斥体 `ghfdujhuiGYGyftgfTshyhrshdemjutdgjndtgFUYfuyhFTU&FK`（多份样本一致）；C2 形如 `https://193.164.150.225:1200/`、`http://79.137.207.233/`、`http://78.142.0.42/`，路径 `alive_status_send/`、`getLocalization/`；加密桌面/Downloads/Documents 及已用空间小于 3GB 的驱动器目录；后缀列表包括 pdf/doc/xls/ppt/rar/zip/txt/图片等且只加密小于 55MB 的文件；输出后缀 `.homuencrypted`；配置文件 `%APPDATA%\HMW\User.ini` 写入 `BFX0` 标记；加密前清空回收站、隐藏并置自身只读、修改壁纸、弹窗显示外联获取的勒索信。
- **利用限制**：若后续变种改用非对称封装或每文件随机密钥，本方法失效；遇到 CD/DVD 驱动器可能因样本未判断驱动器类型而异常退出（原文兼容性问题），取证时不影响离线解密。

## 检测与防御

- **检测**：监控 `%APPDATA%\HMW\User.ini`（内容 `BFX0`）、互斥体名、`.homuencrypted` 文件批量出现、`SHEmptyRecycleBin` 调用、桌面壁纸被改与 `alive_status_send/`、`getLocalization/` 外联；内存/样本中搜索字符串 `oralcumshot1998`。
- **响应**：及时隔离主机、保留样本与加密文件、从样本提取口令后离线批量解密；对已删除文件结合卷影/备份恢复。
- **防御**：离线/不可变备份与恢复演练；EDR 拦截批量文件改写与回收站清空；限制样本外联 C2；禁止用户态程序随意改写桌面壁纸/自隐藏。
