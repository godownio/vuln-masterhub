---
id: code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv
title: CryptNet 混合加密格式：每文件随机 AES-256-CBC key/IV + 硬编码 RSA-2048 公钥封装 key/IV 附文件尾
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv
tags:
- windows
- ransomware
- cryptnet
- aes-cbc
- rsa-2048
- hybrid-encryption
- file-format
- malware-analysis
- dotnet
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:16:04+08:00'
  notes: 已对照原文与 img18/19/21 核对：32 字符 key/16 字符 IV、RSAKeyValue(AQAB, 2048 位)、ASCII(key+token+iv) RSA 封装附文件尾、<524288 走 AES-256-CBC 全量均符；smethod_16(712) 具体分隔符值原文未展示，按占位 SEP 处理；未执行样本
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv/
draft: false
kb_aliases:
- CryptNet 加密格式
- 每文件随机 AES key/IV
- RSA 公钥封装 AES 密钥
- RSAKeyValue 硬编码公钥
- 混合加密勒索
- 小文件 AES-256-CBC 全量加密
- 随机后缀改名
---

## 一句话结论

CryptNet 为每个被选中的文件生成随机的 32 字符 ASCII AES-256 key 和 16 字符 IV，用样本内硬编码的 RSA-2048 公钥（XML `RSAKeyValue`，Exponent `AQAB`）加密 `key + 分隔符 + IV` 的 ASCII 字节串，并把 RSA 密文块追加到加密文件末尾；小于 512KB 的文件走 AES-256-CBC 全量加密，加密后按扩展名白名单筛选结果改名为“原名 + 随机 5 字符后缀”，每个目录写入勒索说明。私钥不在样本中，受害者仅凭样本无法解密。

## 原理

- **每文件独立随机密钥**：`smethod_6` 用 `smethod_9(32)` 生成 32 字符随机字符串作为 AES key、`smethod_9(16)` 生成 16 字符 IV；`AesCryptoServiceProvider` 设置 `KeySize=256`、`BlockSize=128`、`Mode=1`（CBC），`Key/IV = ASCII(text/text2)`。每个文件重新生成，泄露一个文件的 key 不影响其他文件。
- **RSA 封装**：`bytes = ASCII(key + smethod_16(712) + IV)` 把 key、分隔符、IV 拼成短的 ASCII 字节串，再调用 `smethod_7(Class0.string_0, bytes)` 用静态构造函数中 `smethod_16(3694)` 解出的 RSA 公钥加密。公钥以 XML `<RSAKeyValue><Modulus>…</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>` 形式硬编码，是 2048 位公钥；RSA 只封装约 48 字节的 key/IV，不对整文件做非对称运算。
- **文件格式**：`AES-CBC 密文（小文件全量）|| RSA_encrypt(ASCII(key + 分隔符 + IV))`。加密结果 `byte_0` 在密文写入后通过追加模式的 `FileStream` 写到文件尾，攻击者服务器用对应私钥解出该文件的 key/IV。
- **为什么采用混合加密**：AES-CBC 速度快、适合文件内容；RSA 解决“密钥如何安全交给攻击者”的问题。受害者拿到样本也只能看到公钥，无法反解文件尾的 RSA 块，因此无法自行恢复。
- **应用上下文（文件筛选/改名/勒索说明）**：`smethod_1` 用 `Directory.GetFiles` 遍历目录，按扩展名白名单 `string_3`（文档、图片、数据库、压缩包、代码、备份等数百项）筛选；跳过勒索说明文件名（`smethod_3()`）；只读文件先置为 `FileAttributes.Normal`；加密成功后 `File.Move` 为“原名 + 随机 5 字符后缀”；每个目录首次处理时写入 `RESTORE-FILES-<随机串>.txt` 勒索说明（内容由 `smethod_15` 解码，含 `.onion` 地址与受害者 DECRYPTION ID）。系统盘会排除 `windows.old`、`program files`、`windows`、`$recycle.bin` 等目录，非系统盘异步加密。
- **单实例与展示行为**：入口用 `new Mutex(true, Environment.MachineName, ref flag)` 保证同一主机只有一个实例；`smethod_12` 生成黑底白字勒索图并调用 `SystemParametersInfo(20, 0, path, 3)`（SPI_SETDESKWALLPAPER）设为壁纸。这些是样本应用层行为，不改变加密格式本身。

## 触发条件

- 目标为 Windows 主机，样本以当前用户权限运行；对目标目录有读写与改名权限（管理员权限还可执行反恢复操作，见关联卡）。
- 目标目录存在扩展名命中白名单的文件，且文件大小小于 `524288` 字节（本卡的小文件全量加密分支）。
- 样本内嵌 RSA 公钥、私钥只在攻击者侧；受害者无法从样本中提取私钥。
- 文件未被样本自身跳过（勒索说明、已加密后缀等）。

## 利用步骤

1. 枚举驱动器与目录；非系统盘异步处理，系统盘跳过关键目录后递归子目录。
2. `smethod_1` 遍历文件：扩展名白名单命中、跳过勒索说明、清除只读属性。
3. 小文件（`Length < 524288`）：`smethod_6` 生成随机 32 字符 key 与 16 字符 IV。
4. `File.ReadAllBytes` 读入原文，`fileStream.SetLength(0)` 清空，用 AES-256-CBC 写入密文（默认 PKCS7 填充）。
5. 用硬编码 RSA-2048 公钥加密 `ASCII(key + 分隔符 + IV)`，把结果追加到文件尾。
6. `File.Move` 改名为原名 + 随机 5 字符后缀；目录内写入勒索说明。
7. 受害者按说明访问 `.onion`、提交 DECRYPTION ID 并支付赎金；攻击者用私钥解出每个文件的 key/IV 后解密。

## PoC

原文为 .NET 样本逆向，无独立可运行武器化 PoC。以下为按截图还原的加密格式伪代码，仅用于分析与检测（私钥不在样本中，无法实际解密）：

```csharp
byte[] plain = File.ReadAllBytes(path);
string key = RandAscii(32);                    // smethod_9(32)
string iv  = RandAscii(16);                    // smethod_9(16)

// 1) AES-256-CBC 全量加密
using var aes = new AesCryptoServiceProvider {
    KeySize = 256, BlockSize = 128,
    Key = Encoding.ASCII.GetBytes(key),
    IV  = Encoding.ASCII.GetBytes(iv),
    Mode = CipherMode.CBC                       // Mode = 1
};
using var ms = new MemoryStream();
using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
    cs.Write(plain, 0, plain.Length);

// 2) RSA 公钥封装 key + 分隔符 + IV，附到文件尾
byte[] blob = Encoding.ASCII.GetBytes(key + SEP + iv);   // SEP = smethod_16(712)
byte[] rsaBlob = RsaEncryptWithEmbeddedPublicKey(blob);   // XML RSAKeyValue, Exponent AQAB
File.WriteAllBytes(path, ms.ToArray());
using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write))
    fs.Write(rsaBlob, 0, rsaBlob.Length);

// 3) 改名 + 同目录勒索说明
File.Move(path, path + "." + RandAscii(5));
File.WriteAllText(dir + "\\RESTORE-FILES-" + RandAscii(9) + ".txt", ransomText);
```

## 变体与关联

- **同样本大文件分支**：[[code-analysis-reverse-windows-ransomware-large-file-intermittent-encryption-three-128kb]] 只对首/中/尾各 128KB 做 AES-CBC 读改写，仍复用本卡的每文件 key/IV 与 RSA 封装格式。
- **取证恢复对照**：[[defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery]] 是在动态调试中对 CryptoAPI 的 key/IV 设置下断点取密钥；[[defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery]] 是样本误打包 RSA 私钥后可恢复。本卡只有公钥，两者都不适用，除非拿到攻击者私钥或从内存/服务器侧取得密钥材料。
- **反恢复前置**：[[defense-incident-response-ransomware-pre-encryption-cleanup]] 覆盖勒索加密前删除卷影/备份编录、禁用系统恢复、停止备份服务的通用行为；本样本的三条 `vssadmin`/`bcdedit`/`wbadmin` 命令与该卡同一场景。
- **格式变体**：AES-CBC/GCM/ECB 模式、RSA-OAEP/PKCS#1 v1.5 填充、key+IV 分隔符位置、封装块放在文件头或尾、随机后缀长度均可变化；需要按样本还原，不能仅凭扩展名判断。

## 检测与防御

- 文件侧：同目录出现 `RESTORE-FILES-*.txt`；大量文件扩展名变为随机 5 字符后缀；文件尾存在固定长度 RSA 块（2048 位模长约 256 字节）；同一批文件的 key/IV 各不相同。
- 进程侧：.NET 样本创建 `Mutex(Environment.MachineName)`；批量 `File.Move` 改名、`FileAttributes.Normal` 清除只读；调用 `SystemParametersInfo(SPI_SETDESKWALLPAPER)` 改壁纸。
- 防御：离线/不可变备份与异地副本；WDAC/AppLocker 限制未知 .NET 样本；启用 Controlled Folder Access；对高价值目录做写入/改名监控；定期演练恢复。
- 响应：隔离主机、保全样本与内存（密钥可能只在内存中短暂存在）；不要支付赎金；用备份恢复；追踪 `.onion` 地址与受害者 ID。授权测试中不得对生产数据实际运行。
