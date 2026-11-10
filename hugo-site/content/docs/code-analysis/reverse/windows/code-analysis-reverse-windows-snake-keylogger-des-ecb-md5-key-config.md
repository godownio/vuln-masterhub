---
id: code-analysis-reverse-windows-snake-keylogger-des-ecb-md5-key-config
title: Snake Keylogger 配置解密：MD5(硬编码 key) 前 8 字节作 DES 密钥 + Base64 + ECB，还原 SMTP 账号/口令/服务器/端口
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: snake-keylogger-des-ecb-md5-truncated-key-config-decrypt
tags:
- reverse
- windows
- dotnet
- malware
- snake-keylogger
- des
- ecb
- md5
- base64
- config-decryption
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:56:00+08:00'
  notes: 已对照原文与图46-48核对：smethod_15 的 MD5(ASCII key)[:8] DES key、Mode=2(ECB)、FromBase64String+TransformFinalBlock、ASCII 解码去填充、key=BsrOkyi... 及解密结果 info@wso-security.com/UWzDeXWsD8/us2.smtp.mailhostbox.com/587 均与原文一致；未运行样本复现
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-snake-keylogger-des-ecb-md5-key-config/
draft: false
kb_aliases:
- Snake Keylogger 配置解密
- smethod_15 解密
- DES ECB Base64 配置
- MD5 前 8 字节 DES key
- Snake Tracker SMTP
- 恶意软件配置解密
---

## 一句话结论

Snake Keylogger 的配置解密函数 `smethod_15(cipher, key)` 先对硬编码字符串 `key` 做 MD5、取前 8 字节作为 DES 密钥，用 `DESCryptoServiceProvider` 的 ECB 模式（`Mode = 2`）对 Base64 解码后的密文 `TransformFinalBlock`，再按 ASCII 解码并去掉末字节填充；把反编译代码里同一 `string_12` 作 key 逐字段解密，就能还原发件邮箱、SMTP 口令、SMTP 服务器、收件邮箱和端口（原文结果：`info@wso-security.com / UWzDeXWsD8 / us2.smtp.mailhostbox.com / 587`）。

## 原理

- **密钥派生**：`DESCryptoServiceProvider` 要求 8 字节 key。代码 `byte[] array = new byte[8]; byte[] sourceArray = md5.ComputeHash(Encoding.ASCII.GetBytes(string_28)); Array.Copy(sourceArray, 0, array, 0, 8);`——即 `MD5(ASCII(key))` 的 16 字节摘要只取前 8 字节。密钥本身是样本中硬编码的长字符串（原文 `string_12`），不是随机生成。
- **模式与填充**：`des.Mode = 2` 对应 `CipherMode.ECB`；`CreateDecryptor()` 后 `TransformFinalBlock(Convert.FromBase64String(string_27), 0, len)`。ECB 不需要 IV，密文按 8 字节块独立解密；明文末尾是 PKCS#5/PKCS#7 填充，填充长度为最后一个字节。
- **字段组织**：样本把所有敏感配置都存成 Base64 密文字符串，反编译后是一串 `string_15 = smethod_15("...", string_12)`、`string_16 = smethod_15("...", string_12)` 之类的赋值；`string_15/16` 是 SMTP 发件邮箱与口令，`string_17` 是服务器，`string_18` 是收件邮箱，`string_19` 是端口。密文在源码中可见，key 也在同一个类里，属于“硬编码密钥”而非真正加密。
- **为什么能还原**：DES 是对称算法，解密就是同一密钥的逆变换；Base64 只是编码；ECB 无 IV 依赖；唯一要处理的是 ASCII 解码与填充裁剪。原文 Python 脚本用 `pycryptodome` 复现后成功打印出全部字段。
- **配置用途**：解出的 SMTP 账号用于样本的 `MailMessage`/`SmtpClient` 外传（发件人、收件人、服务器、端口、SSL），也是 IOC 与阻断依据。

## 触发条件

- 拿到 .NET 恶意样本（原文 Snake Keylogger，VB.NET/.NET 4.x），能反编译到 `smethod_15` 或等价的 `DESCryptoServiceProvider + MD5 + Convert.FromBase64String + Mode=2` 组合。
- 样本中硬编码的 key 字符串与密文字符串仍完整（未被打包器/混淆器剥离）。
- 有 Python（pycryptodome）或 .NET 调试环境；不需要运行样本，纯静态即可解密。

## 利用步骤

1. 用 dnSpy/dnSpy32 打开样本，搜索 `DESCryptoServiceProvider`、`ComputeHash`、`FromBase64String`、`Mode = 2`，定位 `smethod_15`。
2. 记录 key 字符串（`string_12`）与各字段密文（`string_15` 起）。
3. 用 Python 复现：`MD5(key.encode('ascii')).digest()[:8]` 作 DES key，ECB 解密 `base64.b64decode(cipher)`。
4. 按最后一个字节裁掉 PKCS 填充；ASCII 解码（忽略不可打印字符）。
5. 逐字段解密，整理发件邮箱/口令/SMTP 服务器/收件邮箱/端口，用于 IOC、外传通道判断和后续取证。
6. 若字段解密乱码：检查 key 是否取错、是否用了 `Encoding.UTF8` 而非 ASCII、Mode 是否为 CBC（需要 IV）、密文是否被二次编码。

## PoC

原文 Python 解密脚本（整理）：

```python
from Crypto.Cipher import DES
from Crypto.Hash import MD5
import base64

def snake_decrypt(text, key_string):
    key = MD5.new(key_string.encode('ascii')).digest()[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(text))
    padding_len = decrypted[-1]
    if padding_len < len(decrypted):
        decrypted = decrypted[:-padding_len]
    return decrypted.decode('ascii', errors='ignore')

key = "BsrOkyiChvpfhAkipZAxnnChkMGkLnAiZhGMyrnJfULiDGkfTkrTELinhfkLkJrkDExMvkEUCxUkUGr"
fields = {
    "sender_email": "I22WW+qzjWDd9uzIPosYRadxnZcjebFO",
    "sender_pw":    "MrZp4p9eSu2QFqjr3GQpbw==",
    "smtp_server":  "XHGvc06cCeeEGUtcErhxrCgs7X5wecJ1Yx74dJ0TP3M=",
    "receiver":     "I22WW+qzjWDd9uzIPosYRadxnZcjebFO",
    "smtp_port":    "oXrxxBiV5W8=",
}
for name, ct in fields.items():
    print(name, snake_decrypt(ct, key))
```

原文输出：

```text
sender_email: info@wso-security.com
sender_pw:    UWzDeXWsD8
smtp_server:  us2.smtp.mailhostbox.com
receiver:     info@wso-security.com
smtp_port:    587
```

## 变体与关联

- **其它算法**：同类窃密木马常用 AES-CBC/3DES/DPAPI；看到 `Mode` 数字与 IV 要相应调整，见 [[code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper]]、[[pentest-c2-dotnet-3des-remote-pdf-virtualalloc-shellcode-loader]]。
- **批量配置抽取**：若样本很多，可用 ilspycmd 反编译 + 正则抓密文/key，再批量解密，见 [[code-analysis-reverse-windows-dotnet-batch-ilspycmd-config-regex-extract]]。
- **配置字段扩展**：Snake 还把 FTP 账号、Telegram bot token/chat_id、外传方式选择（`$%SMTPDV$`/`%FTPDV$`/`$%TelegramDv$`）放在同类字符串中；同一 `smethod_15` 可解出全部字段。
- **边界**：key 被混淆/加密时需先还原 key；密文被截断或 Base64 变体（URL-safe、换行）时要先规范化；ECB 模式不提供完整性，解密结果需用字段格式（邮箱、端口、域名）校验。

## 检测与防御

- **配置提取即 IOC**：解出的 SMTP/FTP/Telegram 账号、服务器、端口、收件邮箱可直接用于阻断与溯源；把这些值与网络日志比对，找出已外传的主机。
- **静态检测**：YARA/规则匹配 `DESCryptoServiceProvider` + `MD5` + `Convert.FromBase64String` + `Mode = 2` + 硬编码长字符串的组合；监控 .NET 样本资源中的高熵 Base64。
- **网络侧**：限制终端直连外部 SMTP 587/25、FTP 21、Telegram API；对异常邮件附件（Passwords/User/SnakePW）与 `api.telegram.org/bot` 出站告警。
- **取证**：解出的配置与沙箱网络行为（如 `checkip.dyndns.org`、SMTP 目标 IP）交叉验证；保留样本哈希与解密脚本输出。
- **合规**：仅在授权/隔离环境分析样本；配置中的口令属于敏感数据，报告中脱敏。
