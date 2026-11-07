---
id: ctf-forensics-phishing-email-xor-docx-base64-key
title: 钓鱼邮件附件 XOR 加密 DOCX：从正文 Base64 取真实密钥并解密
type: scenario
domain: ctf
path: ctf/forensics
technique: phishing-email-xor-docx-base64-key
tags:
- ctf
- forensics
- phishing
- email
- eml
- xor
- docx
- base64
- malware-analysis
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/ctf/forensics/ctf-forensics-phishing-email-xor-docx-base64-key/
draft: false
kb_aliases:
- eml 附件取证
- XOR 加密 docx
- Base64 密钥
- 钓鱼邮件分析
- 恶意 exe 释放文档
---

## 一句话结论

钓鱼邮件 `.eml` 的附件压缩包里通常同时放“看起来像文档的乱码 docx”和“负责解密的 exe”。逆向 exe 可看到它用 `fgetc`/`fputc` 逐字节 XOR 把 `tan.docx` 写成 `tan1.docx`，硬编码密钥往往是幌子；真正的密钥藏在邮件正文的 Base64 字符串里。用正文 Base64 解码出的密钥重新 XOR，docx 恢复为合法 ZIP 容器（`PK\x03\x04`），打开即可看到内容/flag。

## 原理

- **双附件分工**：docx 是 XOR 密文，exe 是解密器/诱饵；受害者被诱导运行 exe，exe 读取密文、按密钥 XOR、写出可打开的文档，从而降低警惕。
- **XOR 的可逆性**：`cipher[i] = plain[i] ^ key[i % len(key)]`，同一函数再执行一次即还原；exe 的循环通常是 `while ((c = fgetc(in)) != EOF) fputc(c ^ key[i++ % keylen], out)`。
- **硬编码密钥可能是诱饵**：样本里写死的 `"123456"` 解出来仍是乱码，说明它不是正确密钥；邮件正文/主题/附件名中的 Base64 字符串（如 `Y3RmX2lzX2dvb2RfYm95` → `ctf_is_good_boy`）才是出题人留的真实密钥。
- **DOCX 是 ZIP**：合法 docx 以 `PK\x03\x04` 开头，内部有 `[Content_Types].xml`、`word/document.xml` 等；XOR 解密后先校验 ZIP 魔数，能快速判断密钥是否正确。
- **为什么成立**：XOR 不改变长度，密钥长度远小于文件，重复密钥模式明显；一旦拿到正确密钥，解密是确定性的，且 docx 的 ZIP 结构提供强校验。

## 触发条件

- 拿到 `.eml` 或邮件导出文件，附件为 zip/rar，内含一个乱码 docx 和一个 exe。
- exe 中有文件读写 + 逐字节 XOR 循环，密钥为硬编码字符串或从参数/正文读取。
- 邮件正文/主题/附件名存在 Base64、十六进制或其它编码字符串。
- 解密结果应为 docx/zip 等已知格式，可用魔数验证。

## 利用步骤

1. 解析 `.eml`：提取发件人、主题、正文、附件；保存附件 zip 并解压。
2. 对 exe 做静态分析（strings/IDA）：定位 `fopen`/`fgetc`/`fputc` 循环，确认 XOR 密钥与输入输出文件名。
3. 先用 exe 中的硬编码密钥尝试解密；若结果不是 `PK\x03\x04`，说明密钥不对。
4. 在邮件正文中找 Base64 字符串，解码为候选密钥；也检查主题、附件名、HTML 注释、二维码等位置。
5. 用候选密钥重新 XOR 解密，校验输出文件头为 `PK\x03\x04`，再用 Word/7-Zip 打开。
6. 若 docx 仍打不开，检查密钥是否循环正确、是否有前缀/后缀、是否还叠加了 Base64/压缩。
7. 记录 IOC：发件人、URL、附件哈希、XOR 密钥、释放文件名。

## PoC

```python
import base64

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# 邮件正文中的 Base64 字符串
key = base64.b64decode("Y3RmX2lzX2dvb2RfYm95")   # b"ctf_is_good_boy"
enc = open("tan.docx", "rb").read()
dec = xor_decrypt(enc, key)
assert dec[:4] == b"PK\x03\x04", "key is wrong"
open("tan1.docx", "wb").write(dec)
```

说明：实际样本可能把密钥再包一层（反转、大小写、加盐），以解密后 ZIP 魔数为准迭代验证。

## 变体与关联

- 变体：密钥来自邮件主题、附件文件名、HTML 注释、图片 EXIF 或另一个附件；也可能用 RC4/AES 替代 XOR。
- 变体：exe 不写明文 docx，而是把解密内容注入 Word 进程或直接内存加载；静态分析需转为动态/内存取证。
- 变体：docx 本身是诱饵，真正恶意代码在宏/外链模板/远程图片中；解密后继续检查 `word/_rels`、`vbaProject.bin`、外部关系。
- 关联：[[ctf-forensics-docx-customxml-base64-comment]]（DOCX 内部 Base64 隐藏数据）；[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（从流量恢复 XOR key）；[[defense-forensics-email-header-spoof-detection]]（邮件头溯源）。

## 检测与防御

- 检测：邮件附件同时包含“文档 + 可执行文件”的组合；压缩包内 exe 与 docx 同名/相近名。
- 检测：exe 中出现 `fopen`/`fgetc`/`fputc` 循环、XOR 常量、写 `.docx` 文件名；静态 YARA 可匹配 XOR 解密器模式。
- 检测：邮件正文含长 Base64/十六进制串，且与附件内容相关；HTML 邮件中的隐藏注释/白字。
- 防御：邮件网关沙箱化附件，禁止 exe/脚本；对 docx 做宏与外链检查；终端禁止从邮件附件直接运行可执行文件。
- 防御：对 XOR 解密后的文档继续做二次扫描；培训用户不要运行“修复文档”类附件。
