---
id: defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery
title: PyInstaller 勒索样本取证：解包提取内嵌 RSA 私钥，OAEP 解 AES key，ECB 解密 PDF
type: scenario
domain: defense
path: defense/forensics
technique: pyinstaller-ransomware-rsa-oaep-aes-ecb-recovery
tags:
- forensics
- ransomware
- pyinstaller
- rsa-oaep
- aes-ecb
- pdf
- key-recovery
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:05:29+08:00'
  notes: 已对照 91111 原文数据分析第一、二题核对：PyInstaller 解包、key/pr.pem、RSA-OAEP(SHA256)、AES-256-ECB+PKCS7 与 MD5 52fd2cb4fc43eceb3c79233038bb5f42 均一致。PoC 未在本机复跑。
url: /docs/defense/forensics/defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery/
draft: false
kb_aliases:
- PyInstaller 勒索软件分析
- 内嵌 RSA 私钥恢复
- RSA-OAEP + AES-ECB
- store.key 解密
- 勒索文件恢复
- en.exe
---

## 一句话结论

勒索样本是 PyInstaller 打包的 Python 程序：运行时用 RSA-OAEP(SHA256) 把随机 AES-256 key 加密写入 `store.key`，再用 AES-256-ECB + PKCS7 加密 PDF；但样本把 RSA 私钥 `pr.pem` 一起打包在 `key/` 目录。用 `pyinstxtractor` 解包提取私钥，OAEP 解密 `store.key` 得到 AES key，再 ECB 解密 PDF 并去填充，即可恢复文件并计算 MD5。

## 原理

- **PyInstaller 结构**：PyInstaller 把 Python 脚本、依赖与资源打包为单个 PE；运行时解压到 `sys._MEIPASS`。`pyinstxtractor.py` 解析 CArchive/PYZ，把 `.pyc` 与资源文件还原到 `<exe>_extracted/`。
- **资源路径**：样本的 `resource_path()` 优先使用 `sys._MEIPASS`，在打包后指向解包目录；`find_key_file('pr.pem')` 会去 `key/pr.pem` 找私钥。
- **加密链**：
  1. `generate_aes_key()` 用 `secrets.token_bytes(32)` 生成 AES-256 key；
  2. `encrypt_aes_key_with_rsa()` 用 `public_key.encrypt(aes_key, OAEP(MGF1(SHA256), SHA256))`，写入 `store.key`；
  3. `encrypt_file_aes_ecb()` 对 PDF 做 PKCS7(128) 填充，再用 `AES.MODE_ECB` 加密，输出 `.enc`。
- **为什么能恢复**：对称密钥不是从口令派生，而是随机生成后用 RSA 公钥封装；一旦拿到对应 RSA 私钥，就能解出 AES key。ECB 是确定性、无 IV，逐块解密即可；PKCS7 去填充后得到原始 PDF。
- **取证要点**：不要只搜 `.enc`；勒索程序自身可能携带私钥/公钥、密钥文件、配置或调试信息。PyInstaller 的 `_MEIPASS` 资源常被忽略，解包后应遍历所有目录（尤其 `key/`、`config/`、`resources/`）。
- **安全缺陷**：攻击者把私钥打包进样本，等于把解密能力交给取证方；真实勒索软件可能只在内存中使用公钥、私钥留在服务器，或使用每文件随机 key + 服务器封装。本场景适用于“样本自带私钥”的实现错误。

## 触发条件

- 拿到勒索样本（PE/ELF/ Mach-O）与加密后的文件、`store.key` 等密钥封装文件。
- 样本由 PyInstaller 打包，且资源中包含 RSA 私钥（`pr.pem`/`private_key.pem`）或可推导的密钥材料。
- 加密方案为 RSA-OAEP + AES-ECB（或可从反编译代码确认的类似混合加密）。
- 有 `pyinstxtractor`、Python 反编译工具（uncompyle6/decompyle3/pycdc）与 `cryptography`/`pycryptodome`。

## 利用步骤

1. `file`/`strings` 识别 PE 与 Python/PyInstaller 特征（如 `python3x.dll`、`PYZ`、`MEI`）。
2. 用 `pyinstxtractor.py en.exe` 解包，得到 `en.exe_extracted/`；遍历目录，查找 `key/`、`*.pem`、`*.key`、`*.json`。
3. 找到 `pr.pem`/`public_key.pem`，读取私钥；若 `.pyc` 有混淆，用 pycdc/decompyle 反编译主脚本，确认加密流程与文件扩展名。
4. 用私钥 `PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(store.key)` 得到 32 字节 AES key。
5. 对每个 `.enc` 文件用 `AES.new(aes_key, AES.MODE_ECB).decrypt()`，再 `unpad(..., 128)` 去 PKCS7，写回原文件名。
6. 计算恢复文件的 MD5/哈希，与业务基线/备份比对；抽查 PDF 能否正常打开。
7. 若解密失败，检查 OAEP 的 hash/MGF、key 长度、ECB/CBC 模式、填充方式与文件是否被二次加密。

## PoC

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import hashlib

with open('en.exe_extracted/key/pr.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())

with open('enpdf/store.key', 'rb') as f:
    encrypted_aes_key = f.read()

cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

with open('enpdf/pdfs/0999_内部文档0999.pdf.enc', 'rb') as f:
    encrypted_data = f.read()

cipher_aes = AES.new(aes_key, AES.MODE_ECB)
decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
print(hashlib.md5(decrypted_data).hexdigest())
open('0999_内部文档0999.pdf', 'wb').write(decrypted_data)
```

说明：原文答案为 `52fd2cb4fc43eceb3c79233038bb5f42`；PoC 未在本机复跑。

## 变体与关联

- **打包器变体**：PyInstaller、Nuitka、cx_Freeze、Electron asar；解包工具不同，但“遍历资源找密钥/配置”的思路一致。
- **加密变体**：RSA-OAEP/PKCS1v1.5 + AES-CBC/GCM/ChaCha20；CBC 需要 IV（可能存于文件头），GCM 需要 nonce/tag；ECB 无 IV，最容易恢复。
- **密钥位置变体**：内嵌 PEM、硬编码 hex、配置文件、注册表、环境变量、内存；样本自带的公钥可用于识别对应私钥。
- **关联卡片**：[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（PyInstaller C2 流量解密）、[[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]（勒索样本密钥流逆向）、[[defense-forensics-ransomware-entry-host-encrypted-last]]（勒索入口与加密顺序取证）、[[defense-incident-response-ransomware-pre-encryption-cleanup]]（勒索应急）。
- **边界**：真实勒索软件通常不把私钥放在样本中；若私钥在服务器或使用 ECDH/每文件密钥，需其他途径获取。ECB 只适合本场景的确定性加密。

## 检测与防御

- **检测（防守方）**：监控创建 `store.key`/`.enc` 文件、批量重命名、PDF 文件头被替换；用 YARA 匹配 PyInstaller + RSA/OAEP + AES-ECB 特征；检查样本资源中的 PEM 私钥。
- **防御**：备份（离线/不可变）是勒索恢复的核心；终端启用受控文件夹访问、最小权限、应用白名单；邮件/下载网关拦截未知 PE。
- **响应**：隔离样本与加密文件，保留原始哈希；先提取密钥/验证解密再批量恢复；排查横向移动与持久化；轮换可能泄露的凭据。
- **样本分析**：在隔离环境解包/反编译，不运行样本；对 `_MEIPASS` 资源做完整清单，不要只看入口脚本。
