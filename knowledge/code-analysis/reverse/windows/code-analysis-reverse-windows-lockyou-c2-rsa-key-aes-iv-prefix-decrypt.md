---
id: code-analysis-reverse-windows-lockyou-c2-rsa-key-aes-iv-prefix-decrypt
title: Lockyou 勒索样本解密：向 C2 取 RSA 私钥解出单把 AES key，按文件头 16 字节 IV 做 AES-CBC 还原 .locky 文件
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: lockyou-c2-rsa-privatekey-aes-iv-prefix-decrypt
aliases:
- Lockyou 勒索
- ScadaDB.sql.locky 解密
- 勒索样本 RSA 私钥解密
- encryptedAesKey 解密
- 文件头 IV AES-CBC
- .NET 勒索逆向
- C2 下发 privateKey
tags:
- windows
- ransomware
- dotnet
- rsa
- aes-cbc
- file-decryption
- malware-analysis
- iv-prefix
- c2
- scada
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-11T00:00:30+08:00'
  notes: 已对照原文全文与22/22图核对：Lockyou.exe为PE32 Mono/.NET(~232KB)、AESCrypto从http://39.101.170.47/取privateKey(XML)与encryptedAesKey、RSACryptoServiceProvider.FromXmlString+Decrypt(rgb,false)(PKCS#1v1.5)、EncryptFile先写GenerateIV的16字节IV再CryptoStream加密并删除原文件、AES key base64 cli9gqXpTrm7CPMcdP9TSmVSzXVgSb3jrW+AakS7azk=、勒索说明2BTC、.locky扩展名、解密后ScadaDB.sql含flag04，均与图/原文一致。卡片将原文全零IV脚本改写为读取真实IV前缀，属正确改进且已注明。与PyInstaller RSA-OAEP/AES-ECB、CryptNet每文件key/RSA封装文件尾、CryptoAPI key/IV恢复等勒索卡机制不同，非重复；无sources/文章ID/URL(仅C2 IOC)/长段摘录，路径合法；原文无组件版本，versions为空。单卡为一条完整解密场景，颗粒度可
---

## 一句话结论

Lockyou 是一个 .NET 勒索程序：启动时从硬编码 C2 `http://39.101.170.47/` 分别 GET `privateKey`（XML 格式 RSA 私钥）与 `encryptedAesKey`（Base64 的 RSA 密文），用私钥做 RSA PKCS#1 v1.5 解密得到一把 32 字节 AES key；加密时用该 AES key 对目标文件做 AES-CBC，并把 16 字节 IV 明文写在 `.locky` 文件最前面、其后才是密文，最后删除原文件。拿到这对 privateKey/encryptedAesKey（样本自己就会从 C2 拉取）后，按“RSA 解出 AES key → 取文件头 16 字节为 IV → AES-CBC 解密其余部分”即可还原 `ScadaDB.sql`。

## 原理

- **密钥分发设计缺陷**：`AESCrypto` 构造函数里 `PRIVATE_KEY = GetHttpContent(BACKEND_URL + "privateKey")`、`AES_KEY_ENC = GetHttpContent(BACKEND_URL + "encryptedAesKey")`、`AES_KEY = DecryptRSA(AES_KEY_ENC, PRIVATE_KEY)`。样本把 RSA **私钥**也放在 C2 上通过无认证的 HTTP GET 下发，任何能访问该 C2 的人都能取得同一对材料；`GetHttpContent` 使用 `WebRequest` 发 GET，`Content-Type: application/x-www-form-urlencoded`，并附带 `Authorization: Basic base64(...)` 头。
- **RSA 解密**：`DecryptRSA` 使用 `RSACryptoServiceProvider.FromXmlString(privateKey)` 载入 `<RSAKeyValue>` XML 私钥，`Convert.FromBase64String(encryptedData)` 后 `Decrypt(rgb, false)`，即 RSA PKCS#1 v1.5；解出的字节就是 AES key（Base64 `cli9gqXpTrm7CPMcdP9TSmVSzXVgSb3jrW+AakS7azk=`）。
- **文件加密格式**：`EncryptFile` 中 `AesCryptoServiceProvider` 设置 `Key = AES_KEY`、`GenerateIV()`，先在输出文件写入 `cryptoServiceProvider.IV`（16 字节明文），再把原文件经 `CryptoStream` 加密写入，最后删除原文件。因此 `.locky` 文件 = `IV(16B) || AES-CBC(文件内容)`，扩展名被改为 `.locky`；样本还会释放勒索说明 `如何解密你的文件.txt`、替换壁纸并要求 2 比特币。
- **为什么可以解密**：AES-CBC 解密第 i 个密文块需要前一个密文块作为 IV，而文件头已经以明文保存了真正的 IV；用该 IV 解密 `IV` 之后的密文即可得到完整明文。文章脚本用全零 IV 解密整个文件也能得到除前 16 字节外的正确数据，原因正是前 16 字节本身是 IV、不是原文数据——正确做法应读取前 16 字节作为 IV 并只解密其余部分。
- **样本特征**：`Lockyou.exe` 为 32 位 .NET（PE32, Mono/.NET assembly，约 232 KB），目标扩展名列表包含 `.bak`、`.doc`、`.docx`、`.pptx`、`.gif`、`.zip`、`.csv`、`.sql`、`.ini`、`.html`、`.php`、`.js`、`.css`、`.py`、`.cpp`、`.c` 等；`EncryptFileStart` 还使用 `MD5(insertKey)` 生成十六进制串（可能与文件标记/密钥派生相关）。

## 触发条件

- 主机已运行 `Lockyou.exe` 且文件被加密为 `.locky`；C2 `http://39.101.170.47/` 可访问（或已获得 `privateKey` 与 `encryptedAesKey` 两份材料）。
- 分析环境可运行 .NET 反编译（dotPeek/dnSpy）与 Python（pycryptodome）进行解密。
- 若 C2 已下线且未保存私钥材料，则只能尝试从样本/内存/流量中恢复 AES key，难度显著增加。

## 利用步骤

1. 从被加密主机取得 `Lockyou.exe` 与任一 `.locky` 文件；`file` 确认样本为 .NET PE32。
2. 用 dotPeek/dnSpy 反编译，定位 `AESCrypto` 构造函数与 `EncryptFile`/`DecryptRSA`，确认 C2 地址、`privateKey`/`encryptedAesKey` 端点与文件格式（IV 前缀）。
3. 访问 `http://<C2>/privateKey` 与 `http://<C2>/encryptedAesKey` 取得两份材料（或使用应急响应中已提取的副本）。
4. 将 XML 私钥转为 PEM（`<RSAKeyValue>` 的 Modulus/Exponent/P/Q/DP/DQ/InverseQ/D 可直接转 PKCS#8），用 RSA PKCS#1 v1.5 解密 `encryptedAesKey` 得到 AES key。
5. 对每个 `.locky` 文件：读取前 16 字节为 IV，AES-CBC 解密剩余内容，写回原文件名；校验还原文件（如 SQLite/SQL Server 备份头）是否完整。
6. 若样本使用同一把 AES key 加密所有文件，只需解一次 key；若遇到每文件不同 key 的变体，按变体格式调整。

## PoC

最小解密脚本（Python，需 `pycryptodome`；示意，未在本机对真实样本运行）：

```python
import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

# 1) 先用工具（如 ssleye XML->PEM）或 openssl 把 XML RSAKeyValue 转成 PEM
pem = open('privateKey.pem', 'rb').read()

# 2) RSA 解密 encryptedAesKey 得到 AES key
enc_key = base64.b64decode(open('encryptedAesKey.b64', 'rb').read())
rsa_key = RSA.import_key(pem)
aes_key = PKCS1_v1_5.new(rsa_key).decrypt(enc_key, None)

# 3) 文件头 16 字节为 IV，解密其余部分
blob = open('ScadaDB.sql.locky', 'rb').read()
iv, ciphertext = blob[:16], blob[16:]
plain = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ciphertext)
open('ScadaDB.sql', 'wb').write(plain)
```

说明：文章中的脚本直接把整段密文用全零 IV 解密，依赖“前 16 字节是 IV”这一事实，仅首个明文块为垃圾；上面的写法读取真实 IV 更规范。XML 私钥转 PEM 可用现成工具完成后再喂给脚本。

## 变体与关联

- 关联：[[code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv]]（每文件随机 AES key/IV、RSA 公钥封装 key/IV 附文件尾的混合加密格式）、[[defense-forensics-bianlian-ransomware-hardcoded-aes-cbc-offset-decrypt]]（硬编码 AES-CBC 与偏移解密）、[[defense-incident-response-ransomware-pre-encryption-cleanup]]（勒索前置清理与响应）。
- 变体：AES key 可能内嵌样本或由 C2 下发；IV 可能在文件头、文件尾或固定；可能每文件独立 key；扩展名/勒索说明/壁纸可替换；部分变体会使用 RSA-OAEP 或混合加密封装。
- 边界：C2 下线且无私钥则无法直接解密；若文件被部分加密/截断，需按样本逻辑确认偏移与块大小；本卡结论基于该 .NET Lockyou 样本的代码与一次成功解密，其他家族需重新逆向。

## 检测与防御

- **应急响应**：隔离主机、保留 `Lockyou.exe`、`.locky` 样本、C2 流量与内存镜像；优先尝试从 C2/样本/内存恢复 `privateKey` 与 `encryptedAesKey`；不要按勒索说明支付。
- **检测**：监控硬编码 IP `39.101.170.47` 的 HTTP GET `privateKey`/`encryptedAesKey`；关注 `.locky` 扩展名批量改名、勒索说明文件与壁纸替换；.NET 样本可用 dnSpy 检查 `AESCrypto`/`EncryptFile` 特征字符串。
- **防御**：关键数据库离线/异地备份并验证可恢复性；限制服务器出站访问；应用白名单阻止未知 .NET 程序；对工控/SCADA 网络做分区隔离，避免工程师站直接暴露于可被勒索软件横向移动的网段。
