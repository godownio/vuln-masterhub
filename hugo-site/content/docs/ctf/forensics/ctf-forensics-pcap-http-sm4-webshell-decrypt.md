---
id: ctf-forensics-pcap-http-sm4-webshell-decrypt
title: PCAP 导出 HTTP 上传的加密 webshell：用脚本内置 SM4 实现、key 与密文解密还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-http-export-sm4-encrypted-webshell-decrypt
tags:
- ctf
- forensics
- pcap
- http
- sm4
- webshell
- traffic-analysis
- decryption
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:10:19+08:00'
  notes: 已对照原文与图 23/24/25 核对：Wireshark 导出 HTTP 对象 shell.php 5545 bytes；脚本内置 SM4 S 盒/FK/CK、key a8a58b78f41eeb6a 与 64 字符 Base64 密文（48 字节）；运行原脚本输出 flag{1ac380d6-5820-4e1a-b40e-ddf1789f6b0d}。原文实现/排版存在非标准与重复项，卡内已提示以导出脚本自身 decrypt 为准；未另用标准 SM4 复跑。
url: /docs/ctf/forensics/ctf-forensics-pcap-http-sm4-webshell-decrypt/
draft: false
kb_aliases:
- Checkwebshell
- 流量分析 SM4
- 加密 webshell 解密
- Wireshark 导出 HTTP 对象
- SM4-ECB 解密
- 密钥硬编码流量
---

## 一句话结论

Wireshark 从 PCAP 中导出 HTTP 对象，可拿到攻击者上传的加密 webshell/脚本；脚本里直接内置了自定义 SM4 实现、16 字节密钥 `a8a58b78f41eeb6a` 和 Base64 密文，调用脚本自身的 SM4 解密函数（不要盲目替换成标准 SM4）即可还原出 `flag{...}`。

## 原理

- **HTTP 对象导出**：Wireshark 的 `File > Export Objects > HTTP` 会按 HTTP 响应/请求重建传输的文件，保留文件名、大小和内容。加密 webshell 的上传/下载通常是一个 `text/html` 或 `application/x-www-form-urlencoded` 对象；本题导出的 `shell.php` 约 5.5 KB，其中包含加密逻辑和密文。
- **算法、密钥、密文同文件**：攻击者把 SM4 的 `FK`、`CK`、S 盒、轮函数、密钥和 Base64 密文都写进了脚本。只要拿到脚本，就不需要破解算法或爆破密钥；直接复现脚本的解密路径即可。
- **SM4 与 ECB**：SM4 是 128-bit 分组密码，密钥 16 字节；ECB 模式下每个 16 字节密文块独立解密，最后按 PKCS#7（或脚本自定义的 padding 字节）去填充。本题密文为 64 字节 Base64 解码后 48 字节（3 个块），明文为短 flag。
- **为什么不能直接套标准实现**：原文的 SM4 代码在排版/实现上有非标准之处（例如 S 盒表存在重复值、`crypt_block` 的轮移/反转顺序与常见实现不同），用标准 SM4 库直接解密可能得到乱码。应以导出文件里的 `class SM4`/`decrypt` 为准，或先用已知明文/填充验证实现是否等价。
- **为什么这条链成立**：流量包保留了完整的 HTTP 对象，密文与密钥都在对象内；ECB 无 IV/随机数，密钥固定，离线可重复解密。攻击者的“加密 webshell”只提高了流量特征隐蔽性，没有保护密钥。

## 触发条件

- 拿到包含 HTTP 上传/下载流量的 PCAP，且对象未被分块压缩/加密传输（HTTP 明文或已解密 TLS）。
- 导出的脚本/webshell 内包含完整加密实现、密钥和密文，或密钥可从同包其他对象/配置中得到。
- 使用可运行的 Python/PHP 环境复现脚本中的解密函数；若脚本是 PHP webshell，则需要对应的 PHP 运行时或把算法移植到 Python。
- 目标算法为分组密码的 ECB/固定 IV 模式，或密钥/IV 已随脚本泄露。

## 利用步骤

1. 用 Wireshark 打开 PCAP，`File > Export Objects > HTTP`，按大小/文件名筛出可疑的 `shell.php`、`*.php`、`*.txt`、`*.bin` 对象并保存。
2. 在导出文件中搜索 `SM4`、`Sbox`、`FK`、`CK`、`key`、`base64`、`decrypt` 等特征，定位密钥与密文。
3. 直接调用导出文件中的解密函数（若是 PHP，用对应 PHP 版本执行；若是 Python，修好排版后运行），不要先入为主替换成标准库实现。
4. 解密后按脚本的 padding 规则去填充；若输出乱码，检查字节序、分组顺序、S 盒/轮移实现是否与标准不同，或改用脚本自己的 `decrypt`。
5. 读取明文中的 flag；若脚本还包含回连/命令逻辑，可进一步还原 C2 地址、密钥与操作记录。

## PoC

```python
# 前提：从 PCAP 导出的脚本中已取得 class SM4 的完整实现
# 原文的 key 与密文如下（密文为 Base64）
key = b"a8a58b78f41eeb6a"
ciphertext = "VCWBIdzfjm45EmYFWcqXX0VpQeZPeI6Qqyjsv31yuPTDC80lhFlaJY2R3TintdQu"

# 使用导出脚本自带的 SM4 实现（其 S 盒/轮函数与标准实现可能有差异）
sm4 = SM4(key)
print(sm4.decrypt(ciphertext))
# 原文结果：flag{1ac380d6-5820-4e1a-b40e-ddf1789f6b0d}
```

若导出文件是 PHP，可在隔离环境执行其 `decrypt` 方法；若只想用 Python，需先把脚本中的 `SM4` 类、`SboxTable`、`FK`、`CK` 和 `crypt_block` 原样移植。原文未在本机复跑，且其 S 盒表存在重复项，直接用标准 SM4 库不一定得到同一明文。

## 变体与关联

- **算法变体**：AES-CBC/ECB、DES、RC4、XXTEA、自定义异或流等；关键是先在导出对象中找算法常量和密钥，再决定是否需要逆向。
- **密钥不在同文件**：可从同包的其他上传对象、配置文件、JS 前端、内存镜像或日志中找密钥；也可对弱密钥做字典爆破。
- **传输层加密**：若 PCAP 是 TLS，需要 keylog/私钥解密后再导出 HTTP 对象；否则只能做流量特征分析（大小、时序、域名）。
- **加密 webshell 检测**：关注上传的 PHP 文件包含 `base64_decode`、大整数常量、`Sbox`/`FK`/`CK`、循环移位等特征，以及请求体中的高熵 Base64 字符串。
- 关联：[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（HTTP 流量中的 XOR 密钥恢复）、[[ctf-forensics-pcap-custom-base64-tcp-protocol]]（自定义协议解码）、[[ctf-reverse-custom-sm4-24round-native-so-decrypt]]（SM4 变体逆向）。

## 检测与防御

- **检测**：HTTP 上传对象中出现高熵 Base64、SM4/AES 常量、`Sbox`/`FK`/`CK` 等特征；webshell 文件大小异常、内容混淆；同一客户端短时间内上传脚本并访问。
- **防御**：上传目录禁用脚本执行、白名单校验文件类型并对内容做静态检测；WAF 检测混淆/加密 webshell；对出站流量做 TLS 检查与对象留存；不要依赖“加密 webshell”作为隐蔽手段，密钥一旦随文件落地即可被离线解密。
- **取证建议**：保留原始 PCAP 哈希，导出对象后在副本上分析；记录导出文件名、大小、HTTP 五元组和时间，便于与主机日志关联。
