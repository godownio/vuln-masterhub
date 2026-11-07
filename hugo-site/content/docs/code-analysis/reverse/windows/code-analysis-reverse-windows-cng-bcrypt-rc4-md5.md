---
id: code-analysis-reverse-windows-cng-bcrypt-rc4-md5
title: Windows CNG BCrypt API 定位：RC4/MD5 协议与 MD5 原像
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-cng-bcrypt-rc4-md5
tags:
- reverse
- windows
- cng
- bcrypt
- rc4
- md5
- protocol
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:14:24+08:00'
  notes: 已对照原文与图17/19/21/23核对：bcrypt.dll 导入、BCryptOpenAlgorithmProvider 断点看 pszAlgId、.data 中 R/C/4 与 M/D/5 字符串、BCryptEncrypt thunk、4 字节大端长度+RC4 协议、username MD5 目标 E5D489FD91431D5438EB28F7490F9CE0→ctfer、serial 62001be6b65779c64e67deb560164745（MD5(easyre)）与服务端 AES-CBC 回包均一致。未验证点：原文对算法用“猜测”措辞，图21 字符串支持 RC4/MD5；PoC 未复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-cng-bcrypt-rc4-md5/
draft: false
kb_aliases:
- BCryptOpenAlgorithmProvider
- Windows CNG
- RC4/MD5 识别
- 控制流平坦化
- easyre
- MD5 原像
---

## 一句话结论

样本通过 Windows CNG（`bcrypt.dll`）实现协议加密；在 `BCryptOpenAlgorithmProvider` 下断并查看 `pszAlgId` 即可确认算法为 RC4 与 MD5；协议为“4 字节大端长度 + RC4 数据”，用户名校验是 `MD5(username).upper()` 与目标值比较，短用户名可爆破出原像，serial 则是固定 MD5 字符串。

## 原理

- Windows CNG 的算法通过 `BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, ...)` 打开；`pszAlgId` 是宽字符串算法名（如 `RC4`、`MD5`、`AES`）。在调试器中对该 API 下断，查看第二个参数即可识别算法，无需逆向全部加密代码。
- 协议：客户端先发送 4 字节大端长度，再发送 RC4 加密后的用户名；服务端 RC4 解密后校验。第一阶段通过后，同样格式发送 serial；服务端回包用 AES-CBC 处理。
- 用户名校验：`MD5(username)` 转 32 字节大写十六进制，与 `E5D489FD91431D5438EB28F7490F9CE0` 比较；对短小写字母串爆破即可得到 `ctfer`。
- serial 校验：服务端直接字符串比较目标值 `62001be6b65779c64e67deb560164745`（恰好是 `MD5("easyre")`），区分大小写；提交该字符串即可。
- 控制流平坦化会增加静态分析难度，但动态断在 CNG API + 观察协议数据即可绕过。

## 触发条件

- Windows 样本导入 `bcrypt.dll` 的 `BCryptOpenAlgorithmProvider`/`BCryptHashData`/`BCryptEncrypt`/`BCryptDecrypt`。
- 客户端/服务端使用长度前缀 + 对称加密的简单协议。
- 校验使用 MD5 十六进制比较或固定字符串比较。
- 有本地/远程服务端可交互，或可动态调试客户端。

## 利用步骤

1. 查看导入表，确认 `bcrypt.dll` 相关 API。
2. 在 `BCryptOpenAlgorithmProvider` 下断，运行样本并输入测试数据；读取 `pszAlgId`，记录 RC4/MD5/AES 等算法。
3. 在 `BCryptHashData`/`BCryptEncrypt`/`BCryptDecrypt` 下断，抓取明文/密文/长度，还原协议格式。
4. 提取用户名 MD5 目标值，爆破短字符串原像（如 `hashcat -m 0` 或小写字母枚举）。
5. 提取 serial 目标值；若像 MD5，尝试常见原像或直接提交目标字符串。
6. 按协议构造长度 + RC4 加密数据，发送并读取服务端回包（AES-CBC 解密）。

## PoC

```python
import hashlib
import itertools
import string

target = "E5D489FD91431D5438EB28F7490F9CE0"
for n in range(1, 8):
    for tup in itertools.product(string.ascii_lowercase, repeat=n):
        s = "".join(tup)
        if hashlib.md5(s.encode()).hexdigest().upper() == target:
            print("username =", s)
            raise SystemExit
```

```python
# 协议伪代码：4 字节大端长度 + RC4 数据
import struct, socket

def send_rc4(sock, data: bytes, key: bytes):
    # rc4() 为 RC4 实现
    enc = rc4(key, data)
    sock.sendall(struct.pack(">I", len(enc)) + enc)
```

## 变体与关联

- 变体：CNG 算法换成 AES/SHA-256/HMAC；同样通过 `pszAlgId` 识别。
- 变体：长度前缀可能是小端/变长；RC4 可能被替换为自定义流密码。
- 变体：用户名/序列号校验可能是 MD5、SHA-1、CRC 或固定字符串。
- 关联：[[code-analysis-reverse-windows-api-hook-hidden-aes-branch]]（Windows 加密 API/hook）、[[ctf-reverse-right-shift-constraint-md5-bruteforce]]（MD5 爆破）、[[crypto-hash-md5-digest-strcmp-nullbyte-truncation]]（MD5 比较缺陷）。

## 检测与防御

- 检测：导入 `bcrypt.dll`、调用 `BCryptOpenAlgorithmProvider` 的样本；协议中出现长度前缀 + 高熵数据。
- 防御：不要用 MD5 做认证；使用带盐的强 KDF（PBKDF2/Argon2）或 HMAC；协议加入随机数与完整性保护。
- 响应：确认弱哈希/固定 serial 后，轮换凭据并升级认证方案。
