---
id: code-analysis-reverse-crypto-encoding-identification-decrypt
title: 逆向中加密算法与编码识别：从常量/S 盒/轮数/密钥索引特征定位算法并提取密钥解密
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: disassembly-crypto-encoding-identification
tags:
- reverse-engineering
- crypto
- identification
- aes
- des
- rc4
- rsa
- sm4
- tea
- xtea
- xxtea
- md5
- sha
- base64
- findcrypt
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T13:15:31+08:00'
  notes: 已对照原文与 61 张图核对：MD5 初始常量、AES S 盒/轮数/四步、DES、RC4 KSA/PRGA、SM4 FK/CK/S盒、TEA/XTEA/XXTEA delta 与密钥索引、RSA gmpz_powm、base16/32/58/64 特征均与原文一致；XOR PoC 数组与原文一致（可解出 strongpass）。该卡为识别方法总览，dedup 为 related（具体算法卡），保留；未逐算法跑全量逆运算。
url: /docs/code-analysis/reverse/code-analysis-reverse-crypto-encoding-identification-decrypt/
draft: false
kb_aliases:
- 加密算法识别
- FindCrypt 常量识别
- AES S 盒识别
- RC4 S 盒初始化
- SM4 FK/CK 识别
- TEA delta 识别
- MD5 初始常量
- base 编码识别
- 逆向解密
---

## 一句话结论

逆向遇到“输入经过一段看不懂的变换后与目标数组/摘要比较”时，先按固定常量、查表和循环指纹识别算法：MD5 的 `0x67452301/0xefcdab89/0x98badcfe/0x10325476`、AES 的 S 盒与 10/12/14 轮、DES 的 IP/16 轮 Feistel、RC4 的 256 字节 S 盒初始化、SM4 的 FK `0xa3b1bac6...` 与 CK `0x00070e15...`、TEA 系列的 `0x9e3779b9`（TEA 固定 `key[0..3]`、XTEA 用 `key[sum&3]`、XXTEA 多块循环）、RSA 的大数模幂与 `n/e/c` 初始化；识别后从内存/`init_set_str` 提取密钥或密文，按算法逆运算（RC4/TEA 系列加解密同构、AES 逆轮密钥、RSA `pow(c,d,n)`）恢复明文。base16/32/58/64 只是编码，直接解码即可。

## 原理

- **固定常量是算法指纹**：分组/流密码和哈希在实现中必然包含规范规定的初始值、S 盒、轮常量或魔数；编译器可能改变指令形式，但常量数值和查表结构保留。搜索这些值即可从大量函数中快速锁定加密点。
- **结构指纹补充常量**：AES 的 SubBytes（S 盒查表）→ ShiftRows（行循环移位）→ MixColumns（GF(2⁸) 矩阵乘）→ AddRoundKey（异或轮密钥）四步循环；DES 的 IP/16 轮 Feistel/8 个 S 盒；RC4 的 256 次 `S[i]=i` 初始化、用密钥打乱 S 盒、PRGA 生成密钥流后异或；TEA 系列的 `sum += delta` 与移位/异或混合运算。即使常量被改，循环结构仍可辨认。
- **哈希不可逆，加密可逆**：MD5/SHA 用于“输入摘要 == 目标摘要”时只能爆破/字典；对称加密（AES/DES/RC4/SM4/TEA 系列）在密钥泄露或硬编码时可逆；RSA 在私钥泄露或模数可分解时可逆。
- **编码不是加密**：base16/32/58/64 只是把二进制转可打印字符，看到码表/填充/进制转换即可直接解码；`base58check` 额外带 4 字节 SHA-256 校验，`base64` 用 `+/` 或 URL-safe 的 `-_`。
- **密钥常在进程内**：硬编码密钥是 `.rdata/.data` 里的固定数组；运行时派生的密钥可用断点/内存 dump 在加密调用前取得；RSA 的 `n/e/c` 常以字符串交给 `gmpz_init_set_str` 或大整数数组。
- **算法识别决定逆推路径**：确认算法后才能选择正确工具（CyberChef、Python 库、IDA 脚本）和参数（模式、IV、轮数、端序、填充）；识别错算法会得到乱码。

## 触发条件

- 二进制/固件/脚本中存在不可读的变换函数，输入与固定数组、摘要或密文比较，或网络流量被加密。
- 程序带有固定常量、S 盒、轮常量或明显加密循环（可通过 IDA FindCrypt、常量搜索、字符串/导入表定位）。
- 密钥硬编码、可从内存 dump，或算法参数（密钥长度、轮数、IV）在代码中可见。
- 目标是 crackme/CTF 题、恶意样本配置解密或授权校验，允许静态分析与动态调试。

## 利用步骤

1. **先查哈希/编码**：在二进制中搜索 MD5 初始常量 `0x67452301/0xefcdab89/0x98badcfe/0x10325476`、SHA-256/512 常量表；若命中且最后是摘要比较，走爆破/字典路线。看到 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`、`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` 等码表则按 base 解码。
2. **再查对称加密**：用 IDA FindCrypt 或手动搜索 AES S 盒首字节 `0x63` 起始的 256 字节表、SM4 S 盒 `0xd6,0x90,0xe9`、SM4 FK `0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc`、CK `0x00070e15,0x1c232a31...`、TEA delta `0x9e3779b9`、RC4 的 256 字节 `0..255` 初始化循环。
3. **确认结构与参数**：AES 数轮密钥数量（11 组=AES-128、13=AES-192、15=AES-256）并确认 ECB/CBC/CTR；DES 找 IP/IP⁻¹ 与 16 轮 Feistel；RC4 找 KSA 与 PRGA；TEA 系列看密钥索引是固定 `key[0..3]`（TEA）、`key[sum&3]`/`key[(sum>>11)&3]`（XTEA）还是多块 `for(p=0;p<n-1;p++)`（XXTEA）。
4. **定位密钥/密文**：在加密函数入口下断点，dump 密钥数组、IV、输入缓冲区与输出；或从 `.rdata/.data` 直接读取硬编码数组。RSA 场景记录 `gmpz_init_set_str` 的 `c/n/e` 三个参数与 `gmpz_powm` 的调用顺序。
5. **逆运算**：对称算法用相同密钥解密（RC4/TEA 系列加解密同构，AES/DES/SM4 用逆轮密钥/逆 S 盒）；RSA 若 `n` 可分解则 `d=invert(e,(p-1)(q-1))`、`m=pow(c,d,n)`，若明文空间小可直接枚举；哈希则用字典/掩码爆破。
6. **验证**：解密结果应为可打印字符串/已知文件头（如 `flag{`、PNG `89 50 4E 47`、PE `MZ`）；不符则检查端序、填充、IV、轮数与自定义变体。

## PoC

```python
from Crypto.Util.number import long_to_bytes, inverse

# 1) XOR：从反汇编提取密文数组 PArray 与硬编码 keyStore
PArray  = [38, 34, 37, 55, 55, 61, 33, 51, 32, 39]
keyStore = [85, 86, 87, 88, 89, 90, 81, 82, 83, 84]   # U V W X Y Z Q R S T
print(bytes(c ^ k for c, k in zip(PArray, keyStore)))   # b'strongpass'

# 2) RSA：gmpz_init_set_str(c, n, e) + gmpz_powm(input, input, e, n)
#    若 n 可分解（小素数/已知 p,q），恢复 d 后解密：
c = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35
n = 103461035900816914121390101299049044413950405173712170434161686539878160984549
e = 65537
# p, q = factor(n)                      # 需实际分解
# d = inverse(e, (p - 1) * (q - 1))
# m = pow(c, d, n); print(long_to_bytes(m))

# 3) RC4：识别 256 字节 KSA + PRGA 后，用同一密钥重新生成密钥流异或
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

# 4) TEA 解密核心（与加密对称，使用相同 key，sum 从 delta*rounds 递减）
def tea_decrypt(v0, v1, key, rounds=32):
    delta = 0x9e3779b9; s = (delta * rounds) & 0xffffffff
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1]))) & 0xffffffff
        s = (s - delta) & 0xffffffff
    return v0, v1
```

说明：XOR 示例与 RSA 参数取自原文（原文 RSA 示例用自行生成的 p/q 演示 `m=pow(c,d,n)`，实际题目需先分解 `n`）；AES/DES/SM4/XXTEA 的逆运算可用 CyberChef 或对应库完成，关键在于先确认模式、IV、轮数与端序。

## 变体与关联

- 变体：常量被魔改（自定义 S 盒、改 FK/CK、改 delta、24 轮 SM4、RC4 改轮数/减代替异或）时，先按结构识别“像哪个算法”，再按实际表/参数重写逆运算。
- 变体：只看到哈希常量（MD5/SHA）且目标不可逆，只能字典/掩码/约束爆破；若原文摘要前有自定义变换，需先把变换逆掉。
- 变体：RSA 的 `n/e/c` 由 `gmpz_init_set_str` 以十六进制/十进制字符串传入；确认 base 与端序，必要时对 `n` 做因子分解或利用小指数/共模等缺陷。
- 关联：[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（SM4 常量识别与小端解密）、[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]（AES 轮常量魔改）、[[ctf-reverse-apk-jni-username-xtea-hex-sse-compare]]（XTEA 密钥派生）、[[code-analysis-reverse-windows-game-packet-buffer-encryption-locate]]（封包加密定位）。
- 边界：白盒密码/密钥与算法重度混淆、运行时密钥派生依赖设备指纹时，静态提取可能不可行，需要动态 dump 或模拟执行。

## 检测与防御

- 检测（逆向侧）：FindCrypt/常量搜索命中、S 盒初始化循环、256 字节表、`0x9e3779b9`、`gmpz_powm`、`EVP_Encrypt*`/`CryptEncrypt` 等 API 都是加密实现的强特征；结合字符串 “AES/DES/RC4/SM4” 与错误提示可进一步确认。
- 防御（软件作者）：不要硬编码密钥；使用密钥管理/KDF 与设备绑定；对关键算法做白盒化/自定义变体并配合完整性校验与反调试；避免在客户端做可逆的授权判断。
- 防御（检测硬编码密钥）：代码审计中搜索 `0x9e3779b9`、S 盒、`gmpz_init_set_str` 与大整数数组；对二进制做熵/常量扫描，发现硬编码密钥后评估其保护的数据范围。
