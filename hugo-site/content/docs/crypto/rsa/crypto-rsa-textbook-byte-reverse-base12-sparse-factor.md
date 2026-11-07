---
id: crypto-rsa-textbook-byte-reverse-base12-sparse-factor
title: textbook RSA + 输出字节反转 + 12 进制稀疏多项式分解
type: scenario
domain: crypto
path: crypto/rsa
technique: textbook-rsa-byte-reverse-base12-sparse-polynomial-factorization
tags:
- crypto
- rsa
- textbook-rsa
- android
- jni
- pcap
- base-12
- sparse-polynomial
- factorization
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:38+08:00'
  notes: 已对照原文核对：JNI 0x100 字节常量 XOR 0xA7 得 n、e=65537、BigInteger(1,plaintext)、toByteArray 去前导零后字节反转再 hex、HELLO/MSG 文本协议与整行 hex、12 进制下 q=x^285+x^280+2x^240+2x^200+x^120+2x^40+1、p=n//q、phi/d 解密、flag 分片拼接均一致。未验证点：无 APK/PCAP 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-textbook-byte-reverse-base12-sparse-factor/
draft: false
kb_aliases:
- polarisCTF Whisper Line
- APK JNI libu.so
- 0xA7 XOR 模数
- 输出字节反转
- 12-adic
- base 12 sparse factorization
- Adic December
---

## 一句话结论

Android 客户端用 JNI 实现 textbook RSA（模数由 256 字节常量异或 `0xA7` 得到，`e=65537`，密文字节先去前导零再反转后转十六进制）；从 PCAP 还原 `MSG` 协议并取密文后，把 2044-bit 模数转成 12 进制，可发现其高位极其稀疏，按 `x=12` 的多项式形式恢复 `q = x^285 + x^280 + 2x^240 + 2x^200 + x^120 + 2x^40 + 1`，再 `p=n/q` 完成分解，解密得到对话中的 flag 分片。

## 原理

- **JNI 加密逻辑**：`Java_com_example_polarisctf_Z_x` 中有一段 0x100 字节常量与 `0xA7` 异或后构造 `BigInteger`，即 RSA 模数 `n`；指数固定 `65537`；明文按 `BigInteger(1, plaintext)` 解释，若 `>=n` 先取模，再 `m^e mod n`。
- **输出反转**：`toByteArray` 后去掉前导零字节，再对字节数组原地反转，最后转小写十六进制。因此解密时要先把密文十六进制转字节、反转、再按大端转整数。
- **PCAP 协议**：Java 层发送 `HELLO <name>`、`MSG <to> <cipherhex>`，整行 ASCII 再转十六进制写入 socket；按 TCP 流重组、整体 hex 解码后取 `MSG` 第三字段即密文。
- **12 进制稀疏结构**：设 `x=12`，把因子写成多项式：`p = x^285 + a(x)`（`deg a` 只有 39，系数很小），`q = x^285 + b(x)`（`b` 最高次 `x^280`）。展开
  `n = x^570 + b(x)x^285 + a(x)x^285 + a(x)b(x)`。
  `a(x)x^285` 只影响 285–324 次，`a(x)b(x)` 最高 319 次；因此 `n` 在 325 次以上的孤立高位只能来自 `b(x)x^285`，可直接从 `n` 的 12 进制高位读出 `b(x)` 的稀疏项。
- **恢复因子**：按读出的高位项构造 `q`，`p = n // q`；验证 `p*q == n`，再算 `phi=(p-1)(q-1)`、`d=e^{-1} mod phi`。
- **为什么成立**：题目没有用随机素数，而是用 12 进制下高度稀疏的多项式构造因子；常规 2044-bit 分解不可行，但稀疏结构把问题降为基数转换 + 整数除法。用户名 `Adic`/`December` 是 `12-adic` 的提示。

## 触发条件

- 目标是 textbook RSA（无 padding），模数/指数/密文可从 APK/PCAP 还原。
- 模数在某个基数（案例 12）下具有稀疏高位/低系数多项式结构，因子可写成 `x^k + 小次数多项式`。
- 攻击者能反编译 APK、提取 JNI 常量、重组 PCAP 流量。
- 已知明文前缀/对话格式可用于验证解密结果。

## 利用步骤

1. 反编译 APK，定位 `MainActivity` 与 JNI 方法 `Z.x`；从 `libu.so` 提取 256 字节常量，逐字节异或 `0xA7` 得到 `n`；确认 `e=65537` 与输出反转逻辑。
2. 用 Wireshark/tshark 按 TCP 流重组，hex 解码，提取 `HELLO`/`MSG` 行与 `MSG` 第三字段密文。
3. 把 `n` 转成 12 进制，观察高位稀疏性；按 `x=12` 的多项式形式恢复 `b(x)`，构造 `q`，计算 `p=n//q` 并验证。
4. 计算 `d=inverse(e, (p-1)(q-1))`；对每条密文：字节反转 → 大端整数 → `pow(c,d,n)` → 字节 → 文本。
5. 拼接对话中的 flag 分片，得到最终 flag。

## PoC

```python
# 1) 从 JNI 常量恢复 n
const = bytes.fromhex("...")          # libu.so 中 0x100 字节常量
n = int.from_bytes(bytes(b ^ 0xA7 for b in const), "big")
e = 65537

# 2) 12 进制观察（示意）
def to_base(n, b=12):
    ds = []
    while n:
        ds.append(n % b); n //= b
    return ds[::-1]

digits = to_base(n, 12)
# 高位稀疏：大部分高位为 0，非零项集中在少数位置

# 3) 按稀疏项构造 q（案例）
x = 12
q = x**285 + x**280 + 2*x**240 + 2*x**200 + x**120 + 2*x**40 + 1
assert n % q == 0
p = n // q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# 4) 解密 MSG 密文
cipherhex = "..."
c = int.from_bytes(bytes.fromhex(cipherhex)[::-1], "big")
m = pow(c, d, n)
pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(pt)
```

```text
# 对话中 flag 分片拼接示例
# xmctf{Th3_L0ud3st_Wh1sp3r_1s_1n_th3_PC4P_ju5t_RSA_4nd_4_L1ttl3_R3v3rs3}
```

## 变体与关联

- 基数变体：12 进制可换成其它小基数（2、3、10、16）；关键是因子在该基数下稀疏、低次数项系数小。
- 结构变体：`p = x^k + a(x)`、`q = x^k + b(x)` 的稀疏多项式分解；也可用 Coppersmith 的“已知高位因子”思路处理。
- 协议变体：文本行 + 整体 hex 编码可换成 JSON/二进制；先还原协议再取密文是通用步骤。
- 关联：[[crypto-rsa-fermat-close-prime-factorization]]（接近素数分解）、[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]（部分信息恢复）、[[ctf-crypto-rsa-shared-prime-batch-gcd]]（批量 GCD 分解）。

## 检测与防御

- 检测：RSA 模数在非标准基数下呈现稀疏/低系数结构；APK 中硬编码模数常量；输出字节反转等非标准编码；PCAP 中出现 textbook RSA 密文。
- 防御：使用标准 RSA 密钥生成（随机大素数、`e=65537`、OAEP 填充）；不要把模数/私钥硬编码在客户端；不要用字节反转等自定义编码替代标准序列化。
- 加固：移动端不要把私钥或可逆加密逻辑放在客户端；使用服务端密钥与 TLS；对协议做完整性校验。
