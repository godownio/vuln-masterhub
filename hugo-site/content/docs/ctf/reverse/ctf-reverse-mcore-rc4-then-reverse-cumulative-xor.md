---
id: ctf-reverse-mcore-rc4-then-reverse-cumulative-xor
title: M·CORE 固件逆向：先 RC4（key=testkey）再对结果做「从后往前累加异或」，倒序一次即可还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: rc4-then-reverse-cumulative-xor-decrypt
tags:
- ctf
- reverse
- rc4
- xor-chain
- mcore
- ida
- firmware
- decrypt
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:39:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；.text 中 testkey、.rodata 里 10 个 .long + 1 个 .short 共 42 字节、rc4_crpyt 特征、以及 unxor 从 n-1 递减做 buf[i-1]^=buf[i] 的解密顺序均与正文一致；卡片补的「末字节为 } 说明还有一层反向异或」这一判据来自正文『套个板子发现是乱码，但最后一位是}，猜测是倒序按位异或』的表述，属合理归纳；M·CORE/IDA 插件来源正文给了链接（未访问）；
url: /docs/ctf/reverse/ctf-reverse-mcore-rc4-then-reverse-cumulative-xor/
draft: false
kb_aliases:
- ezCsky
- M·CORE 逆向
- rc4_crypt 识别
- 倒序累加异或
- reverse cumulative xor
- RC4 后接差分异或
- 末位是右花括号判断法
---

## 一句话结论

题目把 `.rodata` 里的 42 字节密文先做标准 RC4（key 就明写在 `.text` 里的 `"testkey"`），再做一遍 `for (i = n-1; i > 0; i--) buf[i-1] ^= buf[i]` 的**反向累加异或**；解密时顺序反过来——先按同样的 `i` 从 `n-1` 递减做一次同式异或（该变换自逆），再做 RC4 解密即可。判断有没有这一步的捷径是：只解 RC4 得到乱码但**最后一位是 `}`**，说明明文经过「从后往前」的链式处理。

## 原理

- **反向累加异或是自逆的**：`buf[i-1] ^= buf[i]` 从 `i=n-1` 递减到 `1` 执行。异或的对称性使它满足「再执行一遍就还原」——但必须以**同样的递减顺序**重跑，因为第 `i-1` 位依赖已经被更新过的第 `i` 位。
- **为什么最后一位不受影响**：循环条件是 `i > 0`，`buf[n-1]` 全程没有被写过，所以它等于 RC4 之后的原值。如果 `buf[n-1]` 解出来是 `}`，而其余字节是乱码，就强烈提示存在「从后往前」的链式变换，而不是密钥/轮数错了。
- **RC4 是流密码，加解密同一操作**：KSA 用 key 打乱 256 字节 S 盒，PRGA 逐字节产出 keystream 异或。因此「解 RC4」就是拿同一 key 再跑一遍，不需要逆 S 盒。
- **顺序不能颠倒**：加密顺序是 `RC4 → 反向累加异或`，所以解密必须是 `反向累加异或（同式重跑）→ RC4`。若先 RC4 再 xor，会得到完全不同的乱码。
- **M·CORE 是 32/16 位混合指令集**：IDA 默认不认，需要额外处理器模块；数据在 `.rodata` 按 `.long`/`.short` 混排出现，必须按小端拼回字节序再当密文，否则长度和前几位都会错。

## 触发条件

- 逆向出「S 盒 256 字节 + KSA `j=(j+S[i]+key[i%k])%256` + PRGA `t=(S[i]+S[j])%256`」这一串特征，函数名可能被改成 `rc4_crypt` 之类但仍能按结构识别。
- 密文之后还有一段逐字节、按下标递减的异或循环（典型 `buf[i-1] ^= buf[i]`）。
- key 与密文都能从二进制静态取出（本例 key 明写为字符串常量）。

## 利用步骤

1. 识别算法家族：在目标函数里找 256 字节 S 盒初始化 + 两轮交换 + `S[(S[i]+S[j])%256]` 取 keystream，即 RC4（可能被改名，如 `rc4_crpyt`）。
2. 静态取 key（`.text` 里的字符串常量，本例 `testkey`）与密文（`.rodata` 里 `.long`/`.short` 混排，按小端展开成字节；注意最后可能只有 2 字节的 `.short`）。
3. 先只做 RC4 解密，检查结果：若整体乱码但**末字节为 `}`**，说明还有一层「反向累加异或」，继续第 4 步。
4. 对 RC4 输出重跑同式反向累加异或：`for i in range(n-1, 0, -1): buf[i-1] ^= buf[i]`。
5. 校验可打印性与 `flag{...}` 格式；若仍乱码，优先怀疑字节序（`.long` 拼回顺序）、密文长度（漏了尾部 `.short`）、以及是否该先 xor 后 RC4。

## PoC

```python
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def unxor(data: bytes) -> bytes:
    d = bytearray(data)
    for i in range(len(d) - 1, 0, -1):
        d[i - 1] ^= d[i]
    return bytes(d)

# .rodata 里的 .long/.short 按小端展开后的 42 字节
# 0x08B88F96 -> 96 8F B8 08，最后一条 .short 0xD1ED -> ED D1
enc = bytes([
    0x96, 0x8f, 0xb8, 0x08, 0x5d, 0xa7, 0x68, 0x44, 0xf2, 0x64,
    0x92, 0x64, 0x42, 0x7a, 0x78, 0xe6, 0xea, 0xc2, 0x78, 0xb8,
    0x63, 0x9e, 0x5b, 0x3d, 0xd9, 0x28, 0x3f, 0xc8, 0x73, 0x06,
    0xee, 0x6b, 0x8d, 0x0c, 0x4b, 0xa3, 0x23, 0xae, 0xca, 0x40,
    0xed, 0xd1,
])
print(unxor(rc4(b"testkey", enc)))
```

`enc` 的字节序必须与二进制里的 `.long` 小端布局一致；若首字节对不上，先用「末位应为 `}`」这个约束反推字节序是否正确。

## 变体与关联

- 后处理变体：`buf[i] ^= buf[i-1]`（正向前缀异或，需从头正序解）、`buf[i] += buf[i-1]`（需减法，且注意进位/模 256）、`buf[i-1] ^= buf[i] ^ const`。
- 前处理变体：也可以先做反向累加异或再做 RC4，解密顺序随之颠倒；靠「末字节是否为 `}`/首字节是否为 `f`」判断哪一层在外。
- 算法变体：RC4 可换成魔改版（S 盒初值 `~i`、PRGA 后加/减常量、反向 KSA），识别方法仍是「256 字节 S 盒 + 交换 + `(S[i]+S[j])%256`」骨架。
- 关联：与「魔改 RC4 逆运算」「RC4 后接减常量异或」同族，区别只在这条的后处理是**自逆的链式异或**而不是逐字节独立运算；与「前缀异或（正向）」方向相反，不能套用同一段解密代码。

## 检测与防御

- 这类题属 CTF 逆向范畴；工程上若要保护固件中的常量，不应只做「RC4 + 简单异或链」，而应使用带认证的 AEAD（AES-GCM/ChaCha20-Poly1305）并把密钥放在安全存储，而不是明文常量。
- 若必须混淆，至少做到：密钥不落常量区、后处理与算法耦合（而非两段可独立剥离的可逆变换）、对密文做完整性校验，避免出现「末位明文可预测」这类自证信息。
- 分析侧自检：单层解密后看末字节/首字节是否符合格式，是最快的「还差几层」判据。
