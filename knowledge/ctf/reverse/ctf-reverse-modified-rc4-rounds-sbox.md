---
id: ctf-reverse-modified-rc4-rounds-sbox
title: 魔改 RC4 识别与解密：轮数/S 盒初始化改动需逐处同步
type: scenario
domain: ctf
path: ctf/reverse
technique: rc4-variant-rounds-sbox-decrypt
aliases:
- 魔改 RC4
- RC4 128 轮
- S 盒初始化改动
- KSA/PRGA 还原
- RC4 解密脚本
tags:
- ctf
- reverse
- rc4
- stream-cipher
- ksa
- prga
- sbox
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:54:48+08:00'
  notes: 已对照原文 RC4 节与图 31-48 核对：256 字节 S 盒、KSA j=(j+s[i]+k[i])%256、PRGA 交换与 t=(s[i]+s[j])%256、加解密同构、str/bytes 的 ord 区别、data 原地修改、IDA 前导零问题、128 轮及 %128/S 盒初始化微调（图 42/44/46/48）均一致。未验证点：原文未展示标准样例的完整输出，PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

RC4 的特征是 256 字节 S 盒、KSA 置乱与 PRGA 逐字节异或；题目若改轮数（如 128 轮）或 S 盒初始化细节，解密时不必重新推导，直接把同一套改动同步到解密脚本即可——RC4 加解密是同一算法，异或自逆。

## 原理

- **KSA**：`sbox[i]=i`，`k[i]=key[i%len]`；对 `i=0..255` 做 `j=(j+sbox[i]+k[i])%256` 并交换 `sbox[i],sbox[j]`。
- **PRGA**：每字节 `i=(i+1)%256`、`j=(j+sbox[i])%256`、交换、`t=(sbox[i]+sbox[j])%256`，输出 `sbox[t]` 与数据异或。
- **加解密同构**：PRGA 生成密钥流后与明文/密文异或，异或自逆；同一函数、同一密钥即可解密。
- **魔改点**：轮数改为 128、S 盒初始化时对 `i` 或 `k` 做微调、交换条件变化、PRGA 取模/下标变化；解密脚本必须与加密逐处一致，否则密钥流不同。
- **实现坑**：Python 中 key 为 `bytes` 时索引是整数，为 `str` 时需 `ord()`；不要混用。`data[k] ^= ...` 原地修改，如需保留密文先复制。IDA 导出 `0x01/0x02/0x0*` 时可能吞掉前导零，长度对不上需手工还原。

## 触发条件

- 反编译中出现长度 256 的数组、两次 256 次循环、`%256` 交换与异或。
- 密钥长度与明文长度无固定关系，加密/解密调用同一函数。
- 轮数/初始化/取模等细节与标准 RC4 不同，需按题目代码同步。

## 利用步骤

1. 定位 S 盒初始化（0..255 填充）、KSA 循环、PRGA 循环三段结构。
2. 对比标准 RC4，记录所有魔改：轮数、循环边界、`j` 公式、交换对象、下标偏移、密钥轮转方式。
3. 把密文处理成整数列表（十六进制或十进制），密钥处理成 bytes 或 str（与脚本索引方式匹配）。
4. 用同一套魔改逻辑实现 `rc4_crypt`，对数据原地异或。
5. 输出字节序列；先看原始字节，再按文本/UTF-8 解码；必要时回加密验证。
6. 若结果乱码，优先检查 key 类型、轮数、S 盒初始化微调、密文长度/前导零。

## PoC

```python
def rc4_init(sbox, key):
    k = [key[i % len(key)] for i in range(256)]
    j = 0
    for i in range(256):
        sbox[i] = i
    for i in range(256):
        j = (j + sbox[i] + k[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]

def rc4_crypt(sbox, data, key):
    rc4_init(sbox, key)
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        t = (sbox[i] + sbox[j]) % 256
        data[n] ^= sbox[t]

data = [235, 13, 97, 41, 191, 155, 5, 34, 243, 50, 40, 151, 227, 134,
        77, 45, 90, 42, 163, 85, 170, 213, 180, 108, 139, 81, 177]
key = b"wanyuanshenwande"   # 若用 str 版本，KSA 中改 ord(key[i % len(key)])
rc4_crypt([0] * 256, data, key)
print(bytes(data))
```

原文实测：该密文/密钥解出可读明文；魔改 RC4 题（128 轮、S 盒初始化微调）把同一改动同步到解密脚本后得到正确结果，未同步则输出错误。

## 变体与关联

- **魔改变体**：轮数 128/16、KSA 中 `j` 公式变化、S 盒初值变化、PRGA 交换顺序变化、密钥按块轮转。
- **载体变体**：字符串/十六进制/字节数组输入；C 版 `int sbox[256]` 与 Python 列表；原地修改 vs 返回新 bytes。
- **关联卡片**：[[ctf-reverse-base64-table-index-mutation]]（同类魔改算法还原）、[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（RC4 与弱随机数组合）、[[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]（密钥流还原）。
- **边界**：若魔改引入非线性/密钥相关 S 盒且不可逆，需具体分析；密文长度与前导零丢失会导致密钥流错位。

## 检测与防御

- **CTF 验证**：解密后看字节序列是否可打印；再用同一函数加密回去比对密文。
- **防御视角**：RC4 已有已知弱点（密钥流偏差），不应在新系统中使用；魔改轮数/初始化不构成安全增强。
- **检测信号**：二进制中出现 256 字节 S 盒、`%256` 交换、两次 256 循环；密钥长度与明文无关。
- **复盘**：先确认 KSA/PRGA 三段结构，再逐行对比标准 RC4 找魔改点；不要直接套标准库。
