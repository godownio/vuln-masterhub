---
id: ctf-reverse-modified-sha512-pbkdf2-nonstandard-rc4-decrypt
title: 魔改 SHA-512 常量 + PBKDF2 + 非标准 RC4 KSA：VMP 脱壳后解密 flag.enc
type: scenario
domain: ctf
path: ctf/reverse
technique: modified-sha512-pbkdf2-nonstandard-rc4-decrypt
aliases:
- 魔改 SHA-512
- PBKDF2-HMAC-SHA512
- 非标准 RC4 KSA
- S[i]=i+4
- Kilogram
- VMP 脱壳解密
tags:
- ctf
- reverse
- sha512
- pbkdf2
- rc4
- vmp
- unpacking
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:48:01+08:00'
  notes: 已对照原文 Kilogram 节与图 26-34 核对：VMP 2.XX-3.XX、flag.enc 布局 8+64+32+payload+16、S[i]=(i+4)、patched K 0xF57D4FF7FEE6ED0D、key_base=sha512(salt+b"Lilac+present")、PBKDF2 10000/64、解出 JPEG flag，均与原文 exp 一致。未验证点：PoC 未本机复跑，sha512_patched 完整实现需按原文 K 表补全；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

样本经 VMP 脱壳后，`flag.enc` 的布局是“8 字节头 + 64 字节加密 key1 + 32 字节 salt + 加密 payload + 16 字节校验”；程序用被改过一项 K 常量的 SHA-512 与 PBKDF2-HMAC-SHA512 派生 key2，再用 `S[i]=(i+4) mod 256` 的非标准 KSA 生成 keystream，依次解出 key1 和 payload，得到一张含 flag 的 JPG。

## 原理

- **样本与脱壳**：PE64、VMProtect 2.XX-3.XX；先用脱壳机 dump 主程序，IDA 静态反编译会被 VMP 噪声干扰。更快的切入点是动态：程序运行后内存出现 `"flag"`/`"./flag.enc"` 字符串，给字符串地址下硬件读/写断点，跟到写文件逻辑，直接落在加密流程。
- **第一层 key1**：程序生成 64 字节 `key1`（SHA-512 输出），初始化 S-box `S[i]=(i+4) mod 256`（不是标准 RC4 的 0..255），用 key1 做 KSA-like 打乱；再用打乱后的 S-box 前 64 字节 XOR key1 本身，得到 `key1_enc`，写入文件头。
- **第二层 key2**：生成 64 字节 `key2`（PBKDF2-HMAC-SHA512），同样用 `S[i]=i+4` 的 KSA-like 打乱 S-box，再 XOR 真正的 payload。
- **文件布局**：`[0:8]` header、`[8:0x48]` key1_enc(64)、`[0x48:0x68]` salt(32)、`[0x68:-0x10]` enc_payload、`[-0x10:]` check(16)。
- **魔改 SHA-512**：静态 `findcrypt` 能看到 md5/sha512/pbkdf2，但直接用标准库对不上；回看代码发现 SHA-512 的 K 常量表有一项被替换为 `0xF57D4FF7FEE6ED0D`（原文标注 patched constant）。这会导致 SHA-512、HMAC-SHA512、PBKDF2-HMAC-SHA512 全部不同，必须用同一张修改后的 K 表复现。
- **解密链**：`key_base = sha512_patched(salt + b"Lilac+present")`；`key2 = pbkdf2_hmac_sha512(key_base, salt, 10000, 64)`；用 key2 的 KSA-like keystream 解 `key1`；用 key1 的 KSA-like keystream 解 payload；payload 以 `FF D8 FF E0` 开头，写成 `out.jpg` 打开即见 flag。

## 触发条件

- 样本带 VMP/压缩壳，静态分析噪声大；`findcrypt`/字符串能看到 SHA-512/PBKDF2/RC4 痕迹。
- 程序生成/读取 `flag.enc`，文件头有固定布局（8 字节头 + 64 字节 key + 32 字节 salt + payload + 16 字节校验）。
- 标准 SHA-512/PBKDF2 复现结果与程序不一致，提示哈希常量/S-box 被改。
- 加密流程是 XOR 流（KSA-like），同一 keystream 可逆。

## 利用步骤

1. 脱壳/dump 主程序，IDA 定位 `./flag.enc` 字符串与写文件逻辑；或动态下硬件断点跟到加密函数。
2. 从 `flag.enc` 按布局切出 `key1_enc`、`salt`、`enc_body`。
3. 用**修改后的 K 表**实现 SHA-512；计算 `key_base = sha512(salt + b"Lilac+present")`。
4. 用修改后的 HMAC-SHA512 实现 PBKDF2：`key2 = pbkdf2_hmac_sha512(key_base, salt, 10000, 64)`。
5. 实现非标准 KSA：`S[i]=(i+4)&0xFF`，KSA 用 key2；`key1 = key1_enc XOR S2[:64]`。
6. 用 key1 再做一次 KSA-like：`payload = enc_body XOR S1[i & 0xFF]`。
7. 写 `out.jpg`，检查 `FF D8 FF E0` 文件头并打开图片读取 flag；若图片损坏，检查 K 表/S-box 初值/PBKDF2 迭代次数。

## PoC

```python
import struct
from pathlib import Path

# sha512_patched / hmac_sha512_patched：按原文 K 表实现，
# 将标注的常量替换为 0xF57D4FF7FEE6ED0D（其余与标准 SHA-512 相同）。

def ksa_like(key: bytes) -> bytearray:
    S = bytearray(((i + 4) & 0xFF) for i in range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

data = Path("flag.enc").read_bytes()
key1_enc = data[8:8+64]
salt     = data[8+64:8+64+32]
enc_body = data[8+64+32:-16]

key_base = sha512_patched(salt + b"Lilac+present")
key2 = pbkdf2_hmac_sha512_patched(key_base, salt, iterations=10000, dklen=64)

s2 = ksa_like(key2)
key1 = bytes(key1_enc[i] ^ s2[i] for i in range(64))
s1 = ksa_like(key1)
body = bytes(enc_body[i] ^ s1[i & 0xFF] for i in range(len(enc_body)))
Path("out.jpg").write_bytes(body)
print("JPEG" if body[:4] == b"\xff\xd8\xff\xe0" else "bad header")
```

说明：PoC 展示文件切分、PBKDF2 与非标准 KSA 解密；`sha512_patched`/`pbkdf2_hmac_sha512_patched` 需按原文修改后的 K 表实现（标准库不适用）。未在本机对附件复跑。

## 变体与关联

- **魔改哈希常量**：只改 K 表一项即可让所有 HMAC/PBKDF2 结果不同；用 `findcrypt` 定位常量表，逐项与标准值比对。
- **非标准 S-box 初值**：`S[i]=i+4`、`S[i]=i^0x..`、自定义置换；KSA/PRGA 也要同步改。
- **文件格式**：header/key/salt/payload/check 布局可能不同；用 `binwalk`/十六进制查看定位 `FF D8` 或 `PK`。
- **关联**：[[ctf-reverse-modified-rc4-rounds-sbox]]（魔改 RC4）、[[defense-forensics-wcdb4-sqlcipher-offline-decrypt]]（PBKDF2-HMAC-SHA512 派生）。

## 检测与防御

- 识别：PE 带 VMP/压缩壳、`findcrypt` 出现 SHA-512/PBKDF2/RC4、常量表与标准值不一致。
- 防护：不要用自定义哈希/流密码实现加密；使用标准 AEAD/KDF 和密钥管理；对关键逻辑做完整性校验。
- 取证：保留脱壳后的内存 dump 与 `flag.enc`；先验证 JPEG/文件头再判断解密成功。
