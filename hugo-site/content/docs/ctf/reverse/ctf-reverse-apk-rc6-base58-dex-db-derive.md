---
id: ctf-reverse-apk-rc6-base58-dex-db-derive
title: APK 多源参数派生 RC6 密钥：DEX 音律序列 + ELF 常量 + assets DB CRC 流
type: scenario
domain: ctf
path: ctf/reverse
technique: apk-rc6-base58-dex-db-derive
tags:
- ctf
- reverse
- apk
- android
- rc6
- base58
- dex
- elf
- assets
- crc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:34+08:00'
  notes: 已对照原文核对：cw=javaHash(package)^raw_size^MAGIC_MASK 派生 TEA key、FNV1a64(swap_bits(sequence))、DEX K1.MAGIC_MASK/HarpMelodyManager 频率序列、appview_cache.db CRC32 流取 seed1@0x80/seed2@0xB4、RC6 44 子密钥/20 轮、Base58→XOR(K1)→RC6、实测 flag ISCC{JiuSiQuwkMV*Hrmc&B?N=fYW&%u} 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-apk-rc6-base58-dex-db-derive/
draft: false
kb_aliases:
- 蔡文姬胡笳琴
- RC6 解密
- Base58 目标
- DEX 静态字段
- appview_cache.db
- CRC 流 seed
- 音律序列
---

## 一句话结论

APK 的 `cw` 参数由包名、原始媒体大小、DEX 中的 `MAGIC_MASK` 与按频率排序的音律序列经 Java `hashCode`/FNV1a64/TEA 派生；`assets/appview_cache.db` 用 `cw` 的 CRC32 做流式 XOR 得到两个 seed，再与 native 的 `K1`/`K2`/`target`/RC6 参数一起完成 Base58→XOR(K1)→RC6 解密，得到 32 字节 flag 主体。

## 原理

- **多源绑定**：`cw = "cw:" + TEA(FNV1a64(swap_bits(sequence)), key(package, raw_size, magic_mask)) + ":" + crc32`。包名来自 native 类字符串，原始大小取 `res/` 下最大媒体文件，`MAGIC_MASK` 是 DEX 中 `K1` 类的静态 int 字段，音律序列来自 `HarpMelodyManager` 的 `new SkinData(code, freq)` 并按频率升序拼接。
- **DEX 解析**：从 `classes*.dex` 的 string_ids/type_ids/field_ids/class_defs 中读静态字段初值，或从 `<init>` 的 `const-string` 指令中提取 `(code, freq)` 对；这样不依赖 jadx 也能恢复序列。
- **DB 派生 seed**：`appview_cache.db` 前 16 字节是 salt，其余是密文；`crc = crc32(cw + salt)`，`dec_byte(i) = encrypted[i] ^ ((crc_bytes[i & 3] + i) & 0xFF)`，在偏移 `0x80` 与 `0xB4` 处各取 4 字节小端作为 `seed1`/`seed2`。
- **RC6**：`p = rol(seed2,13) ^ seed1 ^ p_xor`，`q = rol(seed2,25) ^ seed1 (+ q_add)` 后置最低位；扩展 44 个子密钥，做 132 轮 key schedule；解密 20 轮，每轮用 `rol(x*(2x+1),5)` 作为旋转量。
- **Base58 与 XOR**：`target` 是 Base58 字符串（字母表可自定义），解码后按 32 字节取尾部；`xored = target ^ K1`（循环），再分两块 RC6 解密，得到可打印 32 字节主体。

## 触发条件

- APK 内含 native 库（导出 `_K1`、`_K2`、`_TGT` 等符号）与 `assets/*.db`。
- DEX 中有静态常量与音律/序列数据；`target` 为 Base58 字符串。
- 题目提示“音律/琴音/频率”等，说明序列是密钥的一部分。

## 利用步骤

1. 解外层 zip/7z 定位 `.apk`；解压 APK，提取 `lib/*/*.so`（优先 x86_64 或 arm64）与 `assets/appview_cache.db`。
2. 用 pyelftools 读 `.dynsym`/`.symtab`/重定位，解析 `_K1`（字符串）、`_K2`（16 字节）、`_TGT`（Base58 字符串）、`_n_derive_impl` 中的 4 个派生字与 RC6 参数。
3. 解析 `classes*.dex`：读 `K1.MAGIC_MASK` 静态字段；从 `HarpMelodyManager` 的构造器 `const-string` 中提取 `(code, freq)` 并按频率升序拼接序列。
4. 计算 `cw`：`java_hashcode(package) ^ raw_size ^ magic_mask` 生成 key，`fnv1a64(swap_adjacent_bits(sequence))` 生成输入，TEA 32 轮后拼 `cw:<hex>:<crc32>`。
5. 读 DB，按 `crc32(cw + salt)` 流解密，取 `seed1`/`seed2`。
6. 生成 RC6 子密钥，`base58_decode(target)` → 截 32 字节 → XOR `K1` → 两块 RC6 解密 → 拼 `ISCC{...}`。
7. 用 `printable_inner`（32 字节且全可打印）判定候选，若不对则枚举媒体大小候选/序列顺序。

## PoC

```python
def base58_decode(s, alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"):
    n = 0
    for ch in s:
        n = n * 58 + alphabet.index(ch)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip(alphabet[0]))) + out

def derive_db_seeds(db, cw):
    salt, enc = db[:16], db[16:]
    crc = zlib.crc32(cw.encode() + salt) & 0xFFFFFFFF
    cb = crc.to_bytes(4, "little")
    dec = lambda i: enc[i] ^ ((cb[i & 3] + i) & 0xFF)
    return (int.from_bytes(bytes(dec(0x80+i) for i in range(4)), "little"),
            int.from_bytes(bytes(dec(0xB4+i) for i in range(4)), "little"))
```

## 变体与关联

- **参数提取变体**：ARM64 用 `ADRP+LDR` 取派生字，x86_64 用 `lea rip-relative`；符号可能被 strip，需要按字符串/交叉引用定位。
- **算法变体**：TEA 可能换 RC6/XXTEA；CRC 流可能换成 LCG/AES-CTR；Base58 字母表可能自定义。
- **关联卡片**：[[ctf-reverse-apk-chacha20-counter-one-native]]、[[ctf-reverse-apk-knapsack-chacha20-vault]]、[[mobile-android-sqlcipher-static-key-derivation]]（assets DB 密钥派生）。
- **边界**：若 DB 太小或偏移不对，`dec_byte` 会越界；若媒体大小有多个候选，需要逐个尝试并用可打印性判定。

## 检测与防御

- **CTF 验证**：先确认 `cw` 的 CRC 与 DB 解密出的 seed 能生成可打印明文，再用 `printable_inner` 与 `ISCC{}` 格式判定。
- **防御**：不要把密钥派生所需的全部材料放在客户端；assets DB 加密密钥不应由可预测的包名/文件大小派生；native 常量做混淆并做完整性校验。
- **检测信号**：APK 内同时存在自定义 Base58 表、RC6 常量、CRC 流解密代码与 assets 数据库。
