---
id: ctf-reverse-tag-crc32-encrypted-sqlite-seed-rc6
title: 加密 SQLite 资源库逆向：点击序列→TEA/CRC32 tag→CRC32 流解密→seed 驱动改版 RC6
type: scenario
domain: ctf
path: ctf/reverse
technique: tag-crc32-encrypted-sqlite-seed-rc6
aliases:
- 蔡文姬的胡笳琴音波谜阵
- appview_cache.db
- cw tag
- libmobile04.so
- RC6-like
- HarpMelodyManager
tags:
- ctf
- reverse
- android
- sqlite
- crc32
- xor-stream
- tea
- rc6
- base58
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:55+08:00'
  notes: 已对照原文核对：8 个 Skin 频率升序得 CWJXMASFLOWSTARROSEGOALDANCEMAGI、bit swap/FNV-1a 64/TEA-like 32 轮/CRC32 生成 cw:ca7d2d9202ddb306:1adc6143、DB 前 16 字节 salt+CRC32 流 XOR、offset 0x80/0xB4 seed、K1/K2/TGT/Base58/RC6-like 关系与 body GuiHanQu8s9Dp68*G-ZN_#9Z3zLIbet6 均与卡片一致。注意：原文称对前 16 字节之后的密文解密，卡内 PoC 对整个文件异或并断言 data[:16] 为 SQLite 头，存在偏移歧义，已在卡内注明按实际实现校准。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

点击 8 个皮肤按频率升序得到 32 字符序列；Java 层用 bit swap→FNV-1a→TEA-like→CRC32 生成 `cw:...` tag；native 用 `crc32(tag + 前 16 字节)` 派生循环 XOR 流解密 `assets/appview_cache.db`，从解密后的 SQLite 取两个 seed，初始化改版 RC6 反推 32 字节 flag body。

## 原理

- **皮肤频率排序**：8 个 Skin code 对应频率，按升序 `CWJ(261.6) < XMAS(293.7) < FLOW(329.6) < STAR(349.2) < ROSE(392.0) < GOAL(440.0) < DANCE(493.9) < MAGI(523.3)`，拼接 `CWJXMASFLOWSTARROSEGOALDANCEMAGI`（32 字符，与 flag body 等长）。
- **tag 生成**：对序列每字节 bit swap `((b & 0xaa) >> 1) | ((b & 0x55) << 1)`；FNV-1a 64 位；拆低/高 32 位；TEA-like 32 轮（delta `0x9e3779b9`，key 为 4 个 32 位常量）；小端打包 8 字节；CRC32；格式 `cw:%s:%08x`。本题正确 tag 为 `cw:ca7d2d9202ddb306:1adc6143`。
- **key 常量**：`0x798510a9, 0x9928c3fb, 0x8d3e0a81, 0x275bf2c1` 由 native 读取调用者包名后做异或/移位派生；换包名会改变 tag。
- **DB 解密**：读文件前 16 字节，`crc = crc32(tag + first_16_bytes)`；对数据按 `data[i] ^= ((crc >> ((i * 8) & 0x18)) + i) & 0xff` 解密。`((i*8)&0x18)` 让每 4 字节取 CRC32 的不同字节位置，`+i` 是位置扰动；正确 tag 解密后明文头为 `SQLite format 3`。
- **seed 提取**：解密后的数据库中，offset `0x80` 取小端 `0xed4d19b8`，offset `0xb4` 取小端 `0x7d510557`，用于初始化 RC6-like。
- **RC6-like 校验**：`K1="PMDZH"`、`K2="8&GZN*@9Z3zLIbet"`、`TGT="6zQoRVxR2FJKADz7nHNXKWmErDTXYBfWKJ7M578rk2Ks"`；`TGT` 按 Bitcoin 风格 Base58 解码为 32 字节。关系为 `Base58Decode(TGT) == RC6_encrypt(body) XOR repeat(K1)`，所以 `body = RC6_decrypt(Base58Decode(TGT) XOR repeat(K1))`。
- **结果**：body `GuiHanQu8s9Dp68*G-ZN_#9Z3zLIbet6`，flag `ISCC{GuiHanQu8s9Dp68*G-ZN_#9Z3zLIbet6}`。

## 触发条件

- APK assets 中有非明文 SQLite/数据库文件；native 读取文件头并做 CRC/XOR。
- Java 层有 bit swap/FNV/TEA/CRC32 组合，生成带前缀的 tag。
- 数据库解密后出现 SQLite 头，且固定偏移有 seed。
- 有 Base58 密文和自定义分组密码常量。

## 利用步骤

1. 从 DEX 找 Skin 表/频率，按升序得到点击序列；确认 body 长度 32。
2. 复现 tag 生成：bit swap → FNV-1a 64 → TEA-like → 小端 8 字节 → CRC32；用已知 tag `cw:ca7d2d9202ddb306:1adc6143` 校准 key 顺序/字节序。
3. 用 tag 解 DB：读前 16 字节，算 `crc32(tag + header)`，按公式 XOR；断言 `SQLite format 3`。
4. 从解密 DB 的 `0x80`/`0xb4` 取两个小端 seed；确认 RC6-like 的轮数/常量/S 盒派生。
5. Base58 解码 `TGT` 得 32 字节密文；先 XOR `repeat(K1)`，再 RC6 解密；必要时用 `K2` 校验。
6. 拼 `ISCC{...}`；用 native 或重加密复核。

## PoC

```python
import struct
import zlib

MASK = 0xffffffff

def u32(x):
    return x & MASK

def swap_bits(bs):
    return bytes((((b & 0xaa) >> 1) | ((b & 0x55) << 1)) & 0xff for b in bs)

def fnv64(bs):
    h = 0xcbf29ce484222325
    for b in bs:
        h ^= b
        h = (h * 0x100000001b3) & 0xffffffffffffffff
    return h

def tea(v0, v1, k):
    s = 0
    delta = 0x9e3779b9
    for _ in range(32):
        s = u32(s + delta)
        v0 = u32(v0 + ((((v1 << 4) & MASK) + k[0]) ^ u32(v1 + s) ^ ((v1 >> 5) + k[1])))
        v1 = u32(v1 + ((((v0 << 4) & MASK) + k[2]) ^ u32(v0 + s) ^ ((v0 >> 5) + k[3])))
    return v0, v1

seq = b"CWJXMASFLOWSTARROSEGOALDANCEMAGI"
h = fnv64(swap_bits(seq))
k = [0x798510a9, 0x9928c3fb, 0x8d3e0a81, 0x275bf2c1]
v0, v1 = tea(h & MASK, (h >> 32) & MASK, k)
raw = struct.pack("<II", v0, v1)
tag = "cw:%s:%08x" % (raw.hex(), zlib.crc32(raw) & MASK)
print("derived tag =", tag)  # 与目标 cw:ca7d2d9202ddb306:1adc6143 对比校准

# 用目标 tag 解 DB（以目标实际实现为准：若前 16 字节作为 IV 跳过，
# 则从 offset 16 开始应用同一公式）
data = bytearray(open("appview_cache.db", "rb").read())
crc = zlib.crc32(b"cw:ca7d2d9202ddb306:1adc6143" + bytes(data[:16])) & MASK
for i in range(len(data)):
    data[i] ^= ((crc >> ((i * 8) & 0x18)) + i) & 0xff
assert bytes(data[:16]) == b"SQLite format 3\x00"
seed1 = struct.unpack_from("<I", data, 0x80)[0]
seed2 = struct.unpack_from("<I", data, 0xb4)[0]
print(hex(seed1), hex(seed2))  # 0xed4d19b8 0x7d510557
```

tag 生成部分若与目标示例不一致，说明 FNV 输入、TEA key 顺序或字节序还依赖包名/资源大小，需按 native/Java 实现继续校准；RC6 解密器原文未完整给出，置信度标 medium。

## 变体与关联

- **tag 链变体**：FNV-1a 32/64、TEA/XTEA/XXTEA、CRC32/CRC64；先逐层验证中间值，不要直接跳到最终 tag。
- **加密容器变体**：SQLite、ZIP、自定义 DB；用魔数判断解密是否正确。
- **自定义分组密码变体**：RC6/RC5/XXTEA；先识别轮常量、字长、字节序、S 盒派生。
- **关联卡片**：[[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]（CRC32 种子流）、[[mobile-android-sqlcipher-static-key-derivation]]（SQLCipher 密钥）、[[ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer]]（多层自定义密码）。
- **边界**：tag 依赖包名/签名等环境值时，换包后 tag 变；RC6 变体的 S 盒派生未在原文展开，需按 so 实现补齐。

## 检测与防御

- **防御视角**：不要把密钥/seed 放在可离线解密的资源库；使用服务端校验/设备密钥；数据库加密应使用成熟方案并正确管理密钥。
- **检测信号**：assets 中非标准 DB、CRC32 + XOR 循环、Base58 密文、自定义分组密码常量。
- **CTF 逆向**：先校准 tag 链，再解 DB；用 `SQLite format 3` 魔数验证解密正确性。
