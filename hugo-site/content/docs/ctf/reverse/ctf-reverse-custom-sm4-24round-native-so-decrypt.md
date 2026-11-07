---
id: ctf-reverse-custom-sm4-24round-native-so-decrypt
title: 自定义 SM4 变体逆向：24 轮 + 自定义 S-box/FK/CK 的 native .so 解密
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-sm4-variant-24-round-native-decrypt
tags:
- ctf
- reverse
- sm4
- custom-sbox
- native
- so
- pyinstaller
- crypto
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:40:11+08:00'
  notes: 已对照原文re3与图1-21核对：PyInstaller ELF→client.pyc+crypt_core.so、PyMethodDef(off_D5C0/sub_9820)定位encode_data、PKCS#7填充、24轮、T/T' rotate常量2/10/18/24与13/23、自定义S-box前16字节EC CA 0E F3...、FK字节71DC3F7358ADBA8E83F7332D3B1F86A4、CK 24项、自定义Base64字母表派生16字节key，均与原文/截图一致。PoC已按原文表与pcap密文本机复跑，解出readme/flag/config，flag=dart{f4b547fc-b3d0-44c3-bf21-8f3fb5ad3220}。未验证点：CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-custom-sm4-24round-native-so-decrypt/
draft: false
kb_aliases:
- 魔改 SM4
- 自定义 S-box SM4
- 24 轮 SM4
- crypt_core.so
- PyInstaller 客户端加密
- 自定义 FK/CK SM4
---

## 一句话结论

一个 PyInstaller 打包的 ELF 客户端把加密逻辑放在 `crypt_core.so` 的 `encode_data` 中，算法结构是 SM4，但轮数改为 24 轮、S-box/FK/CK 全部自定义；从 `.rodata` 提取三张表、按相同的 T/T' 轮函数和逆序轮密钥实现解密，即可还原 pcap 中被加密外发的文件内容。

## 原理

- **定位加密入口**：PyInstaller ELF 用 pyinstaller-ng 解包，得到 `client.pyc` 与 `crypt_core.so`；`client.pyc` 反编译后可见 `import crypt_core` 并调用 `crypt_core.encode_data(data, key)`。在 `.so` 中查找 `PyMethodDef` 表（IDA 中 `off_D5C0` 指向方法名 `encode_data` 与函数 `sub_9820`），即可定位实现。
- **确认是 SM4 家族**：`sub_9820` 先做 PKCS#7 填充（`n16 = 16 - n % 16`），再调用分组加密；核心函数呈现 SM4 的典型结构：
  - 128 bit 分组 = 4 个 32 bit 字；
  - 密钥扩展 `rk[i] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i])`，其中
    `T'(x) = tau(x) ^ rol(x,13) ^ rol(x,23)`；
  - 轮函数 `X[i+4] = X[i] ^ T(X[i+1]^X[i+2]^X[i+3]^rk[i])`，其中
    `T(x) = tau(x) ^ rol(x,2) ^ rol(x,10) ^ rol(x,18) ^ rol(x,24)`；
  - 最后 4 个字反序输出。
  这些 rotate 常量（2/10/18/24 与 13/23）是识别 SM4（含魔改版）的最强特征。
- **与标准 SM4 的差异**：
  - **24 轮**而不是标准 32 轮：密钥扩展只生成 24 个轮密钥，`CK` 表也只有 24 项；
  - **S-box 自定义**：`.rodata` 0xAC10 起的 256 字节，前 16 字节为 `EC CA 0E F3 08 F0 2A A2 3B 18 2B 5C 37 BD 12 A8`；
  - **FK 自定义**：`.rodata` 0xAD10 起为 `71DC3F7358ADBA8E83F7332D3B1F86A4`（按字节还原后即 Python 中的 `[0x3b1f86a4, 0x83f7332d, 0x58adba8e, 0x71dc3f73]`，注意大小端）；
  - **CK 自定义**：`.rodata` 0xAD20 起 24 个 32 bit 常量，如 `865C7AA7B0535D2D657904A49A148706`。
- **密钥来源**：`client.pyc` 中 `KEY_B64` 用自定义 Base64 字母表
  `QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890!@`
  编码；先映射回标准表 `A-Za-z0-9+/` 再 `base64.b64decode`，取前 16 字节作为 SM4 密钥。
- **解密**：按 24 轮密钥逆序 `rk[23-i]`，每轮用 `T`（不是 `T'`）做轮函数，最后 `[X24,X25,X26,X27]` 反序；对每个 16 字节块解密后按 PKCS#7 去填充。pcap 中 JSON 的 `ciphertext` 字段逐条解出 `readme.txt`、`flag.txt`、`config.txt`。

## 触发条件

- 拿到 PyInstaller 打包的 ELF/Python 程序，核心加密在 native `.so`/`.pyd`；
- `.so` 中能找到 SM4 的 T/T' rotate 常量与 4 字状态结构，但 S-box/FK/CK/轮数与标准不同；
- 能从 `.rodata` 提取完整表与密钥材料（或通过动态调试 dump）；
- 有至少一组已知密文/明文用于验证表的大小端与轮数。

## 利用步骤

1. 用 pyinstaller-ng 解包，提取 `client.pyc` 与 `crypt_core.so`，反编译 pyc 找 `encode_data` 调用与密钥字符串。
2. IDA 打开 `.so`，在 `PyMethodDef` 表中定位 `encode_data` 实现；确认 PKCS#7 填充与分组加密调用。
3. 在 `.rodata` 定位 S-box（256 字节）、FK（4 字）、CK（轮数 × 4 字）；核对 endianness。
4. 按标准 SM4 的 T/T' 公式实现 `tau/L/Lp/key_schedule/decrypt`，把轮数改为实际值（案例 24）。
5. 用密钥字符串按自定义字母表映射 + base64 解码得到 16 字节 key。
6. 解 pcap 中每条密文，按 PKCS#7 去填充，验证文件头/可读文本。
7. 若结果乱码，检查：S-box 字节序、FK/CK 大小端、轮数、最后 4 字是否反序、是否用了 `T'` 而非 `T`。

## PoC

```python
import base64

KEY_B64 = "eUYme4MkN1KSC1bWJZJ2w3FUJCiEXT13D2u1KmiNtfhXKZYE"
CUSTOM = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890!@"
STD    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
key16 = base64.b64decode(KEY_B64.translate(str.maketrans(CUSTOM, STD)))[:16]

# SBOX: 从 .rodata 0xAC10 取 256 字节
# FK  : [0x3b1f86a4, 0x83f7332d, 0x58adba8e, 0x71dc3f73]
# CK  : 24 个 32 bit 常量，从 .rodata 0xAD20 取
SBOX = [...]      # 256 字节
FK   = [0x3b1f86a4, 0x83f7332d, 0x58adba8e, 0x71dc3f73]
CK   = [...]      # 24 项

def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff

def tau(x):
    return (SBOX[(x >> 24) & 0xff] << 24) | (SBOX[(x >> 16) & 0xff] << 16) | \
           (SBOX[(x >> 8) & 0xff] << 8) | SBOX[x & 0xff]

def L(x):  return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24)
def Lp(x): return x ^ rotl(x, 13) ^ rotl(x, 23)

def key_schedule(key16, rounds=24):
    MK = [int.from_bytes(key16[i:i+4], 'big') for i in range(0, 16, 4)]
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(rounds):
        t = Lp(tau(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]))
        K.append(K[i] ^ t)
        rk.append(K[i+4])
    return rk

def dec_block(block, rk):
    X = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 16, 4)]
    for i in range(len(rk)):
        t = L(tau(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[len(rk)-1-i]))
        X.append(X[i] ^ t)
    out = X[len(rk):len(rk)+4][::-1]
    return b''.join(x.to_bytes(4, 'big') for x in out)

def pkcs7_unpad(b):
    p = b[-1]
    return b[:-p] if 0 < p <= 16 and b.endswith(bytes([p]) * p) else b
```

```python
rk = key_schedule(key16, rounds=24)
pt = b''.join(dec_block(ct[i:i+16], rk) for i in range(0, len(ct), 16))
print(pkcs7_unpad(pt).decode('utf-8', errors='replace'))
```

## 变体与关联

- 魔改点可能是 S-box、FK、CK、轮数、输出字序中的任意组合；只要 T/T' 的 rotate 常量还在，就可按 SM4 识别并替换参数。
- 同类 native Python 扩展逆向：从 `PyMethodDef` 表找导出函数，再沿调用链定位加密；与 PyInstaller 解包卡配合使用。
- 关联 [[ctf-reverse-multistage-pe-vm-modified-sm4]]：另一种 32 轮、替换 FK/CK/S-box 的魔改 SM4，但加密逻辑在 PE 自定义 VM 中。
- 关联 [[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]：标准 SM4 的常量识别与小端解密。
- 关联 [[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]：PyInstaller CArchive/PYZ 提取。
- 边界：表不完整、轮数未知或加了两层以上变换时，需要动态调试 dump 运行时表；密钥若派生自环境/CRC 等，需要先还原派生逻辑。

## 检测与防御

- 对于分析者：优先找 T/T' rotate 常量与 4 字结构，再核对 S-box/FK/CK 是否标准；用已知明文验证 endianness。
- 对于防御者：不要把密钥硬编码在客户端或 native 库中；加密逻辑不应作为保密边界，服务端应使用标准算法与受保护密钥。
- 检测：客户端二进制中出现自定义 256 字节 S-box + 24/32 个 CK 常量、`encode_data` 之类导出；网络流量为固定长度块加密后的 JSON。
- 加固：使用标准库/硬件加密、密钥白盒或服务端加密，避免可被离线提取的算法参数。
