---
id: ctf-reverse-go-pic-rc4-short-key-png-header-bruteforce
title: Go CTF pic.exe：5 字符 RC4 密钥 + PNG 文件头已知明文爆破
type: scenario
domain: ctf
path: ctf/reverse
technique: go-rc4-short-key-png-header-bruteforce
aliases:
- 2024 羊城杯 pic
- pic.exe
- Go RC4 密钥爆破
- PNG 文件头已知明文
- KeySizeError RC4 识别
tags:
- ctf
- reverse
- go
- rc4
- brute-force
- known-plaintext
- png
- file-encryption
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:03:25+08:00'
  notes: '已对照 content.md 与图 09-14 核对：Input your key、密钥长度 5（key_2[1]/v49[1] != 5）、isDebuggerPresent、main_KeySizeError_Error 的 crypto/rc4: invalid key size、main_NewCipher、./flag.png、前 4 字节密文 85 43 72 78、文章 RC4 脚本额外 XOR key[1] 与 17 均一致。文章未给出字符集 Map、未展示最终 key/flag，卡片已标 confidence=medium 并说明为可复现框架；未在本机爆破。frontmatter 无 sources/source_url。'
---

## 一句话结论

Go 逆向题 `pic.exe` 要求输入 5 字符密钥，用 RC4（题中为变体：额外 XOR `key[1]` 与常量 17）处理 `flag.png`；由于 PNG 文件头 `89 50 4E 47 0D 0A 1A 0A` 是已知明文，而密钥只有 5 个字符，可以直接枚举字符集，用前 4 字节密文解出候选明文并比对 PNG magic，爆破出密钥后解密整个文件。

## 原理

- **算法识别**：二进制中 `main_KeySizeError_Error` 的字符串是 `crypto/rc4: invalid key size`，并且出现 `main_KeySize`/`main_NewCipher` 函数，说明程序使用 Go 标准库 `crypto/rc4`（或与其兼容的实现）。
- **密钥长度**：`main_main` 反编译中读取输入后执行 `if key_2[1] != 5 { os.Exit(0) }`，即只接受长度 5 的密钥；这是爆破可行性的关键前提。
- **已知明文**：程序打开 `./flag.png` 并对其做 RC4 变换。PNG 文件的前 8 字节固定为 `89 50 4E 47 0D 0A 1A 0A`，其中前 4 字节足以作为爆破判别条件。
- **爆破**：RC4 的 KSA/PRGA 由密钥决定，密钥空间为 `|charset|^5`；对每个候选密钥只解密前 4 字节，与 `[0x89,0x50,0x4E,0x47]` 比较即可筛出正确密钥，再解密完整文件。
- 文章脚本的 RC4 在标准 PRGA 输出后额外做了 `^ ord(key[1]) ^ 17`，说明题目对 RC4 做了小改动；逆向时必须按二进制实际实现复刻，不能直接套标准库。
- 本质：短密钥 + 已知文件格式头 = 可离线验证的密钥搜索；不需要理解全部加密逻辑，只需要一个可验证的明文前缀。

## 触发条件

- 程序使用短密钥（本例 5 字符）加密/解密一个已知格式的文件（PNG/ZIP/ELF/JPEG/PDF 等）。
- 二进制中能识别算法与密钥长度，或至少能确认“密钥长度很小”。
- 加密结果文件（本例 `flag.png`）可获取，且文件头保持原样（未被额外压缩/封装）。
- 密钥字符集可猜测（大小写字母、数字、常见符号）。

## 利用步骤

1. 用 IDA 打开 `pic.exe`，通过 `Input your key:` 字符串定位 `main_main`，把输入缓冲区重命名。
2. 观察 `isDebuggerPresent` 反调试调用：静态分析可忽略，动态运行需 patch 掉或在非调试环境执行。
3. 识别密钥长度检查 `key_2[1] != 5`，以及 `main_KeySizeError_Error` 中的 `crypto/rc4: invalid key size`，确认 RC4 + 5 字符。
4. 从 `flag.png` 读取前 4 字节密文（文章示例为 `85 43 72 78`）。
5. 按二进制里的 RC4 变体实现解密函数，枚举字符集生成长度 5 的候选密钥，比较解密结果是否等于 PNG magic。
6. 命中后输出密钥，用它解密完整 `flag.png`，得到原始图片/flag。

## PoC

```python
import itertools
from tqdm import tqdm

def rc4_variant(enc, key):
    s = list(range(256))
    t = [ord(key[i % len(key)]) for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + s[i] + t[i]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = []
    for k in range(len(enc)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        x = (s[i] + s[j]) % 256
        # 文章题目的变体：额外 XOR key[1] 与常量 17
        out.append(enc[k] ^ s[x] ^ ord(key[1]) ^ 17)
    return out

# 前 4 字节密文（从 flag.png 读取）
enc = [0x85, 0x43, 0x72, 0x78]
# 按目标程序实际接受的字符集调整；文章脚本中的 Map 未给出，需要自行确定
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

for tup in tqdm(itertools.product(charset, repeat=5)):
    key = "".join(tup)
    if rc4_variant(enc, key) == [0x89, 0x50, 0x4E, 0x47]:
        print("key =", key)
        break
```

```text
# 命中后：
# 1) 用该 key 对完整 flag.png 做同样的 RC4 变体变换（加密/解密同一函数）
# 2) 得到合法 PNG（文件头 89 50 4E 47 ...），打开查看 flag
```

## 变体与关联

- 已知明文可换成其他格式：ZIP `50 4B 03 04`、ELF `7F 45 4C 46`、JPEG `FF D8 FF E0`、PDF `25 50 44 46`、PE `4D 5A`；只要前缀足够长且固定即可。
- 密钥长度 4-6 时可直接枚举；更长时可用已知明文恢复 RC4 内部状态、或利用密钥派生弱点（如只由时间戳/用户名生成）。
- 若程序用标准库 RC4 且无额外 XOR，直接按标准 KSA/PRGA 实现；若像本题有变体，必须逐指令复刻（注意额外常量、密钥下标、初始状态）。
- 关联：[[ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer]]（Go + 改造 RC4 的多层逆向）、[[ctf-reverse-modified-rc4-rounds-sbox]]（改造 RC4 的另一种变体）、[[code-analysis-reverse-go-binary-layout-symbol-recovery]]（本题用到的 Go 二进制布局与符号恢复基础）。
- 边界：文章脚本中的字符集 `Map` 未给出，且未展示最终 key/flag；本卡给出的是可复现的爆破框架，实际字符集和变体常量需按目标二进制调整。若密钥包含不可打印字节或长度更大，枚举空间会急剧增大。

## 检测与防御

- 检测（逆向方）：优先找 `KeySizeError`、`NewCipher`、`KeySize`、`crypto/rc4` 字符串与密钥长度比较；用文件 magic 做已知明文验证。
- 防御（CTF/软件开发方）：不要用 5 字符短密钥；使用带盐的 KDF（PBKDF2/scrypt/Argon2）派生密钥；使用 AEAD（AES-GCM/ChaCha20-Poly1305）并校验完整性；避免让密文文件保留可预测的固定头（可先压缩/封装）。
- 加固：反调试只能提高动态分析成本，不能阻止离线爆破；关键是通过足够大的密钥空间与认证加密让已知明文攻击不可行。
