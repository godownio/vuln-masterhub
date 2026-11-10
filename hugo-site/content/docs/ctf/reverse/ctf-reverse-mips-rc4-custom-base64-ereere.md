---
id: ctf-reverse-mips-rc4-custom-base64-ereere
title: MIPS CTF 逆向 ereere：字符串定位换表 Base64 与标准 RC4，按加密顺序逆解出 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: mips-rc4-custom-base64-reverse
tags:
- ctf
- reverse
- mips
- rc4
- base64
- custom-alphabet
- ida
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T07:46:43+08:00'
  notes: 已对照原文全文及图 01-11 核对：MIPS/IDA mipsrop 安装、字符串窗口密文 ScDZC...== 与字母表 ZYX.../+9876543210、sub_400864 标准 RC4 KSA/密钥 flag{123321321123badbeef012}、sub_4009DC 标准 PRGA、sub_400550 换表 Base64 与 CyberChef 输出 flag{RC_f0ur_And_Base_s1xty_f0ur_Encrypt_!} 均一致。未验证点：PoC 未在本机复跑，未实际安装 mipsrop 插件；CTF 题无组件版本。
url: /docs/ctf/reverse/ctf-reverse-mips-rc4-custom-base64-ereere/
draft: false
kb_aliases:
- 攻防世界 ereere
- MIPS 逆向
- 换表 Base64 逆向
- 标准 RC4 识别
- RC4 KSA/PRGA 逆解
- CyberChef 逆解 RC4
- mipsrop 插件
---

## 一句话结论

攻防世界 `ereere` 是一个 MIPS 程序：`shift+F12` 可见明文的“please input your flag:”、密文 `ScDZC1cNDZaxnh/2eW1UdqaCiJ0ijRIExlvVEgP43rpxoxbYePBhpwHDPJ==` 和自定义 Base64 字母表；跟进交叉引用可见主流程为“输入 → 标准 RC4（密钥 `flag{123321321123badbeef012}`）→ 换表 Base64 → 与密文比较”。按相反顺序先用自定义字母表做 Base64 解码，再用同一密钥和标准 RC4 解密，即得 `flag{RC_f0ur_And_Base_s1xty_f0ur_Encrypt_!}`。

## 原理

- **MIPS 与 IDA 插件**：MIPS 程序的伪代码/ROP 辅助依赖 IDA 7 + `mipsrop` 插件；旧插件是 Python2 代码，在 IDA 7 的 Python3 下需把 `from shims import ida_shims` 改为 `import ida_shims` 并为 `print` 加括号，然后在 `File → Script command` 中 `import mipsrop; mipsrop = mipsrop.MIPSROPFinder()` 加载，之后可在 `Edit → Plugins → MIPS ROP Finder` 使用（该插件主要服务 MIPS 栈溢出/ROP，本题只用于逆向辅助）。
- **字符串三角定位**：`shift+F12` 打开字符串窗口，看到输入提示、密文和一段 64 字符的字母表 `ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz/+9876543210`；该字母表不是标准 Base64，说明程序使用了换表。
- **主流程**：对密文/字母表 `Ctrl+X` 找交叉引用，定位主函数；主函数依次调用 `sub_41A6E0`（类似 `strlen`，用于取输入长度）、`sub_4009DC`（RC4 加/解密）、`sub_400550`（换表 Base64），最后 `sub_41A1E0` 与密文比较。
- **识别标准 RC4**：`sub_400864` 先 `for(i=0;i<256;i++) S[i]=i;`，再做 `j = (j + S[i] + key[i % len(key)]) & 0xff` 与交换——这是标准 RC4 KSA；`sub_4009DC` 先调用 KSA，再 `i=(i+1)%256; j=(j+S[i])%256; swap; t=(S[i]+S[j])%256; data[k] ^= S[t]`——标准 RC4 PRGA。KSA 中使用的密钥数组 `aFlag1233213211` 即字符串 `flag{123321321123badbeef012}`。
- **识别换表 Base64**：`sub_400550` 逐个取 3 字节输入、按 `>>2`、`(x&3)<<4 | ...` 等标准 Base64 分组方式，用自定义字母表 `aZyxwvutsrqponm...`（与字符串窗口的字母表一致）替换标准 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`，并以 `=` 补齐。
- **为什么逆序可行**：Base64 与 RC4 均为可逆变换（RC4 加解密同一操作，Base64 换表只需把自定义字母表映射回标准表）；程序加密顺序是 RC4 后 Base64，所以解密顺序是 Base64 反变换后 RC4。
- **边界**：字母表/密钥硬编码在该样本；换表 Base64 的索引若有额外异或/加减（本样本没有）需按实际代码调整；CyberChef 的 From Base64 需选择自定义 Alphabet，RC4 Passphrase 用 Latin1 输入；若密文包含非字母表字符需关闭 Remove non-alphabet chars 或按代码处理。

## 触发条件

- 拿到 MIPS 架构的 CTF 逆向题（`file` 显示 MIPS/MIPSEL，IDA 需 MIPS 支持/插件）。
- 字符串窗口能看到输入提示、密文、非标准 Base64 字母表等明显线索。
- 能定位主函数并识别 RC4 KSA/PRGA 与 Base64 换表逻辑。
- 仅用于授权 CTF/逆向分析。

## 利用步骤

1. 用 `file`/IDA 确认 MIPS 架构；按需安装/修复 `mipsrop` 插件（Python3 兼容）。
2. `shift+F12` 查看字符串：记录提示、密文 `ScDZC...`、字母表 `ZYXWVUTS.../+9876543210`。
3. 对密文/字母表 `Ctrl+X` 找交叉引用，定位主函数；重命名 `sub_41A6E0` 为 `strlen_like`、`sub_4009DC` 为 `rc4_crypt`、`sub_400550` 为 `base64_custom`。
4. 分析 `sub_400864`：确认 256 次初始化、`key[i % len]` 加和交换，即标准 RC4 KSA；从密钥数组读取密钥 `flag{123321321123badbeef012}`。
5. 分析 `sub_4009DC`：确认 PRGA 与逐字节 XOR；分析 `sub_400550`：确认自定义字母表替换。
6. 逆序解密：先按自定义字母表把密文 Base64 解码为 RC4 密文字节，再用密钥做 RC4 解密。
7. 用 CyberChef（From Base64→自定义 Alphabet→RC4）或 Python 脚本得到 flag，与格式核对。

## PoC

CyberChef 两个操作：

```text
1) From Base64
   Alphabet: ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz/+9876543210
   Input:    ScDZC1cNDZaxnh/2eW1UdqaCiJ0ijRIExlvVEgP43rpxoxbYePBhpwHDPJ==
2) RC4
   Passphrase: flag{123321321123badbeef012}
   Input format: Latin1
   Output format: Latin1
```

等价 Python：

```python
import base64

alpha = "ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz/+9876543210"
std   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ct    = "ScDZC1cNDZaxnh/2eW1UdqaCiJ0ijRIExlvVEgP43rpxoxbYePBhpwHDPJ=="

data = base64.b64decode(ct.translate(str.maketrans(alpha, std)))

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

print(rc4(data, b"flag{123321321123badbeef012}").decode())
```

输出：

```text
flag{RC_f0ur_And_Base_s1xty_f0ur_Encrypt_!}
```

说明：原文使用 CyberChef 完成同样的两步逆解；Python 中 `str.translate` 把自定义字母表映射回标准表后再 `b64decode`。若自定义字母表含 `/+` 重排，必须逐字符映射，不能直接 `b64decode`。

## 变体与关联

- **换表 Base64**：更多换表/索引魔改变体见 [[ctf-reverse-base64-table-index-mutation]]（本样本是纯换表，无索引异或/加法）。
- **RC4 变体**：若 KSA/PRGA 被改动（轮数、密钥重复方式、异或后再减），按修改点同步逆运算，见 [[ctf-reverse-modified-rc4-rounds-sbox]]、[[ctf-reverse-modified-rc4-keytable-subtract-xor]]。
- **MIPS 逆向/ROP**：`mipsrop` 插件主要用于 MIPS ROP gadget 搜索，见 [[binary-pwn-rop-mips32-stack-frame-gadget-args]]；本题的 MIPS 架构只影响工具配置，不改变算法逆解。
- **工具**：CyberChef 的 From Base64 支持自定义 Alphabet，RC4 算子可直接指定 Passphrase；Python 脚本更适合批量/复杂变体。
- **边界**：若密文尾部 `=` 数量/字母表长度与标准 Base64 不符，需确认程序是否使用自定义补齐规则。

## 检测与防御

- **检测（CTF 出题）**：自定义字母表 + 标准算法组合容易被 CyberChef 一把梭；可通过索引变换、密钥混淆、算法变体提高难度，但不应作为真实安全边界。
- **防御（真实产品）**：换表 Base64 与 RC4 都不提供现代安全性；敏感数据应使用 AES-GCM/ChaCha20-Poly1305 等认证加密，密钥由 KMS 管理，不要硬编码在二进制中。
- **分析侧**：识别 RC4 的关键是 256 字节 S 盒初始化 + `j=(j+S[i]+key[i%len])` 交换；识别换表 Base64 的关键是 64 字符字母表与 3→4 分组位运算；两者可组合成“先 Base64 反变换再 RC4”的通用逆解流程。
