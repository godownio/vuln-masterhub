---
id: ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer
title: Go 程序 paper.bin 多层逆向：XOR/ROL 解包 + RC4-like 控制块 + 改造 XXTEA 参数派生
type: scenario
domain: ctf
path: ctf/reverse
technique: go-paper-bin-rc4-custom-xxtea-multilayer
tags:
- ctf
- reverse
- go
- file-format
- xor
- rol
- rc4
- xxtea
- key-derivation
- static-analysis
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:47+08:00'
  notes: 已对照原文 RE2 一节核对：paper.bin 218 字节/PAPR/0x20260404/size 198/seed 0x31415926/sentinel 0x5A17C4D2、XOR+ROL 解包公式、22/16/16/72/72 切分、p0 paper-window::cold-ink、p1 交错+p2 改造 RC4、CF4! 控制块、key4/delta/salt 派生、p3 合并、p5 (R+key_mix)^shift_mix 与重加密自校验、明文与 flag 均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer/
draft: false
kb_aliases:
- 墨烬残页
- RE2
- ink_ashes.exe
- paper.bin
- PAPR
- paper-window::cold-ink
- 改造 XXTEA
- CF4! 控制块
---

## 一句话结论

Go 程序 `ink_ashes.exe` 运行时会破坏 `paper.bin` 且不直接打印 flag，必须静态还原：`paper.bin` 头部给出 `PAPR/版本/size/seed/sentinel`，对 `paper[20:]` 做 XOR+ROL 解包后切出 keyObf/pageOdd/pageEven/leafA/leafB；`paper-window::cold-ink` 解出 key，交错+RC4-like 解出以 `CF4!` 开头的控制块，从控制块派生改造 XXTEA 的 `key4/delta/salt`，再合并 leafA/leafB 的 DWORD 并解密，得到 `flag{...}|mode=static-only|trail=paper`。

## 原理

- **文件结构**：`paper.bin` 共 218 字节；头部 `magic=PAPR`、`version=0x20260404`、`size=198`、`seed=0x31415926`、`sentinel=0x5A17C4D2`；正文从偏移 20 开始。
- **XOR/ROL 解包**：`decoded[i] = paper[20+i] ^ key_byte ^ ((9*i+65)&0xff)`，其中 `key_byte=(rol32(seed,i%31) >> (8*(i%4))) & 0xff`。这是按位置轮换 seed 字节的轻量混淆，静态即可还原。
- **分层切分**：`keyObf[0:22]`、`pageOdd[22:38]`、`pageEven[38:54]`、`leafA[54:126]`、`leafB[126:198]`；每层对应不同的解包/解密函数（原文 p0/p1/p2/p3/p5）。
- **p0 解 key**：对 `keyObf` 做 `b ^ ((7*i+51)&0xff)` 得到 `paper-window::cold-ink`，作为 p2 的 RC4-like 密钥。
- **p1 交错 + p2 RC4-like**：`p1` 把 pageOdd/pageEven 逐字节交错；`p2` 是改造的 RC4：KSA 中 `j=((i>>1)^(7*i))+s[i]+j+key[i%len]`，PRGA 中用 `key[i%len]&3`、`key[(5*i+3)%len]` 等位置相关项，最后输出 `s[(i+si+s[idx])&0xff] ^ ((13*i+90)&0xff) ^ c`。解密后控制块以 `CF4!` 开头。
- **控制块派生**：控制块 8 个 u32；`tail=word[7]`；`xxtea_key[i]=word[i+1] ^ rol32(tail,5*i+1)`；`delta=word[5] ^ 0x9E3779B9`；`salt=word[6]`。这些参数全部由控制块决定，不能写死标准 XXTEA 常量。
- **p3 合并**：`note[i]=leafA[i] ^ rol32(leafB[i], (i%5)+1)`，得到 18 个 u32 密文。
- **改造 XXTEA**：`p4_decrypt` 使用 `sum=delta*(52//n+6)`，每轮 `p5` 的混合为 `(R + key_mix) ^ shift_mix`；反编译容易误读成 `R + (key_mix ^ shift_mix)`，必须以汇编/实测为准。解密后 `rstrip(b"\0")` 得到 ASCII 明文。
- **自校验**：脚本用 `p4_encrypt(plain) == note` 验证解密正确，再按 `|` 切出 flag。

## 触发条件

- 目标为 Go/原生程序 + 自定义数据文件，程序运行时会修改/删除数据文件，不能依赖动态运行。
- 数据文件有明确 magic/version/size/seed/sentinel，正文经过 XOR/ROL/交错/RC4-like/XXTEA 等多层变换。
- 控制块/密钥可由文件内字段或固定字符串派生；加密参数不是标准常量。
- 明文为 ASCII/flag，末尾有可识别分隔符/校验。

## 利用步骤

1. 备份原始 `paper.bin`（程序会覆盖/破坏它），读取头部 magic/version/size/seed/sentinel。
2. 按 `decoded[i]=paper[20+i]^key_byte^((9*i+65)&0xff)` 解包，按 22/16/16/72/72 切分。
3. p0 解出 `paper-window::cold-ink`；p1 交错 pageOdd/pageEven；p2 RC4-like 解出 `CF4!` 控制块。
4. 从控制块 word 派生 `xxtea_key/delta/salt`。
5. p3 合并 leafA/leafB 为 18 个 u32；p4 改造 XXTEA 解密，`rstrip(b"\0")`。
6. 用 p4_encrypt 重新加密比对 note，确认参数/公式正确；按 `|` 取 flag。

## PoC

关键函数（按原文脚本重写，未在本库复跑）：

```python
def p0(data):
    return bytes(b ^ ((7 * i + 51) & 0xFF) for i, b in enumerate(data))

def p1(left, right):
    out = bytearray()
    for a, b in zip(left, right):
        out += bytes([a, b])
    return bytes(out)

def p5(sumv, y, z, p, e, salt, key):
    idx = (p & 3) ^ e
    key_mix = (sumv ^ y) + (z ^ key[idx])
    shift_mix = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))
    r = salt ^ rol32(sumv, p + e)
    return ((r + key_mix) & 0xFFFFFFFF) ^ (shift_mix & 0xFFFFFFFF)

# 控制块
control = p2(p1(decoded[22:38], decoded[38:54]), key)
assert control[:4] == b"CF4!"
words = struct.unpack("<8I", control)
tail = words[7]
xxtea_key = [words[i + 1] ^ rol32(tail, 5 * i + 1) for i in range(4)]
delta = words[5] ^ 0x9E3779B9
salt = words[6]

# leafA/leafB -> note -> p4_decrypt
note = [a ^ rol32(b, (i % 5) + 1) for i, (a, b) in enumerate(zip(leaf_a, leaf_b))]
plain = p4_decrypt(note, delta, salt, xxtea_key)
```

原文实测明文 `flag{da0c4814-a079-44c6-aec1-3178130c1052}|mode=static-only|trail=paper`；未在本库复跑。

## 变体与关联

- **文件格式变体**：magic/version/size/seed/sentinel + 多层切片；先按头字段还原种子/长度，再逐层解包。
- **加密变体**：RC4/RC4-like、XXTEA/TEA、自定义 Feistel、XOR/ROL；注意反编译对运算符优先级的误读。
- **参数派生变体**：控制块字段异或/旋转派生 key/delta/salt；不要默认标准常量。
- **关联卡片**：[[ctf-crypto-self-referential-key-tea-variant]]（TEA 变体/自引用密钥）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（UPX + VM 逆向）。

## 检测与防御

- **对逆向方**：先备份数据文件，静态还原格式；反编译结果要用汇编/重加密验证，尤其是 `(a+b)^c` 与 `a+(b^c)` 的优先级。
- **对保护方**：自定义文件格式/加密参数只能提高静态分析成本；应使用标准密码学 + 完整性校验，并把密钥放在受保护位置。
- **对题目设计方**：运行时破坏输入文件可以阻止“直接跑出 flag”，但也会给选手制造不可复现问题；应提供原始文件或明确说明备份。
