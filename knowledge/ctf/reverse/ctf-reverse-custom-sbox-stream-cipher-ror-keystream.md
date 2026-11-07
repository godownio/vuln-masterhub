---
id: ctf-reverse-custom-sbox-stream-cipher-ror-keystream
title: 自定义 S 盒流密码逆向：魔改 KSA 条件索引 + ROR3 密钥流 + 前后异或链解密
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-sbox-stream-cipher-ror-keystream
aliases:
- EasyRE
- 上海市大学生网络安全大赛
- 魔改 RC4
- S 盒流密码
- ROR3 密钥流
- 链式异或混淆
tags:
- ctf
- reverse
- stream-cipher
- sbox
- rc4-variant
- keystream
- xor
- ror
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V243
  verified_at: '2026-11-07T13:40:04+08:00'
  notes: 已对照原文与14张图核对：S 盒初始化 j=(j+S[i]+i%7+4919)&0xff、i%3 分支 S[3*i]、ROR3、k_part=(i*j)%16、S_lookup 组合、链式异或逆序，与原文 exp 一致；已实际运行 PoC 复现 flag{Th1s_1s_A_Fl4w3d_Crypt0}（截图为小写 l），并修正卡内原误写 FL4w3d。dup-scan 与各 RC4/流密码变体卡为 related，非同一链。未验证点：未运行原始二进制；无 sources/版本。
---

## 一句话结论

加密函数分三段：先用 `j = (j + S[i] + i%7 + 4919) & 0xff` 打乱 256 字节 S 盒；主循环按 `i` 递增，当 `i%3==0` 时用 `j = (S[3*i] + j) & 0xff`、否则用 `j = (S[i] + j) & 0xff` 交换 `S[i]/S[j]`，再以 `(i*j)%16` 与 `S[(S[i]_old + S[i]) & 0xff]` 组合出密钥流，对密文做 `ROR(C,3)`、减 `k_part`、再异或 `S_lookup`；最后一段是链式异或 `C'[0]=C[0]^0x42`、`C'[i]=(C[i]^C[i-1])^0x42`。按逆序先解阶段 3，再复刻 S 盒初始化与主循环，即可从 29 字节密文恢复 `flag{Th1s_1s_A_Fl4w3d_Crypt0}`。

## 原理

- **S 盒是状态，不是常量表**：第一阶段把 `S[0..255]` 初始化为 `0..255`，并用密钥无关的 `j = (j + S[i] + i%7 + 4919) & 0xff` 做置换。`-7*(i/7)+i` 等价于 `i%7`，这是编译器对取模的优化，逆向时按 `i%7` 理解即可。
- **主循环是流密码**：每个明文字节对应一次 S 盒更新与一个密钥流字节。`i` 每轮自增；`i%3==0` 时索引跳变为 `S[3*i]`（`i` 最大 28，仍在 256 内），否则用 `S[i]`；交换后保存 `S_i_old`，密钥流由 `k_part=(i*j)%16` 与 `S_lookup=S[(S_i_old+S[i])&0xff]` 组合。
- **可逆的逐字节变换**：密文先循环右移 3 位（`ROR(C,3)`），再减去 `k_part`（8 位取模），最后异或 `S_lookup` 得到明文。三步都可逆，因此解密只需按相同顺序复刻 S 盒状态并做逆运算。
- **阶段 3 是链式异或**：加密最后把阶段 2 的输出 `C` 变成 `C'[0]=C[0]^0x42`、`C'[i]=C[i]^C[i-1]^0x42`；解密先按 `C[0]=C'[0]^0x42`、`C[i]=C'[i]^C'[i-1]^0x42` 还原，再把结果喂给主循环的逆运算。
- **为什么必须按逆序**：三个阶段串联，阶段 2 的 S 盒状态在加密过程中被修改；解密必须从阶段 3 的输出反推阶段 2 的输入，再用与加密完全相同的 S 盒初始化和更新顺序生成同一密钥流。

## 触发条件

- 二进制中存在 256 字节的 `S[i]=i` 初始化循环、随后的交换循环，以及逐字节的异或/移位/查表运算。
- 程序把用户输入经过该函数后与 `.rdata` 中的固定密文比较，或直接把密文数组硬编码。
- 可静态反编译（IDA/Ghidra）或动态调试，能读出密文与常量（本例 `0x42`、`4919`、`i%7`、`i%3`）。

## 利用步骤

1. 在 IDA 中定位加密函数（本例 `sub_140001070`），确认三个阶段的边界：S 盒初始化、逐字节主循环、末尾链式异或。
2. 从 `.rdata`/字符串引用处提取密文数组（本例 29 字节：`93 F9 8D 92 52 57 D9 05 ... EF 57`）与常量 `0x42`。
3. 先写阶段 3 逆运算，得到阶段 2 的输出 `intermediate_flag`。
4. 按 `j=(j+S[i]+i%7+4919)&0xff` 复刻 S 盒；按 `i`、`j`、`i%3` 分支复刻主循环，生成与加密相同的密钥流。
5. 对每个字节做 `plain = ((ROR(cipher,3) - (i*j)%16) & 0xff) ^ S[(S_i_old+S[i])&0xff]`，拼接输出并验证是否为 `flag{...}`。
6. 若结果乱码，检查 `ROR` 方向、`i%3` 分支、`S_i_old` 取的是交换前还是交换后的值，以及 `k_part` 是否应在交换后计算。

## PoC

```python
def ROR(v, b):
    return ((v >> b) | (v << (8 - b))) & 0xFF

enc = bytearray([
    0x93,0xF9,0x8D,0x92,0x52,0x57,0xD9,0x05,0xC6,0x0A,0x50,
    0xC7,0xDB,0x4F,0xCB,0xD8,0x5D,0xA6,0xB9,0x40,0x95,0x70,
    0xE7,0x9A,0x37,0x72,0x4D,0xEF,0x57
])
n = len(enc)

# 逆阶段 3：链式异或
mid = bytearray(n)
mid[0] = enc[0] ^ 0x42
for i in range(1, n):
    mid[i] = (enc[i] ^ enc[i - 1]) ^ 0x42

# 复刻阶段 1：S 盒初始化
S = bytearray(range(256))
j = 0
for i in range(256):
    tmp = S[i]
    j = (j + S[i] + (i % 7) + 4919) & 0xFF
    S[i], S[j] = S[j], tmp

# 逆阶段 2：逐字节密钥流
out = bytearray(n)
i = j = 0
for k in range(n):
    i = (i + 1) & 0xFF
    if i % 3 == 0:
        j = (S[3 * i] + j) & 0xFF
    else:
        j = (S[i] + j) & 0xFF
    s_i_old = S[i]
    S[i], S[j] = S[j], S[i]
    k_part = (i * j) % 16
    s_lookup = S[(s_i_old + S[i]) & 0xFF]
    out[k] = ((ROR(mid[k], 3) - k_part) & 0xFF) ^ s_lookup

print(out.decode())   # flag{Th1s_1s_A_Fl4w3d_Crypt0}
```

## 变体与关联

- 变体：S 盒初始化可用密钥参与（`j=(j+S[i]+key[i%len])&0xff`）、主循环可用 `i%3`/`i%5` 等条件选择不同索引，或把 ROR 换成 ROL/加减组合；逆向时以实际指令为准。
- 变体：末尾混淆可能是 `C[i]^C[i-1]`、`C[i]+C[i-1]` 或固定常量异或；先把该层逆掉再处理主循环。
- 关联：[[ctf-reverse-miniprogram-variant-rc4-reverse-ksa]]（RC4 KSA 变体）、[[ctf-reverse-modified-rc4-rounds-sbox]]（改轮数/ S 盒的 RC4）、[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（从 S 盒/常量识别加密算法）。
- 边界：若 S 盒初始化依赖随机数或输入，静态复刻会失败，需要动态 dump 运行时 S 盒；若主循环使用加密状态而非明文索引，需先确定状态更新顺序。

## 检测与防御

- 检测（逆向侧）：256 字节 `S[i]=i` 初始化、交换循环、逐字节 XOR/移位/查表是流密码（尤其 RC4 变体）的强特征；`.rdata` 中的定长密文与循环次数一致时可确认。
- 防御（CTF/软件）：不要自创流密码；使用标准 AES-GCM/ChaCha20-Poly1305 并正确管理 nonce；若必须混淆，至少不要让 S 盒状态与密钥流可被静态复刻。
- 分析侧：对魔改算法先写出加密伪代码，再逐行求逆；不要直接套标准 RC4 脚本。
