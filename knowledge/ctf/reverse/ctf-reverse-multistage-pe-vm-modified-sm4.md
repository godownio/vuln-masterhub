---
id: ctf-reverse-multistage-pe-vm-modified-sm4
title: 多阶段 PE + 自定义 VM 魔改 SM4 逆向
type: scenario
domain: ctf
path: ctf/reverse
technique: multistage-pe-vm-modified-sm4
aliases:
- 多阶段 PE
- 自定义 VM
- 魔改 SM4
- Disguise
- 花指令
- PE 内嵌二阶段
tags:
- ctf
- reverse
- pe
- vm
- sm4
- unpacking
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:14:15+08:00'
  notes: 已对照原文核对：第一层 input[i]-=i 假校验、0x470000 长度 0x15000、0x41C000 DWORD 低字节 ^0x07 还原 MZ、二阶段 key We1c0me_t0_xmctf、替换 FK [0x12345678,0x9ABCDEF0,0xFEDCBA98,0x87654321]、SM4 轮函数 T/T'、48 字节 3 块与 0x421018 密文比较、flag xmctf{We1c0me_t0_the_w0r1d_0f_VM_And_PEL0ader!!} 均一致。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

第一层 PE 只做 `input[i] -= i` 的假校验，真正的二阶段 PE 用 DWORD 低字节异或 `0x07` 藏在 `.data`；二阶段用自定义 VM 实现魔改 SM4（key `We1c0me_t0_xmctf`、替换 FK/CK/S-box、标准 T/T' 轮函数），对 48 字节输入分 3 块做 32 轮加密后与 12 个 DWORD 比较，按 SM4 解密即可恢复 flag。

## 原理

- 第一层 `sub_4133A0` 对输入做 `input[i] -= i`，再与 `byte_480CD4` 比较；逆运算 `plain[i] = encoded[i] + i` 得到 fake flag（`This is a fake flag`）。
- `sub_412C10` 从 `0x470000` 读取长度 `0x15000`，从 `0x41C000` 起按 DWORD 读取，取低字节异或 `0x07`，写入新缓冲区；结果以 `MZ` 开头，是二阶段 PE。
- 二阶段 VM 的指令分发包含算术/控制流/内存读写；通过识别 S-box 表、FK/CK 常量和轮函数，可确认它实现的是 SM4：
  - key schedule：`rk[i] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i])`，`T'(x)=tau(x)^rol(x,13)^rol(x,23)`；
  - round：`X[i] ^= T(X[i+1]^X[i+2]^X[i+3]^rk[i])`，`T(x)=tau(x)^rol(x,2)^rol(x,10)^rol(x,18)^rol(x,24)`；
  - 最后反序 `[X0,X1,X2,X3] -> [X3,X2,X1,X0]`。
- 与标准 SM4 的差异：FK 被替换为 `[0x12345678,0x9ABCDEF0,0xFEDCBA98,0x87654321]`，CK/S-box 也可能被替换；但轮函数结构不变，按实际常量实现即可解密。
- 输入 48 字节 = 3 个 16 字节块；密文是 `0x421018` 起的 12 个 DWORD；用 32 轮轮密钥逆序解密。

## 触发条件

- 第一层 PE 的 `.data` 中存在大块高熵数据，按 DWORD 低字节/异或等规律可还原出 `MZ`。
- 二阶段包含自定义 VM/解释器，指令分发与算术/内存操作。
- VM 中出现 256 项 S-box、32 个 CK 常量、4 个 FK 常量、32 轮循环。
- 输入按 16 字节分组、与 DWORD 数组比较。

## 利用步骤

1. 分析第一层，提取 `input[i]-i` 的 fake 校验与 `.data` 加密块参数（长度、起始地址、异或值）。
2. 按 `decoded[i] = (dword[i] & 0xFF) ^ 0x07` 还原二阶段 PE，检查 `MZ`。
3. 在二阶段中定位 S-box/FK/CK 与 VM 轮函数，确认 SM4 变体。
4. 提取 key、密文、轮常量；实现 key schedule 与 32 轮解密（轮密钥逆序）。
5. 对 3 个密文块解密，拼接明文，去掉填充/截断到 flag。
6. 用格式校验；若失败，检查字节序、FK/CK 是否被替换、是否反序。

## PoC

```python
def rol32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def tau(x, sbox):
    return ((sbox[(x >> 24) & 0xFF] << 24) | (sbox[(x >> 16) & 0xFF] << 16)
            | (sbox[(x >> 8) & 0xFF] << 8) | sbox[x & 0xFF])

def t_key(x, sbox):
    y = tau(x, sbox)
    return y ^ rol32(y, 13) ^ rol32(y, 23)

def t_round(x, sbox):
    y = tau(x, sbox)
    return y ^ rol32(y, 2) ^ rol32(y, 10) ^ rol32(y, 18) ^ rol32(y, 24)

def sm4_decrypt(key, ciphertext, fk, ck, sbox):
    mk = [int.from_bytes(key[i:i+4], "big") for i in range(0, 16, 4)]
    state = [mk[i] ^ fk[i] for i in range(4)]
    rk = []
    for i in range(32):
        tmp = state[(i+1) & 3] ^ state[(i+2) & 3] ^ state[(i+3) & 3] ^ ck[i]
        state[i & 3] ^= t_key(tmp, sbox)
        rk.append(state[i & 3])

    out = bytearray()
    for b in range(0, len(ciphertext), 4):
        x = ciphertext[b:b+4]
        for i in range(32):
            tmp = x[(i+1) & 3] ^ x[(i+2) & 3] ^ x[(i+3) & 3] ^ rk[31 - i]
            x[i & 3] ^= t_round(tmp, sbox)
        x = [x[3], x[2], x[1], x[0]]
        for w in x:
            out.extend(w.to_bytes(4, "big"))
    return bytes(out)
```

## 变体与关联

- 变体：SM4 的 FK/CK/S-box 被替换，或轮数/反序不同；按实际常量实现。
- 变体：VM 可能是栈式/寄存器式，指令集不同；先写反汇编器再识别算法。
- 变体：二阶段可能是 ELF/Shellcode；提取方式类似。
- 关联：[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（SM4 常量识别）、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（自定义 VM）、[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]（多阶段 PE）。

## 检测与防御

- 检测：PE `.data` 中大块高熵数据、DWORD 低字节异或模式、VM 解释器与 SM4 常量。
- 防御：不要在客户端存放完整校验逻辑；使用服务端校验、代码签名与反篡改。
- 响应：确认二阶段可提取后，视为逻辑泄露，轮换相关密钥并审计客户端。
