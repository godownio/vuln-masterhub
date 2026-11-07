---
id: ctf-reverse-aes256-custom-rcon-key-schedule-decrypt
title: AES-256-CBC 密钥扩展 Rcon 魔改：自定义轮常量表重建轮密钥并解密
type: scenario
domain: ctf
path: ctf/reverse
technique: aes256-custom-rcon-key-schedule-decrypt
aliases:
- 魔改 AES
- 自定义 Rcon
- AES 密钥扩展
- RC4+AES 混合
- 自定义轮常量
- AES-256 CBC 逆向
tags:
- ctf
- reverse
- aes
- rcon
- key-schedule
- rc4
- pe
- unpacking
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:40:12+08:00'
  notes: 已对照原文re2与图22-46核对：自定义Rcon [0x9C,0x10,0x13,0x15,0x19,0x01,0x31]、AES-256的Nk=8/Nr=14/60字扩展与i%8==0/4分支、标准S-box与逆轮函数、CBC首块用IV异或、PKCS#7去填充、KEY/IV/CT与原文一致；外层RC4解.mydata/.hello亦与图40-44一致。PoC已用原文KEY/IV/CT本机复跑，解出dart{c3d4f5cc-8aab-46ce-a188-2fc453f3b288}。未验证点：CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
---

## 一句话结论

当二进制使用 AES-256-CBC 但把密钥扩展中的 `Rcon` 表换成自定义常量（案例 `9C 10 13 15 19 01 31`）时，标准 AES 库会用错误的轮密钥解出乱码；从 `.rodata` 提取自定义 Rcon、按 AES-256 的 60 字密钥扩展重建轮密钥，再用标准逆轮函数解密并 CBC 异或，即可还原明文。

## 原理

- AES-256 密钥扩展：`Nk=8`、`Nr=14`、共 `4*(Nr+1)=60` 个 32 bit 字。对 `i >= 8`：
  - 若 `i % 8 == 0`：`temp = SubWord(RotWord(w[i-1])) ^ Rcon[i/8]`；
  - 若 `i % 8 == 4`：`temp = SubWord(w[i-1])`；
  - `w[i] = w[i-8] ^ temp`。
  `Rcon` 只在 `i=8,16,24,32,40,48,56` 这 7 处参与异或，因此替换 Rcon 会让这些位置之后的所有轮密钥偏离标准值。
- 标准 AES `Rcon[1..7] = 01 02 04 08 10 20 40`；案例二进制中的表是
  `[0x9C, 0x10, 0x13, 0x15, 0x19, 0x01, 0x31]`。只看 S-box 是标准 AES 表，但解密结果会全错。
- 解密流程本身不变：`AddRoundKey(K14) → 13 轮 [InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns] → InvShiftRows → InvSubBytes → AddRoundKey(K0)`；CBC 模式下每块明文 = `AES_dec(ct_block) XOR prev_ct`（首块 prev = IV），最后 PKCS#7 去填充。
- 识别信号：
  - `.rodata` 出现 7 个特殊 32 bit/8 bit 常量（如案例的 `9C 10 13 15 19 01 31`）；
  - 密钥扩展代码含 `xtime`（`0x11B` 多项式）、`SubWord/RotWord`、60 字循环；
  - 有标准 AES S-box，但用标准库解密失败；
  - 对称加密前常伴随 RC4 等解密层（案例 `.mydata`/`.hello` 先用 RC4 解密）。

## 触发条件

- 分析目标使用 AES（S-box/ShiftRows/MixColumns 标准），但密钥扩展的 Rcon 或轮数被修改；
- 能从二进制/内存中取得 32 字节 key、16 字节 IV 与至少一块密文；
- 标准 AES 库解密结果不合理，且二进制中存在非标准 Rcon 表；
- 能确认 CBC 模式与填充方式（案例 PKCS#7）。

## 利用步骤

1. 在 IDA 中定位 AES 逆轮函数与密钥扩展；确认 14 轮、60 字、`0x11B` 的 xtime。
2. 在 `.rodata` 找 7 个 Rcon 常量；与标准 `01 02 04 08 10 20 40` 对比。
3. 提取 key/IV/ciphertext（可能来自 `.rdata`、配置或动态调试）。
4. 用自定义 Rcon 实现 `key_expand_256_custom`，生成 15 组轮密钥。
5. 实现标准 AES-256 逆轮（或在标准库基础上替换轮密钥，若库允许），按 CBC 逐块解密并 XOR。
6. PKCS#7 去填充，验证 flag/文本格式；若乱码，检查 Rcon 大小端、轮密钥顺序、IV 与首块处理。

## PoC

```python
SBOX = [ ... ]  # 标准 AES S-box，256 字节
RCON = [0x9C, 0x10, 0x13, 0x15, 0x19, 0x01, 0x31]

def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = xtime(a)
    return p

def key_expand_256_custom(key, rcon):
    w = list(key)
    i = 8
    while i < 60:
        t = w[4*(i-1):4*i]
        if i % 8 == 0:
            t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]  # RotWord + SubWord
            t[0] ^= rcon[i//8 - 1]
        elif i % 8 == 4:
            t = [SBOX[x] for x in t]                               # SubWord
        prev = w[4*(i-8):4*(i-8)+4]
        w.extend([prev[j] ^ t[j] for j in range(4)])
        i += 1
    return [w[16*r:16*(r+1)] for r in range(15)]

def inv_shift_rows(s):
    idx = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    return [s[i] for i in idx]

def inv_mix_columns(s):
    out = s[:]
    for c in range(4):
        i = 4*c
        a0, a1, a2, a3 = s[i:i+4]
        out[i+0] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9)
        out[i+1] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13)
        out[i+2] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11)
        out[i+3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14)
    return out

def dec_block_custom(ct, rk, inv_sbox):
    s = [ct[i] ^ rk[14][i] for i in range(16)]
    for r in range(13, 0, -1):
        s = inv_shift_rows(s)
        s = [inv_sbox[x] for x in s]
        s = [s[i] ^ rk[r][i] for i in range(16)]
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = [inv_sbox[x] for x in s]
    return bytes(s[i] ^ rk[0][i] for i in range(16))

def cbc_decrypt(key, iv, ct, rcon):
    inv_sbox = [0]*256
    for i, v in enumerate(SBOX):
        inv_sbox[v] = i
    rk = key_expand_256_custom(key, rcon)
    prev, out = iv, bytearray()
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16]
        dec = dec_block_custom(blk, rk, inv_sbox)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = blk
    p = out[-1]
    return bytes(out[:-p]) if 0 < p <= 16 else bytes(out)
```

```python
KEY = bytes.fromhex("c23012ab39101833f8ed4e468da15d8d8cfbf0726899dc7c846e7ecf32bbdaf8")
IV  = bytes.fromhex("aeba0dbbca267f9906ed7c70e38d8b11")
CT  = bytes.fromhex("9b5e1e8fd7c34362a23786c0ce3d3cf4"
                    "c3b688ff3c9c13d2bb6f49ceff59a25c"
                    "36e4619e6061c3bb3f63af003b3d8da7")
print(cbc_decrypt(KEY, IV, CT, RCON).decode())
```

## 变体与关联

- 魔改点可能是 Rcon、S-box、ShiftRows、MixColumns、轮数、末轮是否省略 MixColumns 的任意组合；逐一与标准 AES 对比即可定位。
- 案例外层还有 RC4 解密 `.mydata`/`.hello`（标准 RC4），可用现成的 RC4 逆向卡处理。
- 关联 [[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]]：自定义 S-box + ShiftRows 的 AES 变体；本卡补充 Rcon 只在密钥扩展中生效、标准 S-box 也会让标准库解密失败的情况。
- 关联 [[ctf-reverse-png-lsb-custom-sbox-aes256-decrypt]]：从图像 LSB 提取自定义 S-box 后解密 AES-256。
- 关联 [[ctf-reverse-multistage-pe-vm-modified-sm4]]：同为“识别分组密码结构并替换魔改参数”的逆向思路。
- 边界：若 Rcon 与 S-box 同时被改、或轮密钥在运行时由外部输入派生，需要动态 dump 轮密钥；仅有密文无 key/IV 时无法解密。

## 检测与防御

- 分析侧：先确认算法骨架（S-box、轮数、MixColumns），再逐项比对 Rcon/ShiftRows 等常量；用已知明文-密文对验证。
- 防御侧：不要依赖“魔改算法”作为保密手段；密钥与 IV 不应硬编码在客户端。
- 检测：二进制 `.rodata` 中非标准 Rcon 常量、异常 7 元常量表、AES 密钥扩展与 RC4 组合；网络流量为固定块长度的 CBC 密文。
- 加固：使用标准密码库与硬件加密，密钥由服务端/KMS 管理，避免离线提取。
