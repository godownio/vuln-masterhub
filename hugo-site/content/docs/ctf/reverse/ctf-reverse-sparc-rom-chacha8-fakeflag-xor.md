---
id: ctf-reverse-sparc-rom-chacha8-fakeflag-xor
title: SPARC 大端 ROM 逆向与 ChaCha8 魔改验证：fake_flag XOR 密文再 XOR keystream
type: scenario
domain: ctf
path: ctf/reverse
technique: sparc-rom-chacha8-fakeflag-xor
tags:
- ctf
- reverse
- sparc
- rom
- chacha8
- ghidra
- xor
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:47:43+08:00'
  notes: 已对照原文 JustROM 节核对：SPARC save/restore/retl 机器码、ROM/RAM 映射、FUN_00004238 ChaCha8 8 轮旋转 16/12/8/7、counter=1/nonce 0x41414141 等、key 于 ROM 0xC000、ciphertext/fake_flag、expected=fake_flag^ciphertext 与 user_input=expected^keystream，均与原文 exp 一致。未验证点：PoC 未本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-sparc-rom-chacha8-fakeflag-xor/
draft: false
kb_aliases:
- SPARC ROM 逆向
- ChaCha8 魔改
- fake_flag XOR
- JustROM
- SPARC 大端
---

## 一句话结论

当 ROM 中看到 `9D E3 BF A0`（save）、`81 E8 00 00`（restore）、`81 C3 E0 08`（retl）时，可判定为 SPARC 32-bit 大端；用 Ghidra 恢复出 ChaCha8（8 轮、旋转 16/12/8/7）后，按“`expected = fake_flag XOR ciphertext`、`enc_input = user_input XOR keystream`、比较相等”的验证逻辑，反推 `user_input = expected XOR keystream`。

## 原理

- **SPARC 识别**：SPARC 的 `save`/`restore`/`retl` 机器码有固定模式；`9D E3 BF A0` 是典型 `save %sp,-0x60,%sp`，`81 E8 00 00` 是 `restore`，`81 C3 E0 08` 是 `retl`。题目给出 ROM/RAM 映射：ROM base `0x10800000` size `0x10000`，RAM base `0x107F0000` size `0x14000`。
- **ChaCha8 识别**：`FUN_00004238` 中出现 quarter round 结构，旋转常量 `16,12,8,7`，但只跑 8 rounds（4 个 double-round），不是标准 ChaCha20 的 20 rounds；状态初始化 `FUN_0000409c` 使用 `"expand 32-byte k"` sigma、256-bit key、counter=1、nonce `0x41414141/0x42424242/0x43434343`。
- **验证逻辑**：
  1. 内置 `ciphertext`（32 字节真密文）和 `fake_flag`（32 字节 `"There_is_nothing_you_wanna_get.."`）；
  2. `expected = fake_flag XOR ciphertext`；
  3. 生成 ChaCha8 keystream（32 字节），`enc_input = user_input XOR keystream`；
  4. 比较 `enc_input == expected`，相等则通过。
- **反推**：`user_input = expected XOR keystream`；因为 XOR 是对合，且 ChaCha8 是对称流密码，知道 key/nonce/counter 即可生成同一 keystream。
- **字节序**：ROM 中的 key 按大端读成 8 个 word；ChaCha 输出字节流按 little-endian 打包；这两点必须与二进制一致，否则 keystream 不同。

## 触发条件

- 输入是 ROM/固件镜像，机器码呈现 SPARC `save/restore/retl` 特征。
- 反编译中出现 16 字状态、sigma 常量、quarter round（旋转 16/12/8/7）和 8 轮循环。
- 验证逻辑是 XOR 比较（`expected = fake_flag XOR ciphertext`、`enc_input = user_input XOR keystream`）。
- 能从 ROM 固定偏移读到 key、nonce、ciphertext、fake_flag。

## 利用步骤

1. 用 `xxd`/Ghidra 确认 SPARC 32-bit 大端；按题目映射加载 ROM/RAM。
2. 定位 ChaCha core 与状态初始化函数，确认轮数（8）和旋转常量（16/12/8/7）。
3. 从 ROM 偏移 `0xC000` 读 32 字节 key（8 个大端 word）、nonce 3 个 word、counter=1；读 32 字节 ciphertext 和 fake_flag。
4. 实现 ChaCha8 block：sigma + key words + counter + nonce，4 个 double-round（共 8 rounds），输出加回初始状态，按 little-endian 打包 32 字节 keystream。
5. 计算 `expected = fake_flag XOR ciphertext`，`user_input = expected XOR keystream`。
6. 解码得到 flag；用 ROM 的加密路径复验（`user_input XOR keystream == expected`）。

## PoC

```python
import struct

def rotl32(x, r):
    x &= 0xFFFFFFFF; r &= 31
    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))

def qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = rotl32(x[b] ^ x[c], 7)

def chacha8(state):
    st, x = state[:], state[:]
    for _ in range(4):  # 8 rounds = 4 double rounds
        qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13)
        qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12)
        qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
    return [(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)]

KEY = bytes.fromhex("112233445566778899aabbccddeeff00"
                    "deadbeefcafebabe0badf00d13371337")
FAKE = b"There_is_nothing_you_wanna_get.."
CT = bytes.fromhex("37329bf636a918fcf2e749736149f8d4"
                   "4cf26ac93c4c628378125c055f30959d")
sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
state = sigma + list(struct.unpack(">8I", KEY)) + [1] + [0x41414141, 0x42424242, 0x43434343]
ks = b"".join(struct.pack("<I", w) for w in chacha8(state))[:32]
expected = bytes(a ^ b for a, b in zip(FAKE, CT))
print(bytes(a ^ b for a, b in zip(expected, ks)).decode())
```

说明：PoC 按原文 ChaCha8 与 fake_flag XOR 逻辑重写；未在本机对 ROM 附件复跑。

## 变体与关联

- **ChaCha20**：标准 20 rounds（10 double-rounds）；轮数不同导致 keystream 完全不同，必须按二进制确认。
- **Salsa20**：quarter round 的旋转常量与列/对角线顺序不同；识别 sigma 与状态布局。
- **大端/小端**：ROM key 按大端读 word、输出按 little-endian 打包；字节序错会导致全错。
- **fake_flag 技巧**：用 `fake_flag XOR ciphertext` 得到 `expected`，再与 keystream XOR；本质是“已知明文/诱饵”混淆，不增加密码强度。
- **关联**：[[ctf-reverse-gba-dma-boolean-circuit-unary-input]]（ROM 逆向）、[[ctf-reverse-wasm-login-fnv1a-feistel-xorshift-keystream]]（自定义流密码）。

## 检测与防御

- 识别：固件中出现 sigma `"expand 32-byte k"`、旋转常量 16/12/8/7、8/20 轮循环；`findcrypt`/Ghidra 可辅助。
- 防护：不要用固定 nonce/counter 的流密码硬编码 key；使用 AEAD、随机 nonce、密钥管理。
- CTF：即使使用 fake_flag/多层 XOR，只要 key/nonce 可从 ROM 读取，就能复现 keystream。
