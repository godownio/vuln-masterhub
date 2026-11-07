---
id: ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt
title: Rust ELF 后门魔改 AES-128-CBC：自定义 S-box 与 ShiftRows，逆向外带流量解密 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-aes-variant-traffic-decrypt
tags:
- reverse
- aes
- custom-sbox
- shiftrows
- rust
- elf
- c2
- traffic-decrypt
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:29:41+08:00'
  notes: 已对照原文与图05/06/07核对：/home/ccb/flag.txt 与 192.168.117.1:9961、自定义 S-box@0x6970、ShiftRows [0,3,1,2]@0x6930、key@0x5280=4a7f2c91...、IV@0x5270=8e1af655...、Rcon@0x6a70、5 块密文、解密出 flag{F1n@1ly_...} 均与原文一致。PoC 未本机复跑；原文未标注组件版本。
url: /docs/ctf/reverse/ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt/
draft: false
kb_aliases:
- 魔改 AES
- 自定义 S-box AES
- 自定义 ShiftRows
- CBC 外带解密
- Rust ELF 后门加密
---

## 一句话结论

Rust ELF 后门读取 `/home/ccb/flag.txt` 后并非用标准 AES，而是用“自定义 S-box + 自定义 ShiftRows `[0,3,1,2]`”的 AES-128-CBC 加密，再把密文 POST 到 C2；从二进制 `.rodata` 提取 key、IV、S-box、Rcon 与 ShiftRows 表，按相同的魔改参数实现逆 cipher，即可解密流量中的外带密文拿到 flag。

## 原理

- 标准 AES 解密失败时，应怀疑实现被魔改。该样本与标准 AES-128 的差异有三处：
  1. S-box 是自定义的 256 字节置换表（位于文件偏移 `0x6970`），不是标准 AES S-box；
  2. ShiftRows 行移位表为 `[0,3,1,2]`（标准为 `[0,1,2,3]`），即第 1 行左移 3、第 2 行左移 1、第 3 行左移 2；
  3. CBC 使用固定 IV（偏移 `0x5270`），key 位于 `0x5280`，Rcon 位于 `0x6a70`。
- 加密流程仍是标准 AES 的 10 轮结构：AddRoundKey → SubBytes（自定义表）→ ShiftRows（自定义表）→ MixColumns，最后一轮不含 MixColumns；CBC 逐块 XOR 前一块密文。
- 因为 S-box 与 ShiftRows 都被替换，标准库无法解密；必须用样本自带的表实现逆 S-box、逆 ShiftRows、逆 MixColumns，再按 CBC 逐块解密。
- 逆向入口是明文字符串 `/home/ccb/flag.txt` 与 C2 地址 `192.168.117.1:9961`；在 IDA 中交叉引用可定位 `payload::main`，再顺着 `xmmword_5280`、`byte_6970`、`qword_6930`、`byte_6A70` 找到全部参数。

## 触发条件

- 拿到样本 ELF 与包含外带 POST 的 pcap/密文。
- 能定位并提取自定义 S-box、ShiftRows、key、IV、Rcon（符号/字符串未完全剥离时更容易）。
- 密文长度是 16 的倍数，使用 PKCS#7 填充。

## 利用步骤

1. `strings` 搜索 `/home/ccb/flag.txt`、C2 地址、`src/main.rs` 等特征，定位 `main`。
2. 在反汇编中识别 AES 轮结构，记录 key（`0x5280`）、IV（`0x5270`）、S-box（`0x6970`）、Rcon（`0x6a70`）、ShiftRows 表（`0x6930`）。
3. 从 pcap 提取 `POST /api/telemetry` 的 body（hex），按 16 字节分块。
4. 用自定义 S-box 生成逆 S-box，按 `[0,3,1,2]` 做逆 ShiftRows，标准逆 MixColumns，CBC 解密并去 PKCS#7。
5. 校验明文中的 `flag{...}`。

## PoC

```python
SBOX = open('payload_decrypted.elf','rb').read()[0x6970:0x6970+256]  # 自定义 S-box
KEY  = bytes.fromhex('4a7f2c91b35ed816fa4309cc7be5283d')
IV   = bytes.fromhex('8e1af65530c974bb2d974e1160daa73c')
SHIFT = [0, 3, 1, 2]          # 自定义 ShiftRows：第 r 行左移 SHIFT[r]
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

# 关键差异：逆 S-box 用样本表；逆 ShiftRows 对第 r 行右旋 SHIFT[r] 位
def inv_shift_rows(s):
    for r in range(1, 4):
        sh = SHIFT[r] & 3
        s[r] = s[r][-sh:] + s[r][:-sh]
```

```python
# 解密流程（与标准 AES 相同的逆轮结构，仅替换表与移位）
# add_round_key(state, round_keys, 10)
# for r in 9..1: inv_shift_rows; inv_sub_bytes(inv_sbox); add_round_key(r); inv_mix_columns
# inv_shift_rows; inv_sub_bytes; add_round_key(0)
# CBC: plaintext_block = dec(block) XOR prev；prev = block
```

```text
密文示例（5 块，hex）：
08a76a304f8a7d64baace233c30d8e78
9e27ec1ae589e7b36252ea00ecf2a9c2
74b18754f4758095956a08dc1c6793e0
7cf91658ae232ac3935aa17c03294a62
5c90ba2ef4b482ffb145388829ed5554
```

## 变体与关联

- 其他魔改方式：缺 Rcon、修改 MixColumns 矩阵、不同 ShiftRows 顺序、轮数变化；均可通过对比标准常量/表识别。
- 若 S-box 被加密或运行时生成，可动态 dump 轮函数使用的表。
- 关联：[[ctf-reverse-modified-rc4-rounds-sbox]]（同类“改轮函数/S-box”逆向）、[[ctf-reverse-whitebox-aes-runtime-table-reconstruction-mitm]]（AES 表白盒重建）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定 key 的 AES 识别）。

## 检测与防御

- 检测：ELF 中出现非标准 256 字节 S-box 表、非 `[0,1,2,3]` 的 ShiftRows 表、固定 key/IV 与 C2 地址组合；进程读取敏感文件后向固定 IP POST 定长密文。
- 取证：提取样本中的表与 key/IV，按相同魔改参数解密外带流量，还原被窃数据。
- 防御：监控敏感文件读取与异常外联；对二进制做常量/表特征扫描；限制后门进程的文件与网络权限。
