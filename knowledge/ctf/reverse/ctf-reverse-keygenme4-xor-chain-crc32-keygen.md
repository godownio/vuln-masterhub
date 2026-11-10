---
id: ctf-reverse-keygenme4-xor-chain-crc32-keygen
title: keygenme 序列号校验逆向：128 hex→16 DWORD、16 个固定密钥、XOR 链式(extra=前一密文块)解密、CRC32 校验与注册机编写（movzx/movsx 差异）
type: scenario
domain: ctf
path: ctf/reverse
technique: keygenme-xor-chain-crc32-registration
aliases:
- keygenme 注册机
- 序列号校验逆向
- XOR 链式解密
- extra = 前一密文块
- CRC32 完整性校验
- license 结构体还原
- movzx 与 movsx 符号扩展差异
tags:
- ctf
- reverse
- keygen
- xor
- crc32
- license
- byte-order
- windows
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T21:46:56+08:00'
  notes: 已对照原文核对：128 hex→16 DWORD、16 个 get_key 固定密钥、链式 XOR（extra=前一密文块 enc[i-1]）、自定义 sum_crc32（movzx 零扩展 vs 同系列 movsx 符号扩展）、license 结构偏移、注册机 C 代码均与 content.md 一致；为完整可复用的可逆注册机算法（非未打通/理论链），路径合法，dedup 非同链、dup-scan 无 pair；未验证点：未在本机编译运行注册机，该批次卡按 KB 现状不含 sources/source_url 溯源字段。
---

## 一句话结论

对这类 Windows x86 keygenme，序列号是 128 个十六进制字符转成的 16 个 DWORD，程序用 16 个 `get_key_N` 提供的固定 DWORD 密钥做「链式异或」解密（`plain[i] = enc[i] ^ keys[i] ^ enc[i-1]`，`enc[-1]=0`），还原出 `license{name[32], sn, featureset, expiration, pad[16], crc32}` 结构，再用自定义 CRC32 校验前 15 个 DWORD 与第 16 个 `crc32` 字段；因算法完全对称可逆，注册机只需构造 license、算 CRC32、做同样异或加密并输出 16 个 `%08X`。

## 原理

- **输入编码**：序列号字符串长度 128（十六进制字符），按每 8 字符切一段 `int(hex[i:i+8],16)` 得到 16 个 DWORD；结构按内存布局是 16 个 DWORD = 64 字节（`name[32]` 占 8 个 DWORD、`sn`/`featureset`/`expiration` 各 1 个、`pad[16]` 占 4 个、`crc32` 占 1 个）。
- **密钥**：16 个 `get_key_0..get_key_15` 函数各返回一个固定 DWORD，构成 `keys[16]`（如 `0x10D88067、0xBC16D3D5、0xE7039A64、...`）。
- **链式 XOR**：解密循环 `data[i] = enc[i] ^ keys[i] ^ extra`，`extra` 初值 0、每轮结束后置为 `enc[i]`（**前一密文块**）。因此 `plain[i] = enc[i] ^ keys[i] ^ enc[i-1]`，与 CBC 模式「前一密文块参与下一块」同构；加密方向对称：`enc[i] = plain[i] ^ keys[i] ^ enc[i-1]`。注意 extra 取的是「当前块加密后的结果」而非明文，这是易写错的点。
- **校验字段**：解密后实际只用到 3 个业务字段 —— `data[8]`（sn）、`data[9]`（featureset）、`data[10]`（expiration）；完整性用 CRC32：`calculate_crc32(data[:-1]) == data[15]`（前 15 个 DWORD 的 CRC 存于最后一个 DWORD）。
- **自定义 CRC32 的坑**：程序里的 `sum_crc32` 是逐字节 `crc = data[i] ^ 0xFFFFFFFF ^ crc`、内循环 8 次 `crc = (crc>>1)^0xEDB88320` 或 `crc >>= 1`、每字节后再 `crc ^= 0xFFFFFFFF` 的变体，不是可直接套标准库的实现；更关键的是**字节扩展成 DWORD 时是零扩展还是符号扩展**：本题用 `movzx ecx, byte ptr [eax]`（零扩展），同系列前一题用 `movsx esi, byte [eax+ecx]`（符号扩展），照搬前一题的 CRC 算法会一直算不对。
- **字节序**：C 里直接把 license 当 `DWORD*` 输出，内存中 little-endian 字节序自然成立；用 Python 写注册机/解析器时需显式处理 DWORD→8 位十六进制字符串的字节顺序。
- **为什么可逆**：加密是逐块异或、密钥固定、校验是线性 CRC 且作为结构字段存在，没有单向函数或数字签名，故输入空间完全可构造。

## 触发条件

- CTF Windows x86 keygenme：输入为十六进制序列号字符串，程序提示 name / serial / featureset / expiration。
- 已能看清 `main` 逻辑（对混淆程序需先去混淆），能拿到 16 个 `get_key_N` 的固定返回值与 `sum_crc32` 实现。
- 校验为对称 XOR + CRC32（无公钥签名/哈希链）；目标仅需生成合法序列号。

## 利用步骤

1. 把输入的 128 字符 hex 按 8 字符切成 16 个 DWORD `enc[0..15]`。
2. 从 `get_key_0..15` 提取 16 个固定 DWORD 密钥 `keys[16]`。
3. 链式解密：`plain[i] = enc[i] ^ keys[i] ^ (i? enc[i-1] : 0)`，得到 license 的 16 个 DWORD。
4. 读字段：`sn=plain[8]`、`featureset=plain[9]`、`expiration=plain[10]`；验证 `crc32(plain[0..14]) == plain[15]`。
5. 写注册机：声明与程序一致的 license 结构（`char name[32]; DWORD sn, featureset, expiration; char pad[16]; DWORD crc32;`）→ 读入 name/sn/featureset/expiration → `crc32 = sum_crc32((unsigned char*)&license, 60)` → 对 16 个 DWORD 执行 `enc[i] = plain[i] ^ keys[i] ^ enc[i-1]` → 逐个 `printf("%08X", dword)` 输出。
6. 注意 Python 实现的 DWORD 字节序与 `movzx`（零扩展）版本的 CRC；用程序自带 `sum_crc32` 语义对齐，不要套用同系列其它题的 `movsx` 版本。

## PoC

解密（Python 骨架）：

```python
def hex_to_dwords(s): return [int(s[i:i+8],16) for i in range(0,len(s),8)]
keys = [0x10D88067,0xBC16D3D5,0xE7039A64,0x39EC8A6D,
        0xFF09B4BF,0xF828DB76,0x8BE40C8E,0xF7AA583E,
        0x60858E23,0xE487F5A3,0x39A57B89,0xB006573E,
        0x79609807,0x620AD108,0x5CD86398,0x6CA94B51]
def dec(enc):
    out, extra = [], 0
    for i,c in enumerate(enc):
        out.append(c ^ keys[i] ^ extra); extra = c   # extra 取密文块
    return out
data = dec(hex_to_dwords(serial128))
print("sn=%x feature=%x expiration=%x" % (data[8],data[9],data[10]))
assert crc32_of(data[:-1]) == data[15]
```

注册机加密（C 骨架）：

```c
DWORD extra = 0;
for(int i=0;i<16;i++){
  dwords[i] = dwords[i] ^ keys[i] ^ extra;
  extra = dwords[i];              // 更新为当前密文块
}
for(int i=0;i<16;i++) printf("%08X", dwords[i]);
```

（按文章算法最小化整理，未在本机编译运行；`crc32_of` 需按题目 `movzx` 版 `sum_crc32` 实现。）

## 变体与关联

- 变体：`extra` 若取「前一明文块」则变为另一种链式，写注册机前必须确认 extra 更新的是密文还是明文；本题取密文（`enc[i]`）。
- 变体：CRC32 实现可能是标准 CRC-32/ISO-HDLC、带 `^0xFFFFFFFF` 前后处理的变体，或逐字节符号扩展（`movsx`）版，需逐题比对反汇编还原。
- 变体：DWORD 输出顺序（大小端）与 name 字段长度变化会改变结构布局，须以实际 `data[8..10]`、`data[15]` 偏移为准。
- 关联：[[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]（同样 XOR+CRC32 组合但带 MT19937 流）、[[ctf-reverse-aes-mixcolumns-extra-xor-0x55]]（魔改对称算法写注册机）、[[ctf-misc-crc32-four-byte-preimage-gf2-linear]]（CRC32 线性性质）；本题是固定密钥 + 链式 XOR + CRC32 的最简可逆形态。
- 局限：结论依赖具体题目二进制，密钥与 CRC 实现需实测提取；仅适用于算法可逆、无签名校验的注册机题。

## 检测与防御

- CTF 逆向方法，无真实攻击危害；不执行目标程序中的任何指令，只静态还原算法。
- 软件保护方：对称 XOR + CRC32 校验是可逆的，不能抵抗注册机；应改用非对称数字签名（私钥签发、公钥验签）、把校验分散进业务逻辑、结合硬件/在线激活，并对关键常量做保护。
- 使用方（解题）：先确认 CRC 的字节扩展方式（`movzx`/`movsx`）与字节序，这是最常见的「算法对但结果不对」原因；用已知合法序列号回归验证解密与 CRC 后再批量生成。
