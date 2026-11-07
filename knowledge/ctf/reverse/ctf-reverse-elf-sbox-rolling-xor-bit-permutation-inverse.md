---
id: ctf-reverse-elf-sbox-rolling-xor-bit-permutation-inverse
title: ELF 三层可逆校验逆解：256 字节 S-box + 前缀异或链 + 8 位重排
type: scenario
domain: ctf
path: ctf/reverse
technique: elf-sbox-rolling-xor-bit-permutation-inverse
aliases:
- Vital Signs
- S-box 替换
- 滚动异或
- 前缀异或链
- bit 置换
- 三层可逆
tags:
- ctf
- reverse
- elf
- sbox
- rolling-xor
- bit-permutation
- inverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:22:42+08:00'
  notes: 已对照原文核对：长度 37、256 字节置换 S-box、state=0x37*len+0x42=0x35 的前缀异或链、bit map [5,2,7,0,6,1,4,3]、目标数组与三层逆变换、flag SDG{544f9da43e2c8f5ffc05f80a84d6a039} 均一致。未验证点：无 ELF 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

strip ELF 校验输入长度 37，依次做 256 字节 S-box 替换、`state=0x37*len+0x42` 的前缀异或链、8 位重排 `[5,2,7,0,6,1,4,3]`，最后 `memcmp`；三层都可逆，从目标数组反推 flag。

## 原理

- **S-box 替换**：`tmp[i] = table[input[i]]`；表是 0~255 的置换，可构造逆表 `inv_table[table[i]] = i`。
- **前缀异或链**：`state = 0x37*len + 0x42`（len=37 时为 0x35）；`state ^= tmp[i]; tmp[i] = state`。逆推：`old[i] = prev ^ new[i]; prev = new[i]`。
- **位重排**：`out[i]` 的第 `map[b]` 位来自 `tmp[i]` 的第 b 位；对 `[5,2,7,0,6,1,4,3]` 求逆映射，逐位还原。
- **可逆性**：三层都是双射，无需爆破；从 `target` 逆 bit → 逆 rolling → 逆 S-box 即得输入。

## 触发条件

- 二进制 strip 但有 `Wrong.`/`Correct!`/长度校验等字符串。
- 反汇编可见 S-box 查表、`xor` 链、bit 测试/移位组合。
- 存在固定目标数组与 `memcmp`。
- 输入长度/格式可推断（如 37 字节 `SDG{32hex}`）。

## 利用步骤

1. `strings`/`objdump` 定位长度校验、S-box 表、bit map、目标数组。
2. 从 `.rodata` 提取 256 字节 table 与 8 字节 bit map。
3. 逆 bit 重排：对每个目标字节，按 `inv_map` 把位放回原位置。
4. 逆 rolling XOR：用同一 seed（`0x37*len+0x42`）从前往后 `old = prev ^ new`。
5. 逆 S-box：`inv_table[b]` 还原输入字节，拼字符串。

## PoC

```python
table = bytes.fromhex("7bce2174...")   # 256 字节
target = bytes.fromhex("70dcd4050afe0aa37dc35ca8286f05cd...")
bit_map = [5, 2, 7, 0, 6, 1, 4, 3]
length = 37
seed = (0x37 * length + 0x42) & 0xFF

inv_map = [0] * 8
for src, dst in enumerate(bit_map):
    inv_map[dst] = src

def inv_bit(b):
    x = 0
    for dst in range(8):
        if (b >> dst) & 1:
            x |= 1 << inv_map[dst]
    return x

stage2 = bytes(inv_bit(b) for b in target)
stage1, prev = [], seed
for b in stage2:
    stage1.append(prev ^ b)
    prev = b
inv_table = [0] * 256
for i, v in enumerate(table):
    inv_table[v] = i
print(bytes(inv_table[b] for b in stage1).decode())
```

## 变体与关联

- **S-box 变体**：表有重复值（需爆破/约束）、动态生成、AES S-box；可先验证是否为置换。
- **rolling 变体**：初值依赖输入长度/常量、反向滚动、加/减而非 XOR；逆推方向要对应。
- **bit 置换变体**：map 长度 8/16/32、按字节/字重排、结合 rotate。
- **关联卡片**：[[ctf-reverse-png-lsb-custom-sbox-aes256-decrypt]]（自定义 S-box）、[[ctf-reverse-self-referential-key-tea-variant]]（可逆混合层）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（滚动哈希逆推）。
- **边界**：若某层不可逆（哈希/有损），需爆破或换路径；若目标数组被加密/压缩，先解外层。

## 检测与防御

- **CTF/验证**：逆出的输入应满足长度与格式；正向重跑三层应等于 target。
- **防御**：客户端校验只用于体验，最终由服务端验证；不要依赖简单可逆变换作为授权；加壳/混淆提高成本。
- **检测信号**：ELF 中出现 256 字节置换表、bit map、固定目标数组；`memcmp` 前有多层可逆变换。
