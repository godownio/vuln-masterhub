---
id: ctf-reverse-custom-feistel-20round-dword-key-rotation-inverse
title: 20 轮自定义 Feistel 逆推：key 指针按 4 字节取模 12 循环取 dword，正向两分支交换、逆向只需把 prev/next 角色对调
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-feistel-round-inverse-key-rotation-mod12
tags:
- ctf
- reverse
- feistel
- crypto-algorithm
- key-schedule
- dynamic-debugging
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:18:55+08:00'
  notes: 已对照原文核对；本次核对未读取图片；zistel 的 20 轮循环、key 12 字节按 cnt*4%12 取 dword、box[i]=i&3 置换、enc 与 key 常量、逆向把 prev/next 角色对调并倒序跑，均与原文代码一致；key 由 love 初始化一段为原文正文描述（截图未读）；未验证点：PoC 未在本机执行
url: /docs/ctf/reverse/ctf-reverse-custom-feistel-20round-dword-key-rotation-inverse/
draft: false
kb_aliases:
- zistel
- 自定义 Feistel 加密逆向
- 20 轮轮函数逆推
- 按 dword 循环取 key
- 交换分支还原明文
---

## 一句话结论

当题目把 8 字节明文块拆成两个 32 位分支、用 `for cnt in range(20)` 做 `next = prev ^ F(roundkey, next); swap(prev,next)` 的 Feistel 结构时，解密不需要求 `F` 的逆——只要把初始的两个分支**按正向输出顺序反着喂**（密文后半段当 `next`、前半段当 `prev`），再按 `cnt = 19..0` 逆序跑同一轮函数即可，轮密钥仍是 `key[cnt*4 % 12 : +4]` 那个 dword。

## 原理

- 正向：`tmp = next; next = prev ^ F(k_i, next); prev = tmp`。注意 `prev` 更新为旧的 `next`，而 `next` 变成 `prev ^ F(...)`，这是一个**交换型 Feistel**（不需要 `F` 可逆），因为旧 `next` 被完整保留在 `prev` 中。
- 逆向：给定 `(prev_i, next_i)`，能唯一恢复 `(prev_{i-1}, next_{i-1}) = (next_i ^ F(k_i, prev_i), prev_i)`。也就是把 `prev`/`next` 的角色对调后重跑同一行代码：`tmp = prev; prev = next ^ F(k_i, tmp); next = tmp`。这就是为什么 exp 里只有两行被注释/反注释交换，而没有重写 `F`。
- 轮密钥派生：`count = cnt * 4`，`dword_key = key[(count+3)%12]<<24 | ... | key[count%12]`。`key` 是 12 字节，按 4 字节步进并对 12 取模，所以 20 轮里轮密钥以 3 个 dword 为周期循环（第 0/3/6/… 轮同钥）。逆向时 `cnt` 必须与正向一一对应，否则轮密钥错位。
- 轮函数 `F` 自身含一个**基于 key 字节取值的置换**：`box[i] = i & 3`，然后用 `key` 的每个字节的低 2 位决定把 `v10` 的第 i 个字节与第 `box[arr2[i]]` 个字节交换，最后整体再 `^ key`。因为 `F` 只做异或与置换（都是自逆或可交换的），只看密文无法分辨它内部顺序，但 Feistel 结构保证**不需要**分辨。
- key 由程序内部用固定字符串（原文为 `"love"`）初始化，直接下断点/动调从内存读出即可，不必逆 key 调度代码。

## 触发条件

- 目标算法是“两个 32 位分支 + 多轮 + 每轮只对其中一个分支做 `F` 后异或”的 Feistel/类 Feistel 结构。
- 轮函数 `F` 只使用异或、字节置换、加减等可复算运算（无需可逆性）。
- 轮密钥可从二进制常量或动调内存直接获得。

## 利用步骤

1. 静态定位加密函数，确认循环轮数（本例 20）、每轮分支更新顺序与是否有额外 swap。
2. 记录轮密钥派生表达式；确认 `key` 长度与取模方式（本例 12 字节，`cnt*4 % 12`）。
3. 动调在 key 初始化之后下断，dump 12 字节 key。
4. 按“正向最后一次输出”的顺序取出密文两块：`next = 前 4 字节`、`prev = 后 4 字节`（因为正向最后一步把 `prev` 写到了块的前半段）。
5. 从 `cnt = 19` 递减到 0，跑反向更新式，循环结束后 `prev`/`next` 就是明文两块。
6. 逐个 8 字节块处理后拼接，得到 flag 文本。

## PoC

```python
enc = [0x58,0x31,0x29,0x33,0x11,0x02,0x76,0x60,
       0x46,0x5F,0x18,0x42,0x29,0x6F,0x74,0x63]
key = [0x83,0xD1,0xDB,0xBB,0x2E,0x0F,0x34,0x05,0xAD,0xDE,0xEF,0xBE]
box = [i & 3 for i in range(256)]
inp = [0x44,0x41,0x53,0x43,0x54,0x46,0x7b,0x61,
       0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x7d]  # 占位明文，用于自校验

def num_to_arr(num):
    r = []
    while num:
        r.append(num & 0xff); num >>= 8
    return r

def F(k, n):                      # 轮函数：xor -> 字节置换 -> xor
    a1, a2 = num_to_arr(k ^ n), num_to_arr(k)
    for i in range(4):
        j = box[a2[i]]
        a1[i], a1[j] = a1[j], a1[i]
    return (a1[0] | a1[1] << 8 | a1[2] << 16 | a1[3] << 24) ^ k

def enc_block(prev, nxt):
    for cnt in range(20):
        c = cnt * 4
        k = (key[(c+3)%12]<<24)|(key[(c+2)%12]<<16)|(key[(c+1)%12]<<8)|key[c%12]
        prev, nxt = nxt, prev ^ F(k, nxt)
    return prev, nxt

def dec_block(prev, nxt):         # 仅把角色对调、轮序反走
    for cnt in range(19, -1, -1):
        c = cnt * 4
        k = (key[(c+3)%12]<<24)|(key[(c+2)%12]<<16)|(key[(c+1)%12]<<8)|key[c%12]
        prev, nxt = nxt ^ F(k, prev), prev
    return prev, nxt

def to_dword(b, off, le=True):
    q = b[off:off+4]
    return int.from_bytes(bytes(q), "little" if le else "big")

# 自校验：加密后再解密应回到原文
for off in range(0, 16, 8):
    p, n = dec_block(*enc_block(*(to_dword(inp, off), to_dword(inp, off+4))))
    assert p == to_dword(inp, off) and n == to_dword(inp, off+4)

# 解密：密文前半段是正向最后的 next，后半段是 prev
out = []
for off in range(0, len(enc), 8):
    prev = to_dword(enc, off+4)   # 注意：前 4 字节给 next，后 4 字节给 prev
    nxt  = to_dword(enc, off)
    p, n = dec_block(prev, nxt)
    out += list((p.to_bytes(4, "little") + n.to_bytes(4, "little")))
print(bytes(out))
```

## 变体与关联

- 变体：轮数改为 16/32、`key` 长度改成 16 或 24 时，只改 `range()` 与取模常数，逆推结构不变。
- 变体：若正向在循环外多做了一次 `next = F(key0, next)`（不在 Feistel 内），逆向要先单独消掉这一项。
- 变体：`F` 里混入加法/乘法时，仍按“先逆最后一步、逐轮回退”的思路重写 `F_inv`，而不是靠猜。
- 关联：[[ctf-reverse-custom-vm-tea-like-30round-block-bruteforce]]（另一类多轮自定义分组加密逆推）、[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]（结构识别 + 逆向还原的一般方法）。
- 边界：只适用于分支完整保留的交换型 Feistel；若实现里 `prev` 被就地覆盖（丢失旧 `next`），该简单对调法失效，必须求 `F` 的逆。

## 检测与防御

- 本题为 CTF 反解题，无线上防御面。工程上可借鉴的点：不要把“算法保密”当安全边界，自定义 Feistel 在没有密钥保密的情况下等于无加密。
- 自我保护建议：轮密钥由运行时输入/环境派生而非硬编码，避免动调一次即 dump；对 `F` 加白盒/查表混淆提高逆向成本。
