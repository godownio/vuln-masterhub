---
id: ctf-reverse-xorshift-fisher-yates-inverse-permutation-38byte-transform
title: xorshift Fisher-Yates 逆置换 + 38 字节自定义变换逆解
type: scenario
domain: ctf
path: ctf/reverse
technique: xorshift-fisher-yates-inverse-permutation-38byte-transform
tags:
- ctf
- reverse
- xorshift
- fisher-yates
- permutation
- byte-transform
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T10:01:24+08:00'
  notes: 已对照原文与图 24/26/28/30 核对：38 字节长度、cat3 的 12+13+13 拼接、p() 的 xorshift32 seed 0xF5A4ADA5 + Fisher-Yates 逆表、t() 的 16 字节状态/ROR8/inv 查表、xmmword_2180 反序 42 19 A7 5C ... 均一致。卡片 PoC 只实现逆表与参考串，完整 t_transform 需按原文逐行复刻；未复跑。
url: /docs/ctf/reverse/ctf-reverse-xorshift-fisher-yates-inverse-permutation-38byte-transform/
draft: false
kb_aliases:
- ReM3_Again
- xorshift32 洗牌
- Fisher-Yates 逆置换
- 38 字节变换
- xmmword 端序
---

## 一句话结论

程序用固定 seed 的 xorshift32 做 Fisher-Yates 洗牌生成 256 字节置换及逆表，再用一个 38 轮、16 字节状态的自定义变换 `t()` 把 `.rodata` 中 38 字节参考串变成真正的 flag；因为 `t()` 每轮只做 ROR8、查逆表、加减和状态更新，按反编译逐条复刻即可直接算出 `KCTF{aN0Th3r_r3_I_h0PE_y0U_eNj0YED_IT}`，关键是注意 `xmmword` 在 IDA 显示顺序与内存顺序相反。

## 原理

- **多分支/decoy**：`main` 要求输入长度 38；`chk_first_*` 三组检查命中只打印“Success! ...but you won't get points...”的假 flag；真校验是 `cat3` 拼出 38 字节参考串 `v5`，`t(v6, v5, v9)` 变换得到目标 `v6`，再 `eq(s, v6)` 比较。因此 **`v6` 就是 flag**。
- **置换表**：`p(v8, v9)` 先填 `perm=[0..255]`，再用 xorshift32（seed `0xF5A4ADA5`）从末尾 `pos=255..0` 做 Fisher-Yates：`state=xorshift32(state); j=state%(pos+1); swap(perm[pos],perm[j])`；最后 `inv[perm[i]]=i`，`v9` 是逆表。
- **38 字节参考串**：`cat3` 从 `x_r0` 取 12 字节、`x_r1` 取 13 字节、`x_r2` 取 13 字节，拼成 38 字节；这些都在 `.rodata`。
- **变换 `t()`**：维护 16 字节状态 `i[16]`（初始来自 `xmmword_2180`），每轮：
  - 取参考字节 `v12`；
  - 用常量 `0x6A124DE908B17733` 的第 `(idx&7)` 字节、`v10/v4/v12` 混合，`ROR8` 后索引 `inv` 表；
  - `v14 = (inv[table_index] - v13) & 0xFF` 作为输出；
  - 更新 `i[idx&0xF]`、`i[(idx+3)&0xF]`，以及 `v5/v4/v8/v10/v6/v7` 等滚动变量。
- **端序坑**：IDA 显示 `xmmword_2180 = 6A124DE908B177332F910ED35CA71942h`，但 SSE `movdqu` 的内存顺序是低 qword 在前；按显示顺序初始化会得到一半乱码，按反序 `42 19 A7 5C D3 0E 91 2F 33 77 B1 08 E9 4D 12 6A` 才得到完整可打印 `KCTF{...}`。
- **为什么可行**：`t()` 是确定性变换，无随机/无外部输入；只要复刻状态更新和常量/端序，就能直接算出目标串。

## 触发条件

- 输入长度固定（38），程序有多组 `chk_first` 假 flag 分支；真校验调用 `cat3` + `t` + `eq`。
- 反编译中出现 `perm=[0..255]`、`xorshift` 三步移位异或、`div` 取余、`swap`、`inv[perm[i]]=i`。
- `t()` 中有 16 字节状态、`ROR8`、常量 `0x6A124DE908B17733`、逆表查表。
- `.rodata` 中有三段 `x_r0/x_r1/x_r2` 常量，合计 38 字节。

## 利用步骤

1. 从 `main` 定位真校验分支（`cat3` + `t` + `eq`），确认 `v6` 是目标 flag。
2. 从 `.rodata` 读出 `x_r0`（12 字节）、`x_r1`（13 字节）、`x_r2`（13 字节），拼接为 38 字节参考串。
3. 实现 xorshift32：`x ^= x<<13; x ^= x>>17; x ^= x<<5`（32 位掩码）；从 seed `0xF5A4ADA5`、`pos=255..0` 做 Fisher-Yates，得到 `perm`；再 `inv[perm[i]]=i`。
4. 按反编译实现 `t_transform(ref, inv, i_init)`：逐轮 ROR8、查表、输出、状态更新；`i_init` 用 **内存反序**（`42 19 A7 5C D3 0E 91 2F 33 77 B1 08 E9 4D 12 6A`）。
5. 输出 38 字节，检查 `KCTF{`/`}` 和可打印性；若乱码，尝试 IDA 显示顺序/反序、`idx` 边界、`&0xF` 索引。
6. 用程序本地运行复验；或动态调试 dump `v6` 直接得到 flag。

## PoC

```python
def ror8(x, r):
    r &= 7; x &= 0xFF
    return ((x >> r) | ((x << (8-r)) & 0xFF)) & 0xFF

def xorshift32(v):
    v &= 0xFFFFFFFF
    v ^= (v << 13) & 0xFFFFFFFF
    v ^= v >> 17
    v ^= (v << 5) & 0xFFFFFFFF
    return v & 0xFFFFFFFF

def build_inv():
    perm = list(range(256)); state = 0xF5A4ADA5
    for pos in range(255, -1, -1):
        state = xorshift32(state)
        j = state % (pos + 1)
        perm[pos], perm[j] = perm[j], perm[pos]
    inv = [0] * 256
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

ref = bytes([0x0F,0x5F,0x6F,0xF7,0x01,0x0F,0xB2,0x18,0xEE,0xD3,0x37,0x84,
             0xD2,0x4C,0xA4,0x79,0x4A,0xF7,0x18,0xCF,0x68,0x78,0x26,0xFC,0x37,
             0xD0,0x8B,0x99,0x5A,0xE7,0xF5,0x46,0x37,0x82,0x48,0xFB,0xFE,0x0B])
i_init = bytes.fromhex("4219A75CD30E912F3377B108E94D126A")  # 内存反序
inv = build_inv()
# t_transform 的完整逐轮逻辑见原文；核心为 ROR8 + inv[..] - v13 与 16 字节状态更新
```

说明：PoC 给出 xorshift/Fisher-Yates 逆表与参考串；完整 `t_transform` 需按原文逐行复刻（ROR8、`inv` 查表、`i[idx&0xF]`/`i[(idx+3)&0xF]` 更新）。未在本机对附件复跑。

## 变体与关联

- **xorshift 变体**：移位常量 13/17/5、seed、32/64 位；按反编译调整。
- **Fisher-Yates 方向**：从 255 到 0、`j=state%(pos+1)`；方向/取模写错会得到不同置换。
- **端序**：`xmmword`/`movdqu` 的内存顺序与 IDA 显示顺序可能相反；用可打印性/`KCTF{` 判定。
- **关联**：[[ctf-reverse-fnv1a-decoy-29byte-transform-inverse]]（同场比赛的另一逐字节变换）、[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（可逆变换 + 诱饵串）、[[crypto-prng-mt19937-buggy-randbelow-z3-shuffle]]（洗牌逆向）。

## 检测与防御

- 识别：`perm=[0..255]` + xorshift + `div` 取余 + 交换 + 逆表；16 字节状态的逐字节变换。
- CTF 防守：这种“固定 seed 洗牌 + 可逆变换”没有密钥，静态复刻即可还原；应使用带密钥的密码学构造。
- 真实系统：不要用固定 seed PRNG 生成置换/密钥；使用 CSPRNG 和标准加密。
