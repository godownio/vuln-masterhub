---
id: ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse
title: 字节对加法+ROL8+缓冲区轮转的五轮可逆变换逆向：解析求逆与诱饵串识别
type: scenario
domain: ctf
path: ctf/reverse
technique: byte-pair-add-rol8-buffer-rotate-inverse
aliases:
- Conway's Trap
- 字节对加法
- ROL8 求逆
- 缓冲区循环左移
- 诱饵字符串
tags:
- ctf
- reverse
- arx
- byte-transform
- rol8
- inverse
- decoy
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:26:38+08:00'
  notes: 已对照原文核对：单轮 (a+b)&0xff、rol8(x0^b,1)、整体左移 1 字节、逆变换先右移再 ror8 求 b/a、目标 df7b... 5 轮得 seed 0b5e...、诱饵串 Evergreen... 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

16 字节缓冲区按相邻字节对做 `(a+b)&0xff` 与 `rol8(x0^b,1)`，每轮结束后整体循环左移 1 字节；每一步都是 256 字节上的双射，因此可从目标值逐轮解析求逆，无需爆破；同时程序数据区里能“解密出一句英文”的长串可能只是诱饵，不参与最终比较。

## 原理

- **单轮变换**：对 `i = 0,2,...,14` 取 `a=buf[i]`、`b=buf[i+1]`，写入 `buf[i]=(a+b)&0xff`、`buf[i+1]=rol8(buf[i]^b,1)`；随后 `buf = buf[1:] + buf[:1]`（整体循环左移 1 字节）。
- **为什么可逆**：记变换后一对为 `x0=(a+b) mod 256`、`x1=rol8(x0 xor b,1)`。先做 `t=ror8(x1,1)=x0 xor b`，得 `b=x0 xor t`；再由 `x0=(a+b) mod 256` 得 `a=(x0-b) mod 256`。加法模 256、异或、8 位循环移位都是双射，所以整轮双射。
- **轮间顺序**：程序先做字节对变换、再整体循环左移；求逆必须先“循环右移 1 字节”回到变换后的布局，再做字节对逆变换。顺序写反会得到自洽但错误的 seed。
- **确定性**：变换不含密钥、随机数或输入相关的分支，目标常量直接给出 5 轮后的 16 字节，逆向是纯确定性的；轮数从目标常量前的一小段循环计数或直接观察循环边界得到。
- **诱饵识别**：程序里另有一段长十六进制串，用求出的 seed 作重复流密钥按 `((c - seed[i & 0xf]) & 0xff) ^ seed[i & 0xf]` 解密可得到一句通顺英文（“Evergreen broadleaf forests do not shed their leaves in winter”）。它能被解开并不代表它是 flag；判断依据是它是否进入最终比较路径。
- **两阶段模型**：seed 校验与 flag 校验之间没有密钥派生关系，seed 可独立求解；flag 内部内容另由比较缓冲区反推。

## 触发条件

- 输入为固定长度（如 16 字节）缓冲区，程序提示 seed 为 32 个十六进制字符。
- 反编译中出现“按 2 字节步进、先加后异或再 rol/ror、循环末尾 memmove/rotate”的紧凑循环。
- 循环结束后与一个固定十六进制常量逐字节比较，循环次数固定（本例 5 轮）。
- 数据区存在可被某把“密钥”异或/加减解出可读文本的长串。

## 利用步骤

1. 从比较点向上定位目标常量与轮数，确认每轮内是“字节对变换 → 缓冲区整体轮转”。
2. 实现 `rol8/ror8` 与 `inv_step`：先 `buf = buf[-1:] + buf[:-1]` 撤销轮转，再对每对求 `t=ror8(x1,1)`、`b=x0^t`、`a=(x0-b)&0xff`。
3. 从目标常量开始连续执行 `inv_step` 等于轮数的次数，得到 seed；再正向执行 `step` 相等次数，断言回到目标常量。
4. 用 seed 尝试解密数据区的可疑长串，判断其是否为诱饵：看它是否被后续校验引用；仅“可解密”不足以认定。
5. 对 flag 校验分支继续反推比较缓冲区；若内部长度固定（本例 23 字节），直接按比较逻辑还原。

## PoC

```python
def rol8(x, n=1):
    return ((x << n) | (x >> (8 - n))) & 0xff

def ror8(x, n=1):
    return ((x >> n) | (x << (8 - n))) & 0xff

def step(buf):
    buf = list(buf)
    for i in range(0, 16, 2):
        a, b = buf[i], buf[i + 1]
        buf[i] = (a + b) & 0xff
        buf[i + 1] = rol8(buf[i] ^ b, 1)
    return bytes(buf[1:] + buf[:1])

def inv_step(buf):
    buf = list(buf)
    buf = buf[-1:] + buf[:-1]          # 先撤销整体循环左移
    for i in range(0, 16, 2):
        x0, x1 = buf[i], buf[i + 1]
        t = ror8(x1, 1)                # x0 ^ b
        old_b = x0 ^ t
        old_a = (x0 - old_b) & 0xff
        buf[i], buf[i + 1] = old_a, old_b
    return bytes(buf)

target = bytes.fromhex("df7b6a5d4da0f5facf32c4ee4b28b792")
seed = target
for _ in range(5):
    seed = inv_step(seed)
assert seed.hex() == "0b5e321c68e0e4fb2d972226e8c70f8d"
for _ in range(5):
    assert step(seed) == target
print("seed =", seed.hex())

# 诱饵串：seed 作重复流密钥
enc = bytes.fromhex(
    "5986898a77726599708c726f716a72757596868f82657b8a8b8a6f6e6f7a8b"
    "727998789075697a92758d7669837570876d8e789582"
)
trap = bytes((((c - seed[i & 0xf]) & 0xff) ^ seed[i & 0xf])
             for i, c in enumerate(enc))
print("trap =", trap.decode())   # Evergreenbroadleafforests...，诱饵
```

## 变体与关联

- **轮转方向变体**：每轮可能是循环右移、按 4 字节/字轮转，或 `memmove` 只移动部分字节；按实际反编译顺序撤销。
- **运算变体**：加法可换成减法/异或，`rol8` 可换成 `ror8`、固定次数旋转或 32 位旋转；只要每步双射都可用同样方法解析求逆。
- **轮数未知**：把 `inv_step` 当迭代函数，正向/反向各试若干轮，用最终比较常量或明密文对断言。
- **诱饵变体**：诱饵可能用相同 seed 加密、用另一常量加密，或干脆是明文；判断标准始终是“是否参与最终校验”。
- **关联卡片**：[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（逐轮可逆 ARX 求逆）、[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（rol/xor/ror 求逆）。

## 检测与防御

- **检测特征**：二进制中出现极紧的 8/16/32 字节循环，含 `add`、`xor`、`rol/ror`、`memmove`，循环后紧跟 `memcmp` 常量；`strings` 能看到 `Enter seed`、`Wrong Seed` 等两阶段提示。
- **分析建议**：先写出单轮正向函数，再用目标常量做一次正向断言；不要从诱饵串或题名直接下结论。
- **防御视角**：这类变换只是提高逆向成本，不构成密码学保护；真正需要保密的数据应使用带密钥的标准原语，且不要把可解密诱饵与真实校验放在同一可执行文件中。
