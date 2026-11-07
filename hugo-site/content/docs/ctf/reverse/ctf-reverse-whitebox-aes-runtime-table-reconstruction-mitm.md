---
id: ctf-reverse-whitebox-aes-runtime-table-reconstruction-mitm
title: 白盒 AES 运行时表重建与按列 MITM 逆向：Polaris 混淆外壳下的 10 轮查表
type: scenario
domain: ctf
path: ctf/reverse
technique: whitebox-aes-runtime-table-reconstruction-mitm
tags:
- ctf
- reverse
- whitebox
- aes
- table-reconstruction
- mitm
- chow
- splitmix64
- obfuscation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:26:44+08:00'
  notes: 已对照原文核对：表尺寸 0x30/0xa000/0x24000/0x1000/0x4000、splitmix64 常数与洗牌/stride/head/源表逻辑、10 轮 SubBytes/9 轮 T0-T3/final 编码、按列 2+2 MITM、flag ISCC{real_whitebox_AES_with_polaris_mir} 均与卡片一致；0x4000 编码层原文 PoC 未消费，卡片已注明。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-whitebox-aes-runtime-table-reconstruction-mitm/
draft: false
kb_aliases:
- 北极星混淆
- Polaris
- 白盒 AES
- Chow 方案
- T-table
- splitmix64 表重建
---

## 一句话结论

外层 Polaris 风格控制流混淆不影响白盒查表：先复刻初始化函数里 splitmix64 + 伪随机洗牌的表生成逻辑，离线重建 5 张运行时表，再按“10 轮 SubBytes、9 轮 MixColumns T 表、final 输出编码”逆向，每列用 `(a,b)/(c,d)` 拆分 meet-in-the-middle 把 2^32 降到 2^17，即可恢复明文。

## 原理

- **表尺寸就是指纹**：`0x30` = 3 个 16 字节块（最终比较的密文）；`0xa000` = `10*16*256`（10 轮、16 个位置、每位置一张 256 项字节替换表，SubBytes）；`0x24000` = `9*16*4*256`（9 个中间轮、每输出字节 4 个分量表 T0–T3，MixColumns 的 8×32 查表展开）；`0x1000` = `16*256`（最后一轮的按字节输出编码）；`0x4000` = 额外双射编码层（Chow 方案的内部状态保护）。
- **不是 memcpy，而是洗出来的**：初始化函数把固定 seed、目标长度和一个单字节参数混成状态，用 splitmix64 风格更新（常数 `0x9e3779b97f4a7c15` 是黄金比例 64 位表示，另有 `0xbf58476d1ce4e5b9`、`0x94d049bb133111eb`），计算与长度互素的步长 `stride` 和起点 `head`，再按 `pos=(i*stride+head)%len` 从 rodata 源表族取字节，与伪随机字节、位置扰动项异或。只要逐行复刻这段逻辑，就能在 Python 里重建同样的表；也可以在 `0xcf710` 首次执行后直接 dump 内存。
- **白盒 AES 消费方式**：16 字节状态先逐位置查 byte table，按 ShiftRows 风格重排；每列 4 个字节分别查 4 张 T 表后异或成新列；重复 9 轮；最后一轮只做 byte substitution + 行移位 + 输出编码。外层状态机再乱，表的消费结构不变。
- **按列 MITM**：中间轮列变换是 `F(a,b,c,d)=T0[a]^T1[b]^T2[c]^T3[d]`。直接枚举一列 2^32；拆成左半 `(a,b)` 建 2^16 字典、右半 `(c,d)` 查表，时间降到 2^17。三个块（0x30/16=3）分别逆完，最后去 PKCS#7 padding。
- **逆向顺序**：最终输出编码 → 最后一轮 SubBytes → 第 9 到第 1 轮逐列 MITM → 每轮再逆 SubBytes；ShiftRows 用位置映射 `ROW_LAYOUT` 还原。

## 触发条件

- stripped 64 位 PIE ELF，导入 `ptrace`、`getppid`、`clock_gettime`、`open/read/close` 等，存在反调试/环境探测外壳。
- 初始化函数只执行一次（全局标志短路），内部连续生成多张尺寸规整的大表，尺寸符合 AES 白盒的 `10*16*256`、`9*16*4*256`、`16*256` 等分解。
- 二进制中出现 splitmix64 常数或类似的 64 位混合常量；rodata 中有一族源表指针。

## 利用步骤

1. 先运行确认只有 yes/no 输出；看导入表识别反调试，但不要陷入主状态机。
2. 沿 `.eh_frame`/调用边界找规整函数：读文件、字符串包含、取时间、32 位循环移位、初始化大表、单表生成。
3. 定位初始化函数与单表生成函数，抠出 seed、长度、marker、源表指针、splitmix64 常数、步长/起点/扰动公式；在 Python 中复刻，或运行到初始化后用调试器 dump 五张表。
4. 按尺寸切分表：`0xa000` 建 10×16 个逆 S 盒；`0x1000` 建 16 个逆输出编码；`0x24000` 建 9×16×4 个 T 分量表。
5. 从 0x30 密文按块逆：逆 final 编码 → 逆最后一轮 byte substitution → 对 8..0 轮逐列 MITM → 逆该轮 SubBytes。
6. 拼接三个块，去 PKCS#7，得到 flag；用原程序输入验证。

## PoC

```python
import math
import struct
from elftools.elf.elffile import ELFFile

MASK64 = (1 << 64) - 1
ROW_LAYOUT = ((0, 5, 10, 15), (4, 9, 14, 3), (8, 13, 2, 7), (12, 1, 6, 11))
# (源表指针基址, 源表行数, 输出长度, 表 seed)
LAYOUT = {
    "cipher": (0x183BC0, 5, 0x30, 0x61F29C0D87A453B1),
    "rounds": (0x183BF0, 11, 0xA000, 0xD3B5407C19EA8F26),
    "mixes":  (0x183C50, 13, 0x24000, 0x7A8CE153D604B92F),
    "final":  (0x183CC0, 7, 0x1000, 0xC94E2F81A73D650B),
}

class Img:
    def __init__(self, path):
        self.fp = open(path, "rb"); self.elf = ELFFile(self.fp)
        self.fp.seek(0); self.data = self.fp.read()
        self.loads = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    def va(self, va):
        for s in self.loads:
            if s["p_vaddr"] <= va < s["p_vaddr"] + s["p_filesz"]:
                return s["p_offset"] + va - s["p_vaddr"]
        raise ValueError(hex(va))
    def read(self, va, n): return self.data[self.va(va): self.va(va) + n]
    def qwords(self, va, n): return struct.unpack("<" + "Q" * n, self.read(va, n * 8))

def sm64(state):
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, (z ^ (z >> 31)) & MASK64

def mix_seed(seed, length, marker):
    cur = seed ^ ((length * 0xD1342543DE82EF95) & MASK64) ^ ((marker * 0x6A09E667F3BCC909) & MASK64)
    acc = 0
    for _ in range(4):
        cur, out = sm64(cur ^ acc); acc ^= out
    return acc & MASK64

def pick_stride(modulus, seed):
    step = ((seed >> 17) | 1) % modulus or 1
    while math.gcd(step, modulus) != 1:
        step = (step + 2) % modulus or 1
    return step

def src_byte(img, sources, count, seed, index):
    row = (index * pick_stride(count, seed) + ((seed >> 23) % count)) % count
    return img.read(sources[row] + index // count, 1)[0]

def materialize(img, ptr_base, row_count, out_size, seed):
    sources = img.qwords(ptr_base, row_count)
    state = mix_seed(seed, out_size, 0)
    stride = pick_stride(out_size, state)
    head = (mix_seed(state ^ 0xA5A5A5A55A5A5A5A, out_size, 0) >> 19) % out_size
    result = bytearray(out_size); stream = state
    for i in range(out_size):
        pos = (i * stride + head) % out_size
        stream, rnd = sm64(stream)
        rnd_byte = (rnd >> ((i & 7) * 8)) & 0xff
        jitter = (pos * 0xA7 + i * 0x3D) & 0xff
        result[pos] = rnd_byte ^ jitter ^ src_byte(img, sources, row_count, seed, i)
    return bytes(result)

def build_inv(blob, rounds, stride):
    out = [[[0] * 256 for _ in range(16)] for _ in range(rounds)]
    for r in range(rounds):
        for pos in range(16):
            base = r * stride + pos * 0x100
            for x in range(256):
                out[r][pos][blob[base + x]] = x
    return out

def undo_column(mix, state, rnd, col):
    want = tuple(state[4 * col + i] for i in range(4))
    left = {}
    for a in range(256):
        for b in range(256):
            acc = []
            for row in range(4):
                oi = 4 * col + row; base = rnd * 0x4000 + oi * 0x400
                acc.append(mix[base + a] ^ mix[base + 0x100 + b])
            left[tuple(acc)] = (a, b)
    for c in range(256):
        for d in range(256):
            need = []
            for row in range(4):
                oi = 4 * col + row; base = rnd * 0x4000 + oi * 0x400
                need.append(mix[base + 0x200 + c] ^ mix[base + 0x300 + d] ^ want[row])
            pair = left.get(tuple(need))
            if pair is not None:
                return pair + (c, d)
    raise RuntimeError("column recovery failed")

def recover_block(block, mix, inv_round, inv_final):
    sr = sum(ROW_LAYOUT, ())
    lifted = [0] * 16
    for out_pos in range(16):
        lifted[sr[out_pos]] = inv_final[out_pos][block[out_pos]]
    state = [inv_round[9][i][lifted[i]] for i in range(16)]
    for rnd in range(8, -1, -1):
        prev = [0] * 16
        for col, group in enumerate(ROW_LAYOUT):
            for idx, v in zip(group, undo_column(mix, state, rnd, col)):
                prev[idx] = v
        state = [inv_round[rnd][i][prev[i]] for i in range(16)]
    return bytes(state)

img = Img("./traditional_re")
cipher = materialize(img, *LAYOUT["cipher"])
round_blob = materialize(img, *LAYOUT["rounds"])
mix_blob = materialize(img, *LAYOUT["mixes"])
final_blob = materialize(img, *LAYOUT["final"])
inv_round = build_inv(round_blob, 10, 0x1000)
inv_final = build_inv(final_blob, 1, 0x1000)[0]
plain = b"".join(recover_block(cipher[i:i + 16], mix_blob, inv_round, inv_final)
                 for i in range(0, len(cipher), 16))
pad = plain[-1]
print(plain[:-pad].decode() if 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad) else plain)
```

## 变体与关联

- **表获取方式变体**：复刻生成逻辑、在初始化后 dump 内存、或对 `0x14cff0` 做单步记录；只要拿到五张表，后续相同。
- **白盒方案变体**：Chow 方案之外还有 BGE 攻击、DCA 差分计算分析、线性变换编码；表尺寸和轮数会随 AES-128/192/256 变化，先按 `轮数*16*256` 等关系确认。
- **MITM 变体**：列内 4 项可拆成 1+3、2+2；2+2 最均衡（2^16+2^16）；若表项是 32 位，注意 Python 字典键为元组、内存占用要分块释放。
- **关联卡片**：[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（常量识别标准分组算法）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定 key/密文复现）、[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（混淆外壳下的真实算法提取）。

## 检测与防御

- **检测特征**：大块规整表（`0xa000`/`0x24000`/`0x1000`）、splitmix64 常数、初始化函数只执行一次、主流程大量间接跳转；`ptrace/getppid` 等反调试导入只是外壳。
- **分析建议**：不要试图恢复全部控制流；先按表尺寸和消费方式识别算法，再决定是复刻表生成还是内存 dump。
- **防御视角**：白盒 AES 是混淆而非密码学安全；面对内存 dump、DCA/BGE 仍可恢复密钥或明文。真正保护应结合硬件安全模块、代码完整性校验与动态密钥派生。
