---
id: ctf-reverse-bytewise-multilayer-sbox-rot-nibble-mod257-inverse
title: 多层字节变换逆向：S 盒→ROR2→mod257 逆元→半字节线性映射→ROL3/XOR→按下标 ROL 的逆序还原
type: scenario
domain: ctf
path: ctf/reverse
technique: bytewise-multilayer-sbox-rot-nibble-mod257-inverse
aliases:
- Hardtest
- 多层字节变换
- AES S 盒逆
- mod 257 求逆
- 半字节线性映射
- 按下标循环移位
- 逐字节可逆混淆
tags:
- ctf
- reverse
- custom-cipher
- sbox
- rotate
- modular-inverse
- bit-manipulation
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:10:23+08:00'
  notes: 已对照原文代码与图 32/33 核对：BYTE_2120 24 字节、S 盒→ROR2→x^255 mod257→半字节 *3/*5→ROL3/XOR 0x5A→按下标 ROL((idx%7)+1)；卡内 decrypt_one 顺序与原文脚本一致，原文运行输出 Bl@st1ng_1s_a_g00d_Way!!，补 flag{} 得 flag。卡内 S 盒为节选（原文完整表很长），已注明需从二进制导出完整 byte_2020；未本机复跑完整脚本。
---

## 一句话结论

题目对 flag 的每个字节依次做 AES S 盒替换、循环右移 2、模 257 求逆（`x→x^255 mod 257`）、半字节线性映射（高 4 位乘 3、低 4 位乘 5）、循环左移 3 后 XOR `0x5A`、再按字节下标做 `(idx%7)+1` 位循环左移；这些步骤全是双射，按相反顺序逐字节求逆即可从 24 字节密文还原出 `Bl@st1ng_1s_a_g00d_Way!!`。

## 原理

- **S 盒**：`byte_2020` 是 AES 的 256 字节 S 盒；加密时 `y=S[x]`。解密时先建逆表 `INV_S[y]=x`（S 盒是置换，逆表唯一）。
- **循环移位**：`ROR2` 的逆是 `ROL2`；`ROL3` 的逆是 `ROR3`；按下标 `r=(idx%7)+1` 的 ROL 的逆是对应位数的 ROR。8 位循环移位都是双射。
- **模 257 求逆**：`sub_1313` 对字节 `x` 计算 `x^255 mod 257`（`x=0` 特判为 0）。257 是素数，`F_257^*` 的阶为 256，故 `x^255 ≡ x^{-1}`；该映射是自逆的（再算一次 `x^255` 回到 `x`），因此解密再次调用同一函数即可。
- **半字节线性映射**：加密把高 4 位乘以 3、低 4 位乘以 5（模 16）。3 在模 16 下的逆元是 11（`3*11=33≡1`），5 的逆元是 13（`5*13=65≡1`），所以解密为 `hi*11 mod 16`、`lo*13 mod 16`。
- **XOR 与移位顺序**：加密是 `ROL3(x) XOR 0x5A`；解密必须先 `XOR 0x5A`，再 `ROR3`。顺序不能反，因为 XOR 与移位不交换。
- **按下标移位**：`sub_1492` 对第 `idx` 个字节左移 `(idx%7)+1` 位；解密时对同一 `idx` 右移相同位数。
- **为什么能完整还原**：每一步都是字节集合上的双射，且密钥/参数（S 盒、3/5、0x5A、下标规则）都硬编码在二进制里；只要逆序、逆运算、下标对齐，结果唯一。

## 触发条件

- 题目给出一个固定长度的密文字节数组（本例 24 字节），并提示“输入数字后验证 flag”。
- 反编译可见逐字节的 S 盒查表、循环移位、模素数求逆、半字节乘常数、XOR 与下标相关移位等操作。
- 变换链是纯双射、无数据依赖分支（或分支可由输入/索引确定），没有哈希/不可逆压缩。
- 已知明文格式（`flag{...}`）可用于验证还原结果。

## 利用步骤

1. 在 `main`/校验函数中定位密文数组（本例 `BYTE_2120`）、S 盒（`byte_2020`）与每个变换函数。
2. 按加密顺序记录每一步：`S` → `ROR2` → `x^255 mod 257` → 半字节 `*3/*5` → `ROL3` → `XOR 0x5A` → 按下标 `ROL((idx%7)+1)`。
3. 构造逆运算并**逆序**应用：`INV_S` → `ROL2` → `x^255 mod 257`（自逆）→ 半字节 `*11/*13` → `ROR3` → `XOR 0x5A`（XOR 自逆，但要在 ROR3 之前）→ `ROR((idx%7)+1)`。
4. 对每个字节按其下标应用第 3 步；拼接得到 ASCII。
5. 若结果缺少 `flag{}`，按题目要求补上前缀/后缀；用可打印性和 `flag{` 前缀验证。
6. 若某个参数不确定（例如移位方向），用已知明文 `f`/`l`/`a`/`g` 反推并测试。

## PoC

```python
BYTE_2120 = [
    0x97, 0xD5, 0x60, 0x43, 0xB4, 0x10, 0x43, 0x73,
    0x0F, 0xDA, 0x43, 0xCD, 0xD3, 0xE8, 0x73, 0x4A,
    0x94, 0xC3, 0xCD, 0x71, 0xBD, 0xDC, 0x97, 0x1A,
]
S = [  # AES S-box（节选写法：完整 256 字节表按题中 byte_2020 填入）
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    # ... 其余 240 字节 ...
]
INV_S = [0] * 256
for i, v in enumerate(S):
    INV_S[v] = i

def rotl8(x, r): return ((x << r) & 0xFF) | (x >> (8 - r))
def rotr8(x, r): return rotl8(x, 8 - r)

def inv_mod257(x):
    return 0 if x == 0 else pow(x, 255, 257)   # 257 素数，x^255 = x^{-1}

def inv_nibble(w):
    hi = (11 * ((w >> 4) & 0xF)) & 0xF          # 3 的逆元 11
    lo = (13 * (w & 0xF)) & 0xF                 # 5 的逆元 13
    return (hi << 4) | lo

def decrypt_one(y, idx):
    x = INV_S[y]                 # 逆 S 盒
    x = rotl8(x, 2)              # 逆 ROR2
    x = inv_mod257(x)            # 自逆
    x = inv_nibble(x)            # 逆半字节线性映射
    x = rotr8(x, 3) ^ 0x5A       # 先 XOR 再逆 ROL3
    x = rotr8(x, (idx % 7) + 1)  # 逆按下标 ROL
    return x

pt = bytes(decrypt_one(y, i) for i, y in enumerate(BYTE_2120))
print(pt.decode())               # Bl@st1ng_1s_a_g00d_Way!!
# flag{Bl@st1ng_1s_a_g00d_Way!!}
```

原文脚本给出了完整 S 盒表与 `decrypt_one`，运行输出 `Bl@st1ng_1s_a_g00d_Way!!`，按题目格式补 `flag{}` 即得 flag。上面的 S 盒为节选，实际复现时请从二进制导出完整 `byte_2020`；原文未在本机复跑完整脚本。

## 变体与关联

- **模数不同**：模素数 `p` 的求逆用 `pow(x, p-2, p)`；若映射是 `x^k`，逆为 `x^(k^{-1} mod p-1)`，需先求 `k` 的模逆。
- **半字节映射**：常数不一定是 3/5；解密用各自模 16 的逆元（奇数才有逆元）。
- **移位方向/顺序**：加密与解密必须严格逆序；XOR 与移位交换性差，先 XOR 还是先移位会导致错误。
- **数据依赖变换**：若某步使用前一个字节/状态（CBC 式），需要从已知 IV/首字节开始链式逆推，而不是逐字节独立。
- 关联：[[ctf-reverse-mmx-simd-block-xor-swap-rot-add]]（XOR/交换/移位/加法的逆序还原）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（SM4 常量识别）、[[ctf-reverse-png-lsb-custom-sbox-aes256-decrypt]]（自定义 S 盒/块密码逆向）。

## 检测与防御

- **CTF 识别**：逐字节查表 + 循环移位 + 模素数求逆 + 半字节线性映射，是典型的“可逆混淆”题；先列变换顺序，再从已知明文验证逆运算。
- **防御/设计**：可逆混淆不能提供机密性；真实场景应使用标准认证加密（AES-GCM/ChaCha20-Poly1305）并把密钥放在服务端，不要用自制 S 盒/移位链保护敏感数据。
- **检测特征**：二进制中出现 256 字节 S 盒、`pow(x,255,257)` 形式的模幂、`(idx%7)+1` 的移位次数、固定 XOR 常量，可能是此类校验逻辑。
