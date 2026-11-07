---
id: mobile-harmony-hap-arkts-native-sbox-affine-unicorn
title: HarmonyOS HAP 逆向：ArkTS 派生 seed + native S-box/128 位仿射变换，Unicorn 黑盒 + GF(2) 消元反解 UUID
type: scenario
domain: mobile
path: mobile/harmony
technique: harmony-hap-arkts-native-sbox-affine-unicorn
aliases:
- 云栈密令
- RE3
- CloudSeal
- cloud.wind
- libcloudseal.so
- ArkTS 派生 seed
- 128 位仿射变换
- Unicorn 黑盒求逆
tags:
- harmonyos
- hap
- arkts
- native
- arm64
- unicorn
- sbox
- affine
- gf2
- reverse
- ctf
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:49+08:00'
  notes: 已对照原文 RE3 一节核对：HAP 结构（modules.abc.pa/cloud.profile/libcloudseal.so）、cloud.wind=3f0a9cc14d62e837b5f19a047bd2c6e0、derive_seed order/xorv/加法/ror8、stage1 sbox[uuid[pidx]^const^seed]、stage2 128 位仿射的 Unicorn 全 0/基向量黑盒+GF(2) 消元、rank=128、反 S-box/反置换、flag 均一致。未验证点：PoC 未在本机复跑（卡内为骨架，全文见原文）；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

HarmonyOS HAP 里 ArkTS 侧从 `resources/base/profile/cloud.profile` 读取 `cloud.wind`，经固定置换/异或/加法/`ror8` 派生 16 字节 seed，再调用 native `CloudSeal_NativeCheck`；native 先做 `stage1[i]=sbox[uuid[pidx[i]]^const[i]^seed[i]]`，再做 128 位仿射变换。把仿射阶段放进 Unicorn ARM64 当黑盒：全 0 输入得偏移、128 个基向量构造矩阵、GF(2) 高斯消元求出目标 stage1，最后反 S-box/反置换/异或 seed 与 const 即得 UUID。

## 原理

- **HAP 结构**：HarmonyOS HAP 可按 ZIP 解包，关键文件为 `ets/modules.abc.pa`（ArkTS 字节码）、`resources/base/profile/cloud.profile`（配置）、`libs/arm64-v8a/libcloudseal.so`（native 库）。
- **ArkTS 侧**：`checkCloudSeal(input)` 读取 `cloud.profile` 的 `cloud.wind`，调用 `deriveWindSeed(profileHex)` 得到 seed，再调用 `native.CloudSeal_NativeCheck(input, seed)`；真实 `cloud.wind` 为 `3f0a9cc14d62e837b5f19a047bd2c6e0`。
- **seed 派生**：固定置换 `order=[9,0,14,5,2,11,7,12,1,15,4,10,3,8,13,6]`，`v=profile[order[i]]^xorv[i]`，`v=(v+0x31+i*13)&0xff`，`seed[i]=ror8(v,(i+3)&7)`；xorv 为 16 字节常量表。
- **stage1（S-box 代换）**：把 32 个 UUID hex 字符解析成 16 字节；`stage1[i]=sbox[uuid[pidx[i]] ^ const[i] ^ seed[i]]`，其中 `pidx` 是固定置换、`const` 来自 `.rodata`、sbox 是 256 字节表。S-box 对固定表是双射，可反查。
- **stage2（128 位仿射）**：对 16 字节输入做线性变换加常量：`out = M·in ⊕ c`（比特层面）。如果直接逆汇编很费时，可把 native 的 stage2 函数放进 Unicorn 执行：全 0 输入得到 `c`；对 128 个基向量 `e_i` 各跑一次，`out_i ^ c` 就是矩阵第 i 列；由此构造 128×128 的 GF(2) 矩阵，解 `M·x = target ^ c` 得到 stage1。
- **反解**：GF(2) 消元要求矩阵满秩（本题 rank=128）；得到 stage1 后，对每个 i 用 `inv_sbox[stage1[i]] ^ const[i] ^ seed[i]` 还原 `uuid[pidx[i]]`，再按 pidx 逆置换回 16 字节，hex 格式化即 UUID。
- **为什么用 Unicorn**：native 是 ARM64，host 可能是 x86；Unicorn 可以按 ELF PT_LOAD 段映射、设置 SP/寄存器、在目标返回地址停住，把复杂仿射阶段当纯函数黑盒，避免逐条逆汇编。

## 触发条件

- 目标为 HarmonyOS HAP/APP，ArkTS 侧把关键参数（seed/密钥）传给 native 库。
- native 校验由可逆的 S-box 代换 + 线性/仿射变换组成，且能在 Unicorn 中独立执行。
- 能提取 HAP 内的 `.so`、profile、ABC 字节码，并定位 native 函数入口/返回地址。
- 明文为 `flag{UUID}` 格式，可用格式与 S-box 双射校验。

## 利用步骤

1. 解包 HAP（ZIP），读取 `resources/base/profile/cloud.profile` 的 `cloud.wind`，提取 `libs/arm64-v8a/libcloudseal.so`。
2. 从 ArkTS 字节码/字符串定位 `checkCloudSeal` 与 `deriveWindSeed`，还原置换/xorv/加法/ror8 参数，算出 seed。
3. 用 pyelftools 解析 `.so` 的 PT_LOAD 段，在 Unicorn 中映射；定位 stage2 函数入口与返回地址，设置 SP/寄存器。
4. 先跑全 0 输入得到偏移 `c`；再对 128 个基向量各跑一次，构造矩阵列；用 GF(2) 高斯消元解出 target 对应的 stage1。
5. 读取 sbox/pidx/const 表，反 S-box、反置换、异或 seed/const，得到 16 字节 UUID。
6. 格式化为 `flag{8-4-4-4-12}`，用 native 校验/`--check` 复核。

## PoC

seed 派生与 affine 求解核心（按原文脚本重写，未在本库复跑）：

```python
def derive_seed(profile):
    order = [9, 0, 14, 5, 2, 11, 7, 12, 1, 15, 4, 10, 3, 8, 13, 6]
    xorv = [0x42,0x17,0xC3,0x5A,0x99,0x21,0xE4,0x0D,
            0xB6,0x78,0x34,0xAA,0x6F,0xC0,0x11,0x5D]
    out = []
    for i in range(16):
        v = profile[order[i]] ^ xorv[i]
        v = (v + 0x31 + i * 13) & 0xff
        out.append(ror8(v, (i + 3) & 7))
    return bytes(out)

def solve_affine(native, target):
    zero = native.run_stage2(bytes(16))
    cols = []
    for bit in range(128):
        vec = bytearray(16)
        vec[bit // 8] = 1 << (bit % 8)
        out = native.run_stage2(bytes(vec))
        cols.append(bytes(a ^ b for a, b in zip(out, zero)))
    rhs = int.from_bytes(bytes(a ^ b for a, b in zip(target, zero)), "little")
    # 构造 128 行增广矩阵并做 GF(2) 消元，解出 value
    ...
    return value.to_bytes(16, "little")
```

原文实测 `stage1` 求解 rank=128，最终 `flag{f35b8ad6-2c51-4a85-93c0-0e6279347b1a}`；未在本库复跑。

## 变体与关联

- **HAP 变体**：ArkTS/ABC 字节码、native `.so`、资源 profile；先解包再分层分析。
- **代换变体**：S-box、逆 S-box、固定置换、异或常量；确认双射后反查。
- **线性层变体**：GF(2) 仿射、AES-like MixColumns、矩阵乘；可用 Unicorn/模拟器黑盒构造矩阵。
- **关联卡片**：[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]（VM 保护识别）、[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（自定义 VM 求逆）。

## 检测与防御

- **对逆向方**：不要逐条逆汇编复杂 native 函数；先判断是否线性/仿射，用 Unicorn 黑盒构造矩阵；用格式/校验复核。
- **对保护方**：S-box + 仿射只能提高静态分析成本；真正的强度来自运行时密钥、反调试、代码完整性校验与白盒密码。
- **对 HarmonyOS 应用**：不要把密钥/seed 只放在 profile 中；native 校验应结合设备绑定/服务端挑战，避免离线重放。
