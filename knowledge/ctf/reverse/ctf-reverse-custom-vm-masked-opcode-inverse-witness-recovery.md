---
id: ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery
title: 自定义 VM 校验器逆向：掩码 opcode + 可逆指令反向执行恢复 witness
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-vm-masked-opcode-inverse-witness
aliases:
- compile_me_maybe
- 自定义 VM 逆向
- opcode 掩码
- witness 恢复
- 可逆指令反向执行
- nibble S-box 求逆
- xorshift 流解密
tags:
- ctf
- reverse
- vm
- opcode-masking
- invertible
- sbox
- xorshift
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:55:55+08:00'
  notes: 已对照原文 §compile_me_maybe 核对：checker_program 掩码 opcode、xor/add/mul/rotl/xorr/addr/swap/sbox/perm/mix/not 可逆、从 checker_target 反推 64B witness、xorshift64 流解密 flag，opcode/常量与原文一致；未本机复跑。
---

## 一句话结论

校验器是一段自定义 VM：`checker_program` 的每个 opcode 先与 `checker_opcode_mask(step)` 异或，VM 指令 `xor/add/mul/rotl/xorr/addr/swap/sbox/perm/mix/not` 在 32 位模意义下全部可逆；从 `checker_target` 出发按相反顺序执行逆指令，即可恢复 64 字节 witness，再用 witness 派生 xorshift64 流解密 flag。

## 原理

- 程序把 witness 当作 64 字节 / 16 个 little-endian `u32` 寄存器，执行 `checker_program`，要求最终寄存器等于 `checker_target`。
- `checker_program` 中的 opcode 不是明文，而是 `opcode = byte ^ checker_opcode_mask(step)`，其中 `checker_opcode_mask` 是一个由 step 驱动的 32 位混合函数；先还原指令流才能反汇编。
- VM 指令均为可逆运算：
  - `xori`：`reg ^= imm`（自逆）；
  - `addi`：`reg = reg - imm mod 2^32`；
  - `muli`：立即数为奇数，存在模逆，`reg = reg * inv(imm) mod 2^32`；
  - `rotl`：逆向为 `rotr`；
  - `xorr`：`left ^= right`（自逆）；
  - `addr`：`left = left - right mod 2^32`；
  - `swap`：交换两个寄存器（自逆）；
  - `sbox`：按 nibble 查表，先求逆 S-box；
  - `perm`：按 `register_permutations[pidx]` 重排，逆向按原映射写回；
  - `mix`：`new_right = old_right ^ rotl(new_left, amount*3+1)`、`new_left = old_left - rotl(old_right, amount)`，逆向先恢复 `old_right` 再恢复 `old_left`；
  - `not`：按位取反（自逆）。
- 从 `checker_target` 开始，反向遍历指令并执行对应逆操作，最终得到 witness；这是“可逆 VM 校验器”的标准反推方法，不需要求解约束/SMT。
- 恢复 witness 后，`seed_from_witness` 用 xorshift64 混合 64 字节得到 seed，`stream_byte(seed,i)` 生成密钥流，再按 `encrypted[permutation[i]] ^ stream ^ witness[...] ^ salt`、旋转与减法还原明文。

## 触发条件

- 校验器把输入拆成固定数量寄存器，执行一段自定义指令序列，最后与常量目标比较。
- 指令集只包含可逆运算（异或、加减、旋转、置换、S-box、混合），没有数据相关分支/不可逆哈希。
- opcode 可能被掩码/加密，但掩码函数可由 step 复现。
- 能提取 `checker_program`、`checker_target`、`register_permutations`、`nibble_sbox`、`encrypted`、`permutation` 等数组。

## 利用步骤

1. 从 `data.hpp`/二进制中提取各数组，按 C 数组语法解析为整数列表。
2. 复现 `checker_opcode_mask(step)`，逐步解码 opcode 与操作数，得到指令列表（halt/xori/addi/muli/rotl/xorr/addr/swap/sbox/not/perm/mix）。
3. 初始化 `regs = checker_target[:]`，从最后一条指令向前遍历，按上述逆操作修改寄存器。
4. 反向执行到第一条指令后，把 16 个 `u32` 按 little-endian 拼成 64 字节 witness。
5. 用 witness 复现 `seed_from_witness` 与 `stream_byte`，按 `decrypt_flag` 的置换/旋转/减法还原明文。
6. 可选：把 witness 写回 `generated_witness.hpp` 并编译原程序，验证输出一致。

## PoC

```python
def inverse_substitute_nibbles(x, inv_sbox):
    out = 0
    for shift in range(0, 32, 4):
        out |= inv_sbox[(x >> shift) & 0xF] << shift
    return out & 0xFFFFFFFF

def recover_witness(instructions, target, perms, inv_sbox):
    regs = target[:]
    for inst in reversed(instructions):
        op = inst[0]
        if op == "xori":
            _, t, imm = inst; regs[t] ^= imm
        elif op == "addi":
            _, t, imm = inst; regs[t] = (regs[t] - imm) & 0xFFFFFFFF
        elif op == "muli":
            _, t, imm = inst; regs[t] = (regs[t] * pow(imm, -1, 2**32)) & 0xFFFFFFFF
        elif op == "rotl":
            _, t, n = inst; regs[t] = rotr32(regs[t], n)
        elif op == "xorr":
            _, l, r = inst; regs[l] ^= regs[r]
        elif op == "addr":
            _, l, r = inst; regs[l] = (regs[l] - regs[r]) & 0xFFFFFFFF
        elif op == "swap":
            _, l, r = inst; regs[l], regs[r] = regs[r], regs[l]
        elif op == "sbox":
            _, t = inst; regs[t] = inverse_substitute_nibbles(regs[t], inv_sbox)
        elif op == "not":
            _, t = inst; regs[t] = (~regs[t]) & 0xFFFFFFFF
        elif op == "perm":
            _, pidx = inst
            old = [0] * 16
            for i, src in enumerate(perms[pidx]):
                old[src] = regs[i]
            regs = old
        elif op == "mix":
            _, l, r, amount = inst
            new_l, new_r = regs[l], regs[r]
            old_r = new_r ^ rotl32(new_l, amount * 3 + 1)
            old_l = (new_l - rotl32(old_r, amount)) & 0xFFFFFFFF
            regs[l], regs[r] = old_l, old_r
    return b"".join(x.to_bytes(4, "little") for x in regs)
```

案例恢复出的 witness 写入 `generated_witness.hpp` 后编译运行，输出 `NepCTF{N0t_th1s_rUNtimE_m4y_be_next_T1me}`。

## 变体与关联

- 变体：opcode 掩码可能依赖前一条指令/寄存器而非 step；需要从入口动态跟踪或解方程恢复。
- 变体：VM 含不可逆操作（乘法取高 32 位、哈希、数据相关分支）时，反向执行不成立，需要约束求解/SMT/符号执行。
- 变体：S-box 可能是 8 位而非 nibble；置换可能多维/多层，逆向时按层级倒序。
- 关联：[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（可逆变换求逆）、[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（自定义 VM ISA 提取）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（常量识别）。

## 检测与防御

- 防御：校验器不要只用可逆运算拼接；加入密码学哈希/签名或不可逆压缩，防止直接反推 witness。
- 防御：opcode 掩码密钥不要硬编码在二进制中；对关键常量做白盒/混淆并配合完整性校验。
- 检测：二进制中出现大段解释器循环、opcode 表、S-box/置换表、`checker_target` 常量；运行时有大量寄存器间接跳转。
- 响应：发现校验逻辑可逆后，评估是否有其他隐藏校验路径；更新算法并重新发布。
