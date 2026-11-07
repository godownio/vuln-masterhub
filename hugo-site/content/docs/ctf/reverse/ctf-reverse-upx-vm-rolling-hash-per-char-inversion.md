---
id: ctf-reverse-upx-vm-rolling-hash-per-char-inversion
title: UPX 自解压 ELF 内存 dump + VM 逐字符可逆变换反推（滚动 hash 与 pair check 复核）
type: scenario
domain: ctf
path: ctf/reverse
technique: upx-selfextract-memory-dump-vm-per-char-inversion
tags:
- ctf
- reverse
- upx
- unpacking
- elf
- vm
- bytecode
- rolling-hash
- inversion
- x86-64
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:46+08:00'
  notes: 已对照原文 RE1 一节核对：UPX!/springwind vm 字符串、gdb 输入前 dump 5 页、长度 42+flag{}/} 约束、opcode 1-8 语义、逐字符公式 R1=input^key→R0^=R1→rol→add→cmp target、input[i]=ror32(target-add,rot)^prev^key、target 表 0x2040、pair 表 0x2100、滚动 hash/pair check 复核均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-upx-vm-rolling-hash-per-char-inversion/
draft: false
kb_aliases:
- 春风栈桥
- RE1
- UPX 脱壳
- 自解压 ELF
- springwind vm
- VM 逐字符反推
- 滚动 hash 校验
- pair check
---

## 一句话结论

“春风栈桥”是一个 UPX 自解压的 Linux x86-64 ELF：运行时把主体解到匿名映射，需在输入前用 gdb dump 内存拿到未打包代码；主体是 VM 校验器，每个字符执行 `R1=input[i]^key; R0^=R1; R0=rol32(R0,rot); R0+=add; cmp R0,target[i]`，因此可从 target 逐字符反推 `input[i]=ror32(target[i]-add,rot)^上一轮R0^key`，最后用滚动 hash 与 pair check 复核。

## 原理

- **UPX 自解压**：`strings` 可见 `UPX!` 与 `== springwind vm ==`；程序运行时在匿名映射中解压主体，静态反编译看到的只是壳。用 gdb 在 `read` 输入前 `dump memory`，按页导出得到 `re1_unpacked_5pages.bin`，再在 dump 上做反汇编/分析。
- **输入约束**：`main` 检查长度 42、前缀 `flag{`、后缀 `}`；因此 flag 主体是 36 字节 UUID（含连字符）。
- **VM ISA**：opcode 1 `mov reg,imm32`；2 `load reg,input[idx]`；3 `xor reg,imm8`；4 `xor reg,reg`；5 `rol reg,imm8`；6 `add reg,imm32`；7 `cmp reg,target[idx]`；8 `halt`。字节码结构固定，可以顺序解析。
- **逐字符变换**：对第 i 个字符，`R1=input[i]`、`R1^=key_i`、`R0^=R1`、`R0=rol32(R0,rot_i)`、`R0+=add_i`、`assert R0==target[i]`。`R0` 的初值来自第一条 `mov`，之后每轮以上一轮 target 作为新状态。
- **可逆性**：`add` 可减、`rol32` 可 `ror32`、`xor` 自逆；因此 `input[i]=ror32(target[i]-add_i,rot_i) ^ previous_R0 ^ key_i`。逐字符反推不需要爆破，O(n)。
- **复核**：程序还对整串做滚动 hash（a/b/c/d 四个 32 位状态，混合 `rol/xor/sub`）与 21 组 pair check（相邻字节、移位、异或常量）；反推结果必须同时通过这两个校验，才能排除“自洽但错误”的分支。
- **为什么需要 dump**：UPX 壳在运行时才解压，静态段可能被压缩/加密；在输入前 dump 能拿到真实 VM 字节码与 target 表，避免手工脱壳。

## 触发条件

- 目标为 UPX 或其他自解压壳保护的 ELF/PE，静态反编译看不到主体逻辑。
- 程序运行时解压到匿名映射/可写段，能在关键输入前用调试器 dump 内存。
- 主体是 VM/字节码校验器，逐字符变换可逆，且有 target 表/滚动 hash/pair check 可复核。
- 有 gdb/调试权限，或能静态脱壳。

## 利用步骤

1. `strings`/`file`/`checksec` 确认 UPX 与架构；定位程序入口与输入读取点。
2. 在 gdb 中在 `read` 前下断点，`dump memory re1_unpacked.bin <start> <end>` 导出匿名映射/解压后的代码段。
3. 在 dump 上反汇编，定位 `main`、VM 解析器、target 表（本题 `0x2040` 起 42 个 u32）与 pair 表（`0x2100` 起 21 个 u16）。
4. 解析 VM 字节码，确认每条指令的 `key/rot/add/target` 与状态寄存器。
5. 按公式逐字符反推，更新 `state=target[i]`；得到 42 字节候选。
6. 用滚动 hash 与 pair check 复核；通过后输出 flag。

## PoC

```python
def ror32(x, n):
    x &= 0xFFFFFFFF
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# ops: 从 dump 解析出的 VM 指令序列（load/xor_imm/xor_reg/rol/add/cmp）
state = ops[0][2]          # 第一条 mov reg0, imm32
flag = []
pc = 1
for i in range(42):
    load, xor_imm, xor_reg, rot, add, cmp_ = ops[pc:pc + 6]
    pc += 6
    key, shift, addend = xor_imm[2], rot[2], add[2]
    ch = ror32((targets[i] - addend) & 0xFFFFFFFF, shift) ^ state ^ key
    flag.append(ch & 0xFF)
    state = targets[i]

flag = bytes(flag)
assert flag.startswith(b"flag{") and flag.endswith(b"}")
assert hash_check(flag) and pair_check(flag, pair_targets)
print(flag.decode())
```

原文实测得到 `flag{d8c9e14d-4acb-43e5-a709-bbe8983eef63}`；未在本库复跑。

## 变体与关联

- **壳变体**：UPX、ASPack、Themida、VMProtect；优先在运行时 dump，静态脱壳需处理 IAT/重定位。
- **VM 变体**：寄存器/栈式、字节/字操作、8/32 位 rotate、非线性 S-box；核心是确认语义后可逆。
- **复核变体**：滚动 hash、pair check、CRC、HMAC；用它们排除错误分支。
- **关联卡片**：[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（自定义 VM 的 ISA 抠取与逐轮求逆，纯静态/差分验证）、[[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]（原生 VM + WASM 协同）。

## 检测与防御

- **对逆向方**：不要只静态看壳；在输入前 dump 解压后的内存，确认 VM 语义后再写逆变换；用滚动 hash/pair check 复核，避免“自洽但错误”。
- **对保护方**：UPX 只能提高静态分析成本；真正的强度来自运行时密钥、反调试、代码完整性校验与语义混淆。
- **对题目设计方**：target 表/VM 字节码不要以明文数组直接暴露；复核逻辑应与主变换使用不同的状态，避免被同一逆变换绕过。
