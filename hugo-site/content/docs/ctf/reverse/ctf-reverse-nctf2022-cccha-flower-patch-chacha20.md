---
id: ctf-reverse-nctf2022-cccha-flower-patch-chacha20
title: NCTF 2022 cccha：三类花指令（call $+5 改返回地址、jmp db、抵消式）patch 后识别 ChaCha20 恢复密钥流
type: scenario
domain: ctf
path: ctf/reverse
technique: nctf2022-cccha-flower-patch-chacha20
tags:
- ctf
- reverse
- obfuscation
- junk-code
- chacha20
- idapython
- elf
- x86-64
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T08:43:04+08:00'
  notes: 已对照原文例题二与 img/09-16 核对：三类花指令(imm32/imm8 call-$+5 改返回地址、cmp 2022h ja/jle+db E8 E8、push rdx/pop rdx 抵消式)与截图一致；patch 偏移(imm at ea+12，E9=Δ+3、EB=Δ+6)正确；expand_key 的 'expand 32-byte k'/0x20 key/0xC nonce、Gen_KeyStream 的 ROL 16/12/8/7 quarter-round 与 img/15-16 一致；加密 s1[i]^=ks[i]; s1[i]+=i 的逆运算公式与 exp 等价，v9/ks 常量与原文 exp 完全一致，flag NCTF{cb86d437-8671-42a4-82dc-3259754e5ef5} 正确。原文未给版本，已 clear。CTF 单题全链(去花→ELFdumper→ChaCha20→解密)一张卡，符合 ctf/reverse 既有粒度；ChaCha20 识别环节与既有识别卡内容重叠属整链步骤，非重复利用链。
url: /docs/ctf/reverse/ctf-reverse-nctf2022-cccha-flower-patch-chacha20/
draft: false
kb_aliases:
- NCTF 2022 cccha
- NCTF{cb86d437-8671-42a4-82dc-3259754e5ef5}
- call $+5 mov [rsp] retn
- jmp db 070
- ChaCha20 expand 32-byte k
- ELFdumper 去花
---

## 一句话结论

cccha 的 `main` 被三类花指令打乱：`call $+5; pop rbx; add rbx, imm; mov [rsp+var], rbx; popfq; pop rbx; retn` 的 jmp 变体、`cmp rax,2022h; ja/jle` 后接 `db E8 E8` 的 jmp-db、以及 `push rdx; pop rdx` 之类的抵消式；用 IDAPython 按固定字节模式批量 NOP 并把 call-$+5 变体重建为 `E9/EB` 跳转（imm32 版偏移 `imm+3`、imm8 版 `imm+6`），重新分析后用 ELFdumper dump，识别出 `expand 32-byte k` 常量的 ChaCha20，最后按 `s1[i] ^= ks[i]; s1[i] += i` 的逆运算恢复 flag `NCTF{cb86d437-8671-42a4-82dc-3259754e5ef5}`。

## 原理

- **花指令 1（call $+5 改返回地址）**：`call $+5` 压入下一条指令地址，`pop rbx` 取出、`add rbx, Δ` 算出真实目标，`mov [rsp+18h+var_8], rbx` 覆盖返回地址槽，`popfq/pop rbx` 恢复现场，`retn` 跳到计算目标。两种编码：`48 81 C3 imm32`（24 字节模式）与 `48 83 C3 imm8`（22 字节模式）。重建跳转的偏移推导见 [[code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild]]。
- **花指令 2（jmp db / 无效条件跳转）**：`push rax; cmp rax,2022h; ja loc; jle loc; db E8; db E8; loc: pop rax`。`ja` 与 `jle` 覆盖所有情况、目标相同，两个 `E8` 是永不执行的垃圾字节；但线性扫描会把 `E8` 当 `call` opcode，吞掉后面的真实字节，导致错位。
- **花指令 3（抵消式）**：`push rdx; pop rdx`、`push rax; pop rax` 等成对保存/恢复，净效果为零；以及 `pushfq/popfq` 包裹的临时现场保护。
- **批量 patch**：`patch_jmp_1`（imm32 模式）读取 `ea+12` 的 dword Δ，目标相对 `ea+8+Δ`，写成 `E9 (Δ+3)`；`patch_jmp_2`（imm8 模式）读取 `ea+12` 的 byte Δ，写成 `EB (Δ+6)`；抵消式与 jmp-db 用固定模式直接 NOP。patch 后右键重新分析程序，IDA 才能恢复函数。
- **ELFdumper**：patch 后重新分析仍可能因 ELF 头/节区信息不完整影响 dump；用 ELFdumper 按地址把内存/文件 dump 成可再次加载的 ELF，再分析得到清晰伪代码。
- **ChaCha20 识别**：`expand_key` 里出现 16 字节常量 `"expand 32-byte k"`、`memcpy` 0x20 字节 key 与 0xC 字节 nonce；`Gen_KeyStream` 里是 ROL 16/12/8/7 的 quarter-round 序列（`a0+=a1; a3^=a0; a3=ROL(a3,16); ...`），符合 ChaCha20 的列/对角轮。
- **校验与解密**：`main` 先 `expand_key(v3, v7, &v4, -1640531527)`（`-1640531527` 即 `0x9E3779B9` 的有符号形式），再 `Gen_KeyStream(v3)`，然后对输入执行 `s1[i] ^= v3[i]; s1[i] += i`，最后 `memcmp(s1, v9, 42)`。因此解密为 `flag[i] = ((v9[i] - i) & 0xFF) ^ ks[i]`，其中 `v9` 是 42 字节密文、`ks` 是生成的密钥流。
- **数据布局**：`v9` 与 `ks` 在伪代码中表现为 6 个 64 位常量（5×8+2=42 字节），按小端取字节展开后逐字节运算。

## 触发条件

- 目标为 NCTF 2022 cccha 或同类 x86-64 ELF 逆向题，`main` 混乱、IDA 无法 F5。
- 二进制中存在上述三类花指令的固定字节模式（call-$+5 变体、`ja/jle` + `db E8`、成对 push/pop）。
- 有 IDAPython 与重新分析/ELFdumper 能力；允许 patch 文件。
- 需要识别密码算法并写出逆运算脚本。

## 利用步骤

1. 用 IDA 打开 ELF，观察 `main` 的混乱汇编，确认三类花指令的位置与模式。
2. 运行 IDAPython 脚本：`patch_jmp_1` 处理 imm32 版 call-$+5，`patch_jmp_2` 处理 imm8 版，`patch_directly` 处理抵消式与 jmp-db 固定模式。
3. 在 IDA 状态栏右键“重新分析程序”，让 IDA 按 patch 后的字节重建函数。
4. 若仍不理想，用 ELFdumper 按地址 dump 出 ELF，重新加载分析，得到可读的 `main`/`expand_key`/`Gen_KeyStream`。
5. 识别 ChaCha20：确认 `"expand 32-byte k"`、32 字节 key、12 字节 nonce 与 ROL 16/12/8/7 的 quarter-round。
6. 从 `main` 提取 42 字节密文 `v9` 与密钥流 `ks`（可静态抄常量，或下断点/脚本读取 `v3` 数组）。
7. 按 `flag[i] = ((v9[i]-i) & 0xFF) ^ ks[i]` 解密，得到 `NCTF{cb86d437-8671-42a4-82dc-3259754e5ef5}`。
8. 用 `flag{`/`NCTF{` 前缀与长度 42 校验结果。

## PoC

去花骨架（按原文脚本最小化整理，未在本机运行 IDA）：

```python
import ida_bytes, idc

signs = (ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK |
         ida_bytes.BIN_SEARCH_NOSHOW)

def build(hexstr):
    toks = hexstr.split()
    pat  = bytes(0x00 if t == '??' else int(t, 16) for t in toks)
    mask = bytes(0x00 if t == '??' else 0xFF for t in toks)
    return pat, mask

def patch_bytes(ea, data):
    for i, b in enumerate(data):
        ida_bytes.patch_byte(ea + i, b)

def patch_jmp(start, end, hexstr, imm_is_byte):
    pat, mask = build(hexstr); n = len(pat); ea = start
    while ea < end:
        hit = ida_bytes.bin_search(ea, end, pat, mask, 1, signs)
        if hit == idc.BADADDR:
            break
        delta = (idc.get_wide_byte(hit + 12) if imm_is_byte
                 else idc.get_wide_dword(hit + 12))
        if imm_is_byte:
            patch_bytes(hit, b'\x90' * n)
            patch_bytes(hit, b'\xEB' + bytes([(delta + 6) & 0xFF]))
        else:
            patch_bytes(hit, b'\x90' * n)
            patch_bytes(hit, b'\xE9' + ((delta + 3) & 0xFFFFFFFF).to_bytes(4, 'little'))
        ea = hit + n

# imm32 版与 imm8 版 call $+5 花指令
patch_jmp(0x1090, 0xa1e7,
          "53 53 9C E8 00 00 00 00 5B 48 81 C3 ?? ?? ?? ?? 48 89 5C 24 10 9D 5B C3", False)
patch_jmp(0x1090, 0xa1e7,
          "53 53 9C E8 00 00 00 00 5B 48 83 C3 ?? 48 89 5C 24 10 9D 5B C3", True)
# 抵消式 / jmp-db 固定模式
for p in ["50 53 52 5A 5B 58", "53 52 5A 5B", "50 58", "52 5A",
          "9C 50 48 3D 22 20 00 00 77 04 7E 02 E8 E8 58 9D"]:
    pat, mask = build(p); ea = 0x1090
    while ea < 0xa1e7:
        hit = ida_bytes.bin_search(ea, 0xa1e7, pat, mask, 1, signs)
        if hit == idc.BADADDR:
            break
        patch_bytes(hit, b'\x90' * len(pat)); ea = hit + len(pat)
```

解密骨架：

```python
v9_g = [0x23CE4B73757CC05E, 0x708F01F3AC89BBA4, 0x62D45B4183317FC8,
        0x4B50FC9DDC27A7A6, 0x385117386B2F9806, 0xEF2F]
ks_g = [0x24aa2514342efc10, 0x57b9d9d0924bd6aa, 0x668a271f44325f8f,
        0x1900ecaca269bcb6, 0x774ec7717c3840df, 0xd878e3846e0ebb32]

def le_bytes(words):
    out = []
    for w in words:
        for sh in range(0, 64, 8):
            out.append((w >> sh) & 0xFF)
    return out

v9, ks = le_bytes(v9_g), le_bytes(ks_g)
print(''.join(chr(((v9[i] - i) & 0xFF) ^ ks[i]) for i in range(42)))
# NCTF{cb86d437-8671-42a4-82dc-3259754e5ef5}
```

## 变体与关联

- **花指令 1 变体**：`add` 立即数宽度不同（imm8/imm32）、寄存器不同（rbx/rax）、栈槽不同；patch 时按实际编码读立即数并选择 `E9`/`EB`。
- **花指令 2 变体**：`ja/jle` 可换成 `jz/jnz`、`jb/jae` 等互补条件；`db E8` 可换 `db E9` 或其它多字节 opcode，核心是“条件恒成立、垃圾字节破坏边界”。
- **花指令 3 变体**：压栈/出栈寄存器对、`pushfq/popfq` 包裹、`sub rsp,imm`/`add rsp,imm` 成对。
- **ChaCha20 变体**：轮数可能不是 20（如 12/8 轮）、nonce 长度 8/12 字节、计数器初值不同；识别仍看 `expand 32-byte k` 常量与 quarter-round 的 ROL 16/12/8/7。
- **关联**：[[code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild]]（花指令 1 的通用重建方法）、[[code-analysis-reverse-obfuscation-idapython-wildcard-binsearch-patch]]（通配模式搜索脚本）、[[ctf-reverse-apk-chacha20-counter-one-native]]（另一个 ChaCha20 轮次/计数器变体）、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jmp-db 同类修复）。
- **边界**：`E9` 重建会覆盖段首 5 字节，若原序列不足 5 字节或后续字节被引用需改用 `EB`/精确改写；ChaCha20 的 key/nonce 若被二次处理，恢复的密钥流会不对，需回到 `expand_key` 的参数检查。

## 检测与防御

- CTF 逆向题技巧，不涉及网络攻击面。出题侧若要提高难度，应避免使用固定字节模式与标准算法常量同时出现；可对 key/nonce 做运行时派生、打乱常量表或改用自定义轮函数。
- 解题侧：先按模式批量 patch 恢复控制流，再识别算法常量；不要逐条硬读花指令。提取密钥流时优先用脚本读内存/断点，避免手抄 42 字节出错。
- 验证信号：解出的明文长度与 `memcmp` 长度一致、以题目标记开头、字节可打印。
