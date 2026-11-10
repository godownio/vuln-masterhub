---
id: ctf-reverse-gfctf2021-wordy-jmp-db-patch-putchar-extract
title: GFCTF 2021 wordy：jmp-db 花指令 EB FF C0 BF ?? 00 00 00 E8 批量 NOP 后重建 main 并自动提取 putchar 字符
type: scenario
domain: ctf
path: ctf/reverse
technique: gfctf2021-wordy-jmp-db-putchar-extract
aliases:
- GFCTF 2021 wordy
- GFCTF{u_are2wordy}
- jmp db 花指令
- putchar 字符提取
- EB FF C0 BF
- IDAPython 自动去花
tags:
- ctf
- reverse
- obfuscation
- junk-code
- ida
- idapython
- x86-64
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T08:43:02+08:00'
  notes: 已对照原文例题一与 img/01-08 核对：EB FF 为目标=下一条指令地址-1(跳入自身第二字节)、FF C0=inc eax、BF imm32=mov edi,imm、E8 rel32=call putchar；模式 EB FF C0 BF ?? 00 00 00 E8、搜索范围 0x1135-0x3100、NOP 前 3 字节、字符在 ea+4、0x1135 按 P 重建 main 均与原文/截图一致；非预期解(把 [rbp-4] 改 1/ NOP jz)与截图 05-07 一致；flag GFCTF{u_are2wordy} 与截图 04/08 一致。原文未给版本，已 clear。CTF 单题全链一张卡，符合 ctf/reverse 既有粒度。
---

## 一句话结论

wordy 的 `main` 被大量 `EB FF C0 BF ?? 00 00 00 E8` 花指令切碎：开头的 `EB FF` 跳进下一条指令、`FF C0` 是 `inc eax`，真正要执行的是后面的 `BF imm32`（`mov edi, imm`）与 `E8 rel32`（`call putchar`），每个字符就藏在 `imm32` 的第一个字节；用 IDAPython 按含 `??` 的模式批量定位、NOP 前 3 字节、在 `0x1135` 按 `P` 重建 `main`，再读取命中地址 `+4` 的字节即可自动拼出 `GFCTF{u_are2wordy}`。

## 原理

- **字节布局**：`EB FF` 是 `jmp` 到自身第二条字节处（目标 = 下一条指令地址 - 1），`FF C0` 是 `inc eax`，`BF imm32` 是 `mov edi, imm32`，`E8 rel32` 是 `call putchar`。CPU 从 `EB` 之后的字节开始解码，能正常执行 `inc eax; mov edi,ch; call putchar`；IDA 的线性/递归扫描从固定边界解码时被 `EB FF` 与前后的 `C0` 打乱，导致函数体变成一堆 `db`/错位指令，无法 F5。
- **为什么 NOP 前 3 字节就恢复**：把 `EB FF C0` 三字节改成 `90 90 90` 后，`BF imm32; E8 ...` 回到正确的指令边界；IDA 在 `0x1135` 处按 `P` 即可重新识别 `main`。这个 patch 同时去掉了 `EB FF` 和 `FF C0`（`inc eax`），不影响后面的 `mov edi, imm; call putchar` 字符输出。
- **字符提取原理**：每个 `mov edi, imm32` 的立即数只有一个字节有效（字符 ASCII），位置在命中地址 `ea + 4`；`call putchar` 紧随其后。遍历所有命中，读取 `ea+4` 并拼成字符串，就是程序的输出（也是 flag 的可见部分）。
- **非预期解**：程序开头把 `[rbp-4]` 置 0，后面的比较恒成立导致正常执行不输出 flag；把 `mov dword ptr [rbp-4], 0` 的立即数改成 1，或把 `jz` NOP 掉，再运行程序即可直接打印 flag；也可用十六进制编辑器直接提取字符串。
- **为什么这是 CTF 常见题型**：花指令模式固定、字符以立即数形式重复出现，既考花指令识别，也考“不要把去花当成目的，要直接提取语义数据”的自动化思路。

## 触发条件

- 目标为 GFCTF 2021 wordy 或同类的 64 位 Linux/Windows 逆向题，`main` 被重复的 jmp-db 花指令切碎。
- IDA 中能看到 `EB FF C0 BF imm32 E8` 的重复字节模式，函数无法正常 F5。
- 有 IDAPython 环境；允许 patch 数据库/文件。
- 需要恢复 `main` 或直接提取输出字符串。

## 利用步骤

1. 在 IDA 中打开样本，观察 `main` 区域的杂乱字节，确认重复模式 `EB FF C0 BF ?? 00 00 00 E8`（`??` 为字符立即数）。
2. 用 `ida_bytes.bin_search` 按通配符模式在 `0x1135`–`0x3100` 范围搜索所有命中。
3. 对每个命中把前 3 字节 patch 为 `0x90`，使后面的 `BF imm32; E8 rel32` 恢复正确边界。
4. 在 `0x1135` 按 `P` 创建函数，F5 查看恢复后的 `main`：大量 `inc eax; mov edi, char; call putchar`。
5. 自动化提取：对每个命中读取 `idc.get_wide_byte(ea+4)`，按地址顺序拼接，得到输出字符串与 flag。
6. 验证：把字符串与 F5 中 `putchar` 的参数逐一对照；必要时动态运行 patch 后程序。
7. 非预期解：把 `mov dword ptr [rbp-4], 0` 改成 1（Keypatch）或 NOP `jz`，运行程序直接输出 flag。

## PoC

```python
import ida_bytes, ida_idaapi, idc

hexstr = "EB FF C0 BF ?? 00 00 00 E8"
toks = hexstr.split()
pat  = bytes(0x00 if t == '??' else int(t, 16) for t in toks)
mask = bytes(0x00 if t == '??' else 0xFF for t in toks)

ea, end, out = 0x1135, 0x3100, ""
while ea < end:
    hit = ida_bytes.bin_search(
        ea, end, pat, mask,
        ida_bytes.BIN_SEARCH_FORWARD |
        ida_bytes.BIN_SEARCH_NOBREAK |
        ida_bytes.BIN_SEARCH_NOSHOW)
    if hit == ida_idaapi.BADADDR:
        break
    for i in range(3):
        ida_bytes.patch_byte(hit + i, 0x90)
    out += chr(idc.get_wide_byte(hit + 4))
    ea = hit + len(pat)
print(out)          # ... GFCTF{u_are2wordy} ...
```

## 变体与关联

- **同类 jmp-db 变体**：`jmp short +N; db garbage`、`jz/jnz` 跳过 `E8`、`jx+jnx` 一个分支跳到 `db E8`；修复思路相同：先恢复正确指令边界，再重建函数。
- **字符提取变体**：立即数可能经异或/加法变换后才输出；若 `mov edi, imm` 的立即数不是直接 ASCII，需跟踪前序运算或动态断点读取 `edi`。
- **关联**：[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jz 跳过 E8 的同类花指令修复）、[[code-analysis-reverse-obfuscation-idapython-wildcard-binsearch-patch]]（通配模式搜索与 patch 脚本）、[[code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild]]（另一类 jmp 变型）。
- **边界**：模式串中的 `??` 位置必须与实际立即数偏移一致；若编译器/版本不同导致 `EB FF C0` 前缀变化，需重新确认模式；patch 后若 `main` 仍无法 F5，检查是否有其它花指令类型叠加。

## 检测与防御

- CTF 逆向题技巧，不涉及攻击面。出题侧若想避免被“读立即数”秒杀，可让字符经过运行时变换、拆分或与密钥相关，而不是直接以明文立即数出现在 `mov` 中。
- 解题侧：先识别花指令模式，再判断“哪些数据本身就是答案”；不要只执着于恢复完整控制流，能直接提取语义数据时优先自动化提取。
- 验证信号：拼接出的字符串以 `flag{`/`GFCTF{` 等题目标记开头，且与 F5 中 `putchar` 参数序列一致。
