---
id: code-analysis-reverse-linux-elf-self-got-read-memfrob-hijack
title: Linux ELF 自劫持 read@GOT：AT_PHDR 解析动态段 + mmap + memfrob(XOR 42) 注入解密逻辑
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: linux-elf-self-got-read-memfrob-hijack
tags:
- linux
- elf
- got-hijack
- memfrob
- dynamic-linking
- reverse
- malware
- anti-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:45+08:00'
  notes: 已对照原文与图片41核对：read fd=1、AT_PHDR/PT_DYNAMIC、memfrob XOR42、flag_enc 与 XOR 解密一致；PoC 未复跑。
url: /docs/code-analysis/reverse/linux/code-analysis-reverse-linux-elf-self-got-read-memfrob-hijack/
draft: false
kb_aliases:
- GOT 自劫持
- read@GOT 覆写
- AT_PHDR
- PT_DYNAMIC 解析
- memfrob
- Satellite Hijack
- 共享库反调试
---

## 一句话结论

恶意 ELF/共享库可以在自身进程内用 `getauxval(AT_PHDR)` 找到 program headers，遍历 `PT_DYNAMIC` 解析 `DT_SYMTAB`/`DT_STRTAB`/`DT_JMPREL`，定位 `read` 的 GOT 表项；再把 mmap 出来的“全星号”数据用 `memfrob()`（逐字节 XOR 42）解密后覆写 `read@GOT`，让后续所有 `read()` 调用进入攻击者函数，从而在运行时劫持输入/解密逻辑并隐藏 flag。

## 原理

- **AT_PHDR**：`getauxval(AT_PHDR)` 返回当前进程 program headers 的虚拟地址（PIE 下也有效）；据此可遍历 `PT_LOAD`/`PT_DYNAMIC`，无需打开磁盘文件。
- **动态段解析**：`PT_DYNAMIC` 指向 `.dynamic` 数组，`DT_SYMTAB` 是符号表地址、`DT_STRTAB` 是字符串表、`DT_JMPREL`/`DT_PLTRELSZ` 是 `.rela.plt` 及其大小。遍历 `Elf64_Rela`（24 字节），`r_info >> 32` 得符号索引，读 `Elf64_Sym.st_name` 从 strtab 取符号名，`r_offset` 即对应 GOT 表项地址。
- **GOT 劫持**：找到 `read` 的 GOT 项后，把它的值改成攻击者函数地址；之后库内/主程序对 `read` 的调用都会跳到攻击者逻辑。若 GOT 只读（Full RELRO），需要 `mprotect` 或其他可写函数指针。
- **memfrob**：glibc 的 `memfrob(void *s, size_t n)` 对每个字节 XOR 42（`0x2A`）并返回原指针；它不是加密，只是混淆。攻击者把密文写成全星号/占位数据，运行时用 `memfrob` 解出真实机器码/数据。
- **环境变量门控**：`library.so` 先把环境变量名逐字节减 1 解码（如 `SAT_PROD_ENVIRONMENT`），`getenv` 非空才进入 `if_env_not_null`，增加静态分析难度并控制触发条件。
- **输入解密**：被替换的 `read()` 用用户输入与 `flag_enc1..5` 做 XOR 校验，`flag[i] = enc[i] ^ i`；xor 的索引参与运算，逆向时按位置还原。
- **为什么有效**：GOT 在可写数据段，运行时修改立即生效；自解析动态段不依赖外部工具/文件，隐蔽性强；memfrob 让字符串扫描看不到明文机器码。

## 触发条件

- 目标为 Linux ELF/共享库，使用动态链接；GOT 可写（Partial/No RELRO；Full RELRO 需额外绕过）。
- 攻击者能执行该 ELF 或让目标加载该共享库；环境变量门控可被设置/满足。
- 目标进程可 `mmap` 可写内存并执行/调用其中的代码（NX 需相应处理）。
- 逆向者能定位 `AT_PHDR`/`PT_DYNAMIC`/`memfrob`/GOT 写操作；或能动态调试 dump 解密后的数据。

## 利用步骤

1. **静态识别**：在 IDA/Ghidra 中搜索 `getauxval`、`AT_PHDR`、`PT_DYNAMIC`、`DT_SYMTAB`、`DT_STRTAB`、`DT_JMPREL`、`memfrob`、`getenv`；这些组合强烈暗示自解析/GOT 劫持。
2. **定位门控**：查看 `getenv` 的参数构造（逐字节减 1/异或等），还原环境变量名；设置该变量进入恶意分支。
3. **跟踪 GOT 写**：找到 `read` 符号的 GOT 地址与写入点；确认写入的数据来自 `mmap` + `memfrob` 解密后的缓冲区。
4. **dump 解密数据**：在 `memfrob` 返回后下断点，dump 目标缓冲区；或按 XOR 42 离线解密全星号数据。
5. **逆向被替换的 read**：分析输入校验/异或逻辑，提取 `flag_enc1..5` 等常量。
6. **还原 flag**：按 `flag[i] = enc[i] ^ i`（或实际索引规则）计算；验证格式 `HTB{...}`。
7. **动态验证**：用 gdb/LD_PRELOAD 复现 GOT 覆写，观察 `read` 调用是否进入新函数；对比 `/proc/pid/maps` 中 GOT 页权限。

## PoC

```python
# 从二进制/内存 dump 中提取的密文
enc = bytes.fromhex("6c357b30763059376656663f753e7c3a4f217c4c78216f246a2c3b66")
flag = bytes(b ^ i for i, b in enumerate(enc))
print(flag.decode(errors="replace"))
# b'l4y3r5_0n_l4y3r5_0n_l4y3r5!}'
```

GOT 定位伪代码（分析用）：

```c
void *phdr = (void *)getauxval(AT_PHDR);
Elf64_Phdr *ph = phdr;
Elf64_Dyn *dyn = NULL;
for (int i = 0; i < ehdr->e_phnum; i++)
    if (ph[i].p_type == PT_DYNAMIC)
        dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);

// DT_SYMTAB / DT_STRTAB / DT_JMPREL
// 遍历 Elf64_Rela，按 r_info>>32 查 Elf64_Sym.st_name == "read"
// 得到 read@GOT 的 r_offset，写入 mmap+memfrob 解密后的函数地址
```

## 变体与关联

- **外部 GOT 劫持**：通过 `/proc/pid/mem` 解析目标 ELF 动态段并覆写 `puts@GOT`；见 [[pentest-c2-linux-proc-mem-got-hijack]]。
- **Full RELRO**：GOT 只读时，改 `.fini_array`、`__malloc_hook`（旧 glibc）、atexit 或 `mprotect` 后再写。
- **memfrob 变体**：自定义 XOR 42 的循环、RC4、简单加减；识别 `^ 0x2A` 常量或 `memfrob` 调用即可。
- **环境变量门控**：逐字节减 1/异或/反转构造变量名；静态分析时把常量还原成字符串，设置变量触发。
- **关联卡片**：[[pentest-c2-linux-proc-mem-got-hijack]]（外部进程 GOT 劫持）；[[binary-pwn-setuid-got-plt-lazy-binding-hijack]]（GOT/PLT 惰性绑定劫持）。

## 检测与防御

- **二进制检测**：扫描 `getauxval(AT_PHDR)` + `PT_DYNAMIC` + `memfrob` + GOT 写组合；对全星号/高熵缓冲区 + XOR 42 循环告警。
- **加固**：使用 Full RELRO（`-z relro -z now`）使 GOT 只读；启用 PIE/ASLR、`-fstack-protector`；限制环境变量注入。
- **运行时**：监控对自身 GOT 页的写入、`mprotect` 改可写、`memfrob` 调用；EDR 可对 `read@GOT` 与磁盘 ELF 符号不一致告警。
- **分析**：在 `memfrob` 后 dump 缓冲区；用 gdb 断点跟踪 GOT 写；对共享库做符号/重定位差异检查。
