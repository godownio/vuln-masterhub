---
id: code-analysis-reverse-linux-tiny-elf-45-byte-overlap
title: 45 字节最小 ELF 可执行文件构造：ELF 头与程序头表重叠 + 装载器忽略字段/零填充，4KB 编译产物压到 45B
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: tiny-elf-header-phdr-overlap-45-byte
tags:
- linux
- elf
- elf-header
- program-header
- nasm
- size-optimization
- ctf
- payload-development
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:30:11+08:00'
  notes: 已对照原文核对：通读 ingest/tmp/13338/content.md（原文 teenys ELF 教程翻译，无图片）；45B PoC 与原文最终版逐行一致，并按 NASM 编码独立模拟字节布局复核（45 字节，e_phoff=4，代码位于偏移 32-39 与 e_shoff/e_flags/p_align 重合，e_phnum 低字节@44=1、高字节零填充，p_paddr=0x00030002 横跨 e_type/e_machine，p_filesz=p_memsz=_start）。修正两处：一句话结论原称“代码藏在 e_ident 填充区”（实为 84B 中间版本，最终 45B 版代码在 e_shoff/e_flags 区；已改为 phdr 从偏移 4 嵌入 ELF 头、代码与 e_shoff/e_flags/p_align 重用）；原理中“选择加载地址 0x10000 让 e_phentsize 落在 p_vaddr 高半部”实为 64B 阶段 0x200000 的技巧，且 p_paddr 与 e_type/e_machine 共同重合（已按原文修正）。dedup top 候选（ELF TEXT 段填充寄生、section header 清零、PT_NOTE 转 PT_LOAD）均非同链，dup-scan 无涉及 pair。未在本机编译/执行 PoC；原文未涉及具体产品版本，未设 affected_versions。
url: /docs/code-analysis/reverse/linux/code-analysis-reverse-linux-tiny-elf-45-byte-overlap/
draft: false
kb_aliases:
- Teensy ELF
- 45 字节 ELF
- 最小 ELF 可执行文件
- ELF 头与程序头重叠
- teensy.html
- size coding ELF
- ELF e_phnum 零填充
---

## 一句话结论

Linux 32 位 ELF 装载器只校验 ELF 头与程序头表（phdr）中的少数字段，其余字段（e_version、e_flags、e_ehsize、全部节头字段）可任意复用，且允许 ELF 头与 phdr 相互重叠、缺失文件尾部由内核零填充；据此用 NASM `-f bin` 手写结构，把“退出码 42”的可执行文件从 gcc 编译的约 4KB 压到 45 字节：phdr 从文件偏移 4 起整体嵌入 ELF 头（其字段与 `e_ident` 尾部及 ehdr 中后段重叠），代码与 `e_shoff`/`e_flags`/`p_align` 等被忽略字段重合，文件在第 45 字节的 `e_phnum` 处截断。

## 原理

- **ELF 结构与装载器需求**：ELF32 头 52 字节（`e_ident[16]` + 8 个字段），程序头表项 32 字节。装载器实际只要求：`e_ident` 前 4 字节为 `7F 45 4C 46`、`e_type=2`（可执行）、`e_machine=3`（i386）、`e_entry` 指向代码、`e_phoff` 指向 phdr、`e_phnum` 正确、`e_phentsize=32`；`e_version`、`e_flags`、`e_ehsize` 与节头相关字段（`e_shoff`/`e_shentsize`/`e_shnum`/`e_shstrndx`）要么被忽略，要么对可执行文件无意义。
- **e_ident 尾部可写**：`e_ident` 中 magic 后的 12 字节为未来扩展预留，内核不检查，可作为代码/数据区；因此 7 字节程序可以放进 ELF 头内部。
- **phdr 与 ehdr 可重叠**：ELF 规定各结构可位于文件任意位置（ELF 头必须在文件头），phdr 与 ehdr 的字段可以一段多用：例如 phdr 的 `p_paddr` 与 ehdr 的 `e_type`/`e_machine` 重合（`p_paddr` 被忽略）、`p_filesz`/`p_memsz` 与 `e_version`/`e_entry` 重合、`p_flags` 与 `e_phoff` 重合、`p_align` 与代码及 `e_shoff` 重合。64 字节阶段还通过选择加载地址 `0x200000` 使 `e_phentsize`（0x20）落在 `p_vaddr` 高半部，进一步对齐字段；最终 45B 版则显式写出 `e_phentsize=0x20`。
- **p_flags 可只留 PF_R**：Linux 的 32 位装载器把“可读”与“可执行”视为互相包含，`p_flags=4`（只读）的段仍可执行，省去 PF_X/PF_W 位。
- **p_filesz 可以大于实际文件**：当 `p_memsz > p_filesz` 且段不可写时装载器不能零初始化尾部，会报错；把 `p_filesz` 设成等于 `p_memsz`（两者都远大于文件实际大小）即可绕过，代价只是数值“不诚实”。
- **尾部零填充**：文件不足 ELF 头长度时内核用零补齐缺失字节；最终版本只写到第 45 字节的 `e_phnum`（低字节 0x01），高字节由零填充提供，故 45 字节即可运行。

## 触发条件

- Linux 内核启用 32 位 ELF 兼容（i386 装载路径；64 位内核需 CONFIG_IA32_EMULATION）。
- 文件具备可执行权限，由 `execve` 直接执行（不作为脚本/动态库加载）。
- 内核版本接受这种重叠/截断结构（原文在当时的 Linux 上验证；不同内核版本的校验严格度可能不同）。
- 需要 NASM 的 `-f bin` 平坦二进制输出与手工 ELF 结构，不依赖 gcc/ld 默认布局。

## 利用步骤

1. 基线：C 版 `int main(void){return 42;}` 经 `gcc -s -O3` 约 2.6KB；改用 `_start` 直接系统调用 `exit(42)` 并 `ld -s` 约 368B。
2. 用 NASM `-f bin` 手写最小 ELF：定义 `org 0x08048000`，手写 `ehdr`（无节头表、`e_phnum=1`）与一个 `phdr`（`p_type=1`、`p_offset=0`、`p_vaddr=$$`、`p_filesz=p_memsz=filesize`、`p_flags=5`、`p_align=0x1000`），代码 `mov bl,42; xor eax,eax; inc eax; int 0x80` 放在 `_start`，得到 91 字节。
3. 把 `_start` 移入 `e_ident` 的填充区，使代码与 ELF 头重叠，降到 84 字节。
4. 让 phdr 与 ehdr 尾部 20 字节重叠（`e_phnum` 压到 `p_paddr` 位置、`e_phentsize` 压到 `p_vaddr` 高半部），加载地址改为 `0x200000`，降到 64 字节。
5. 把代码移入 `e_shoff`/`e_flags` 等被忽略字段，`p_flags=4`，`p_filesz=p_memsz=_start`，加载地址降到 `0x10000`，降到 52 字节。
6. 删除文件末尾可被零填充的 7 个零字节，只保留第 45 字节 `e_phnum=0x01`，得到 45 字节 ELF；`chmod +x` 后执行，`echo $?` 返回 42。

## PoC

```nasm
; tiny.asm  —  NASM: nasm -f bin -o a.out tiny.asm && chmod +x a.out
  BITS 32
                org     0x00010000

                db      0x7F, "ELF"             ; e_ident (magic; 后续字节复用为 phdr)
                dd      1                       ; p_type
                dd      0                       ; p_offset
                dd      $$                      ; p_vaddr
                dw      2                       ; e_type        ; p_paddr
                dw      3                       ; e_machine
                dd      _start                  ; e_version     ; p_filesz
                dd      _start                  ; e_entry       ; p_memsz
                dd      4                       ; e_phoff       ; p_flags (PF_R，仍可执行)
  _start:
                mov     bl, 42                  ; e_shoff       ; p_align
                xor     eax, eax
                inc     eax                     ; e_flags
                int     0x80
                db      0
                dw      0x34                    ; e_ehsize
                dw      0x20                    ; e_phentsize
                db      1                       ; e_phnum（高字节由内核零填充）
```

```bash
nasm -f bin -o a.out tiny.asm
chmod +x a.out
./a.out ; echo $?    # 42
wc -c a.out          # 45
```

## 变体与关联

- 变体：把退出码/程序逻辑换成任意 7 字节级代码（如 `write` 输出、打开文件），但会增大体积；也可把代码继续塞进其他被忽略字段。
- 变体：x86-64 版 ELF 头为 64 字节、字段更宽且校验更严，达到同等极致的重叠更困难，通常以 80-120B 为目标。
- 关联：[[code-analysis-reverse-linux-elf-section-header-zeroing]]（同样利用“节头表对执行非必需”）、[[code-analysis-reverse-linux-elf-pt-note-to-load-injection]]（利用 phdr 改写做注入）、[[binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging]]（体积受限 payload 的另一方向：把 shellcode 压到 10 字节）。
- 边界：这是 ELF 格式/装载器行为的尺寸优化技术，本身不是漏洞或攻击链；不同内核/架构对 `e_phentsize`、`p_align`、重叠字段的校验不同，跨内核版本需重测。原文提到 2024 BraekerCTF 二进制题采用了该文的考点。

## 检测与防御

- 检测：文件大小异常小（<64B）却带 ELF magic 的可执行文件；`e_phoff` 落在 ELF 头内部、phdr 与 ehdr 字段区间重叠、代码位于 `e_ident` 保留区、`e_shoff=0` 且无节头表；`readelf -h/-l` 报字段矛盾但内核仍可执行。
- 防御：对可执行文件做大小/结构完整性基线（如最小合法 ELF 尺寸、ehdr/phdr 不重叠校验）；用 IMA/签名校验与允许列表阻止未签名可执行；用 seccomp/audit 监控异常 `execve`；在 CTF/逆向场景中则作为 ELF 格式与装载器行为的练习样本。
