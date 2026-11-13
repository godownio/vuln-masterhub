# ROP

## 这层是什么

ROP/JOP/COP、gadget 与链构造。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AArch64 ret2csu（x22→x0 参数映射变体）：main 结尾弹栈落到 csu，三段调用 write 泄 libc → read 写 BSS → system](binary-pwn-rop-aarch64-ret2csu-register-mapping-ret2libc.md) | verified | high | 2026-11-13 |
| [AArch64 ret2csu：借 __libc_csu_init 的 LDP 装载 x19-x24 控制 x0-x3 调 mprotect 后跳 BSS shellcode](binary-pwn-rop-aarch64-ret2csu-mprotect-shellcode.md) | verified | high | 2026-11-12 |
| [ARM32 ret2csu：__libc_csu_init 的 mov r2,sb/mov r1,r8/mov r0,r7 + blx r3 循环 gadget，连续三参调用 write/read/system](binary-pwn-rop-arm32-ret2csu-csu-init-loop-gadget.md) | verified | medium | 2026-11-13 |
| [ARM32 无直控 r0 gadget 时的两段式组合：pop {r4-r10,pc} 设 r7、pop {r3,pc} 设 r3，再由 mov r0,r7; blx r3 完成 call func(arg1) 并继续 ROP](binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3.md) | verified | medium | 2026-11-09 |
| [ARM32 静态去符号程序 ret2libc：用 Rizzo 恢复符号定位 system/bin/sh，再以 pop {r0,r4,pc} 供参跳转](binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static.md) | verified | medium | 2026-11-09 |
| [BROP 盲打：无源码/二进制时逐字节探测 stop gadget 与 pop rdi，dump plt 定位 libc 拿 shell](binary-pwn-rop-brop-blind-stop-gadget-plt-dump-libc.md) | verified | high | 2026-11-13 |
| [fini_array 循环复用任意写 + leave_ret 栈迁移：静态无符号二进制在退出链上布置 execve ROP](binary-pwn-fini-array-loop-leave-ret-pivot-rop.md) | verified | high | 2026-11-12 |
| [flag 文件名未知时不靠 shell：ROP 用 read 把路径写进 bss → open 目录 → getdents64 把 dentry 列表读到 bss → write 输出，纯 syscall 链列出目录](binary-pwn-rop-getdents64-directory-listing-unknown-flag-filename.md) | verified | medium | 2026-11-09 |
| [FULL RELRO 且无输出函数：借程序内指针搬运函数把 read@GOT 复制到 BSS，低位覆盖 read→write 泄露 libc 后 ret2libc](binary-pwn-rop-full-relro-bss-got-pointer-copy-low2-read-to-write-leak.md) | verified | high | 2026-11-13 |
| [Full RELRO 无输出栈题：magic gadget 加写 .bss 中的 stdout 指针合成 libc 输出函数泄露 libc（ret2csu + add [rbp-0x3d], ebx）](binary-pwn-rop-bss-stdout-pointer-magic-gadget-leak-orw.md) | verified | high | 2026-11-13 |
| [Hexagon DSP ROP：trap0 系统调用 gadget + 两级栈迁移读取 /flag](binary-pwn-rop-hexagon-dsp-trap0-two-stage-pivot.md) | verified | high | 2026-11-06 |
| [MIPS mipsrop 控制 $fp/$a2 跳栈上 shellcode：addiu $a2,$sp,0x58; jalr $fp 接 move $t9,$a2; jalr $a2](binary-pwn-rop-mips-fp-a2-gadget-stack-shellcode.md) | verified | high | 2026-11-12 |
| [MIPS ret2csu：__libc_csu_init 的 s0-s5 装载与 a0-a2 布置 gadget](binary-pwn-rop-mips-ret2csu-libc-csu-init.md) | verified | high | 2026-11-07 |
| [MIPS ROP 构造字符串到 .bss：sw 任意写、badchar XOR 解码与 fluff 寄存器交换](binary-pwn-rop-mips-bss-string-write-badchars-xor.md) | verified | high | 2026-11-07 |
| [MIPS 栈迁移 + GOT 泄露：pivot 到可控堆缓冲区并计算 libpivot 中 ret2win 偏移](binary-pwn-rop-mips-pivot-got-libpivot-ret2win.md) | verified | high | 2026-11-07 |
| [MIPS32 ROP 基础：fp+4 返回地址定位、t9/ra 跳转与 s0-s7 参数 gadget（ret2win/split/callme）](binary-pwn-rop-mips32-stack-frame-gadget-args.md) | verified | high | 2026-11-07 |
| [MIPS32 栈上 shellcode 的 I/D cache 同步：ROP 调 sleep 后跳转，兼 qemu-user 下 system() fork 失败](binary-pwn-rop-mips32-shellcode-cache-coherence-sleep.md) | verified | high | 2026-11-07 |
| [netatalk CVE-2022-23121：AppleDouble 元数据 ADEID_FINDERI/RFORK 偏移未校验导致 mmap 相对写与栈泄露 → GOT 劫持 ROP 以 root 执行 afprun_bg](binary-pwn-rop-netatalk-cve-2022-23121-appledouble-metadata-oob-got-afprun.md) | verified | high | 2026-11-10 |
| [NX 且 gadget 不足时用 ROP 调 mprotect 再 jmp rsp 切换执行 shellcode](rop-mprotect-jmprsp-shellcode-transition.md) | draft | high | 2026-11-08 |
| [PowerPC 32-bit 大端间接调用劫持：写 40 字节偏移处的函数指针，用 addi r9,r31,0x1C + mr r3,r9 把 /bin/sh 喂给 system](binary-pwn-rop-powerpc32-indirect-call-hijack-register-arg.md) | verified | medium | 2026-11-09 |
| [ret2csu 写 /bin/sh 到 bss：libc 符号偏移正确但字符串偏移不一致时的栈溢出利用](binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch.md) | verified | high | 2026-11-05 |
| [ROP 调 mprotect 把 bss 改 RWX 再 read 写入 shellcode：无程序内 mprotect 时的 NX 绕过](binary-pwn-rop-mprotect-bss-rwx-read-shellcode.md) | verified | high | 2026-11-13 |
| [system("$0") 绕过 sh 关键字过滤：借 argv[0] 拉起 shell](binary-pwn-rop-system-dollar0-bypass-sh-filter.md) | verified | high | 2026-11-06 |
| [Thumb2 的 ldm.w gadget 是 ROP 工具盲区：ROPgadget 需 --align 2 才能检出，ropper/xrop 直接漏报](binary-pwn-rop-thumb2-ldm-gadget-tool-blindspot.md) | verified | high | 2026-11-11 |
| [无 libc 泄露 + seccomp 禁 execve：magic gadget（add [rbp-0x3d], ebx）配合 CSU 写 BSS 伪造参数，调用 fopen/fread/send 读 flag](binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak.md) | verified | high | 2026-11-06 |
| [无 libc 泄露的 seccomp ORW：单字节改写 alarm@GOT 指向 alarm+9 的 syscall，ret2csu 设 rdx 调 open/read/write](binary-pwn-rop-alarm-got-syscall-ret2csu-orw.md) | verified | medium | 2026-11-07 |
| [无 pop rdx 的 ORW 第三参数：用 mov dl, imm; ret 设置 rdx 低字节](binary-pwn-rop-mov-dl-imm-set-rdx-lowbyte.md) | verified | high | 2026-11-06 |
| [栈溢出 ROP：借 mov %rsp,%rdi + jmp *%r13 的自定义函数调用 system](binary-pwn-rop-mov-rsp-rdi-jmp-r13-system.md) | verified | high | 2026-11-05 |
| [缺 pop rdx 时的 ret2csu：借 __libc_csu_init 两段 gadget 调 write(1, GOT, n) 泄 libc 再二次溢出拿 shell](binary-pwn-rop-ret2csu-write-got-leak-ret2libc.md) | verified | high | 2026-11-12 |
| [静态链接无 PIE 栈溢出：用二进制内置 system 与 /bin/sh 直接 ROP](binary-pwn-rop-static-link-ret2system-sh.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
