---
title: 栈利用
weight: 1
---

# 栈利用

## 这层是什么

栈溢出、ROP、ret2libc、SROP。

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
| [2 字节稀疏写栈溢出：改写 max_units/write_index 维持循环并两阶段 ret2libc](binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc/) | verified | high | 2026-11-05 |
| [32 位 Partial RELRO 伪造 reloc_arg 与动态符号结构 ret2dlresolve](binary-pwn-stack-ret2dlresolve-partial-relro-32-fake-reloc/) | verified | high | 2026-11-05 |
| [32 位 PIE 无限堆分配占位 + TLS 栈溢出覆写 SSL 结构体函数指针](binary-pwn-stack-tls-ssl-struct-overwrite-32bit-pie-heap-spray/) | verified | medium | 2026-11-06 |
| [32 位 ret2syscall：用 pop 链布置 execve 系统调用](binary-pwn-stack-ret2syscall-32bit/) | verified | high | 2026-11-05 |
| [32 位 SROP：read 返回值置 eax=0x77，伪造 sigreturn frame 执行 execve("/bin/sh")](binary-pwn-stack-32bit-srop-read-return-sigreturn/) | verified | medium | 2026-11-06 |
| [32 位受限字符栈溢出 + 堆喷 + pop ebp;cld;leave;ret 栈迁移：仅用 0x30/0x31/0x0a 字节构造 ROP 绕过 ASLR](binary-pwn-stack-restricted-char-overflow-heap-spray-pivot-32bit/) | verified | medium | 2026-11-06 |
| [64 位 Partial RELRO 伪造 link_map 实施 ret2dlresolve](binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-linkmap/) | verified | medium | 2026-11-05 |
| [64 位 Partial RELRO 伪造 reloc_arg 与 Elf64_Sym/Rela 结构 ret2dlresolve](binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc/) | verified | high | 2026-11-05 |
| [64 位 ret2syscall：静态链接无 /bin/sh 时先 read 写入 BSS 再 execve](binary-pwn-stack-ret2syscall-64bit-bss-binsh-execve/) | verified | high | 2026-11-06 |
| [64 位受控 heap_backup 指针 + memcpy 写栈：environ 泄露、空字节整形 ROP 与 seccomp ORW](binary-pwn-stack-controlled-pointer-memcpy-environ-orw/) | verified | medium | 2026-11-06 |
| [64 位字符串拷贝溢出改写相邻 heap_backup 指针：两阶段任意 8 字节写覆写 free_hook 为 system](binary-pwn-stack-string-overflow-adjacent-heap-backup-freehook/) | verified | medium | 2026-11-06 |
| [abs(INT_MIN) 负数取模绕过长度检查：0x30 栈缓冲区被 read 到 0xe0 字节](binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow/) | verified | medium | 2026-11-06 |
| [Canary 低字节 NUL 覆盖泄露：溢出 1 字节让 puts/%s 带出剩余 7 字节，左移 8 位还原后二次溢出 ROP](binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak/) | verified | high | 2026-11-06 |
| [CISCN 2024 gostack：Go 栈溢出保留 convT 字符串指针的 read+execve ROP](binary-pwn-stack-go-gostack-convt-pointer-rop/) | verified | medium | 2026-11-06 |
| [cJSON 转义注入任意字节实现栈溢出与返回地址部分覆盖](binary-pwn-stack-cjson-unicode-byte-injection-partial-overwrite/) | verified | high | 2026-11-05 |
| [DIR-505 my_cgi.cgi CONTENT_LENGTH 解析栈溢出：mipseb ROP 调 system 执行命令](binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop/) | verified | high | 2026-11-06 |
| [DIR-815 hedwig.cgi Cookie uid 栈溢出：MIPS ROP 绕过 system 空字节执行命令](binary-pwn-stack-mips-hedwig-cgi-uid-rop/) | verified | high | 2026-11-06 |
| [fork 子进程共享 canary：逐字节爆破栈保护值绕过栈溢出](binary-pwn-stack-fork-canary-bytewise-bruteforce/) | verified | high | 2026-11-06 |
| [Go 二进制栈溢出与 ROP：栈帧偏移探测、defer 干扰与 syscall gadget 链](binary-pwn-stack-go-stack-overflow-rop/) | verified | medium | 2026-11-06 |
| [IoT httpd 多阶段链：自定义 S-box AES 登录绕过 + 负索引泄露 + YCB2025 标记触发栈溢出 ORW](binary-pwn-stack-iot-httpd-custom-aes-negative-index-marker-overflow-orw/) | verified | medium | 2026-11-06 |
| [Ivanti Connect Secure CVE-2025-0282：clientCapabilities 栈溢出覆盖 this 指针劫持虚表调用 ROP](binary-pwn-stack-ivanti-cve-2025-0282-clientcapabilities-vtable-rop/) | verified | medium | 2026-11-06 |
| [minihttpd POST /setmode 值拷贝栈溢出：recv 二阶段写 BSS + 调内置 getflag 读 /flag](binary-pwn-stack-minihttpd-setmode-overflow-ret2getflag/) | verified | medium | 2026-11-06 |
| [mprotect 将 bss 页改为 RWX 后的 ret2shellcode：短 shellcode 写入全局缓冲区再覆盖返回地址](binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page/) | verified | high | 2026-11-06 |
| [NIK Router CGI 组合链：凭据解密 + snprintf 目录截断读 rootkey + 共享内存字符逃逸 + ARM 栈溢出 ROP](binary-pwn-stack-nik-router-cgi-shm-negative-len-arm-rop/) | verified | high | 2026-11-06 |
| [No RELRO 改写 .dynamic 的 DT_STRTAB 实施 ret2dlresolve](binary-pwn-stack-ret2dlresolve-no-relro-dystrtab/) | verified | high | 2026-11-05 |
| [ret2hellor：无 pop rdi 时借 deregister_tm_clones + mov rdi,rax;call puts 泄露 libc，并用 BSS 多段迁移构造 ORW/system 链](binary-pwn-stack-ret2hellor-deregister-tm-clones-bss-migration/) | verified | medium | 2026-11-06 |
| [ret2libc 无 /bin/sh 字符串：先用 gets@plt 写入 bss 再 system@plt 两阶段链](binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage/) | verified | high | 2026-11-06 |
| [ret2libc 绕过 NX](ret2libc/) | draft | high | 2026-11-04 |
| [ret2text：栈溢出跳后门函数及 win+1 栈对齐修正](binary-pwn-stack-ret2text-win-plus-one-align/) | verified | medium | 2026-11-05 |
| [robust_list offset 可控：线程退出把任意地址写成 FUTEX_OWNER_DIED，放大 BSS 长度字段后泄露 canary/libc](binary-pwn-stack-robust-list-offset-futex-owner-died-arbitrary-write/) | verified | high | 2026-11-06 |
| [seccomp ORW 下的自定义 RBP 栈帧校验绕过与栈迁移](binary-pwn-stack-fake-rbp-check-seccomp-orw/) | verified | high | 2026-11-05 |
| [SIGSEGV + sigaltstack 的 ucontext 劫持：伪造 rt_sigreturn 帧调用 system](binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack/) | verified | high | 2026-11-05 |
| [snprintf 返回值当 read 长度：格式化截断后仍按“应写长度”读入导致栈溢出](binary-pwn-stack-snprintf-return-length-read-overflow/) | verified | high | 2026-11-05 |
| [strcmp 空字节截断绕过登录 + 覆盖局部指针回填堆地址的 ret2backdoor](binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text/) | verified | high | 2026-11-05 |
| [TLV 协议长度低字节检查绕过：16 位 memcpy 栈溢出 + 隐藏遥测泄露 libc](binary-pwn-stack-tlv-length-low-byte-check-memcpy-overflow/) | verified | high | 2026-11-06 |
| [unordered_map 单桶 bucket_size 无界复制栈溢出：键模数控制同桶并强制 13→29 扩容](binary-pwn-stack-unordered-map-bucket-copy-stack-overflow/) | verified | high | 2026-11-06 |
| [仅 gets 栈溢出 + 伪造 link_map ret2dlresolve：跳过 PLT0 push 传假 link_map，ret2gets 复用 rdi 传 /bin/sh](binary-pwn-stack-gets-only-ret2dlresolve-fake-linkmap-ret2gets/) | verified | medium | 2026-11-06 |
| [多线程 HTTP 服务跨连接共享 BSS：一条连接写入 /flag 并保活，另一条连接复用完成 ROP 读文件](binary-pwn-stack-multithread-http-cross-connection-bss-reuse/) | verified | medium | 2026-11-06 |
| [无 PIE/无 Canary 的 read 栈溢出：本地 root 服务经 SSH/Chisel 隧道 ret2plt system('sh')](binary-pwn-stack-ret2plt-system-sh-local-root-service/) | verified | high | 2026-11-06 |
| [无输出函数 + 0x20 短读的 BSS 栈迁移：借 _libc_start_main 内 write gadget 泄 libc 并反复 _start 分块写 ORW](binary-pwn-stack-bss-pivot-write-gadget-chunked-orw/) | verified | high | 2026-11-06 |
| [栈溢出后用可控 rbp 逐轮任意写：GOT 改写 read→write 泄露 libc、_dl_runtime_resolve 重解析恢复 read、0x30 分块 ROP 完成 seccomp ORW](binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop/) | verified | high | 2026-11-06 |
| [栈迁移（leave; ret）：把栈切到 BSS 上的预置 ROP 链](binary-pwn-stack-pivot-leave-ret-bss/) | verified | high | 2026-11-05 |
| [线程 TLS stack_guard 覆盖绕过栈 Canary：保留 tcbhead 关键字段后 ROP](binary-pwn-stack-tls-stack-guard-overwrite-canary-rop/) | verified | high | 2026-11-06 |
| [自制 HTTP 服务 URL 解码栈溢出：%p 泄露栈地址 + URI 编码 shellcode](binary-pwn-stack-http-uri-unescape-overflow-stack-leak-shellcode/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
