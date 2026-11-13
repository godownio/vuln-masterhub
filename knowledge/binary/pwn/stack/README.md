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
| [0x10 溢出 + 未截断 printf 泄漏 saved rbp：leave;ret 迁回栈缓冲区分段 ROP，seccomp ORW 读 flag](binary-pwn-stack-0x10-overflow-printf-rbp-leak-leave-ret-orw.md) | verified | high | 2026-11-09 |
| [0x10 短溢出 + 两轮 read 接力调整 rsp 迁 BSS：ret2libc 泄 libc 接 one_gadget，或 seccomp 下分两段 ORW](binary-pwn-stack-0x10-two-round-read-relay-bss-pivot.md) | verified | high | 2026-11-13 |
| [0x10 短溢出经 BSS 栈迁移串联三段 SROP ORW：区分 syscall 包装器与裸 syscall 指令的传参布局](binary-pwn-stack-short-overflow-bss-pivot-3stage-srop-orw-syscall-wrapper.md) | verified | high | 2026-11-12 |
| [2 字节稀疏写栈溢出：改写 max_units/write_index 维持循环并两阶段 ret2libc](binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc.md) | verified | high | 2026-11-05 |
| [32 位 gets 栈溢出 ret2win：0x14+4 字节填充覆盖 EIP 直跳 system("/bin/sh") 后门](binary-pwn-stack-32bit-gets-ret2win-backdoor.md) | verified | high | 2026-11-11 |
| [32 位 Partial RELRO 伪造 reloc_arg 与动态符号结构 ret2dlresolve](binary-pwn-stack-ret2dlresolve-partial-relro-32-fake-reloc.md) | verified | high | 2026-11-05 |
| [32 位 PIE 无限堆分配占位 + TLS 栈溢出覆写 SSL 结构体函数指针](binary-pwn-stack-tls-ssl-struct-overwrite-32bit-pie-heap-spray.md) | verified | medium | 2026-11-06 |
| [32 位 ret2libc GOT 三连泄露：puts@plt 泄 puts/gets/setvbuf、按低 12 位定 libc 版本、返回 main 二次溢出 system('/bin/sh')](binary-pwn-stack-ret2libc-32bit-got-leak-libc-version-second-stage.md) | verified | high | 2026-11-09 |
| [32 位 ret2syscall：用 pop 链布置 execve 系统调用](binary-pwn-stack-ret2syscall-32bit.md) | verified | high | 2026-11-05 |
| [32 位 SROP：read 返回值置 eax=0x77，伪造 sigreturn frame 执行 execve("/bin/sh")](binary-pwn-stack-32bit-srop-read-return-sigreturn.md) | verified | medium | 2026-11-06 |
| [32 位受限字符栈溢出 + 堆喷 + pop ebp;cld;leave;ret 栈迁移：仅用 0x30/0x31/0x0a 字节构造 ROP 绕过 ASLR](binary-pwn-stack-restricted-char-overflow-heap-spray-pivot-32bit.md) | verified | medium | 2026-11-06 |
| [64 位 Partial RELRO 伪造 link_map 实施 ret2dlresolve](binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-linkmap.md) | verified | medium | 2026-11-05 |
| [64 位 Partial RELRO 伪造 reloc_arg 与 Elf64_Sym/Rela 结构 ret2dlresolve](binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc.md) | verified | high | 2026-11-05 |
| [64 位 ret2syscall：静态链接无 /bin/sh 时先 read 写入 BSS 再 execve](binary-pwn-stack-ret2syscall-64bit-bss-binsh-execve.md) | verified | high | 2026-11-06 |
| [64 位 strcpy 栈溢出因 NUL 截断只能覆盖低 4 字节 RIP：借同段 call rsp gadget 跳 shellcode](binary-pwn-stack-strcpy-nul-truncated-partial-rip-call-rsp.md) | verified | high | 2026-11-12 |
| [64 位受控 heap_backup 指针 + memcpy 写栈：environ 泄露、空字节整形 ROP 与 seccomp ORW](binary-pwn-stack-controlled-pointer-memcpy-environ-orw.md) | verified | medium | 2026-11-06 |
| [64 位字符串拷贝溢出改写相邻 heap_backup 指针：两阶段任意 8 字节写覆写 free_hook 为 system](binary-pwn-stack-string-overflow-adjacent-heap-backup-freehook.md) | verified | medium | 2026-11-06 |
| [abs(INT_MIN) 负数取模绕过长度检查：0x30 栈缓冲区被 read 到 0xe0 字节](binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow.md) | verified | medium | 2026-11-06 |
| [ARM32 栈溢出 ret2win：0x24 填充覆盖保存的 LR，直跳后门函数 getshell/读 flag](binary-pwn-stack-arm32-ret2win-backdoor-qemu.md) | verified | high | 2026-11-12 |
| [C++ 异常展开伪造调用帧：把返回地址改成 catch landing pad 跳过 canary 校验并 ROP](binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass.md) | verified | high | 2026-11-08 |
| [C++ 栈上容器 push 超容量越界：edit 只用对象内「容量」字段做边界，覆写容量后获得 32 位粒度栈读写，泄 libc 后按槽写 ROP](binary-pwn-stack-cpp-stack-vector-capacity-overwrite-32bit-word-write-rop.md) | verified | medium | 2026-11-08 |
| [Canary 低字节 NUL 覆盖泄露：溢出 1 字节让 puts/%s 带出剩余 7 字节，左移 8 位还原后二次溢出 ROP](binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak.md) | verified | high | 2026-11-06 |
| [CHOP 异常利用：改写返回地址进 __cxa_call_unexpected try 块，借 .eh_frame CFI 从栈恢复 r12 指向后门再由 __terminate 调用](binary-pwn-stack-chop-cxa-call-unexpected-golden-gadget.md) | verified | high | 2026-11-13 |
| [CISCN 2024 gostack：Go 栈溢出保留 convT 字符串指针的 read+execve ROP](binary-pwn-stack-go-gostack-convt-pointer-rop.md) | verified | medium | 2026-11-06 |
| [cJSON 转义注入任意字节实现栈溢出与返回地址部分覆盖](binary-pwn-stack-cjson-unicode-byte-injection-partial-overwrite.md) | verified | high | 2026-11-05 |
| [close(1) 关闭 stdout 的盲态栈溢出：write(fd2,got) 泄露 libc 后 system("/bin/sh") 再 exec 1>&0 恢复输出](binary-pwn-stack-close-stdout-blind-ret2libc-fd-restore.md) | verified | high | 2026-11-08 |
| [DIR-505 my_cgi.cgi CONTENT_LENGTH 解析栈溢出：mipseb ROP 调 system 执行命令](binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop.md) | verified | high | 2026-11-06 |
| [DIR-815 hedwig.cgi Cookie uid 栈溢出：MIPS ROP 绕过 system 空字节执行命令](binary-pwn-stack-mips-hedwig-cgi-uid-rop.md) | verified | high | 2026-11-06 |
| [fork 共享 PIE 基址逐页爆破：p16 部分覆盖返回地址低 2 字节，16 次尝试命中后门所在页](binary-pwn-stack-pie-page-bruteforce-fork-partial-overwrite.md) | verified | high | 2026-11-12 |
| [fork 子进程共享 canary：逐字节爆破栈保护值绕过栈溢出](binary-pwn-stack-fork-canary-bytewise-bruteforce.md) | verified | high | 2026-11-06 |
| [Go gRPC 服务端的 pwn：用 pbtk 从二进制还原 .proto 重建客户端，再打 base64 解码缺少长度校验的固定栈缓冲区，ROP ORW 把 flag 写到连接 fd](binary-pwn-stack-grpc-go-protobuf-extract-base64-fixed-buffer-orw.md) | verified | medium | 2026-11-09 |
| [Go 二进制栈溢出与 ROP：栈帧偏移探测、defer 干扰与 syscall gadget 链](binary-pwn-stack-go-stack-overflow-rop.md) | verified | medium | 2026-11-06 |
| [Hexagon 架构栈溢出（qemu-hexagon 无 ASLR）：改写 FP 触发 dealloc_return 栈迁移，用 r0=memw(fp-8) gadget 给 system 传参](binary-pwn-stack-hexagon-qemu-fp-pivot-dealloc-return.md) | verified | medium | 2026-11-08 |
| [IoT httpd 多阶段链：自定义 S-box AES 登录绕过 + 负索引泄露 + YCB2025 标记触发栈溢出 ORW](binary-pwn-stack-iot-httpd-custom-aes-negative-index-marker-overflow-orw.md) | verified | medium | 2026-11-06 |
| [Ivanti Connect Secure CVE-2025-0282：clientCapabilities 栈溢出覆盖 this 指针劫持虚表调用 ROP](binary-pwn-stack-ivanti-cve-2025-0282-clientcapabilities-vtable-rop.md) | verified | medium | 2026-11-06 |
| [minihttpd POST /setmode 值拷贝栈溢出：recv 二阶段写 BSS + 调内置 getflag 读 /flag](binary-pwn-stack-minihttpd-setmode-overflow-ret2getflag.md) | verified | medium | 2026-11-06 |
| [MIPS SROP：sigreturn(v0=4119) 栈迁移到 .bss + execve 两阶段利用](binary-pwn-stack-mips-srop-sigreturn-bss-execve.md) | verified | high | 2026-11-07 |
| [MIPS 栈地址泄露 + 长度变量篡改扩大 read：ret2shellcode 在栈上执行 execve](binary-pwn-stack-mips-stack-leak-length-tamper-ret2shellcode.md) | verified | medium | 2026-11-12 |
| [mprotect 将 bss 页改为 RWX 后的 ret2shellcode：短 shellcode 写入全局缓冲区再覆盖返回地址](binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page.md) | verified | high | 2026-11-06 |
| [NIK Router CGI 组合链：凭据解密 + snprintf 目录截断读 rootkey + 共享内存字符逃逸 + ARM 栈溢出 ROP](binary-pwn-stack-nik-router-cgi-shm-negative-len-arm-rop.md) | verified | high | 2026-11-06 |
| [No RELRO 改写 .dynamic 的 DT_STRTAB 实施 ret2dlresolve](binary-pwn-stack-ret2dlresolve-no-relro-dystrtab.md) | verified | high | 2026-11-05 |
| [PHP 扩展 lverifier.so 用户名栈溢出：固定 800 拷贝 + SHORT_USERNAME_LEN 16 位截断，写入 root docroot 的 PHP WebShell](binary-pwn-stack-php-extension-lverifier-username-overflow-root-webshell.md) | verified | medium | 2026-11-08 |
| [PIE partial write 绕过：覆盖返回地址低 2 字节跳同页后门，第 4 个 nibble 未知按 1/16 概率重连爆破](binary-pwn-stack-pie-partial-overwrite-low2-bytes-1-in-16-brute.md) | verified | high | 2026-11-13 |
| [PIE 基址泄露：puts 越界打印栈上 __libc_csu_init 返回地址并读 6 字节还原 elf.address](binary-pwn-stack-pie-base-leak-csu-init-return-address.md) | verified | high | 2026-11-08 |
| [ret2gets 泄露 libc：gets 返回后 rdi 残留 _IO_stdfile_0_lock，覆盖 cnt 绕过 NUL 截断由 puts 打印 owner 中的 TLS 指针](binary-pwn-stack-ret2gets-stdfile-lock-tls-leak.md) | verified | high | 2026-11-08 |
| [ret2hellor：无 pop rdi 时借 deregister_tm_clones + mov rdi,rax;call puts 泄露 libc，并用 BSS 多段迁移构造 ORW/system 链](binary-pwn-stack-ret2hellor-deregister-tm-clones-bss-migration.md) | verified | medium | 2026-11-06 |
| [ret2libc 无 /bin/sh 字符串：先用 gets@plt 写入 bss 再 system@plt 两阶段链](binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage.md) | verified | high | 2026-11-06 |
| [ret2libc 绕过 NX](ret2libc.md) | draft | high | 2026-11-04 |
| [ret2reg：溢出返回时 eax 指向可控缓冲区，EIP 改为 call eax 执行栈上 shellcode](binary-pwn-stack-ret2reg-call-eax-stack-shellcode.md) | verified | high | 2026-11-13 |
| [ret2text：栈溢出跳后门函数及 win+1 栈对齐修正](binary-pwn-stack-ret2text-win-plus-one-align.md) | verified | medium | 2026-11-05 |
| [robust_list offset 可控：线程退出把任意地址写成 FUTEX_OWNER_DIED，放大 BSS 长度字段后泄露 canary/libc](binary-pwn-stack-robust-list-offset-futex-owner-died-arbitrary-write.md) | verified | high | 2026-11-06 |
| [RouterOS SMB NetBIOS 名字解析未授权栈溢出：64 字节覆盖 EIP，借固定地址 vdso 的 int 0x80 走 ret2syscall](binary-pwn-stack-mikrotik-routeros-smb-netbios-cve-2018-7445-vdso-ret2syscall.md) | verified | high | 2026-11-08 |
| [seccomp ORW 下的自定义 RBP 栈帧校验绕过与栈迁移](binary-pwn-stack-fake-rbp-check-seccomp-orw.md) | verified | high | 2026-11-05 |
| [seccomp 禁 open/execve 时的 64 位 SROP 链：mprotect 改 bss 为 RWX 后执行 openat ORW shellcode](binary-pwn-stack-srop-mprotect-openat-shellcode-seccomp.md) | verified | medium | 2026-11-07 |
| [SIGSEGV + sigaltstack 的 ucontext 劫持：伪造 rt_sigreturn 帧调用 system](binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack.md) | verified | high | 2026-11-05 |
| [snprintf 返回值当 read 长度：格式化截断后仍按“应写长度”读入导致栈溢出](binary-pwn-stack-snprintf-return-length-read-overflow.md) | verified | high | 2026-11-05 |
| [SSP Leak：溢出改写栈上 argv[0] 指针，借 __stack_chk_fail→__fortify_fail 打印实现任意地址读](binary-pwn-stack-ssp-leak-argv0-arbitrary-read.md) | verified | high | 2026-11-13 |
| [stb_image PIC 噪声数组越界写相邻栈变量：构造 PIC 像素把 privilege 改成 0x1337](binary-pwn-stack-stb-image-pic-noise-offbyone-adjacent-variable.md) | verified | high | 2026-11-07 |
| [strcmp 空字节截断绕过登录 + 覆盖局部指针回填堆地址的 ret2backdoor](binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text.md) | verified | high | 2026-11-05 |
| [strncmp 用 strlen(NUL 截断) 作比较长度绕过随机数校验，返回 buf[7]=0xff 经 char 转负放大 read 长度溢出 231 缓冲区 ret2libc](binary-pwn-stack-strncmp-nullbypass-buf7-length-read-overflow-ret2libc.md) | verified | high | 2026-11-13 |
| [Synology BC500 摄像头 libjansson parse_object 的 sscanf("%s %s") 栈溢出：未授权 JSON key 打穿 v9/v10，ARM32 gadget 执行 $HTTP_A 命令](binary-pwn-stack-synology-bc500-jansson-parse-object-sscanf-overflow.md) | verified | high | 2026-11-11 |
| [TEEgris KEYMST 可信小程序 RSA 公钥指数栈溢出：pub_exp_size 可控泄到 0x1f8 字节，qiling 构造输入后在安全世界 ROP](binary-pwn-stack-teegris-keymst-rsa-pubexp-overflow-secure-world-rop.md) | verified | high | 2026-11-11 |
| [Tenda AC15 httpd R7WebsSecurityHandler 的 Cookie password 经无宽度 sscanf 溢出：非黑名单 URI + .png 后缀过扩展名检查，ARM uClibc ret2libc 劫持控制流](binary-pwn-stack-tenda-ac15-r7webssecurityhandler-cookie-password-sscanf-arm-rop.md) | verified | high | 2026-11-13 |
| [Tenda AC15 httpd SetFirewallCfg firewallEn strcpy 栈溢出：ARM 偏移 52 + ret2libc 构造 system 命令执行（CVE-2023-27021）](binary-pwn-stack-tenda-ac15-setfirewallcfg-firewallen-strcpy-arm-rop.md) | verified | high | 2026-11-12 |
| [Tenda AC15 httpd setMacFilterCfg deviceList strcpy 栈溢出：ARM ROP 调 system（CVE-2018-18708）](binary-pwn-stack-tenda-ac15-setmacfiltercfg-devicelist-strcpy-arm-rop.md) | verified | high | 2026-11-07 |
| [TLV 协议长度低字节检查绕过：16 位 memcpy 栈溢出 + 隐藏遥测泄露 libc](binary-pwn-stack-tlv-length-low-byte-check-memcpy-overflow.md) | verified | high | 2026-11-06 |
| [unordered_map 单桶 bucket_size 无界复制栈溢出：键模数控制同桶并强制 13→29 扩容](binary-pwn-stack-unordered-map-bucket-copy-stack-overflow.md) | verified | high | 2026-11-06 |
| [Vivotek CC8160 httpd upgrade.cgi Content-Length 差值 strncpy 栈溢出：ARM 32 位偏移 52 + pop{r1,pc}/mov r0,r1 调 system 反弹 shell](binary-pwn-stack-vivotek-cc8160-upgrade-cgi-content-length-strncpy-arm-rop.md) | verified | high | 2026-11-08 |
| [Windows /GS 双写绕过：任意 4 字节写同时改 .data 中的 Cookie 种子与栈上 canary，让校验等式成立](binary-pwn-stack-win-gs-dotdata-cookie-replace-bypass.md) | verified | low | 2026-11-11 |
| [Windows /GS 虚函数绕过：溢出改写栈上 this 指针，虚调用在 canary 校验前 call 到缓冲区 shellcode](binary-pwn-stack-win-gs-vtable-overwrite-bypass.md) | verified | medium | 2026-11-11 |
| [Windows 32 位 ASLR 部分地址覆盖绕过：仅覆写返回地址低 2 字节跳到固定偏移 jmp eax](binary-pwn-stack-win32-aslr-partial-overwrite-jmp-eax.md) | verified | high | 2026-11-11 |
| [Windows DEP 绕过：Ret2Libc 调 VirtualProtect/VirtualAlloc 恢复页执行并跳入 shellcode](binary-pwn-stack-win-dep-ret2libc-virtualprotect-bypass.md) | verified | medium | 2026-11-11 |
| [Windows x64 服务栈溢出：movsx 有符号长度检查绕过 + IRETD 运行时构造 CS/SS 跳 shellcode](binary-pwn-stack-win64-movsx-length-iret-segment-shellcode.md) | verified | medium | 2026-11-09 |
| [x86-64 SROP：栈上伪造 rt_sigreturn frame，借 read 返回值置 rax=15 一次恢复全部寄存器执行 execve](binary-pwn-stack-x64-srop-sigreturn-frame-execve.md) | verified | high | 2026-11-08 |
| [仅 gets 栈溢出 + 伪造 link_map ret2dlresolve：跳过 PLT0 push 传假 link_map，ret2gets 复用 rdi 传 /bin/sh](binary-pwn-stack-gets-only-ret2dlresolve-fake-linkmap-ret2gets.md) | verified | medium | 2026-11-06 |
| [任意空字节写入改返回地址低位：栈上 NOP 滑板 + shellcode 劫持](binary-pwn-stack-arbitrary-null-byte-return-redirect-shellcode.md) | verified | high | 2026-11-07 |
| [单字节栈溢出只覆盖返回地址最低字节：把 ret 落到同函数页内的后门 system("/bin/sh")](ctf-pwn-onebyte-ret-overwrite-backdoor-system.md) | verified | high | 2026-11-09 |
| [多线程 HTTP 服务跨连接共享 BSS：一条连接写入 /flag 并保活，另一条连接复用完成 ROP 读文件](binary-pwn-stack-multithread-http-cross-connection-bss-reuse.md) | verified | medium | 2026-11-06 |
| [定长 read 读长大于口令缓冲 + strcmp 在 NUL 处判等：正确口令后接 \0 填充，边过校验边覆盖返回地址跳后门](binary-pwn-stack-strcmp-nullbyte-read-overflow-ret2backdoor.md) | verified | high | 2026-11-09 |
| [异常处理中的 saved RBP 劫持：溢出改写 rbp，handler 尾声 leave;ret 从 [rbp+8] 取返回地址调用任意 GOT 函数](binary-pwn-stack-cpp-exception-rbp-overwrite-handler-leave-ret.md) | verified | high | 2026-11-13 |
| [无 PIE/无 Canary 的 read 栈溢出：本地 root 服务经 SSH/Chisel 隧道 ret2plt system('sh')](binary-pwn-stack-ret2plt-system-sh-local-root-service.md) | verified | high | 2026-11-06 |
| [无栈泄漏两段 SROP：首次 sigreturn 用 read 把 /bin/sh 写入 data 段，借 leave;ret 续链再 execve](binary-pwn-stack-two-stage-srop-read-data-leave-ret-execve.md) | verified | medium | 2026-11-13 |
| [无输出函数 + 0x20 短读的 BSS 栈迁移：借 _libc_start_main 内 write gadget 泄 libc 并反复 _start 分块写 ORW](binary-pwn-stack-bss-pivot-write-gadget-chunked-orw.md) | verified | high | 2026-11-06 |
| [栈上 C++ 对象的虚表指针被溢出改写 + raise() 抛异常走 unwind 跳过 __stack_chk_fail：unique_ptr 析构时的虚调用变成任意代码执行（自定义 canary 也拦不住）](binary-pwn-stack-cpp-unwind-destructor-vtable-hijack-skip-canary.md) | verified | high | 2026-11-09 |
| [栈溢出 + mmap 地址泄露后改用 ld-linux 的 pop rax/ret gadget 完成 execve](binary-pwn-stack-ld-linux-rop-mmap-leak-execve.md) | verified | low | 2026-11-07 |
| [栈溢出后用可控 rbp 逐轮任意写：GOT 改写 read→write 泄露 libc、_dl_runtime_resolve 重解析恢复 read、0x30 分块 ROP 完成 seccomp ORW](binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop.md) | verified | high | 2026-11-06 |
| [栈缓冲区溢出覆盖相邻局部变量绕过判断：改 32 位 int 与 64 位魔数让校验走进 system('/bin/sh') 分支](binary-pwn-stack-adjacent-local-variable-overwrite-check-bypass.md) | verified | high | 2026-11-09 |
| [栈迁移（leave; ret）：把栈切到 BSS 上的预置 ROP 链](binary-pwn-stack-pivot-leave-ret-bss.md) | verified | high | 2026-11-05 |
| [没有 leave;ret 可用来迁移栈时，把 __stack_chk_fail 的 GOT 改成 vuln 内部的 ret，让 Canary 失败路径重新进入漏洞函数打第二轮溢出](binary-pwn-stack-stack-chk-fail-got-reenter-vuln-ret-second-overflow-jmp-rsp.md) | draft | high | 2026-11-08 |
| [登录用户名有长度检查而密码 fgets(800) 无校验写入 48 字节缓冲：登录失败照常返回，覆盖 saved RIP 直跳后门](binary-pwn-stack-login-fgets-unbounded-password-ret2backdoor.md) | verified | high | 2026-11-09 |
| [短读栈迁移：覆盖 saved rbp 后跳回函数内 lea rax,[rbp+buf]，借原 read 把二段 ORW 链读入 BSS 再 leave;ret 迁栈](binary-pwn-stack-lea-rax-rbp-buf-short-read-bss-migration-orw.md) | verified | high | 2026-11-09 |
| [程序自带 syscall(15) 的 SROP：call 压栈使伪造 frame 前移 8 字节，改 rip/rsp 迁移 libc bss 后 ORW](binary-pwn-stack-sigreturn-call-offset8-libc-bss-orw.md) | verified | high | 2026-11-13 |
| [线程 TLS stack_guard 覆盖绕过栈 Canary：保留 tcbhead 关键字段后 ROP](binary-pwn-stack-tls-stack-guard-overwrite-canary-rop.md) | verified | high | 2026-11-06 |
| [线程栈大溢出直达 TLS：用同一填充值同时覆盖栈 Canary 与 tcbhead_t.stack_guard 绕过检查](binary-pwn-stack-thread-large-overflow-tls-stack-guard.md) | verified | high | 2026-11-13 |
| [自制 HTTP 服务 URL 解码栈溢出：%p 泄露栈地址 + URI 编码 shellcode](binary-pwn-stack-http-uri-unescape-overflow-stack-leak-shellcode.md) | verified | medium | 2026-11-05 |
| [自定义长度函数对空串返回 -1 存入 unsigned __int8 变 255：256 字节栈越界拷贝改写 file 变量读 flag](binary-pwn-stack-negative-one-length-uint8-truncation-oob-copy.md) | verified | medium | 2026-11-09 |
| [长度检查变量为 unsigned __int8：strlen(260) 截断成 4 绕过 3-8 限制，strcpy 仍按全量复制溢出栈 ret2text](binary-pwn-stack-uint8-strlen-truncation-length-check-strcpy-ret2text.md) | verified | high | 2026-11-13 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
