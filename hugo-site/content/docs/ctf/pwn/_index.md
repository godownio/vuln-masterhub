---
title: CTF Pwn
weight: 1
---

# CTF Pwn

## 这层是什么

Pwn 题型技巧。

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
| [/proc/self/mem 任意内存写：把文件编辑器变成 .rodata 改写器，篡改硬编码黑名单首字节绕过 /secret.txt 拦截](ctf-pwn-proc-self-mem-rodata-string-patch/) | verified | high | 2026-11-07 |
| [16 位 YOLOOS VM 逃逸：guest 越界写内核栈 + MMIO cache 映射宿主栈 + instruction limit 泄露 PIE](ctf-pwn-yoloos-vm-escape-mmio-cache-instruction-limit/) | verified | high | 2026-11-06 |
| [2025 CISCN easy_rw：proxy 配置覆盖令 RSA d=1 + 哈希 NUL 截断绕过认证，后端 2.31 堆泄露与 backdoor 栈溢出 ORW](ctf-pwn-webpwn-proxy-config-overwrite-heap-leak-backdoor-orw/) | verified | high | 2026-11-06 |
| [AWD 批量利用编排：目标扫描 + 并发加载 exp.py + 结果收集](ctf-pwn-awd-batch-scan-concurrent-exp-runner/) | verified | high | 2026-11-05 |
| [AWD 流量捕获：用 pwn_waf 的 catch 包装替换题目二进制，落盘对手全部 exp 输入](ctf-pwn-awd-pwn-waf-catch-binary-replace-traffic-capture/) | verified | medium | 2026-11-08 |
| [AWD 轮次循环编排：bash 并发计数打靶 + flags 收集归档 + 批量提交计分接口](ctf-pwn-awd-round-loop-flag-collect-submit/) | verified | medium | 2026-11-08 |
| [AWDP fix：UAF 释放点的二进制级补丁（原地压缩 / 弹栈 / jmp）](ctf-pwn-awdp-uaf-free-patch/) | verified | medium | 2026-11-05 |
| [AWDP fix：栈溢出/整数比较/输入长度类漏洞的二进制补丁（push 立即数缩长度、jle→jbe 修符号、.eh_frame 注入 read）](ctf-pwn-awdp-stack-overflow-length-compare-binary-patch/) | verified | medium | 2026-11-08 |
| [AWDP fix：格式化字符串漏洞的二进制级补丁（IDA/KeyPatch 改 printf 调用）](ctf-pwn-awdp-format-string-patch/) | verified | high | 2026-11-05 |
| [Base64 解码功能按「长度/4*3」分配但解码补全可多写 1~3 字节：改下一 chunk size 造 0x80 与 0x40 重叠，unsorted 泄 libc 后打 __free_hook](ctf-pwn-base64-decode-len-rounding-chunk-overlap-freehook/) | verified | medium | 2026-11-08 |
| [blind pwn：负数长度符号绕过泄露栈/canary + debug 泄露 write 地址后 ret2libc](ctf-pwn-blind-negative-length-stack-leak-debug-write-ret2libc/) | verified | medium | 2026-11-07 |
| [C 程序命令注入文件名过滤绕过：fl''ag 引号拼接绕过 strstr(file,"flag")](ctf-pwn-command-injection-filename-shell-quote-bypass/) | verified | high | 2026-11-06 |
| [C++ 异常对象指向可控全局缓冲区：catch 把 __cxa_begin_catch 返回值当命令交给 system](ctf-pwn-cpp-exception-payload-src-system-command/) | verified | medium | 2026-11-08 |
| [CTF Pwn 数值校验绕过：strtod 十六进制浮点与 strtoull 解析差异](ctf-pwn-hexfloat-strtoull-parser-differential/) | verified | high | 2026-11-05 |
| [CTF webpwn 双进程架构：proxy 全局溢出改写 RSA n/d 绕过鉴权 + 后端负索引泄露与栈溢出 ORW](ctf-pwn-webpwn-proxy-rsa-auth-bypass-backend-oob-rop/) | verified | high | 2026-11-06 |
| [ELO 积分负分未截断 + 32 位零扩展入库：sqlite3_bind_int64 把 -1 存成 4294967295 登顶排行榜](ctf-pwn-elo-negative-score-zero-extension-leaderboard/) | verified | high | 2026-11-06 |
| [encrypt 白名单正则 vs run 只校验首命令 + shell=True：用泄露密钥伪造加密命令实现命令注入 RCE](ctf-pwn-encrypted-command-whitelist-bypass-shell-injection/) | verified | high | 2026-11-08 |
| [GCC 15 / Ubuntu 26.04 PWN 靶场适配：__libc_csu_init 消失、CET 默认开启、手动注入 pop rdi gadget 与栈对齐](ctf-pwn-gcc15-ubuntu2604-cet-no-libc-csu-adaptation/) | verified | high | 2026-11-06 |
| [HTTP 解析 Content-Length 用 size_t 且按 --n 递减：传 0 得到 SIZE_MAX，溢出后可控制 saved EBP 让文件读取函数从 bss 里的 flag 字符串处读文件](ctf-pwn-http-content-length-zero-size-t-underflow-ebp-control-file-read/) | verified | medium | 2026-11-09 |
| [int16 长度检查符号绕过 + sprintf 格式化字符串泄 canary + 栈溢出 ORW（seccomp 禁 execve）](ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw/) | verified | high | 2026-11-07 |
| [interpreter 序列化解析器重复字段膨胀堆溢出：unsorted bin 泄露 + tcache 毒化 __free_hook](ctf-pwn-interpreter-serialization-expansion-heap-overflow/) | verified | high | 2026-11-05 |
| [justledger 多级链：SQLite 扩展自定义 free-list 任意写 + 低字节长度校验绕过 + 格式化字符串密文参数泄露](ctf-pwn-justledger-sqlite-extension-free-list-lowbyte-format-string-chain/) | verified | high | 2026-11-06 |
| [libpng 调色板对象 UAF + 页地址 oracle 绕过 safe-linking，六段中继到账本/议会](ctf-pwn-libpng-palette-uaf-page-oracle-six-stage-relay/) | verified | high | 2026-11-06 |
| [libxml2 push parser dict 表越界写网关：DTD 错误回调把 dict->size 加 1，hash%129==128 的 entry.valid 落到相邻 s_2+4](ctf-pwn-xmlbridge-libxml2-dict-size-increment-oob-entry-valid/) | verified | high | 2026-11-06 |
| [Linux 内核模块租约克隆 UAF：对象复用泄露内核基址/通道字段 → 栈枢轴 ROP commit_creds](ctf-pwn-linux-module-lease-clone-uaf-commit-creds-kpti/) | verified | high | 2026-11-06 |
| [nginx 模块状态机 UAF → broker/vault 对象图 → 有符号字节码负索引读 → ROP 读 flag](ctf-pwn-nginx-module-state-machine-uaf-signed-bytecode-negative-index/) | verified | high | 2026-11-06 |
| [note 数组负下标越界：view(-1) 泄露 copy relocation FILE*，create(-5) 覆写 puts@GOT 为 system](ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system/) | verified | high | 2026-11-06 |
| [Person 链表 null 字节溢出：fgets 多写 1 字节覆盖 next 低字节，重定向链表任意读 flag](ctf-pwn-linked-list-null-byte-next-pointer-lowbyte/) | verified | high | 2026-11-07 |
| [PHP 扩展 Minclude 无长度限制 memcpy 栈溢出：/proc/self/maps 泄 libc/栈后 ROP 反弹 shell（2020 De1CTF mixture）](ctf-pwn-php-extension-minclude-stack-overflow-maps-rop/) | verified | medium | 2026-11-08 |
| [PHP 扩展双堆块间接指针 + off-by-null：edit 任意地址写改 efree GOT 为 system 执行命令（D3CTF PwnShell）](ctf-pwn-php-extension-heap-offbynull-efree-got-system/) | verified | medium | 2026-11-08 |
| [Pwn 题 JSON 交互逆向：从 null/true/false、引号与 {[ 分支及 ,/} 闭合校验识别 JSON 输入并构造合法请求](ctf-pwn-json-input-parser-reversing/) | draft | high | 2026-11-08 |
| [Redis 模块多级 UID 隔离链：对象复用泄密、有符号索引写 route 头、负索引读控制块、tcache safe-linking 投毒与六层隧道](ctf-pwn-redis-module-multi-uid-chain-signed-index-tcache-tunnel/) | verified | high | 2026-11-06 |
| [Rust Vec/VecDeque UAF 全链：delete 只 free 不清 len 保留 Vec 元数据，View 复用为任意读 → tcache 投毒到栈改返回地址进后门](ctf-pwn-rust-vec-uaf-leak-environ-tcache-stack-backdoor/) | verified | high | 2026-11-08 |
| [Rust 菜单题隐藏开关：id 的二进制位选择全局常量异或，等价 32 元 GF(2) 方程组用高斯消元解出开门 id](ctf-pwn-bitmask-xor-global-gate-gf2/) | verified | high | 2026-11-08 |
| [scanf 有符号整数回绕绕过上下界校验：输入 -2 使 v+16 落到 0..14 的合法区间触发 system("/bin/sh")](ctf-pwn-signed-int-wrap-range-check-system/) | verified | high | 2026-11-09 |
| [scanf 长度输入溢出覆盖 printf 参数区：格式化字符串泄露堆地址并读取堆上 flag](ctf-pwn-scanf-overflow-printf-args-heap-flag-leak/) | verified | medium | 2026-11-07 |
| [Signal handler 栈溢出覆盖 rt_sigframe：SROP 两阶段 open/read/write 读 flag](ctf-pwn-signal-handler-rt-sigframe-srop-orw/) | verified | high | 2026-11-06 |
| [srand(time(0)) 作为 hash 混淆密钥：本地同秒复算 rand 序列 + 指针特征校验（高 4 位/低 12 位）恢复 libc 基址](ctf-pwn-time-seed-hash-replay-partial-leak-libc/) | verified | high | 2026-11-08 |
| [tcache poisoning 改写全局 note 数组元数据：借相邻 size 字段伪造 chunk，把 data 指向 flagbuf 直接打印](ctf-pwn-tcache-poison-global-note-array-flagbuf-print/) | verified | high | 2026-11-06 |
| [tcache UAF 回收已 free chunk 绕过 strncmp + printf("%s") 越界读 canary + ret2libc](ctf-pwn-tcache-uaf-reclaim-strncmp-bypass-printf-canary-leak-ret2libc/) | verified | high | 2026-11-07 |
| [UAF 重叠伪造 note 结构实现任意读：safe-linking 恢复堆地址 + 远程 ELF dynsym 解析 environ 扫栈取 flag](ctf-pwn-uaf-overlap-fake-note-aar-safe-linking-dynsym-environ-stack-scan/) | verified | high | 2026-11-06 |
| [vaultcache：Redis 模块 RDB 长度 off-by-8 破坏相邻 sds 头得到 64KB OOB，broker tcache 投毒与 jmp_buf 校验绕过转接 ledger](ctf-pwn-vaultcache-redis-module-rdb-off-by-8-sds-oob/) | verified | high | 2026-11-06 |
| [VFS 模拟 inode 软链接权限漏洞：任意读写 + SROP ORW](ctf-pwn-vfs-inode-link-permission-srop-orw/) | verified | high | 2026-11-05 |
| [VM pwn 全链：变长 opcode 驱动堆 UAF，largebin 泄 libc → tcache 劫持 environ 泄栈 → 再劫持返回地址写 ROP](ctf-pwn-vm-heap-uaf-largebin-environ-stack-rop/) | verified | high | 2026-11-08 |
| [VM 合法指令集即攻击面：用 syscall opcode（rax/rdi/rsi/rdx 全可控）配合「取栈地址」opcode 绕过 PIE，纯字节码拼出 open/read/write，61 字节读出 flag](ctf-pwn-vm-syscall-opcode-stack-leak-61byte-orw/) | verified | medium | 2026-11-09 |
| [VM 套堆题：用 case '3'/'5' 把寄存器映射成 heap(opt,size,ptr,size) 四参，借 data 段中转实现 add/free/edit/show 与 UAF 泄露](ctf-pwn-vm-opcode-heap-primitive-wrapper-uaf-leak/) | verified | high | 2026-11-08 |
| [VM 操作数栈 push 无上界：越界回读 canary/返回地址并覆写栈帧，seccomp 下构造 ORW ROP](ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop/) | verified | high | 2026-11-06 |
| [VM 操作数栈索引有符号下溢：负下标从 .bss 栈反向覆写 puts@GOT 为 system](ctf-pwn-vm-stack-index-signed-underflow-got-system/) | verified | high | 2026-11-06 |
| [vnctf2022 classic_httpd：base64 类型化命令协议暴露任意读/写，泄 PIE/libc 后改 GOT 为 system 执行命令](ctf-pwn-httpd-base64-typed-command-arb-rw-got-system/) | verified | medium | 2026-11-08 |
| [web pwn httpd：请求路径 /"s"h 经 shell 引号删除拼成 /sh，绕过 "sh"/"bin" 子串黑名单并借 popen 的 sh 执行反弹 shell](ctf-pwn-httpd-shell-quote-splice-sh-bin-filter-popen/) | verified | medium | 2026-11-08 |
| [WKCTF2024 baby_stack：echo_inner off-by-null 改 rbp 低字节栈迁移 + 格式化字符串泄 libc + ret2libc](ctf-pwn-offbynull-stack-migration-format-leak-ret2libc/) | verified | medium | 2026-11-08 |
| [保留 Canary 也能打：把 __stack_chk_fail 的 GOT 改成 leave;ret，溢出后用 jmp rsp 落地 shellcode](ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode/) | verified | high | 2026-11-08 |
| [入口是 call rdx 且只收可见字符：用 AE64 以 rdx 为基址寄存器编码，openat+sendfile 精简 ORW 读 flag](ctf-pwn-visible-char-ae64-rdx-base-openat-sendfile-orw/) | verified | medium | 2026-11-09 |
| [全保护堆题组合链：%7$p 泄 canary + UAF show 泄 unsorted bin + 栈溢出 ret2libc](ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections/) | verified | high | 2026-11-06 |
| [凭据在本地逐字符比较且错在不同位置：用返回文案差异逐个字符爆破出用户名与密码，先进门再打后面的堆](ctf-pwn-login-char-by-char-prefix-brute-local-credential/) | verified | high | 2026-11-09 |
| [单字节 offset 校验 vs int 类型：负数/大偏移绕过 add 边界，libc 堆溢出 + stdin FSOP 栈迁移](ctf-pwn-byte-offset-check-int-heap-overflow-stdin-fsop/) | verified | medium | 2026-11-06 |
| [反向越界写 GOT 但粒度被卡到 16 字节：先把 exit@GOT 改成菜单函数换取无限次写，再泄 libc 把 printf@GOT 改 system](ctf-pwn-got-write-granularity-exit-got-loop-ret2system/) | verified | medium | 2026-11-09 |
| [只改 kind 不重分配导致类型混淆：chorus 写入越界覆盖相邻 exhibit 的 perform](ctf-pwn-type-confusion-reclassify-adjacent-oob-perform/) | verified | high | 2026-11-06 |
| [只溢出 2 字节却已泄露栈地址：改 saved ebp 低位 + 后续 leave;ret 把栈迁回缓冲区，再跳后门拿 shell](ctf-pwn-two-byte-overflow-saved-ebp-leave-ret-stack-pivot-backdoor/) | draft | medium | 2026-11-09 |
| [堆残留取 flag：启动时 flag 读入堆后 free，按 size class 重新申请并读未初始化内存](ctf-pwn-heap-residual-uninitialized-read-flag/) | verified | high | 2026-11-06 |
| [字节白名单 shellcode：只用 imul/add/xor/xchg 构造 syscall，shmget/shmat 取 RWX 后 readv 二阶段 ORW](ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw/) | verified | medium | 2026-11-06 |
| [字节码 VM 8 位有符号偏移越界写：反向改写相邻全局命令缓冲区触发 system RCE](ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system/) | verified | high | 2026-11-05 |
| [字节码沙箱边界取自输入头部：mem_size 与真实栈缓冲尺寸脱钩导致越界写与无泄漏 ROP](ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop/) | verified | high | 2026-11-06 |
| [寄存器与栈被全清空的极简 execve shellcode：借保留的 rdi 指向输入 buffer，mov al,59; add rdi,8; syscall 直接拿 shell](ctf-pwn-minishell-cleared-registers-rdi-residual-execve/) | verified | high | 2026-11-08 |
| [按分钟派生 XOR 流 + 栈溢出 ROP：先泄 keystream 再编码 payload](ctf-pwn-time-keyed-xor-stream-stack-overflow/) | verified | high | 2026-11-06 |
| [无 libc 文件的 libc 版本识别：unsorted bin 泄 main_arena，用 __malloc_hook/__realloc_hook 固定偏移查 libc-database](ctf-pwn-libc-database-main-arena-hook-offset-identification/) | verified | medium | 2026-11-07 |
| [无 show 的 off-by-one 堆题：tcache 与 unsorted 叠块改 stdout 泄 libc，再 setcontext 走 mprotect+ORW 绕沙箱](ctf-pwn-offbyone-tcache-stdout-leak-mprotect-orw-sandbox/) | verified | medium | 2026-11-08 |
| [无泄漏且无 pop rdi gadget 时，用 VM 越界读栈残留 libc 指针并算术自举 ROP](ctf-pwn-vm-arith-bootstrap-rop-residual-libc-pointer/) | verified | high | 2026-11-08 |
| [无附件远程 pwn：超长密码触发自带 panic 逻辑，fopen(argv[0]) 读出自身 ELF 回显以恢复二进制](ctf-pwn-panic-self-dump-argv0-binary-recovery/) | verified | high | 2026-11-09 |
| [有符号长度检查 + 无符号形参放大：负数长度逐字节读溢出栈，写空相邻密码登 root 后 ret2libc](ctf-pwn-signed-length-unsigned-param-amplify-password-blank-ret2libc/) | verified | medium | 2026-11-08 |
| [未播种 rand 门控的栈数组越界：先改上界再写返回地址 ret2win](ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win/) | verified | high | 2026-11-06 |
| [本地 glibc 环境修补：从 libc 提取版本、复制 ld/依赖并 patchelf 递归改 NEEDED](ctf-pwn-patchelf-local-glibc-dependency-pool/) | verified | high | 2026-11-05 |
| [栈上 int 数组下标未校验：越界写覆盖返回地址跳转隐藏 print_flag](ctf-pwn-int-array-oob-index-ret-overwrite/) | verified | high | 2026-11-06 |
| [栈偏移算不准时用同一个 jmp rsp gadget 铺满整个溢出区：rsp 落到哪一格都会滑到尾部 shellcode，配 openat+sendfile 的 ORW 读文件](ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile/) | draft | high | 2026-11-08 |
| [格式化字符串 %N$s 直接读出栈上随机口令泄 libc：配合「两次输入相同即通过」的自证型认证码校验，进入 shell 溢出打 ret2libc](ctf-pwn-format-string-stack-secret-self-compare-auth-ret2libc/) | verified | medium | 2026-11-09 |
| [漏洞在 fork 出的子进程里、canary 又已白送：把两轮读取数据一次性 send 完，才能覆盖到子进程的返回地址](ctf-pwn-fork-child-hidden-func-single-send-canary-overflow/) | verified | medium | 2026-11-09 |
| [登录失败分支打印正确随机密码：二次登录绕过并执行命令](ctf-pwn-login-failure-prints-correct-password/) | verified | high | 2026-11-06 |
| [盲打格式化字符串：%n$p 定位栈 + %7$s+地址 dump 二进制，定位后门并覆写 printf GOT](ctf-pwn-blind-format-string-dump-binary-got-hijack/) | verified | high | 2026-11-06 |
| [相邻 talks/gestures 数组 + 16 字节 fgets 溢出覆写函数指针表，借 gift gadget 调 system](ctf-pwn-adjacent-talks-gestures-function-pointer-overflow-gift/) | verified | high | 2026-11-06 |
| [程序对输入逐字节自增 1 后再 call eax 执行栈上数据：预先减 1 编码 shellcode 即可落地](ctf-pwn-call-eax-stack-shellcode-byte-inc1/) | draft | high | 2026-11-09 |
| [自定义 32 位定长指令集 VM 的访存指令边界检查位宽不一致导致栈越界读写](ctf-pwn-custom-risc-vm-offset-width-mismatch-oob-rw/) | verified | high | 2026-11-08 |
| [自定义 Befunge 类 VM 的 g/p 维度边界用 >rows/>cols：越界读写相邻全局变量泄露 flag](ctf-pwn-befunge-vm-gp-dimension-offbyone-global-oob-read/) | verified | high | 2026-11-07 |
| [自定义 HTTP 服务把请求路径交给 popen：URL 编码空格注入系统命令并读取 flag](ctf-pwn-httpd-path-popen-command-injection/) | verified | medium | 2026-11-08 |
| [自定义 VM 指令集 pwn：用 VM 内存读写改 GOT，exit 重启 + malloc one_gadget](ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget/) | verified | medium | 2026-11-06 |
| [自研空闲链表 UAF + 不校验 next：任意地址分配并覆盖后端函数表](ctf-pwn-custom-freelist-uaf-unchecked-next-arbitrary-alloc-function-table/) | verified | high | 2026-11-06 |
| [菜单堆题 double free 复用同一块：把函数指针表覆盖成 {"/bin/sh", system} 后由 show 间接调用拿 shell](ctf-pwn-double-free-funcptr-table-freehook/) | verified | high | 2026-11-09 |
| [菜单堆题 UAF + 后门只改 next 低 4 字节：伪造 unsorted chunk 泄 libc → overlapping 打 __free_hook](ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook/) | verified | medium | 2026-11-07 |
| [菜单堆题 UAF + 堆溢出：unsortedbin 泄 libc 后 tcache 投毒 __free_hook 为 system](ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system/) | verified | high | 2026-11-07 |
| [负下标全局指针数组越界：改 stdout 泄 libc + 经 __dso_handle 两跳改写 __free_hook 为 system](ctf-pwn-negative-index-pointer-array-stdout-freehook-system/) | verified | medium | 2026-11-07 |
| [负数下标越界读取隐藏槽位 + cookie 编码函数指针改写](ctf-pwn-negative-index-hidden-slot-encoded-fptr/) | verified | high | 2026-11-06 |
| [账单数组索引循环写栈：v2 与 v1[11] 重叠导致逐 32 位可控写，32 位 ret2libc](ctf-pwn-bill-array-index-loop-stack-word-write-ret2libc/) | verified | low | 2026-11-07 |
| [输入 0 触发除零异常，进入 catch 分支里隐藏的 shell() 后门](ctf-pwn-cpp-exception-catch-hidden-shell/) | verified | high | 2026-11-09 |
| [过期回收不清 sessions[] 导致 session/sink 重叠：stale 指针改二级函数指针](ctf-pwn-stale-pool-session-overlap-sink-double-indirect-call/) | verified | high | 2026-11-06 |
| [配置编辑器双重指针误用：任意地址字符串写 + 对齐零字节写构造栈 ROP](ctf-pwn-double-pointer-arbitrary-write-aligned-zero-rop/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
