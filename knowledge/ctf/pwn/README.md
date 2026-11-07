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
| [/proc/self/mem 任意内存写：把文件编辑器变成 .rodata 改写器，篡改硬编码黑名单首字节绕过 /secret.txt 拦截](ctf-pwn-proc-self-mem-rodata-string-patch.md) | verified | high | 2026-11-07 |
| [16 位 YOLOOS VM 逃逸：guest 越界写内核栈 + MMIO cache 映射宿主栈 + instruction limit 泄露 PIE](ctf-pwn-yoloos-vm-escape-mmio-cache-instruction-limit.md) | verified | high | 2026-11-06 |
| [2025 CISCN easy_rw：proxy 配置覆盖令 RSA d=1 + 哈希 NUL 截断绕过认证，后端 2.31 堆泄露与 backdoor 栈溢出 ORW](ctf-pwn-webpwn-proxy-config-overwrite-heap-leak-backdoor-orw.md) | verified | high | 2026-11-06 |
| [AWD 批量利用编排：目标扫描 + 并发加载 exp.py + 结果收集](ctf-pwn-awd-batch-scan-concurrent-exp-runner.md) | verified | high | 2026-11-05 |
| [AWDP fix：UAF 释放点的二进制级补丁（原地压缩 / 弹栈 / jmp）](ctf-pwn-awdp-uaf-free-patch.md) | verified | medium | 2026-11-05 |
| [AWDP fix：格式化字符串漏洞的二进制级补丁（IDA/KeyPatch 改 printf 调用）](ctf-pwn-awdp-format-string-patch.md) | verified | high | 2026-11-05 |
| [blind pwn：负数长度符号绕过泄露栈/canary + debug 泄露 write 地址后 ret2libc](ctf-pwn-blind-negative-length-stack-leak-debug-write-ret2libc.md) | verified | medium | 2026-11-07 |
| [C 程序命令注入文件名过滤绕过：fl''ag 引号拼接绕过 strstr(file,"flag")](ctf-pwn-command-injection-filename-shell-quote-bypass.md) | verified | high | 2026-11-06 |
| [CTF Pwn 数值校验绕过：strtod 十六进制浮点与 strtoull 解析差异](ctf-pwn-hexfloat-strtoull-parser-differential.md) | verified | high | 2026-11-05 |
| [CTF webpwn 双进程架构：proxy 全局溢出改写 RSA n/d 绕过鉴权 + 后端负索引泄露与栈溢出 ORW](ctf-pwn-webpwn-proxy-rsa-auth-bypass-backend-oob-rop.md) | verified | high | 2026-11-06 |
| [ELO 积分负分未截断 + 32 位零扩展入库：sqlite3_bind_int64 把 -1 存成 4294967295 登顶排行榜](ctf-pwn-elo-negative-score-zero-extension-leaderboard.md) | verified | high | 2026-11-06 |
| [GCC 15 / Ubuntu 26.04 PWN 靶场适配：__libc_csu_init 消失、CET 默认开启、手动注入 pop rdi gadget 与栈对齐](ctf-pwn-gcc15-ubuntu2604-cet-no-libc-csu-adaptation.md) | verified | high | 2026-11-06 |
| [int16 长度检查符号绕过 + sprintf 格式化字符串泄 canary + 栈溢出 ORW（seccomp 禁 execve）](ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw.md) | verified | high | 2026-11-07 |
| [interpreter 序列化解析器重复字段膨胀堆溢出：unsorted bin 泄露 + tcache 毒化 __free_hook](ctf-pwn-interpreter-serialization-expansion-heap-overflow.md) | verified | high | 2026-11-05 |
| [justledger 多级链：SQLite 扩展自定义 free-list 任意写 + 低字节长度校验绕过 + 格式化字符串密文参数泄露](ctf-pwn-justledger-sqlite-extension-free-list-lowbyte-format-string-chain.md) | verified | high | 2026-11-06 |
| [libpng 调色板对象 UAF + 页地址 oracle 绕过 safe-linking，六段中继到账本/议会](ctf-pwn-libpng-palette-uaf-page-oracle-six-stage-relay.md) | verified | high | 2026-11-06 |
| [libxml2 push parser dict 表越界写网关：DTD 错误回调把 dict->size 加 1，hash%129==128 的 entry.valid 落到相邻 s_2+4](ctf-pwn-xmlbridge-libxml2-dict-size-increment-oob-entry-valid.md) | verified | high | 2026-11-06 |
| [Linux 内核模块租约克隆 UAF：对象复用泄露内核基址/通道字段 → 栈枢轴 ROP commit_creds](ctf-pwn-linux-module-lease-clone-uaf-commit-creds-kpti.md) | verified | high | 2026-11-06 |
| [nginx 模块状态机 UAF → broker/vault 对象图 → 有符号字节码负索引读 → ROP 读 flag](ctf-pwn-nginx-module-state-machine-uaf-signed-bytecode-negative-index.md) | verified | high | 2026-11-06 |
| [note 数组负下标越界：view(-1) 泄露 copy relocation FILE*，create(-5) 覆写 puts@GOT 为 system](ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system.md) | verified | high | 2026-11-06 |
| [Person 链表 null 字节溢出：fgets 多写 1 字节覆盖 next 低字节，重定向链表任意读 flag](ctf-pwn-linked-list-null-byte-next-pointer-lowbyte.md) | verified | high | 2026-11-07 |
| [Redis 模块多级 UID 隔离链：对象复用泄密、有符号索引写 route 头、负索引读控制块、tcache safe-linking 投毒与六层隧道](ctf-pwn-redis-module-multi-uid-chain-signed-index-tcache-tunnel.md) | verified | high | 2026-11-06 |
| [scanf 长度输入溢出覆盖 printf 参数区：格式化字符串泄露堆地址并读取堆上 flag](ctf-pwn-scanf-overflow-printf-args-heap-flag-leak.md) | verified | medium | 2026-11-07 |
| [Signal handler 栈溢出覆盖 rt_sigframe：SROP 两阶段 open/read/write 读 flag](ctf-pwn-signal-handler-rt-sigframe-srop-orw.md) | verified | high | 2026-11-06 |
| [tcache poisoning 改写全局 note 数组元数据：借相邻 size 字段伪造 chunk，把 data 指向 flagbuf 直接打印](ctf-pwn-tcache-poison-global-note-array-flagbuf-print.md) | verified | high | 2026-11-06 |
| [tcache UAF 回收已 free chunk 绕过 strncmp + printf("%s") 越界读 canary + ret2libc](ctf-pwn-tcache-uaf-reclaim-strncmp-bypass-printf-canary-leak-ret2libc.md) | verified | high | 2026-11-07 |
| [UAF 重叠伪造 note 结构实现任意读：safe-linking 恢复堆地址 + 远程 ELF dynsym 解析 environ 扫栈取 flag](ctf-pwn-uaf-overlap-fake-note-aar-safe-linking-dynsym-environ-stack-scan.md) | verified | high | 2026-11-06 |
| [vaultcache：Redis 模块 RDB 长度 off-by-8 破坏相邻 sds 头得到 64KB OOB，broker tcache 投毒与 jmp_buf 校验绕过转接 ledger](ctf-pwn-vaultcache-redis-module-rdb-off-by-8-sds-oob.md) | verified | high | 2026-11-06 |
| [VFS 模拟 inode 软链接权限漏洞：任意读写 + SROP ORW](ctf-pwn-vfs-inode-link-permission-srop-orw.md) | verified | high | 2026-11-05 |
| [VM 操作数栈 push 无上界：越界回读 canary/返回地址并覆写栈帧，seccomp 下构造 ORW ROP](ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop.md) | verified | high | 2026-11-06 |
| [VM 操作数栈索引有符号下溢：负下标从 .bss 栈反向覆写 puts@GOT 为 system](ctf-pwn-vm-stack-index-signed-underflow-got-system.md) | verified | high | 2026-11-06 |
| [全保护堆题组合链：%7$p 泄 canary + UAF show 泄 unsorted bin + 栈溢出 ret2libc](ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections.md) | verified | high | 2026-11-06 |
| [单字节 offset 校验 vs int 类型：负数/大偏移绕过 add 边界，libc 堆溢出 + stdin FSOP 栈迁移](ctf-pwn-byte-offset-check-int-heap-overflow-stdin-fsop.md) | verified | medium | 2026-11-06 |
| [只改 kind 不重分配导致类型混淆：chorus 写入越界覆盖相邻 exhibit 的 perform](ctf-pwn-type-confusion-reclassify-adjacent-oob-perform.md) | verified | high | 2026-11-06 |
| [堆残留取 flag：启动时 flag 读入堆后 free，按 size class 重新申请并读未初始化内存](ctf-pwn-heap-residual-uninitialized-read-flag.md) | verified | high | 2026-11-06 |
| [字节白名单 shellcode：只用 imul/add/xor/xchg 构造 syscall，shmget/shmat 取 RWX 后 readv 二阶段 ORW](ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw.md) | verified | medium | 2026-11-06 |
| [字节码 VM 8 位有符号偏移越界写：反向改写相邻全局命令缓冲区触发 system RCE](ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system.md) | verified | high | 2026-11-05 |
| [字节码沙箱边界取自输入头部：mem_size 与真实栈缓冲尺寸脱钩导致越界写与无泄漏 ROP](ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop.md) | verified | high | 2026-11-06 |
| [按分钟派生 XOR 流 + 栈溢出 ROP：先泄 keystream 再编码 payload](ctf-pwn-time-keyed-xor-stream-stack-overflow.md) | verified | high | 2026-11-06 |
| [无 libc 文件的 libc 版本识别：unsorted bin 泄 main_arena，用 __malloc_hook/__realloc_hook 固定偏移查 libc-database](ctf-pwn-libc-database-main-arena-hook-offset-identification.md) | verified | medium | 2026-11-07 |
| [未播种 rand 门控的栈数组越界：先改上界再写返回地址 ret2win](ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win.md) | verified | high | 2026-11-06 |
| [本地 glibc 环境修补：从 libc 提取版本、复制 ld/依赖并 patchelf 递归改 NEEDED](ctf-pwn-patchelf-local-glibc-dependency-pool.md) | verified | high | 2026-11-05 |
| [栈上 int 数组下标未校验：越界写覆盖返回地址跳转隐藏 print_flag](ctf-pwn-int-array-oob-index-ret-overwrite.md) | verified | high | 2026-11-06 |
| [登录失败分支打印正确随机密码：二次登录绕过并执行命令](ctf-pwn-login-failure-prints-correct-password.md) | verified | high | 2026-11-06 |
| [盲打格式化字符串：%n$p 定位栈 + %7$s+地址 dump 二进制，定位后门并覆写 printf GOT](ctf-pwn-blind-format-string-dump-binary-got-hijack.md) | verified | high | 2026-11-06 |
| [相邻 talks/gestures 数组 + 16 字节 fgets 溢出覆写函数指针表，借 gift gadget 调 system](ctf-pwn-adjacent-talks-gestures-function-pointer-overflow-gift.md) | verified | high | 2026-11-06 |
| [自定义 VM 指令集 pwn：用 VM 内存读写改 GOT，exit 重启 + malloc one_gadget](ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget.md) | verified | medium | 2026-11-06 |
| [自研空闲链表 UAF + 不校验 next：任意地址分配并覆盖后端函数表](ctf-pwn-custom-freelist-uaf-unchecked-next-arbitrary-alloc-function-table.md) | verified | high | 2026-11-06 |
| [菜单堆题 UAF + 堆溢出：unsortedbin 泄 libc 后 tcache 投毒 __free_hook 为 system](ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system.md) | verified | high | 2026-11-07 |
| [负下标全局指针数组越界：改 stdout 泄 libc + 经 __dso_handle 两跳改写 __free_hook 为 system](ctf-pwn-negative-index-pointer-array-stdout-freehook-system.md) | verified | medium | 2026-11-07 |
| [负数下标越界读取隐藏槽位 + cookie 编码函数指针改写](ctf-pwn-negative-index-hidden-slot-encoded-fptr.md) | verified | high | 2026-11-06 |
| [账单数组索引循环写栈：v2 与 v1[11] 重叠导致逐 32 位可控写，32 位 ret2libc](ctf-pwn-bill-array-index-loop-stack-word-write-ret2libc.md) | verified | low | 2026-11-07 |
| [过期回收不清 sessions[] 导致 session/sink 重叠：stale 指针改二级函数指针](ctf-pwn-stale-pool-session-overlap-sink-double-indirect-call.md) | verified | high | 2026-11-06 |
| [配置编辑器双重指针误用：任意地址字符串写 + 对齐零字节写构造栈 ROP](ctf-pwn-double-pointer-arbitrary-write-aligned-zero-rop.md) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
