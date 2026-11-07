---
title: 堆利用
weight: 1
---

# 堆利用

## 这层是什么

glibc 堆、UAF、double free、House of 系列。

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
| [__free_hook 接 setcontext+61：bridge gadget 把 rdi 转 rdx，read 自覆写堆栈后 ORW](binary-pwn-heap-freehook-setcontext61-bridge-orw/) | verified | medium | 2026-11-05 |
| [abs(INT_MIN) 长度校验绕过堆溢出：BSS 伪造 chunk 投毒 tcache 劫持 GOT](binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got/) | verified | high | 2026-11-05 |
| [C++ vector<deque<Animal>> 编辑长度不校验：堆溢出伪造相邻 Animal 内容指针，environ 泄露栈后改写 main 返回地址 one_gadget](binary-pwn-heap-cpp-animal-edit-size-mismatch-environ-onegadget/) | verified | medium | 2026-11-06 |
| [calloc 堆题：改相邻 chunk size 造重叠泄露 libc，tcache poisoning 覆写 __malloc_hook/__realloc_hook 并用 realloc+3 调栈帧打 one_gadget](binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget/) | verified | low | 2026-11-06 |
| [CGI VPN 配置堆溢出：strcpy 跨字段覆盖 custom_ptr 后任意写劫持 apply_cb](binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack/) | verified | high | 2026-11-05 |
| [CREATE 失败路径先写全局槽再 free：稳定 stale slot 制造 UAF 读写](binary-pwn-heap-stale-slot-create-failure-uaf/) | verified | high | 2026-11-05 |
| [delete 压缩指针数组不清末槽：glibc 2.23 fastbin dup 打 GOT/environ/栈](binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup/) | verified | high | 2026-11-05 |
| [Forth 解释器 forget 未检查引用计数：tcache 复用伪造 word_t 调 dosys](binary-pwn-forth-dictionary-uaf-tcache-fake-word/) | verified | high | 2026-11-06 |
| [FUSE CoW 引用计数 UAF：异常 offset 让旧数据块 refcount 减一但指针未换，伪造 metadata 任意读写并劫持 fuse_operations](binary-pwn-heap-fuse-cow-refcount-uaf-fuse-operations-hijack/) | verified | high | 2026-11-06 |
| [glibc 2.23 UAF 堆题：unsorted bin 泄露 libc、fastbin dup 打 __malloc_hook，realloc+6 调栈帧满足 one_gadget](binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget/) | verified | high | 2026-11-06 |
| [glibc 2.23 unsafe unlink：伪造 chunk 劫持 chunks 数组后 GOT 泄露与 system 覆写](binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system/) | verified | high | 2026-11-06 |
| [glibc 2.31+ 高版本 large bin attack：中间插入分支的双链表检查与 bk/bk_nextsize 双写点](binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks/) | verified | medium | 2026-11-06 |
| [glibc 2.35 largebin attack 改 _IO_list_all：fake wide FILE 经 setcontext 转 openat2 ORW](binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw/) | verified | high | 2026-11-05 |
| [glibc 2.35 off-by-null + 高版本 unlink：伪造 size/prev_size 通过检查，劫持全局 chunk 数组、__environ 泄露栈并 ROP](binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop/) | verified | medium | 2026-11-06 |
| [glibc 2.37 UAF 链：tcache 毒化全局结构体 + environ 泄露栈 + 栈上 ROP](binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop/) | verified | medium | 2026-11-05 |
| [glibc 2.39 largebin attack 改写 mp_.tcache_bins：放大 tcache 上限后毒化栈返回地址](binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop/) | verified | high | 2026-11-05 |
| [glibc 2.39 leakless RCE：largebin attack 放大 mp_.tcache_bins 后从堆数据分配出 stdout，再以 house of cat/emma FSOP 执行 system](binary-pwn-heap-leakless-mp-tcache-bins-stdout-fsop/) | verified | high | 2026-11-06 |
| [glibc 2.39 tcache safe-linking fd 泄露栈：绕过 environ 的 0x10 对齐限制并把 chunk 分配到栈上](binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack/) | verified | medium | 2026-11-06 |
| [glibc 2.41 exit handler 攻击：覆写 pointer_guard 后伪造 initial __exit_funcs 调 system](binary-pwn-heap-glibc-exit-initial-pointer-guard-forge-system/) | verified | high | 2026-11-07 |
| [glibc 2.41 Tcache Reverse Into Fastbin + fastbin dup：受限 UAF 下构造任意地址分配](binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc/) | verified | high | 2026-11-07 |
| [glibc 2.42+ tcache_key 绕过：UAF 清 key 构造 tcache dup，poisoning 覆写 free@GOT 到 system](binary-pwn-heap-glibc243-tcache-key-bypass-got-system/) | verified | high | 2026-11-05 |
| [glibc 2.43 tcache_perthread_struct 劫持：改写 entries 实现任意地址分配与栈 ROP](binary-pwn-heap-glibc243-tcache-perthread-struct-hijack/) | verified | medium | 2026-11-05 |
| [House of Apple 2 覆盖 _IO_2_1_stderr_ 从 exit 触发 FSOP 拿 shell](binary-pwn-heap-house-of-apple-2-stderr-fsop/) | verified | high | 2026-11-04 |
| [House of Apple2 源码级复现：largebin attack 改 _IO_list_all + _IO_wfile_overflow/_IO_wdoallocbuf 劫持 _wide_vtable](binary-pwn-heap-house-of-apple2-source-analysis-largebin-system/) | verified | medium | 2026-11-06 |
| [House of Apple2 部分覆盖 chunk header：_wide_data 错位修正 + svcudp_reply+26 经 fake xdr_ops 栈迁移 ORW](binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw/) | verified | high | 2026-11-06 |
| [House of Botcake：填满 tcache + unsorted bin 合并绕过 double free 检查，重新投毒 tcache](binary-pwn-heap-house-of-botcake-tcache-poison/) | verified | high | 2026-11-05 |
| [House of Einherjar：off-by-null 清 PREV_INUSE + 伪造 prev_size/fake chunk 向前合并，堆重叠后 tcache poisoning 任意地址分配](binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison/) | verified | high | 2026-11-07 |
| [House of Orange 式 unsorted bin attack + FSOP：改 _IO_list_all 为 main_arena，借 0x60 smallbin 伪造 FILE vtable 调 system](binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system/) | verified | high | 2026-11-06 |
| [House of Peach：无 free 函数时借 sysmalloc 释放旧 top chunk 伪造 unsorted/largebin](binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin/) | verified | high | 2026-11-06 |
| [House of Storm：unsorted bin + large bin 双写伪造任意地址 chunk 劫持 __free_hook](binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk/) | verified | high | 2026-11-05 |
| [nginx rewrite+set 双引擎 is_args 不一致堆溢出（CVE-2026-42945）：+ 号 1→3 展开冲爆 buffer](binary-pwn-heap-nginx-rewrite-isargs-dual-engine-overflow/) | verified | high | 2026-11-05 |
| [pack 压缩后 stale cap：note data 缩小但 cap 未同步，show/edit 越界读写相邻 note 并改全局 exit 函数指针低字节](binary-pwn-heap-pack-stale-cap-oob-note-struct-function-pointer/) | verified | high | 2026-11-06 |
| [protobuf-c 协议堆题 free/overlap 链：content 长度控块伪造大 chunk 泄露 libc/heap，tcache 污染 _IO_list_all 走 wide FILE 魔术 gadget ORW](binary-pwn-heap-protobuf-c-free-overlap-fsop-orw/) | verified | medium | 2026-11-06 |
| [QuickJS 补丁引入的双重弹栈 UAF：OP_put_var 异常路径重复释放，经 JSString 越界泄露与 TypedArray 任意读写劫持 JSRuntime.mf 执行 system("/bin/sh")](binary-pwn-heap-quickjs-put-var-double-pop-uaf-jsruntime-hijack/) | verified | high | 2026-11-06 |
| [Redis HyperLogLog 稀疏编码越界写（CVE-2025-32023）：改相邻 SDS 类型伪造超长字符串泄堆，伪造 module robj 的 free 回调走 ROP](binary-pwn-heap-redis-hll-sparse-oob-sds-type-fake-robj-module-rop/) | verified | high | 2026-11-06 |
| [Redis Stream NACK 共享导致 Double Free：恶意 RDB + DELCONSUMER 的堆利用 RCE](binary-pwn-heap-redis-stream-nack-double-free-rce/) | verified | high | 2026-11-05 |
| [Robo_admin 堆题链：off-by-one 改 size + unlink 泄露 + House of Some + IO_FILE FSOP 执行 shellcode](binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile/) | verified | medium | 2026-11-06 |
| [scanf 数字解析触发内部 malloc(0x800)：固定大小堆题中强制 unsortedbin 排序的分配原语](binary-pwn-heap-scanf-scratch-buffer-malloc-sorting/) | verified | high | 2026-11-06 |
| [stdout 部分覆写泄露 libc：改 _flags 与 _IO_write_base 低字节扩大输出窗口](binary-pwn-heap-stdout-partial-overwrite-libc-leak/) | verified | high | 2026-11-05 |
| [strcmp 逐字节爆破 libc 指针：利用 NUL 截断与指针低字节左移泄露 main_arena](binary-pwn-heap-strcmp-bytewise-libc-pointer-leak/) | verified | high | 2026-11-05 |
| [tcache 毒化 _IO_list_all + House of Apple2（glibc 2.39）：堆块合并/UAF 泄堆后伪造 FILE 调 system](binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2/) | verified | medium | 2026-11-07 |
| [TSU+ 打 tcache_perthread_struct：smallbin bk 塞入堆内假 chunk，直接改写 tcache entries 绕过 safe-linking](binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries/) | verified | high | 2026-11-06 |
| [UAF 函数指针劫持：释放后不置空，同大小分配复用旧块改写回调](binary-pwn-heap-uaf-function-pointer-hijack/) | verified | high | 2026-11-05 |
| [UAF 悬空指针配合 unsorted bin 泄露 libc 基址](binary-pwn-heap-uaf-unsorted-bin-libc-leak/) | verified | high | 2026-11-04 |
| [unsorted bin attack 放大 global_max_fast：BSS 假 fastbin 块覆盖 ptr 数组后改 __free_hook](binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook/) | verified | medium | 2026-11-06 |
| [XOR 编码堆指针 + lucky number 任意 free：strlen 空字节截断制造 note 重叠，泄露 PIE/heap/libc 后 one_gadget](binary-pwn-heap-xor-chunklist-lucky-number-arbitrary-free-uaf/) | verified | medium | 2026-11-06 |
| [事务快照结构未初始化：MULTI/EXEC/ABORT 组合的 UAF、任意 free 与任意读](binary-pwn-heap-uninitialized-tx-context-uaf-arbitrary-free-read/) | verified | high | 2026-11-05 |
| [伪文件系统 off-by-null 触发 House of Einherjar：chunk 重叠后 largebin attack 改 _IO_list_all 转 wide FILE FSOP ORW](binary-pwn-heap-vfs-offby-null-einherjar-largebin-io-list-all-fsop/) | verified | medium | 2026-11-06 |
| [单次任意地址写 00 扩大 stdin 输入缓冲区：覆盖 stdout FILE → puts _IO_sputn → house of emma/cat → setcontext ORW](binary-pwn-heap-nullbyte-stdin-buffer-expand-stdout-fsop/) | verified | high | 2026-11-06 |
| [同页 tcache 双 free 自异或恢复精确堆地址（safe-linking 免泄露）](binary-pwn-heap-safe-linking-self-xor-heap-address/) | verified | high | 2026-11-04 |
| [堆 UAF 结构体复用：free 顺序让 user 结构体被重分配为密码缓冲区，改写 data 指针实现任意读写](binary-pwn-heap-uaf-struct-reuse-data-pointer/) | verified | high | 2026-11-05 |
| [循环双向链表 delete 唯一节点仍走断链分支：current 悬空后 edit 缺 count 检查形成 UAF 写](binary-pwn-heap-circular-dlist-delete-count1-uaf/) | verified | high | 2026-11-06 |
| [换行符 off-by-one：size 差 0xA 多写 1 字节，清 PREV_INUSE 造 unsorted bin 重叠泄露](binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap/) | verified | medium | 2026-11-06 |
| [无 show 堆题：largebin attack 预置 bk + tcache stashing unlink 将固定 mmap 地址塞入 tcache](binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write/) | verified | high | 2026-11-06 |
| [未初始化 WebSocket session + 负 frag_len 下写：伪造堆头进 tcache 并覆盖 session 做 AAR/AAW](binary-pwn-heap-uninitialized-session-negative-fraglen-tcache/) | verified | high | 2026-11-06 |
| [湾区杯2025 digtal_bomb：猜数范围逻辑绕过进入堆菜单，off-by-null + House of Einherjar 造重叠泄露 libc，tcache 投毒 strlen GOT 打 one_gadget](binary-pwn-heap-digtal-bomb-offby-null-einherjar-tcache-strlen-got-onegadget/) | verified | medium | 2026-11-07 |
| [自定义 arena 的 double free 到任意地址分配：cookie 编码 freelist 与 stale 指针](binary-pwn-heap-custom-arena-double-free-cookie-arbitrary-alloc/) | verified | high | 2026-11-05 |
| [自定义堆管理器数组越界 + next 指针任意分配：栈上伪造 chunk 构造 ORW ROP](binary-pwn-heap-custom-manager-array-overflow-next-pointer-stack-chunk-orw/) | verified | high | 2026-11-07 |
| [自定义堆管理器负数长度整数溢出：对齐后极小 chunk 被超长写入覆盖，构造任意读写](binary-pwn-heap-custom-allocator-negative-size-alignment-overflow/) | verified | high | 2026-11-06 |
| [负数 size 绕过长度检查导致 malloc 失败：保留悬垂指针的 UAF 与大堆 house of cat ORW](binary-pwn-heap-negative-size-malloc-failure-stale-pointer-house-of-cat/) | verified | high | 2026-11-06 |
| [高版本 glibc FSOP 任意地址读写：fake IO_FILE 读链 + House of Some 经 _wide_vtable=_IO_file_jumps-0x48 走到 _IO_SYSREAD 写](binary-pwn-heap-fsop-house-of-some-arbitrary-read-write/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
