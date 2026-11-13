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
| [AES 自实现加密堆题：长度不整除 16 时明文直写 + safe_malloc 限制在 0x1000 内封死 tcache，改走低字节毒化篡改 key → unlink 改 Booklist 指针 → environ 泄栈 → 短 ROP gets 二次溢出 ORW](binary-pwn-heap-aes-key-tcache-poison-unlink-booklist-environ-rop/) | draft | high | 2026-11-09 |
| [Android jemalloc 'new' 分配器机制与利用面（前置知识）：arena/extent/slab/bin/tcache 结构与堆风水要点](binary-pwn-heap-android-jemalloc-new-allocator-internals/) | verified | medium | 2026-11-13 |
| [Android Scudo 分配器防御机制与利用面（前置知识）：Block 头/CRC16 校验、Android 关闭 quarantine 的 UAF 复用、double-free 重分配绕过与 TransferBatch 洗牌边界](binary-pwn-heap-android-scudo-allocator-defense-internals/) | verified | medium | 2026-11-13 |
| [Arbitrary Alloc：UAF 改写 fastbin fd 指向 BSS 假块（size=0x7f），单次 free 也能实现任意地址分配并改 GOT](binary-pwn-heap-fastbin-fd-fake-chunk-bss-arbitrary-alloc/) | verified | high | 2026-11-10 |
| [C++ HTTP 待办服务的 PUT 偏移量用有符号比较：负偏移绕过边界检查形成向后任意写，改 content 指针拿任意读写，leak heap/libc/stack 后覆写栈返回地址 ROP](binary-pwn-heap-cpp-http-todo-negative-offset-backward-write-arbitrary-rw-rop/) | verified | medium | 2026-11-08 |
| [C++ vector<deque<Animal>> 编辑长度不校验：堆溢出伪造相邻 Animal 内容指针，environ 泄露栈后改写 main 返回地址 one_gadget](binary-pwn-heap-cpp-animal-edit-size-mismatch-environ-onegadget/) | verified | medium | 2026-11-06 |
| [calloc 堆题：改相邻 chunk size 造重叠泄露 libc，tcache poisoning 覆写 __malloc_hook/__realloc_hook 并用 realloc+3 调栈帧打 one_gadget](binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget/) | verified | low | 2026-11-06 |
| [CGI VPN 配置堆溢出：strcpy 跨字段覆盖 custom_ptr 后任意写劫持 apply_cb](binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack/) | verified | high | 2026-11-05 |
| [Chunk Extend：堆溢出改相邻 chunk size 扩大 free 范围制造 overlapping，泄露 libc 后接 fastbin attack 打 __malloc_hook（glibc 2.23）](binary-pwn-heap-chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook/) | verified | high | 2026-11-09 |
| [cJSON \u 堆溢出全链：数组喷堆绕过 WAF + House of Orange 造 fastbin，改 protobuf 数据段函数指针 ROP](binary-pwn-heap-cjson-unicode-overflow-house-of-orange-fastbin-protobuf-rop/) | verified | high | 2026-11-12 |
| [cJSON parse_string 的 \u 转义越界：长度按字符算、写入按字节走，形成长度双算不一致的受控堆溢出](binary-pwn-heap-cjson-parse-string-unicode-escape-unbounded-overflow/) | verified | medium | 2026-11-08 |
| [CREATE 失败路径先写全局槽再 free：稳定 stale slot 制造 UAF 读写](binary-pwn-heap-stale-slot-create-failure-uaf/) | verified | high | 2026-11-05 |
| [delete 压缩指针数组不清末槽：glibc 2.23 fastbin dup 打 GOT/environ/栈](binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup/) | verified | high | 2026-11-05 |
| [fastbin + small bin 不改 prev_inuse 位完成 overlapping：借 small bin chunk 天然 prev_size=0 绕过合并检查](binary-pwn-heap-fastbin-smallbin-prev-inuse-free-overlapping/) | verified | high | 2026-11-08 |
| [Forth 解释器 forget 未检查引用计数：tcache 复用伪造 word_t 调 dosys](binary-pwn-forth-dictionary-uaf-tcache-fake-word/) | verified | high | 2026-11-06 |
| [free 次数被写死 10 次、且没有 edit 的 UAF 堆题：7 次 free 填满 tcache 后余下 3 次构造 A→B→A fastbin dup，按 safe-linking 编码把 0x50 块分配到 libc 的 strtok GOT，借其 rdi 可控改写成 system](binary-pwn-heap-10-free-quota-fastbin-dup-strtok-got-system/) | verified | high | 2026-11-09 |
| [FUSE CoW 引用计数 UAF：异常 offset 让旧数据块 refcount 减一但指针未换，伪造 metadata 任意读写并劫持 fuse_operations](binary-pwn-heap-fuse-cow-refcount-uaf-fuse-operations-hijack/) | verified | high | 2026-11-06 |
| [glibc 2.23 off-by-one 改相邻 chunk size 造重叠：覆盖 0x10 元数据块指针为 __free_hook，edit 写 system 后 free 触发](binary-pwn-heap-glibc223-offbyone-size-extend-overlap-metadata-ptr-freehook/) | verified | high | 2026-11-13 |
| [glibc 2.23 UAF 堆题：unsorted bin 泄露 libc、fastbin dup 打 __malloc_hook，realloc+6 调栈帧满足 one_gadget](binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget/) | verified | high | 2026-11-06 |
| [glibc 2.23 unsafe unlink：伪造 chunk 劫持 chunks 数组后 GOT 泄露与 system 覆写](binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system/) | verified | high | 2026-11-06 |
| [glibc 2.24–2.27 vtable 校验绕过：vtable 指向 _IO_str_jumps-0x8，让 _IO_OVERFLOW 槽落到 _IO_str_finish 经 _s._free_buffer 调 system](binary-pwn-heap-io-str-jumps-finish-free-buffer-system/) | verified | high | 2026-11-08 |
| [glibc 2.31 off-by-null 无 UAF：伪造 prev_size 落入 unsorted bin 合并出重叠块，tcache 投毒打 __free_hook](binary-pwn-heap-glibc231-offby-null-no-uaf-overlap-tcache-freehook/) | verified | high | 2026-11-13 |
| [glibc 2.31 tcache counts 校验下的 __malloc_hook 毒化：至少两个同尺寸 chunk 入 bin 才能把 fd 改成 hook 并取 one_gadget](binary-pwn-heap-glibc231-tcache-counts-malloc-hook-onegadget/) | verified | medium | 2026-11-08 |
| [glibc 2.31 UAF edit 清 tcache key：同一 chunk 反复 free 填满 tcache，切分 unsorted 块泄 libc 后毒化 __free_hook](binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook/) | verified | medium | 2026-11-11 |
| [glibc 2.31 UAF 堆题：largebin attack 覆写 mp_.tcache_bins 让 large chunk 进 tcache，毒化 __free_hook 为 system](binary-pwn-heap-uaf-largebin-mp-tcache-bins-freehook-system/) | verified | high | 2026-11-13 |
| [glibc 2.31 无 edit 堆题：fastbin 双 free 后倒灌 tcache，重叠块改 fd 打 __free_hook→system](binary-pwn-heap-glibc231-fastbin-stash-tcache-freehook-system/) | verified | high | 2026-11-11 |
| [glibc 2.31+ 高版本 large bin attack：中间插入分支的双链表检查与 bk/bk_nextsize 双写点](binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks/) | verified | medium | 2026-11-06 |
| [glibc 2.32+ safe-linking 下 tcache fd 劫持：空 bin 泄露页号重编码指针打 __free_hook](binary-pwn-heap-glibc232-safe-linking-page-leak-freehook-onegadget/) | draft | high | 2026-11-13 |
| [glibc 2.35 exit 链利用：largebin attack 同时改 __exit_funcs 与 TLS pointer_chk_guard，伪造 initial 调 system](binary-pwn-heap-exit-initial-largebin-tls-key-forge/) | verified | medium | 2026-11-08 |
| [glibc 2.35 fastbin reverse into tcache：fastbin 必须恰好 7 块，改写最后一个 chunk 的 fd 实现任意地址分配](binary-pwn-heap-glibc235-fastbin-reverse-into-tcache-last-fd-arbitrary-alloc/) | verified | medium | 2026-11-08 |
| [glibc 2.35 House of Botcake 变体：0x20 间隔块用 malloc_consolidate 合并后再 unlink，tcache 毒化 _IO_list_all + House of Apple2](binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2/) | verified | medium | 2026-11-08 |
| [glibc 2.35 largebin attack 改 _IO_list_all：fake wide FILE 经 setcontext 转 openat2 ORW](binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw/) | verified | high | 2026-11-05 |
| [glibc 2.35 off-by-null + unlink 劫持 bss chunk/size 数组：改大 size 造堆溢出，largebin attack 改写 stderr 指针 + House of Apple2 执行 system](binary-pwn-heap-glibc235-offby-null-unlink-bss-size-array-largebin-apple2-stderr/) | verified | medium | 2026-11-12 |
| [glibc 2.35 off-by-null + 高版本 unlink：伪造 size/prev_size 通过检查，劫持全局 chunk 数组、__environ 泄露栈并 ROP](binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop/) | verified | medium | 2026-11-06 |
| [glibc 2.35 tcache key 清零绕过 double free：safe-linking 毒化到栈泄露 libc 后写 ROP](binary-pwn-heap-glibc235-tcache-key-clear-stack-poison-rop/) | verified | medium | 2026-11-08 |
| [glibc 2.35 UAF + tcache safe-linking 打全局 ptr 数组：environ 泄栈后改 edit 的 rbp 写 ROP，避开 tcache_key 清零](binary-pwn-heap-glibc235-uaf-tcache-ptr-array-rbp-rop/) | verified | medium | 2026-11-08 |
| [glibc 2.35 单 chunk UAF：清零 tcache key 绕过 double free + 覆写 counts 扩容，environ 泄露栈后 ROP](binary-pwn-heap-glibc235-tcache-counts-key-clear-environ-rop/) | verified | medium | 2026-11-08 |
| [glibc 2.35 堆题打栈：environ 前置 chunk 越界读泄栈、tcache 毒化栈帧写 ORW](binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw/) | verified | high | 2026-11-08 |
| [glibc 2.35 无 UAF 堆溢出：相邻块覆盖泄 libc/heap，large bin attack 改 _IO_list_all 伪造 wide FILE 经 leave_ret 转 open/read/write](binary-pwn-heap-glibc235-overflow-largebin-io-list-all-wide-file-orw/) | verified | high | 2026-11-09 |
| [glibc 2.37 UAF 链：tcache 毒化全局结构体 + environ 泄露栈 + 栈上 ROP](binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop/) | verified | medium | 2026-11-05 |
| [glibc 2.38 off-by-null + largebin 泄露 + tcache_perthread_struct 劫持：伪 counts/entries 返回 stdout 做 IO leak，再投毒栈写 ROP](binary-pwn-heap-glibc238-offby-null-largebin-tcache-perthread-stdout-stack-rop/) | verified | high | 2026-11-13 |
| [glibc 2.39 largebin attack + House of Apple2 直接 system：tcache 指针加密与 libc 基址高位随机化下的泄露适配](binary-pwn-heap-glibc239-largebin-apple2-tcache-encryption-libc-highbyte/) | verified | medium | 2026-11-08 |
| [glibc 2.39 largebin attack 改写 mp_.tcache_bins：放大 tcache 上限后毒化栈返回地址](binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop/) | verified | high | 2026-11-05 |
| [glibc 2.39 leakless RCE：largebin attack 放大 mp_.tcache_bins 后从堆数据分配出 stdout，再以 house of cat/emma FSOP 执行 system](binary-pwn-heap-leakless-mp-tcache-bins-stdout-fsop/) | verified | high | 2026-11-06 |
| [glibc 2.39 tcache safe-linking fd 泄露栈：绕过 environ 的 0x10 对齐限制并把 chunk 分配到栈上](binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack/) | verified | medium | 2026-11-06 |
| [glibc 2.41 exit handler 攻击：覆写 pointer_guard 后伪造 initial __exit_funcs 调 system](binary-pwn-heap-glibc-exit-initial-pointer-guard-forge-system/) | verified | high | 2026-11-07 |
| [glibc 2.41 Tcache Reverse Into Fastbin + fastbin dup：受限 UAF 下构造任意地址分配](binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc/) | verified | high | 2026-11-07 |
| [glibc 2.42+ tcache_key 绕过：UAF 清 key 构造 tcache dup，poisoning 覆写 free@GOT 到 system](binary-pwn-heap-glibc243-tcache-key-bypass-got-system/) | verified | high | 2026-11-05 |
| [glibc 2.43 tcache_perthread_struct 劫持：改写 entries 实现任意地址分配与栈 ROP](binary-pwn-heap-glibc243-tcache-perthread-struct-hijack/) | verified | medium | 2026-11-05 |
| [glibc ≤2.28 off-by-null：伪造 prev_size 指向已释放 chunk，利用 unlink 检查缺陷合并出重叠 unsorted chunk](binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap/) | verified | medium | 2026-11-08 |
| [HackNote 型 UAF：struct 与 content 双分配，重建 note 时新 content 落到旧 struct 上覆写函数指针](binary-pwn-heap-hacknote-content-overlaps-struct-funcptr/) | verified | high | 2026-11-09 |
| [heap2 UAF 认证绕过：free(auth) 后 strdup 连续复用相邻 chunk 覆盖 auth 标志](binary-pwn-heap-uaf-strdup-reuse-auth-flag/) | verified | high | 2026-11-08 |
| [House of Apple 2 覆盖 _IO_2_1_stderr_ 从 exit 触发 FSOP 拿 shell](binary-pwn-heap-house-of-apple-2-stderr-fsop/) | verified | high | 2026-11-04 |
| [House of Apple2 源码级复现：largebin attack 改 _IO_list_all + _IO_wfile_overflow/_IO_wdoallocbuf 劫持 _wide_vtable](binary-pwn-heap-house-of-apple2-source-analysis-largebin-system/) | verified | medium | 2026-11-06 |
| [House of Apple2 部分覆盖 chunk header：_wide_data 错位修正 + svcudp_reply+26 经 fake xdr_ops 栈迁移 ORW](binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw/) | verified | high | 2026-11-06 |
| [House of Banana：伪造 _rtld_global._ns_loaded 的 link_map 链，借 _dl_fini 的 DT_FINI_ARRAY 在 exit 时执行 shell](binary-pwn-heap-house-of-banana-link-map-dl-fini/) | verified | high | 2026-11-08 |
| [House of Blindless：无泄露相对写改 link_map，低位覆盖 DT_FINI 指针经 _dl_fini 调 system@plt](binary-pwn-heap-house-of-blindless-link-map-dt-fini-low-byte/) | verified | high | 2026-11-13 |
| [House of Botcake 无 edit/show 实战：stdout IO leak 后借 unsorted 切割布置第二条 tcache 链，二次投毒打 __free_hook](binary-pwn-heap-house-of-botcake-second-poisoning-io-leak-freehook/) | verified | high | 2026-11-13 |
| [House of Botcake：填满 tcache + unsorted bin 合并绕过 double free 检查，重新投毒 tcache](binary-pwn-heap-house-of-botcake-tcache-poison/) | verified | high | 2026-11-05 |
| [House of Cat：伪造 IO_FILE 借 _IO_wfile_seekoff → _IO_switch_to_wget_mode → _IO_WOVERFLOW 无 vtable 检查劫持 _wide_vtable，经 FSOP / __malloc_assert 触发并 setcontext 栈迁移 RCE](binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check/) | verified | high | 2026-11-08 |
| [House of Corrosion：放大 global_max_fast 后用超大 chunk 造成 main_arena.fastbinsY 数组越界写，按 size=(target-top)*2-0x10 精确落到 _IO_list_all / printf 表并配合 House of Husk 取 one_gadget](binary-pwn-heap-house-of-corrosion-fastbiny-oob-io-list-all-null-fp/) | verified | high | 2026-11-09 |
| [House of Einherjar：off-by-null 清 PREV_INUSE + 伪造 prev_size/fake chunk 向前合并，堆重叠后 tcache poisoning 任意地址分配](binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison/) | verified | high | 2026-11-07 |
| [House of emma：伪造 _IO_cookie_jumps 虚表 + PTR_MANGLE 函数指针，largebin attack 改写 stderr 与 pointer_guard 后经 malloc_assert 触发任意调用](binary-pwn-heap-house-of-emma-cookie-jumps-pointer-guard/) | verified | medium | 2026-11-13 |
| [House of Force：改 top chunk size 为极大值后一次任意大小申请把 top 挪到 __malloc_hook，再申请写入 system](binary-pwn-heap-house-of-force-topchunk-to-malloc-hook/) | verified | high | 2026-11-08 |
| [House of Husk（glibc 2.23–2.35）：unsorted bin attack 放大 global_max_fast，借 main_arena fastbin 数组改写 __printf_function_table/__printf_arginfo_table 后 printf("%X") 调 one_gadget](binary-pwn-heap-house-of-husk-printf-arginfo-table-global-max-fast-onegadget/) | verified | high | 2026-11-07 |
| [House of Husk：劫持 __printf_function_table 与 __printf_arginfo_table[spec] 实现一次任意函数调用](binary-pwn-heap-house-of-husk-printf-arginfo-table/) | verified | high | 2026-11-07 |
| [House of kiwi：__malloc_assert → fflush(stderr) 劫持 _IO_file_jumps.sync 为 setcontext+61，借 IO_helper_jumps 迁到堆上 ROP（glibc 2.29+ 无 exit/无 hook 场景）](binary-pwn-heap-house-of-kiwi-malloc-assert-file-jumps-sync-setcontext/) | verified | medium | 2026-11-13 |
| [House of Lore：伪造 small bin 的 bk/fd 链把目标地址挂入 smallbin，两次 malloc 在栈等任意地址分配 chunk（glibc 2.23-2.30）](binary-pwn-heap-house-of-lore-smallbin-fake-chunk/) | verified | high | 2026-11-08 |
| [House of Orange 式 unsorted bin attack + FSOP：改 _IO_list_all 为 main_arena，借 0x60 smallbin 伪造 FILE vtable 调 system](binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system/) | verified | high | 2026-11-06 |
| [House of Peach：无 free 函数时借 sysmalloc 释放旧 top chunk 伪造 unsorted/largebin](binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin/) | verified | high | 2026-11-06 |
| [House of Pig（glibc 2.31–2.34）：largebin attack 改 _IO_list_all + tcache stashing unlink 植入 __free_hook-0x10 + _IO_str_overflow 的 malloc/memcpy 覆写 system](binary-pwn-heap-house-of-pig-io-str-overflow-tcache-stashing-freehook-system/) | verified | high | 2026-11-07 |
| [House of Rabbit：malloc_consolidate 不校验 fastbin size，BSS 伪造 chunk 经 unsorted/largebin 改写 size 实现任意地址分配](binary-pwn-heap-house-of-rabbit-malloc-consolidate-fake-chunk-largebin-arbitrary-alloc/) | verified | high | 2026-11-08 |
| [House of Roman：无 libc 泄露下 fastbin 局部覆写 + unsorted bin attack 把 __malloc_hook 改写为 one_gadget（12-bit 爆破）](binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce/) | verified | high | 2026-11-08 |
| [House of Spirit：用 BSS 全局计数与指针拼出 0x40 假 fastbin chunk，free 后重新 malloc 覆盖 message 指针劫持 strlen GOT](binary-pwn-heap-house-of-spirit-bss-counter-fake-chunk-strlen-got/) | verified | medium | 2026-11-09 |
| [House of Storm：unsorted bin + large bin 双写伪造任意地址 chunk 劫持 __free_hook](binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk/) | verified | high | 2026-11-05 |
| [jemalloc 无 chunk 头：free 块内任意地址都释放整块，误传 &p_fun_chunk 释放掉 table 造成 stale 指针与多块重叠，取得任意读写后改函数指针走 setcontext](binary-pwn-heap-jemalloc-free-anywhere-in-chunk-whole-chunk-free-overlap/) | verified | medium | 2026-11-09 |
| [Largebin Attack 高低版本差异：2.31 前双写 vs 2.31+ 小者插入分支单写绕过检查](binary-pwn-heap-largebin-attack-version-diff-smaller-insert-bypass/) | verified | high | 2026-11-08 |
| [libc 2.35 菜单堆题：edit 的 num>cnt 越界下标编辑已 free 的 routes[0]，unsorted 泄露 + largebin attack + House of Apple2 ORW](binary-pwn-heap-edit-oob-freed-largebin-house-of-apple2-orw/) | verified | medium | 2026-11-08 |
| [mark 与指针分离的 note 管理器 UAF：delete 只清 mark、元数据小堆块可被重新分配，变成任意读与任意 free](binary-pwn-heap-mark-pointer-split-metadata-uaf-arbitrary-read-free/) | verified | medium | 2026-11-08 |
| [nginx rewrite+set 双引擎 is_args 不一致堆溢出（CVE-2026-42945）：+ 号 1→3 展开冲爆 buffer](binary-pwn-heap-nginx-rewrite-isargs-dual-engine-overflow/) | verified | high | 2026-11-05 |
| [pack 压缩后 stale cap：note data 缩小但 cap 未同步，show/edit 越界读写相邻 note 并改全局 exit 函数指针低字节](binary-pwn-heap-pack-stale-cap-oob-note-struct-function-pointer/) | verified | high | 2026-11-06 |
| [protobuf 堆题 ez_buf：固定 0x30 memcpy 过读泄 libc、UAF 泄 safe-linked tcache 得堆基址，fastbin double free 后毒化 tcache 到 GOT 写 one_gadget](binary-pwn-heap-protobuf-ez-buf-memcpy-overread-tcache-safelink-got-onegadget/) | verified | medium | 2026-11-09 |
| [protobuf 消息驱动的 note 管理器 free 后清零写到固定偏移（写 A060 而非真实 chunk A460）造成稳定 UAF：unsorted bin 泄 libc/heap → free_hook → magic gadget 转 rdx → setcontext+61 → mprotect 堆页 → ORW shellcode](binary-pwn-heap-protobuf-free-zero-wrong-slot-uaf-freehook-mprotect-shellcode/) | verified | medium | 2026-11-09 |
| [protobuf-c 协议堆题 free/overlap 链：content 长度控块伪造大 chunk 泄露 libc/heap，tcache 污染 _IO_list_all 走 wide FILE 魔术 gadget ORW](binary-pwn-heap-protobuf-c-free-overlap-fsop-orw/) | verified | medium | 2026-11-06 |
| [Protostar heap3 负数 size 触发 fastbin unlink：伪造 fd/bk 覆盖 puts@GOT 跳堆上 shellcode](binary-pwn-heap-heap3-negative-size-fastbin-unlink-puts-got-shellcode/) | verified | high | 2026-11-08 |
| [QuickJS 补丁引入的双重弹栈 UAF：OP_put_var 异常路径重复释放，经 JSString 越界泄露与 TypedArray 任意读写劫持 JSRuntime.mf 执行 system("/bin/sh")](binary-pwn-heap-quickjs-put-var-double-pop-uaf-jsruntime-hijack/) | verified | high | 2026-11-06 |
| [Redis HyperLogLog 稀疏编码越界写（CVE-2025-32023）：改相邻 SDS 类型伪造超长字符串泄堆，伪造 module robj 的 free 回调走 ROP](binary-pwn-heap-redis-hll-sparse-oob-sds-type-fake-robj-module-rop/) | verified | high | 2026-11-06 |
| [Redis Stream NACK 共享导致 Double Free：恶意 RDB + DELCONSUMER 的堆利用 RCE](binary-pwn-heap-redis-stream-nack-double-free-rce/) | verified | high | 2026-11-05 |
| [Robo_admin 堆题链：off-by-one 改 size + unlink 泄露 + House of Some + IO_FILE FSOP 执行 shellcode](binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile/) | verified | medium | 2026-11-06 |
| [scanf 数字解析触发内部 malloc(0x800)：固定大小堆题中强制 unsortedbin 排序的分配原语](binary-pwn-heap-scanf-scratch-buffer-malloc-sorting/) | verified | high | 2026-11-06 |
| [stdout 部分覆写泄露 libc：改 _flags 与 _IO_write_base 低字节扩大输出窗口](binary-pwn-heap-stdout-partial-overwrite-libc-leak/) | verified | high | 2026-11-05 |
| [strcmp 逐字节爆破 libc 指针：利用 NUL 截断与指针低字节左移泄露 main_arena](binary-pwn-heap-strcmp-bytewise-libc-pointer-leak/) | verified | high | 2026-11-05 |
| [Tcache Stashing Unlink Attack：calloc 触发 smallbin→tcache 批量搬运，篡改 bk 实现任意地址写 libc 指针与栈上 fake chunk 分配](binary-pwn-heap-tcache-stashing-unlink-calloc-stack-fake-chunk/) | verified | high | 2026-11-08 |
| [tcache 毒化 _IO_list_all + House of Apple2（glibc 2.39）：堆块合并/UAF 泄堆后伪造 FILE 调 system](binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2/) | verified | medium | 2026-11-07 |
| [tcache/fastbin 取出 chunk 不清 next/fd：无 UAF 也能从申请出的块残留指针泄漏堆地址](binary-pwn-heap-no-uaf-heap-leak-tcache-fastbin-stale-fd/) | verified | high | 2026-11-08 |
| [TSU+ 打 tcache_perthread_struct：smallbin bk 塞入堆内假 chunk，直接改写 tcache entries 绕过 safe-linking](binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries/) | verified | high | 2026-11-06 |
| [UAF 函数指针劫持：释放后不置空，同大小分配复用旧块改写回调](binary-pwn-heap-uaf-function-pointer-hijack/) | verified | high | 2026-11-05 |
| [UAF 悬空指针配合 unsorted bin 泄露 libc 基址](binary-pwn-heap-uaf-unsorted-bin-libc-leak/) | verified | high | 2026-11-04 |
| [unsorted bin attack 放大 global_max_fast：BSS 假 fastbin 块覆盖 ptr 数组后改 __free_hook](binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook/) | verified | medium | 2026-11-06 |
| [WKCTF2024 easy_heap：无 del 用 house_of_orange 将 top chunk 送入 fastbin，edit 溢出改 fd 分配到 fake_chunk，改 puts GOT 泄 libc + one_gadget](binary-pwn-heap-house-of-orange-fastbin-got-onegadget/) | verified | medium | 2026-11-08 |
| [WMCTF2023 blindless：Brainfuck 解释器指令集转换为相对任意写，借 mmap 大块邻近 libc 爆破 exit_hook（system + _dl_load_lock）](binary-pwn-heap-wmctf2023-blindless-brainfuck-relative-write-exit-hook-bruteforce/) | verified | medium | 2026-11-13 |
| [XOR 编码堆指针 + lucky number 任意 free：strlen 空字节截断制造 note 重叠，泄露 PIE/heap/libc 后 one_gadget](binary-pwn-heap-xor-chunklist-lucky-number-arbitrary-free-uaf/) | verified | medium | 2026-11-06 |
| [事务快照结构未初始化：MULTI/EXEC/ABORT 组合的 UAF、任意 free 与任意读](binary-pwn-heap-uninitialized-tx-context-uaf-arbitrary-free-read/) | verified | high | 2026-11-05 |
| [仅一次 free 的堆题：House of Orange 造 unsorted bin 泄 libc，再用这一次 free 做 fastbin 改 __malloc_hook 打 one_gadget](binary-pwn-heap-house-of-orange-single-free-fastbin-malloc-hook-onegadget/) | verified | high | 2026-11-09 |
| [伪文件系统 off-by-null 触发 House of Einherjar：chunk 重叠后 largebin attack 改 _IO_list_all 转 wide FILE FSOP ORW](binary-pwn-heap-vfs-offby-null-einherjar-largebin-io-list-all-fsop/) | verified | medium | 2026-11-06 |
| [伪造 unsorted bin chunk 释放时衔接 top chunk：用「下下个 chunk」的 PREV_INUSE=1 跳过 free 合并检查](binary-pwn-heap-fake-unsorted-chunk-prev-inuse-merge-bypass/) | verified | medium | 2026-11-07 |
| [位图式堆管理器的负索引越界：ip/num 掩码使起始下标小于 base，退化成向前任意位写（清 P 位进 unsortedbin → tcache 劫持 GOT）](binary-pwn-heap-bitmap-negative-index-backward-arbitrary-bit-write/) | verified | high | 2026-11-08 |
| [借 malloc_consolidate 在 malloc 路径触发 unlink：伪造 fastbin chunk 制造堆块重叠（glibc 2.29）](binary-pwn-heap-malloc-consolidate-unlink-overlapping-via-malloc/) | verified | high | 2026-11-08 |
| [元数据数组相邻 + 索引上界 off-by-one：add 第 33 块时 size 低字节覆写 chunk_ptr[0] 最低字节，show 改读新地址泄露 heap base](binary-pwn-heap-metadata-array-offbyone-chunkptr-low-byte-heap-leak/) | verified | high | 2026-11-08 |
| [全交互数据被 RC4 加密的堆题：客户端先实现同一 KSA/PRGA 才能泄 libc，再用 UAF 把 free_hook 改成 setcontext+53 迁栈执行 ORW](binary-pwn-heap-rc4-encrypted-io-uaf-freehook-setcontext-orw/) | verified | high | 2026-11-09 |
| [单次任意地址写 00 扩大 stdin 输入缓冲区：覆盖 stdout FILE → puts _IO_sputn → house of emma/cat → setcontext ORW](binary-pwn-heap-nullbyte-stdin-buffer-expand-stdout-fsop/) | verified | high | 2026-11-06 |
| [只能操作最新 chunk 的堆题：劫持 tcache_perthread_struct 批量布置 fake chunk，free_hook→setcontext+53（0x35，mov rsp,[rdi+0xa0]）迁栈执行 ORW](binary-pwn-heap-latest-chunk-only-tcache-perthread-setcontext-orw/) | verified | high | 2026-11-09 |
| [只能申请 fastbin 大小时用耗尽 top chunk 触发 malloc_consolidate：fastbin 块被合并进 unsorted bin，借 UAF-Read 读出 main_arena 指针](binary-pwn-heap-topchunk-exhaustion-malloc-consolidate-fastbin-unsorted-libc-leak/) | verified | high | 2026-11-08 |
| [同页 tcache 双 free 自异或恢复精确堆地址（safe-linking 免泄露）](binary-pwn-heap-safe-linking-self-xor-heap-address/) | verified | high | 2026-11-04 |
| [堆 UAF 结构体复用：free 顺序让 user 结构体被重分配为密码缓冲区，改写 data 指针实现任意读写](binary-pwn-heap-uaf-struct-reuse-data-pointer/) | verified | high | 2026-11-05 |
| [堆题/任意写场景 exit_hook one_gadget：负 size 邻接 libc 映射泄露 + 逐字节改写 _rtld_global](binary-pwn-heap-exit-hook-onegadget-negative-size-arbitrary-write/) | verified | high | 2026-11-08 |
| [巅峰极客 2022 smallcontainer：两段 off-by-null 伪造 prev_size/size 触发 unlink 与 chunk overlap，tcache 篡改 __free_hook 为 system](binary-pwn-heap-dianfeng-2022-smallcontainer-offby-null-unlink-overlap-tcache-freehook/) | verified | high | 2026-11-13 |
| [已知 AES key 但 add 只给 0x30 且分配被锁在堆内时：连续伪造 largebin chunk 打 _IO_list_all → House of Apple2（_IO_wfile_jumps-0x40 + setcontext+61）做 ORW](binary-pwn-heap-aes-key-known-then-largebin-io-list-all-house-of-apple2-orw/) | verified | medium | 2026-11-09 |
| [循环双向链表 delete 唯一节点仍走断链分支：current 悬空后 edit 缺 count 检查形成 UAF 写](binary-pwn-heap-circular-dlist-delete-count1-uaf/) | verified | high | 2026-11-06 |
| [指针数组 idx 无上限 + mmap/堆固定偏移：把受控缓冲区中的 qword 当 chunk_ptr[idx]，实现任意地址写任意值并打 stderr FSOP](binary-pwn-heap-unbounded-idx-pointer-array-mmap-fixed-offset-arbitrary-write/) | verified | high | 2026-11-08 |
| [换行符 off-by-one：size 差 0xA 多写 1 字节，清 PREV_INUSE 造 unsorted bin 重叠泄露](binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap/) | verified | medium | 2026-11-06 |
| [无 show 且只能申请 fastbin 大小：伪造 0xd1 unsorted 块与 fastbin 块重叠把 main_arena 指针写进 fd，部分覆写 stdout 泄露后再打 __malloc_hook](binary-pwn-heap-no-show-fastbin-unsorted-overlap-stdout-bruteforce-malloc-hook/) | verified | medium | 2026-11-08 |
| [无 show 功能时的替代泄露：未初始化栈缓冲区 + read 不补 NUL 打出 libc 指针，再用 UAF 写 tcache fd 打 __malloc_hook](binary-pwn-heap-uninit-stack-buffer-leak-tcache-dup-malloc-hook/) | verified | high | 2026-11-08 |
| [无 show 堆题：largebin attack 预置 bk + tcache stashing unlink 将固定 mmap 地址塞入 tcache](binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write/) | verified | high | 2026-11-06 |
| [无 UAF 的堆题：edit 溢出改写相邻块 size 造 chunk 重叠泄露 libc，再由二次释放同址把 free_hook 写成 system](binary-pwn-heap-size-field-overlap-freehook-after-free-reuse/) | draft | high | 2026-11-09 |
| [有 show 但只能读到代码段地址的 off-by-one 堆题：叠块 + tcache 打 _IO_2_1_stdout_ 泄 libc，再改 __free_hook 走 setcontext + mprotect 执行 ORW shellcode](binary-pwn-heap-offbyone-show-codebase-stdout-leak-freehook-mprotect-orw/) | verified | high | 2026-11-08 |
| [未初始化 WebSocket session + 负 frag_len 下写：伪造堆头进 tcache 并覆盖 session 做 AAR/AAW](binary-pwn-heap-uninitialized-session-negative-fraglen-tcache/) | verified | high | 2026-11-06 |
| [湖湘杯 2019 HackNote：edit 用 strlen 重算大小制造 off-by-one，篡改相邻 chunk size 成 chunk overlap，fastbin attack 改 __malloc_hook 执行 shellcode](binary-pwn-heap-hunan-cup-2019-hacknote-offbyone-strlen-size-overlap-fastbin-malloc-hook-shellcode/) | verified | high | 2026-11-13 |
| [湾区杯2025 digtal_bomb：猜数范围逻辑绕过进入堆菜单，off-by-null + House of Einherjar 造重叠泄露 libc，tcache 投毒 strlen GOT 打 one_gadget](binary-pwn-heap-digtal-bomb-offby-null-einherjar-tcache-strlen-got-onegadget/) | verified | medium | 2026-11-07 |
| [用 environ 作 libc↔栈地址桥：泄露 environ 得栈地址 + 固定偏移定位函数 epilogue 的 rsp，再用任意地址写覆盖返回地址劫持控制流](binary-pwn-heap-environ-leak-fixed-offset-stack-hijack/) | verified | high | 2026-11-09 |
| [用 realloc 的边界语义当原语：size 自选 → size=0 等价 free 造 unsorted bin 泄 libc，再靠 2.27 tcache 无 double-free 检查把 free_hook 写成 system](binary-pwn-heap-realloc-size0-free-tcache-dup-freehook/) | verified | high | 2026-11-09 |
| [笔记堆题：add 只申请 0x1c 却在 edit 里按 0x28 校验并 memcpy 0x20，溢出覆写下一块 chunk 的函数指针为 backdoor](binary-pwn-heap-alloc-0x1c-edit-limit-0x28-chunk-funcptr-backdoor/) | verified | medium | 2026-11-08 |
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
