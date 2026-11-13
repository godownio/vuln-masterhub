---
id: binary-pwn-heap-android-jemalloc-new-allocator-internals
title: Android jemalloc 'new' 分配器机制与利用面（前置知识）：arena/extent/slab/bin/tcache 结构与堆风水要点
type: scenario
domain: binary
path: binary/pwn/heap
technique: android-jemalloc-new-allocator-internals
tags:
- pwn
- heap
- android
- jemalloc
- allocator
- internals
- tcache
- heap-grooming
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V692
  verified_at: '2026-11-13T18:08:29+08:00'
  notes: 已对照原文与5张图逐图核对：图01 梗图（Samsung Galaxy S23 仍用 jemalloc new，非 Scudo）；图02 arena/extent/slab(regions)/large alloc 与 tcache bins_small/bins_large、Random offset 总览；图03 arena_t 的 dirty/muzzy/retained extents、bins[NBINS] 与 bin_t slabcur/slabs_nonfull/slabs_full 指针关系；图04 bin_t 指向各 slab extent 的 ph_link/ql_link；图05 tcache avail 负索引栈（avail[-ncached] 待分配、avail[-1] 最后入栈）与 slab region 关系。卡内 arena(2个)/extent(页对齐、序列号、rtree)/size class(64位 36 small，8~0x3800，slab 0x1000/0x3000/0x5000/0x7000；>0x3800 large)/bin/tcache/opt_retain=1 不 unmap/无内联元数据/无 canary 均与原文一致，未夸大（无完整 exploit，按前置知识写法，severity low、confidence medium 恰当）。修正：extent 选择算法版本表述按原文正文(5.2.1)与所引源码注释(5.2.0)不一致改为并列说明。前置知识定位与既有 binary-pwn-heap-android-scudo-allocator-defense-internals（同 path、同 type/severity/confidence 惯例）一致；dedup 仅自匹配、与 Scudo 卡 related 不同分配器，dup-scan 无 pair；wikilink 目标 Scudo 卡与 jemalloc free-anywhere 卡均存在。原文为机制分析未标受影响版本，未设 affected_versions 正确。未验证点：未在真机/模拟器复测；tcache 上限 0x10000、NBINS=36 等为原文与源码表所载。
url: /docs/binary/pwn/heap/binary-pwn-heap-android-jemalloc-new-allocator-internals/
draft: false
kb_aliases:
- jemalloc new
- Android jemalloc 5
- je_ 符号
- extent_t
- tcache_t
- arena_t
- slabcur
- opt_retain
---

## 一句话结论

Android 10+ libc 中的 jemalloc 'new'（jemalloc >=5，AOSP external/jemalloc_new，提交 b0dbd53 对应 5.1.0）用 arena（2 个，线程绑定其一）、extent（可变大小、页对齐、rtree 全局索引）、slab/region、bin 与线程本地 tcache 管理堆：元数据不与用户数据内联、默认 `opt_retain=1` 不 unmap、无 canary；写 Android 堆利用时的关键结论是——同线程 tcache 使 UAF 复用很容易，跨线程复用需要清空 tcache 且两线程共享同一 arena，大分配有 0x40 粒度的随机偏移，且 <=0x3800 走 slab（36 个 size class）、>0x3800 走 large extent（tcache 只缓存到 0x10000）。

## 原理

- **如何识别**：`readelf -s libc.so | grep je_ | wc -l` 超过 100（文中 292）说明用 jemalloc；再看 `grep extent | wc -l`，新版约 100（文中 81）、旧版约 10。不同设备/ROM 即使同 Android 版本也可能用不同分配器（Pixel 4a 5G Android 13 用 Scudo，Galaxy S23 Android 13 仍是 jemalloc new）。
- **arena**：`arena_t` 独立管理部分内存以减少锁竞争，Android 只有 2 个 arena，线程绑定其一；跨线程 UAF 复用要求两线程落在同一 arena。arena 维护 dirty/muzzy/retained 三个空闲 extent 堆（按释放时间由近到远）与 `bins[NBINS]`（Android 64 位 NBINS=36）。
- **extent**：替代旧版固定 2MB chunk 的可变虚拟内存段（页的整数倍，`pages_map` mmap 创建），有序列号；可拆分（继承父序列号）与合并（保留最小序列号，需地址连续且同 arena）。全局 `extents_rtree` 基数树按地址索引所有 extent，free 时用于定位。`extent_t` 关键字段：`e_bits`（元数据/序列号）、`e_addr`（实际映射地址）、`ql_link/ph_link`（列表/堆节点）、`e_slab_data`（slab 时空闲位图）。**元数据与数据不连续存放**。
- **size class**：`SIZE_CLASSES` 宏按架构定义，64 位 aarch64 下 index 0..35 为 small（8、16、32…0x3800），slab 大小按 class 取 0x1000/0x3000/0x5000/0x7000，region 数 = slab/alloc；> 0x3800 为 large class（0x4000 起，最大到 2^63 级）。
- **bin 与 slab**：每个 size class 一个 `bin_t`，含 `slabcur`（当前加速分配）、`slabs_nonfull` 堆、`slabs_full` 列表；slabcur 满后入 full，从 nonfull 取新 slab。
- **extent 选择算法**：先查当前 arena 的 extents_dirty（原文正文称 5.2.1 起改用 first-fit/最低位，所引源码注释称 best-fit 代码在 5.2.0 已完全移除；旧 best-fit 有泄漏风险），再 muzzy、retained，最后 mmap 新 extent（大小由 `extent_grow_next` 索引查全局 `sz_pind2sz_tab`，新块一部分立即用、其余入 retained）。
- **large 分配**：选 M >= N 的最接近 size class，申请 M+0x1000；返回指针在 base 与 base+0x1000 间以 0x40 粒度随机（`extent_addr_randomize`），仅从 extent 堆取时随机化，从 tcache 取则地址不变。
- **tcache**：每线程 `tcache_t` 含 `bins_small[NBINS]` 与 `bins_large[NSIZES-NBINS]`，每个 `cache_bin_t` 的 `avail` 是负索引栈指针：`avail[-ncached]` 为下一个待分配、`avail[-1]` 为最后入栈；push/pop 只动索引。large 仅 <= `1<<opt_lg_tcache_max`（Android 默认 0x10000）入 tcache。tcache 与 arena 关联，但缓存指针可来自其他 arena 的 extent/slab。
- **flush 机制**：bin 满（`ncached == ncached_max`）时丢弃一半最旧条目；`gc_ticker` 计数到 0 触发 GC，清空 `next_gc_bin` 指向的 bin 并循环，按 low_water 丢弃 3/4 最旧。清出的 small region 回 `arena->bins[i]`，large extent 回 `arena->extents_dirty`。
- **分配/释放路径**：malloc 先查 tcache，再查 arena bin/extent 堆，必要时新 mmap；free 用 rtree 找 extent→size class：small 入 tcache small（满则 flush），large <=0x10000 入 tcache large，>0x10000 直接回 extents_dirty。
- **利用面**：① 无内联 canary，堆溢出可直接覆盖相邻 region/extent（但 large 有 0x40 随机偏移，增加利用难度）；② UAF 同线程释放后可立即从 tcache 拿回同地址；跨线程需 flush 并同 arena；③ 默认 `opt_retain=1`，extent 永不 unmap，释放后内存仍映射可访问。

## 触发条件

- 目标 Android 设备的 libc 使用 jemalloc 'new'（`je_` 符号 ~292、`extent` 符号 ~81；多在 Android 10-13 且非 Pixel 等切 Scudo 的机型）；
- 已存在堆漏洞原语（UAF、堆溢出、double free、可控大小分配/释放），且攻击者能控制分配/释放的时机、大小与线程；
- 需要按目标二进制 dump `je_sz_pind2sz_tab` 与 size class 表确认偏移；TCG/模拟器与真机行为可能不同。

## 利用步骤

（本卡为机制/前置知识，下列为编写利用时的评估步骤，不是完整 exploit）

1. 用 readelf 统计 `je_` 与 `extent` 符号判断分配器新旧；确认 Android 版本与机型。
2. 按 size class 表选定目标分配大小：尽量用 small（<=0x3800，slab 内 region 相邻可控）或 tcache 覆盖的 large（<=0x10000）；避开 >0x10000 的 extent 随机偏移。
3. 评估 UAF：同线程 `malloc→free→malloc` 预期返回同一 region（tcache LIFO），可直接用新对象占位；跨线程需让两线程同 arena 并触发 flush。
4. 评估溢出：小分配无内联元数据，覆盖相邻 region 不影响本块 free；若覆盖 extent 元数据（不连续）需另行信息泄露。
5. 计算堆风水：利用 `avail[-ncached]` 的 LIFO 顺序安排释放次序，使下一次分配命中目标位置；large 分配注意 0x40 随机偏移与 M+0x1000 的预留。
6. 结合具体漏洞选择目标（对象函数指针、长度字段、相邻 region 数据）并构造利用。

## PoC

```text
$ readelf -s libc.so | grep je_ | wc -l
292
$ readelf -s libc.so | grep extent | wc -l
81
# 64 位 aarch64 SIZE_CLASSES 摘要（index, size, slab）
SC(0)=8/0x1000  SC(1)=16/0x1000  SC(2)=32/0x1000  SC(3)=48/0x3000
SC(4)=64/0x1000 ... SC(35)=0x3800/0x7000（最后 small）
SC(36)=0x4000 large ...
# large 分配：malloc(0x9000) → 选 0xa000 class，映射 0xb000，返回 base..base+0x1000 内 0x40 对齐随机指针
```

## 变体与关联

- 变体：`opt_retain=0` 时 retained 会 unmap，释放后访问将 fault；不同机型/Android 版本 size class 与 tcache max 可能不同。
- 关联：[[binary-pwn-heap-android-scudo-allocator-defense-internals]]（Android 11+ 另一分配器，UAF/double-free 防护对照）、[[binary-pwn-heap-jemalloc-free-anywhere-in-chunk-whole-chunk-free-overlap]]（jemalloc 利用思路）、glibc tcache 相关卡（结构对照）。
- 边界：文章为源码分析+机制说明，无完整 Android 漏洞利用；实际利用受 SELinux、JNI/Renderer 沙箱与具体漏洞原语限制。

## 检测与防御

- 防御方：启用 Scudo/MTE 的新系统、限制 `opt_retain`、对敏感进程开启更严格的分配器随机化；及时修补提供 UAF/溢出原语的组件。
- 检测：异常 mmap 增长与不回收（opt_retain）、跨线程同地址复用模式、堆喷与 tcache 布局探测行为。
- 注意：jemalloc new 没有内联 canary、默认不 unmap，不能把"非 glibc"当作天然缓解。
