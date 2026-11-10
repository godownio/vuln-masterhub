---
id: binary-pwn-heap-bitmap-negative-index-backward-arbitrary-bit-write
title: 位图式堆管理器的负索引越界：ip/num 掩码使起始下标小于 base，退化成向前任意位写（清 P 位进 unsortedbin → tcache 劫持 GOT）
type: scenario
domain: binary
path: binary/pwn/heap
technique: bitmap-negative-index-backward-bit-write
tags:
- pwn
- heap
- bitmap
- negative-index
- arbitrary-bit-write
- unsorted-bin
- tcache-poison
- got-hijack
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T13:28:29+08:00'
  notes: 已对照原文与完整 exp 核对（本篇 img 目录 0 张，无需读图）：create 用 (v2-v1)>>3 + 1 的位图 malloc、add/delete 的 ptr[(i-start)/8] |= 1<<((i-start)&7) 与 &= ~ 位运算、ip/num 路由 v2 &= ~((1<<(32-num))-1) 与 v3 = ((1<<(32-num))-1)|v2、num 范围校验 0<num<=31、query 单 bit 读、free(ptr) 后置 0 无 UAF，均与原文一致；方法链（写 size 0x101 → delete /25 清 P 位 → free 进 unsortedbin 泄 libc → 循环进 smallbin → tcache 投毒 → ip 输入 /bin/sh 触发 system）与原文 exp 顺序一致，原文 17 解、完整跑通。核对时把 tcache 投毒目标从写死的 GOT 名改为原文表述的 strtok 内部某个 abs got 表项。未验证点：未本机编译/运行 exp；原文未标注版本/CVE；负下标依赖 i 为有符号整数的整除语义（exp 中 /25 掩码后 v2 落到 base 之前），若目标编译成无符号回绕则退化为正向偏移，此点按原文 exp 现象采纳。
url: /docs/binary/pwn/heap/binary-pwn-heap-bitmap-negative-index-backward-arbitrary-bit-write/
draft: false
kb_aliases:
- IP 段管理器位图越界
- 位图任意位写
- 负索引向前写堆
- 清 P 位进 unsorted bin
- 无 chunk 表堆题
---

## 一句话结论

当程序用一个 malloc 出来的位图（bitmap）按 `(idx - base)/8`、`1 << ((idx - base) & 7)` 来读写"某个区间内是否存在"时，只要有一条路径能把 `idx` 变得 **小于 base**，`(idx - base)` 就变成负数（C 里是有符号整数），下标落到 chunk 用户区之前 —— 于是 `|=` 与 `&= ~` 组合成"向前任意字节任意位的置位/清零"，可以精确改前一块的 `size` 低字节与 `PREV_INUSE` 位，把普通的 create/free 循环变成 unsorted bin 泄漏 + tcache 投毒 + GOT 覆盖。

## 原理

- 位图实现：`ptr[(i - start) / 8] |= 1 << ((i - start) & 7);` 与 `ptr[(i - start) / 8] &= ~(1 << ((i - start) & 7));`。当 `i >= start` 时是块内合法的置位/清零；当 `i < start` 时 `i - start` 为负，C 的整除与取模都向零取整，索引变成负的下标，等价于向前（低地址）访问 —— 直接命中前一个 chunk 的 `size` 字段/`prev_size`/用户数据。
- 使 `i < start` 的关键：`"ip/num"` 格式里先 `v2 &= ~((1 << (32 - num)) - 1)`，这只"清零低 (32-num) 位"，**不会**在之后重新校验 `v2 >= start`（`v2` 的范围检查发生在掩码之前）。若 `start` 本身末几位非 0，掩码后的 `v2` 会小于 `start`，循环 `for (i = v2; i <= v3; ++i)` 就从 base 之前开始写。
- 掩码同时把 `v3 = ((1 << (32 - num)) - 1) | v2` 推到区间尾部，因此一次调用可以在"base 之前 + base 之后"连续刷位，覆盖面足够改到前一 chunk 的头部。
- 位粒度写的好处：不必知道完整字节值，可以只把 `size` 的 `PREV_INUSE`（最低位）清 0，或只改 `size` 的低 2 字节；也能反向清零，便于把伪造值"修"到刚好通过 glibc 校验。
- 进 unsorted bin 的条件：被 free 的 chunk 其"下一个 chunk"不能是 top（否则走 top 合并）。用位写把它后面伪造出一个 `size` 合理的假 chunk（并保证 `prev_inuse`/`prev_size` 与上一块一致，绕过 `corrupted size vs. prev_size`），free 后即链入 unsorted bin，其 `fd`/`bk` 指向 `main_arena`，用"查询"功能逐位读回即可泄漏 libc。
- 没有 chunk 表也照样能打：程序只要"能多次 create（各自 malloc）+ 单次 free"，就能用"泄漏一次 → free → 再 create 更小"的循环，把同一块内存反复取回，从而既拿 libc 又拿 heap 地址。

## 触发条件

- 程序提供"创建区间（malloc 位图）"、按位增删（add/delete）、单次 free、以及某种读回位值的能力（查询某个 `i` 是否置位 = 1 bit 读）。
- `add/delete` 的索引由用户可控，且存在"能算出小于 base 的 idx"的路径（掩码、整型截断、负数输入、区间前缀通配）。
- 分配大小可控（通常由区间长度决定，可申请到 0x2000 量级），且 create 后旧指针被覆盖/释放，没有"只能申请一次"的限制。
- glibc 版本允许 tcache（≥2.26）时打 tcache 毒化；更老版本可用 fastbin dup 或 unsorted bin attack，路径随之变化。

## 利用步骤

1. 选一块大小合适的区间创建位图（示例 `0x530`），用"单 ip 格式"精确置位，把目标 chunk 的 `size` 字段（例如 `0x530` → `0x101`）与伪造的下一个 chunk 头部写进去（`write_addr(base, off, value)`：按 value 的每个 1 位调用 add）。
2. 用 `delete` 的 `"ip/num"` 掩码路由让 `v2` 落到 base 之前，清掉前一 chunk `size` 的最低字节/`PREV_INUSE` 位，使"前一块"看起来已释放。
3. `free()` 位图 → 因为"下一个 chunk"不是 top 且 size 合法，进入 unsorted bin；此时 `fd/bk` 是 libc 指针。
4. 再 `create` 一个略小的区间取回同一块内存（**重叠**），用查询功能按位读回 `fd` 的每一位（`get_bit()` 循环 48 次拼出地址），减去 `main_arena` 固定偏移得到 libc 基址。
5. 重复上述"写入伪造头部 → free → 取回更小块"的循环把 chunk 送进 smallbin，凑满 smallbin 后取回一块时剩余部分会进 tcache；再把 tcache 里已投毒的 `fd` 指向程序内一个会被后续 ip 输入触发的函数指针槽（原文称 `strtok` 内部调用的某个 abs got 表项）。
6. 用 create 把伪造的 tcache 链取回，落在 GOT 上；再用位写把该 GOT 值改为 `system`，随后让程序解析 `/bin/sh\x00`（把它当作一个 ip 输入），即 `strtok`/`atoi` 调用 `system("/bin/sh")`。
7. 全程不用 UAF：只靠"位写改 size + 单次 free"和"反复 create 取回重叠块"完成泄漏与投毒。

## PoC

```python
# 位图式任意位写：按 value 的 1 位逐个 add（pwnlib 风格伪代码）
def write_addr(ip_base, off, value):
    n = value.bit_length()
    for i in range(n):
        if (value >> i) & 1:
            add(ip_base + off * 8 + i)     # 置位
        # 需要清零时改用 delete

# 1) 在新建位图里写入伪造的 chunk 头（改 size 为 0x101，并铺好 fake 下一块）
create(ip_base, size=0x530)
write_addr(ip_base, 0x438, 0x101)

# 2) 用 "ip/num" 掩码把 v2 推到 base 之前，清掉 P 位 / 改 size 低字节
delete(ip_base, "/25")        # num=25 ⇒ 掩码清零低 7 位，v2 可能 < start

# 3) free 后进入 unsorted bin；再 create 略小取回重叠块
free()
create(ip_base, size=0x430)
libc_leak = read_bits(ip_base, 0, 48) - MAIN_ARENA_OFFSET

# 4) 重复循环把块送进 smallbin / tcache，投毒 fd 到 GOT，再把 GOT 写成 system
#    （示例略：见利用步骤 4-7，最后让程序以 "/bin/sh\x00" 作为 ip 输入触发 system）
```

```text
# 观测点
# - free 后 unsorted bin 里出现 fd/bk → main_arena+96
# - tcache entries 指向 GOT 槽地址
# - 最终 system("/bin/sh") 拿 shell
```

## 变体与关联

- 变体：同样的"负索引"来自整型截断（把 `int` 下标截成 `uint8` 后与阈值比较）或"区间前缀通配"（`ip/num` 把 base 清到区间外），都等价于向前/向后越界位写。
- 变体：只有"置位"没有"清零"时，可以先把目标字节读出来做差集，用两次写补齐；或改打只依赖置位的目标（如把 `size` 低字节从 0x01 抬到 0x81 这类"只加位"的改法）。
- 变体：无 tcache 的老 glibc 走 fastbin dup / unsorted bin attack + `__malloc_hook`；有 tcache 但开了 tcache key 校验时改打 smallbin/largebin 或 stashing。
- 关联：[[binary-pwn-heap-custom-allocator-negative-size-alignment-overflow]]（同为"索引/长度符号问题造成的越界写"，但那只给一次性单块覆盖）；[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]（改相邻 chunk size 后伪造 unlink 的同类思路）；[[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]（无 show 堆题如何拿到任意地址分配）。
- 边界：如果 free 前程序会校验 `size` 与 `prev_size` 的一致性（较新 glibc 的 `unlink_chunk`/`malloc_consolidate` 检查更严），伪造必须同时满足 `prev_size == size(prev)`、`next->prev_inuse` 等条件，否则直接 `malloc_printerr` 中止。

## 检测与防御

- 检测：审计位图索引计算是否对"下标 - base"做有符号/无符号一致性检查；对手写的 `ip/num`、掩码类操作在掩码后重新校验 `v2 >= start`。
- 修复：把 `(i - start)` 改成"先判 `i >= start && i <= end` 再计算"，或统一用无符号并在计算前断言；`num` 掩码后重新做区间校验。
- 加固：开启 `_GLIBCXX_ASSERTIONS`/`-fsanitize=address` 让越界位写尽快崩；free 前对 size/prev_size 做完整性校验；业务上限制"单次 add 覆盖的位数量"（例如不超过区间长度）。
- 检测（运行时）：出现 `malloc_printerr: corrupted size vs. prev_size`、unsorted bin 的 `fd/bk` 不指向 arena、tcache entries 落到 .got 段等异常特征。

## 备注

原文为 CTF 题目 writeup（完整 exp 跑通、17 解），属"已打通"场景，故 severity high / confidence high；但它是针对单个题目的利用，具体 GOT 目标与偏移不可直接移植，卡内已抽象为方法链。原文未标注受影响版本/CVE。
