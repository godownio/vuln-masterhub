---
id: binary-pwn-heap-circular-dlist-delete-count1-uaf
title: 循环双向链表 delete 唯一节点仍走断链分支：current 悬空后 edit 缺 count 检查形成 UAF 写
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-circular-dlist-delete-count1-uaf
aliases:
- delete 唯一节点 UAF
- 循环双向链表 UAF
- traverse_and_select 逻辑漏洞
- current 悬空指针
- edit 缺 count 检查
- 链表删除逻辑错误
tags:
- pwn
- heap
- uaf
- linked-list
- logic-bug
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:22:30+08:00'
  notes: 已对照 90762 原文核对：delete 条件 if(traverse_and_select()||count!=1) 在 count==1 且移动>=1 时仍走断链分支，单节点自写后 free 且 current 未清零；edit 仅检查 current/type 不查 count，read 写入 freed+8 形成 UAF 写；struct page 0x320/type+buf_0x308+fd+bk 与原文一致。已修正卡中“type 必须为 2”的表述：edit 只拒绝 type==1，tcache/fastbin 覆盖后的 next 通常即非 1。未复跑 exp。
---

## 一句话结论

当程序用循环双向链表管理堆块、`current` 指向当前节点时，若 `delete` 的条件写成 `if (traverse_and_select() || count != 1)`，用户在只剩 1 个节点时请求“移动 n 步”也会进入多节点断链分支：断链在单节点上退化为自写，但随后仍 `free(current)` 并把 `current` 重新指向这块已释放内存；`edit` 只检查 `current != NULL` 和 `current->type`、不检查 `count`，于是对悬空指针的写入变成一次稳定的 UAF 写。

## 原理

- **数据结构**：每个 page 结构为 `{ type; char buf_[0x308]; page *fd; page *bk; }`，所有 page 组成循环双向链表；全局 `current` 指向当前节点。`add` 把新节点插入 current 前/后并更新 current；`delete` 先 `traverse_and_select()` 让用户移动 current，再断链并 `free`。
- **错误条件**：`delete` 中的判断是 `if (traverse_and_select() || count != 1)`。逻辑或意味着只要 `traverse_and_select()` 返回非 0（用户指定的移动步数 ≥ 1），即使 `count == 1` 也会进入“多节点断链”分支。
- **单节点断链退化**：链表中只有 1 个节点时，`current->fd == current->bk == current`。断链代码 `fd = current->fd; bk = current->bk; fd->bk = bk; bk->fd = fd;` 只是把 current 的 fd/bk 写回自身，不会破坏其他节点；但紧接着执行 `free(current)`，然后 `current = bk`（或 `fd`，二者都等于刚释放的地址），最后 `::current = current`。
- **悬空指针**：正常路径（`count == 1` 且不移动）会走 `else`，`free(current); current = 0;`。但请求移动步数 ≥ 1 时走的是上面的分支，`current` 未被清零，而是指向已释放的 chunk。
- **edit 缺少状态检查**：`edit` 只做 `if (!current) return; if (current->type == 1) return;`，没有检查 `count` 或 current 是否仍在链表中。该检查只拒绝 `type == 1`（marker/只读类型），释放后 type 字段被 tcache/fastbin 的 `next` 覆盖成任意非 1 值（或仍为 2）也会通过，`read(0, current->buf_, 0x308)` 写入 `freed_chunk + 8`，形成 UAF 写。
- **为什么稳定**：tcache/fastbin 释放会覆盖用户区前 0x10 字节（`next`/`key`），type（用户区偏移 0）随之变成加密后的 next 指针；由于检查只与 1 比较，通常仍能通过。若某版本/路径下 type 恰为 1，可先通过同 size 分配写入 type=2 或用其它布局恢复；原文在 delete 后直接 edit 成功。
- **影响**：一次 UAF 写可以改写已释放 chunk 的 fd/next、相邻 chunk 头、或复用后的对象；在该题中它被用来修改 smallbin chunk 的 `bk`，接 TSU+ 完成任意分配。

## 触发条件

- 程序使用循环双向链表 + 全局 `current` 管理堆对象，`delete` 在 `free` 后可能不把 current 置空。
- `delete` 的进入条件把“是否移动”和“节点数是否为 1”用逻辑或组合，导致单节点也能走多节点断链分支。
- 存在 `edit`/`write` 接口只检查 current 非空（和 type），不检查 count 或对象是否已释放。
- 释放后对象的 type 字段不为 1（编辑检查只拒绝 1；tcache/fastbin 覆盖后的 next 通常即非 1），使 edit 不被 type 检查挡住。
- 能控制堆布局，让 UAF 写命中目标（相邻 chunk 头、tcache/smallbin 元数据、复用对象等）。

## 利用步骤

1. 添加一个可写类型（type=2）的 page，使链表中只有 1 个节点、current 指向它。
2. 选择 delete；在“移动步数”处输入 ≥1（方向任选）。`traverse_and_select()` 返回非 0，进入多节点分支；单节点断链自写后 `free(current)`，current 仍指向已释放 chunk。
3. 可选：用 print/show 读取 current->buf_，泄露释放后残留的 tcache/fd 指针或堆地址。
4. 选择 edit；只要 freed chunk 的 type 不为 1（释放后被 tcache `next` 覆盖通常即满足），检查通过，写入 0x308 字节到 `freed+8`，完成 UAF 写。
5. 用这次写修改目标：例如把同 size 已释放 smallbin chunk 的 `bk` 改成堆内假 chunk，接 TSU+；或改相邻 chunk 的 size/fd 做重叠。
6. 若某版本/路径下 type 恰为 1（阻止 edit），先通过同 size 分配写入 type=2，或选择 type 字段不会被覆盖成 1 的布局。
7. 后续按目标链继续：任意分配 → 劫持 hook/FSOP → 栈迁移/ROP。

## PoC

```python
# 伪代码：菜单 1=add, 2=delete, 3=move, 4=print, 5=edit
add(type=2, data=b"A")          # 链表中只有 1 个节点
delete(traverse=1, direction="left")   # count==1 但 traverse 非 0 -> 进入断链分支
# 此时 current 指向已 free 的 chunk（未清零）

edit(payload)                   # edit 只检查 current 非空/type，写入 freed+8 -> UAF 写
```

对应的易错逻辑（C 伪代码）：

```c
if (traverse_and_select() || count != 1) {
    fd = current->fd;          // 单节点时 fd == current
    bk = current->bk;          // 单节点时 bk == current
    fd->bk = bk;               // 自写
    bk->fd = fd;               // 自写
    next = mode ? bk : fd;     // 单节点时 next == 刚释放的地址
    free(current);             // 释放当前节点
    current = next;            // current 仍指向已释放块，未清零
} else {
    free(current);
    current = 0;               // 正常路径才清零
}
```

## 变体与关联

- **delete 后再 delete**：若 count 计数未及时递减或 current 仍非空，可能对同一块再次 free，形成 double free；取决于 `--count` 与检查顺序。
- **print UAF 读**：print 若也只检查 current 非空，可读出已释放 chunk 的 fd/key/残留数据，泄露堆地址或 libc 指针。
- **move 越界**：move 只检查 current 非空，若 current 已释放且其 fd/bk 被改写，移动时会沿伪造链表走到任意地址，形成任意读写的前置。
- **修复方式**：delete 应把 `count == 1` 与“是否移动”分开处理；free 后立即 `current = NULL`；edit/move/print 应校验 `count > 0` 且 current 属于链表；使用引用计数/代际编号避免悬空指针。
- **关联**：[[binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries]]（UAF 写接 TSU+）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 改函数指针）、[[binary-pwn-heap-uaf-struct-reuse-data-pointer]]（UAF 结构体复用）。

## 检测与防御

- **代码审计**：重点检查 `delete` 的 `free` 路径是否在所有分支都把全局/成员指针置空；检查 `if (move() || count != 1)` 这类用逻辑或混合“动作”和“状态”的条件；检查 edit/print/move 是否只做空指针检查而缺少 count/age 校验。
- **运行时防御**：free 后清零指针；使用带引用计数或 generation 的句柄；在 edit 前验证对象仍在链表中（`current->fd->bk == current && current->bk->fd == current`）。
- **检测**：监控对已释放堆块的写（ASAN/UAF 检测）、链表节点 fd/bk 指向非堆地址、或 delete 后仍出现对该对象的 edit/print 调用。
