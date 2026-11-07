---
id: ctf-pwn-linked-list-null-byte-next-pointer-lowbyte
title: Person 链表 null 字节溢出：fgets 多写 1 字节覆盖 next 低字节，重定向链表任意读 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: linked-list-null-byte-next-lowbyte-redirect
tags:
- ctf
- pwn
- heap
- off-by-one
- null-byte
- linked-list
- pointer-corruption
- arbitrary-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:26:13+08:00'
  notes: 已对照原文 person-tracker 核对：fgets size+1 覆盖 next 低字节、0x...9d90->0x...9d00 重定向、name+8 预置 flag-8、show(2,2) 打印 flag 均成立；已修正原文卡片中“edit 修改 next”和“末尾带指针”的不准确表述；未实际执行 exp。
url: /docs/ctf/pwn/ctf-pwn-linked-list-null-byte-next-pointer-lowbyte/
draft: false
kb_aliases:
- Person Tracker
- null by one
- 链表 next 低字节
- 堆溢出 1 字节
- 指针低字节覆盖
- 任意读 flag
---

## 一句话结论

Person Tracker 用 `fgets(new->name, sizeof(new->name) + 1, stdin)` 向 24 字节的 `name` 多写 1 字节，恰好把结构体末尾 `next` 指针的最低字节覆盖为 `\x00`；由于新节点总在链表头、堆块地址高位相同，低字节归零会把新节点的 `next` 重定向到附近的另一个 Person 结构体。该“假节点”偏移 0x20 处的 `next` 字段正好落在另一个节点 `name+8` 的区域，那里在 add 时已写入 `p64(flag_addr - 8)`，于是链表再跳到 `.rodata` 中 flag 常量前 8 字节，最后用“查看姓名”按 `%s` 打印出 flag。

## 原理

- **结构体布局**：`struct Person { uint64_t age; char name[24]; struct Person *next; }`，`name` 之后紧挨 `next`；`fgets(new->name, sizeof(new->name) + 1, stdin)` 的 size 是 25，除 24 字节名字外还会写入一个 NUL，正好落在 `next` 的最低字节。
- **链表插入**：添加节点时 `new->next = root; root = new;`，新节点在链表头；按索引查找时 `person_at_index` 沿 `next` 走 `idx` 步。堆块连续分配、地址高位相同，`next` 的低字节被清零后通常指向同一片堆区中靠前的某个 Person 块（原文 0x...9d90 的 next 由 0x...9d40 变为 0x...9d00）。
- **重定向后的 `next` 来源**：被重定向到的结构体（原文 0x...9d00）偏移 0x20 处正好是另一个 Person 节点 `name+8` 的区域（原文 0x...9d20）；该区域在 add 时已写入 `p64(flag_addr - 8)`，因此假节点的 `next` 直接指向 flag 常量前 8 字节，无需再执行 edit。
- **任意读**：再按索引查看该节点的 `name` 时，`p->name` 的起始地址就是 `flag_addr`（因为 next 指向 `flag-8`，而下一次遍历落到 `flag-8`，其 `name` 偏移 8 → flag），`printf("%s", p->name)` 直接输出 flag 字符串。
- **为什么需要堆布局**：低字节清零只会落到同一 256 字节页内的地址；需要通过多次 add 控制堆块位置与目标 Person 的索引，使重定向后的节点可被编辑。原文先 add 4 个 A 节点，再 add 一个带 `p64(flag-8)` 的节点和一个 24 字节 Z 节点，触发覆盖后 show(2,2)。
- **根因**：`fgets` size 多 1 导致 off-by-one NUL 写入相邻指针；链表按索引遍历且信任被破坏的 `next`；flag 以常量形式放在可读内存。

## 触发条件

- 程序把用户输入写入紧邻指针的定长缓冲区，且 `fgets`/`read` 的 size 比缓冲区大 1（off-by-one NUL）。
- 节点/对象在堆上连续分配，指针高位相同，低字节覆盖可落在可控的相邻对象。
- 程序提供按索引遍历链表、读取/修改字段的功能，且没有对指针做完整性校验。
- flag/敏感数据位于可读的 `.rodata` 或已知地址；二进制 No PIE 或可泄露基址。

## 利用步骤

1. 分析结构体布局与 `fgets` size，确认多写的 1 字节落在 `next` 最低字节。
2. 多次 add 节点，观察堆块地址，构造使 `next` 低字节清零后落到目标 Person 块的布局（原文先 4 个 A 节点）。
3. add 一个节点，在其 name 的偏移 8 处写入 `p64(flag_addr - 8)`（前 8 字节填充），再 add 一个 24 字节 Z 节点；Z 节点的 `fgets` 溢出把 Z 节点 `next`（指向刚添加的节点）的最低字节覆盖为 `\x00`。
4. 触发覆盖后，root（Z 节点）的 `next` 变为低字节清零的地址，按索引 show 该假节点；其偏移 0x20 的 `next` 读出预置的 `flag_addr - 8`。
5. 用 show(2, 2) 遍历到 `flag_addr - 8` 并按 name 打印，得到 flag。
6. 远程/本地 libc 不同会导致堆块数量差异，按实际地址微调 add 数量与索引。

## PoC

```python
from pwn import *

def add(age, name):
    sela(b": ", str(1).encode())
    sela(b": ", str(age).encode())
    sela(b": ", name)

def show(index, choice):
    sela(b": ", str(2).encode())
    sela(b": ", str(index).encode())
    sela(b": ", str(choice).encode())

for i in range(4):
    add(10, b"A" * 8)

add(10, b"A" * 0x8 + p64(0x49B21E - 0x8))
add(10, b"Z" * 24)

show(2, 2)
p.interactive()
```

原文 flag 常量在 `0x49B21E`（`.rodata: aFakectfNotTheR db 'fakectf{not the real flag}'`），远程由 `FLAGVAR` 编译进真实 flag；exp 用 4 个 A 节点 + 一个带 `flag-8` 的节点 + 一个 Z 节点完成低字节覆盖，show(2,2) 打印 flag。

## 变体与关联

- 溢出变体：`fgets` size+1、`strncpy` 少写 NUL、`read` 多 1 字节、数组下标 off-by-one。
- 目标字段变体：链表 `next`、树左右子指针、函数指针、vtable、长度字段；低字节清零通常要求目标在同页/同高位。
- 利用目标变体：把指针指向 `.rodata` flag、GOT、堆上伪造对象；配合 show 实现任意读，配合 edit 实现任意写。
- 关联卡片：[[ctf-pwn-heap-residual-uninitialized-read-flag]]、[[binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap]]、[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]、[[ctf-pwn-scanf-overflow-printf-args-heap-flag-leak]]。
- 边界：若堆块不连续/ASLR 导致低字节覆盖落点不可控，需要先泄露堆地址或做堆喷；若程序对 `next` 做校验（范围/对齐/canary），本手法失效。

## 检测与防御

- **修复越界写**：`fgets(buf, sizeof(buf), ...)` 不要 +1；确保字符串缓冲区与后续指针之间有 padding/校验字段。
- **指针完整性**：链表遍历前校验 `next` 是否在合法堆范围、对齐、非空；使用安全链表/智能指针或把指针与元数据分离。
- **敏感数据隔离**：flag/密钥不要以明文常量放在进程可读内存；放到独立服务/加密存储，按需鉴权读取。
- **编译缓解**：开启 PIE/ASLR、堆保护（如 glibc 的 safe-linking 对应用层链表无效，需应用自身校验）；使用 CFI/指针认证（ARM PAC）。
- **检测**：监控异常索引遍历、指针值突变、低字节为 0 的链表节点；对 show 大量读取 `.rodata` 地址的行为告警。
