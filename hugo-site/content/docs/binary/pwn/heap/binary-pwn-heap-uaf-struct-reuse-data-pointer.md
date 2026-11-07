---
id: binary-pwn-heap-uaf-struct-reuse-data-pointer
title: 堆 UAF 结构体复用：free 顺序让 user 结构体被重分配为密码缓冲区，改写 data 指针实现任意读写
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-uaf-struct-reuse-data-pointer-overwrite
tags:
- pwn
- heap
- uaf
- fastbin
- struct-reuse
- data-pointer
- arbitrary-write
- arbitrary-read
- glibc-2.23
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:43:37+08:00'
  notes: 已对照原文及8张图核对：Delete先free(data)再free(users[id])且不置空、Register先malloc(size)再malloc(0x18)、结构体data/show/size字段偏移、fastbin 0x20 LIFO导致新密码缓冲区复用旧结构体、改写data指针实现任意写与login比较oracle、__free_hook→system收尾均与原文/EXP一致；图03/05/08的堆布局与fastbin链表吻合。未验证点：CTF题无组件受影响版本，未设affected_versions；EXP未本机复跑；frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-uaf-struct-reuse-data-pointer/
draft: false
kb_aliases:
- UserManager UAF
- 结构体复用
- 密码缓冲区重叠 user 结构体
- data 指针劫持
- fastbin 同大小复用
- 任意地址读写
---

## 一句话结论

目标程序注册用户时先 `malloc(size)` 申请密码缓冲区、再 `malloc(0x18)` 申请 user 结构体，删除时却先 `free(密码缓冲区)` 再 `free(user 结构体)`；由于 fastbin 的 LIFO 顺序，之后申请同样大小的新密码缓冲区会优先拿到刚释放的 user 结构体，新密码的写入因此直接覆盖旧 user 结构体的字段（尤其是 `data` 指针），从而把“密码编辑”变成任意地址写、“登录比较”变成任意地址读/比较 oracle。

## 原理

- **对象布局**：每个 user 结构体 0x18 字节，包含密码缓冲区指针 `data`、函数指针 `p`（指向 `show`）和长度 `size`，全局 `users[id]` 保存结构体指针。注册流程：`buf = malloc(size); read(0, buf, size); tmpuser = malloc(0x18); tmpuser->data = buf; tmpuser->p = show; tmpuser->size = size; users[id] = tmpuser;`。
- **释放顺序**：`Delete()` 先 `free(users[id]->data)` 再 `free(users[id])`，且不把 `users[id]` 置空，形成双重 UAF：密码缓冲区与结构体都可被后续分配复用，原 `users[id]` 仍是悬空指针。
- **fastbin LIFO**：示例请求 size=0x18，对应 chunk size 0x20，属于 fastbin。先释放密码 chunk，再释放结构体 chunk，fastbin 0x20 链表头即为 user 结构体；下一次注册同样大小时，第一次 `malloc(0x18)`（密码缓冲区）先返回 user 结构体 chunk，第二次 `malloc(0x18)`（新 user 结构体）返回旧密码 chunk。
- **重叠后果**：新用户的密码缓冲区与旧 user 结构体指向同一块内存。对“新用户密码”的 `edit` 写入，就是在改写旧结构体的字段；由于结构体首字段是 `data` 指针，写入 1 字节即可改其低字节，写入 8 字节即可把 `data` 指向任意地址。
- **任意读写**：
  - 任意写：`edit(new_id, p64(target))` 把旧 user 的 `data` 改为 `target`，再 `edit(old_id, payload)`，程序通过旧 user 的 `data` 指针把 payload 写到 `target`。
  - 任意读/比较：`login(old_id, ...)` 用 `strcmp(input, users[old_id]->data)` 比较输入与该指针指向的内存，形成逐字节比较 oracle；配合 `strcmp` 的 NUL 截断可泄露内存内容（见关联卡）。
- **为什么成立**：漏洞根因不是单一 `free` 未置空，而是“分配顺序（data→struct）与释放顺序（data→struct）相同”导致 fastbin 头部是结构体；若释放顺序相反（先 struct 后 data），下一次同大小分配会先拿到 data chunk，结构体不会被密码写入覆盖。设计上应保证对象与内部缓冲区不同生命周期，或释放后置空并从容器移除。
- **最终利用**：拿到 libc 基址后，用任意写把 `__free_hook` 改成 `system`，再把某块可被 `free` 的密码缓冲区写成 `/bin/sh\x00`，调用 `Delete()`/`free` 触发 `system("/bin/sh")`。

## 触发条件

- 目标为 glibc 堆题（示例 libc 2.23），存在“先分配内部缓冲区、后分配结构体”且“删除时先释放内部缓冲区、后释放结构体”的对象。
- 释放后不置空、不从全局表移除（UAF）；程序仍允许通过旧 id 执行 edit/login（或等价操作）。
- 结构体与缓冲区可被同尺寸的新分配复用（fastbin/tcache 均可能，取决于 glibc 版本与尺寸）。
- 结构体首字段或关键字段是可由密码写入覆盖的指针（本例 `data`），且存在通过该指针的读写路径。
- 攻击者能控制分配尺寸/次数，并知道或能推断结构体字段偏移（用 gdb 堆布局确认）。

## 利用步骤

1. 用 `Register(id=0, size=0x18, "a"*0x18)` 创建一个密码缓冲区与 user 结构体；gdb 确认结构体地址、字段偏移（示例结构体在 chunk+0x10：+0 `data`、+8 `show`、+0x10 `size`）。
2. `Delete(0)`：先释放密码 chunk，再释放结构体；`users[0]` 仍指向已释放结构体。
3. `Register(id=1, size=0x18, "\x55")`：密码 `malloc` 复用到旧结构体 chunk，写入 `\x55` 覆盖旧 `data` 指针低字节；第二个 `malloc` 复用到旧密码 chunk 作为 user 1 的结构体。
4. `edit(1, p8(new_low_byte))`：通过 user 1 的密码写接口继续改写旧 user 0 结构体的 `data` 低字节，把指针移到目标内存区域（示例用于 libc 指针逐字节泄露）。
5. 需要任意写时：`edit(1, p64(target))` 把 `users[0]->data = target`，再 `edit(0, payload)` 将 payload 写到 target。
6. 泄露 libc 后（见 [[binary-pwn-heap-strcmp-bytewise-libc-pointer-leak]]），`edit(1, p64(__free_hook))`、`edit(0, p64(system))`，再把某密码缓冲区写成 `/bin/sh\x00`。
7. 对该缓冲区执行 `Delete`/`free`，触发 `system("/bin/sh")`，获得 shell。

## PoC

原文 EXP 的关键片段（glibc 2.23-0ubuntu11.3，未在本机执行）：

```python
def add(idx, size, content):
    p.sendlineafter(b'Your choice:', b'2')
    p.recvuntil(b'Input the user id:'); p.sendline(str(idx).encode())
    p.sendlineafter(b'Input the password length:', str(size).encode())
    p.sendafter(b'Input password:', content)

def edit(idx, content):
    p.sendlineafter(b'Your choice:', b'4')
    p.recvuntil(b'Input the user id:'); p.sendline(str(idx).encode())
    p.sendafter(b'Input new pass:', content)

def free(idx):
    p.sendlineafter(b'Your choice:', b'3')
    p.recvuntil(b'Input the user id:'); p.sendline(str(idx).encode())

add(0, 0x18, b'a' * 0x18)   # 密码 chunk + user 结构体
free(0)                     # 先 free 密码，再 free 结构体；users[0] 悬空
add(1, 0x18, b'\x55')       # 新密码复用旧结构体，改写 users[0]->data 低字节
edit(1, p8(0x55))           # 继续通过 user1 密码缓冲区改写 users[0]->data
# 之后 edit(0, ...) 即可向 users[0]->data 指向的任意地址写
```

gdb 观察（原文）：fastbin 0x20 链表为 `0x...a01020 → 0x...a01000`（结构体 chunk 在前），结构体内容为 `data=0x...a01010, p=show, size=0x18`；新用户的密码缓冲区与旧结构体重叠。

## 变体与关联

- **tcache 版本**：glibc 2.26+ 的 tcache 也是 LIFO，同样会出现“后释放的结构体先被复用”；但 tcache 有 key 字段、尺寸上限与 safe-linking，需相应调整。
- **释放顺序相反**：若先 free 结构体再 free 数据缓冲区，头部变为 data chunk，重叠利用方式不同；可利用“结构体被复用为数据”或反过来构造。
- **任意写目标**：`__free_hook`/`__malloc_hook`（低版本）、GOT、`_IO_2_1_stdout_`/`stderr`、退出函数指针等；高版本 glibc 需转向 FSOP/`exit_funcs`。
- **关联**：libc 泄露 oracle 见 [[binary-pwn-heap-strcmp-bytewise-libc-pointer-leak]]；通用 UAF 函数指针劫持见 [[binary-pwn-heap-uaf-function-pointer-hijack]]；unsorted bin 泄露见 [[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]。
- **防御/修复**：释放后立即置空并从 `users[]` 移除；对象与缓冲区使用独立分配器/生命周期；避免先释放内部缓冲区再释放容器；开启 tcache key/safe-linking 只提高门槛不根除 UAF。

## 检测与防御

- **代码审计**：查找 `free(obj->buf); free(obj);` 且未置空、未从全局数组删除的模式；检查“分配顺序与释放顺序一致”的结构体/缓冲区组合。
- **运行时检测**：同一对象释放后仍被 edit/login 访问（UAF）；fastbin/tcache 链表出现结构体 chunk 被当作数据块复用；堆元数据异常与重复 free。
- **防御**：使用带所有权/生命周期检查的容器；释放后置空；启用 glibc 的 tcache key、safe-linking、FORTIFY 等缓解；对 CTF 服务限制异常菜单调用序列并做堆完整性检查。
