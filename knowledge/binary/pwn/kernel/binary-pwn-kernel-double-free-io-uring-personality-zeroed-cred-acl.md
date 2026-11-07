---
id: binary-pwn-kernel-double-free-io-uring-personality-zeroed-cred-acl
title: 内核模块 double free + io_uring personality cred 清零：SETXATTR 写 ACL 读 /flag
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-double-free-io-uring-personality-zeroed-cred
aliases:
- d3kheap2pro
- io_uring personality
- IORING_REGISTER_PERSONALITY
- cred 清零
- init_on_alloc 清零
- SETXATTR ACL
- double free 提权
tags:
- kernel
- pwn
- double-free
- io-uring
- personality
- cred
- init-on-alloc
- setxattr
- acl
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:48:56+08:00'
  notes: 已对照原文核对：slot {ptr,cnt} 与 0x800 私有 cache、ALLOC 净 cnt=2、FREE 不清指针与两次 free、无读写接口依赖 init_on_alloc 清零、worker unshare(CLONE_NEWUSER)+IORING_REGISTER_PERSONALITY、reserve 128、IORING_OP_SETXATTR=42 与 FSETXATTR=41 区别、ACL owner/group/other 三 entry、参数 m=384/reserve=128/workers=160/delay_us=100、命中 slot 48（原版）/32（revenge）均一致；两版利用链相同已合并。未验证点：PoC 未在本机复跑，利用有概率；自定义模块非公开 CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

内核模块的 slot 在 `kmem_cache_free` 后不清空指针、计数又允许再 free 一次，形成 0x800 对象批量 double free；模块没有读写接口，但利用 `init_on_alloc` 的分配清零，让被复用的 io_uring registered personality `cred` 变成一份“空 cred”，再以该 personality 提交 `IORING_OP_SETXATTR` 给 `/flag` 写可读 ACL，普通用户即可读取 flag。

## 原理

- 模块维护 `struct slot { void *ptr; int cnt; } slots[512]`，对象来自 0x800 的私有 `kmem_cache`。ALLOC 在 slot 为空时取对象并把 cnt 设为 1，随后 `cnt++`（净效果 2）；FREE 只检查 `ptr != NULL && cnt > 0`，减 cnt 后直接 `kmem_cache_free(cache, ptr)`，不清 `ptr`。
- 因此同一 slot 可 `alloc → free → free`：第二次 free 时 ptr 仍指向已释放对象、cnt 仍大于 0，同一个对象被两次放入 freelist，形成 double free；第三次 free 因 cnt==0 被拒，但两次已足够。
- 模块没有 read/write 对象的接口，不能按常规 double free 改 freelist 指针；可利用的是后续跨 cache 复用：题目环境开启 `init_on_alloc`，重新分配该物理对象时内核会把内容清零。
- 选择 io_uring registered personality 承载 cred：`IORING_REGISTER_PERSONALITY` 把当前进程的 `cred` 引用保存到 io_uring ctx，后续 SQE 可通过 `personality` 字段指定该 cred 执行；worker 先 `unshare(CLONE_NEWUSER)` 再注册，可批量产生大量独立 cred 引用并保持存活。
- 批量 double free 后，再执行 reserve allocation 从被污染的 freelist 取对象；若某个 personality 的 cred 恰好落在被 zero-on-alloc 的 0x800 对象上，其字段被清零，成为一份“空 cred”。空 cred 的 uid/gid 等字段为 0，权限检查可通过。
- 直接 `open("/flag")` 有时因字段过空或 namespace 状态不完整不稳；更稳的是用 `IORING_OP_SETXATTR`（opcode 42，路径版；`IORING_OP_FSETXATTR` 是 41）在该 personality 下给 `/flag` 设置 `system.posix_acl_access`。ACL 只放 owner/group/other 三个 entry，不放 named uid entry——named uid 会碰到空 `user_ns`，容易 panic。
- ACL 设置为 `ACL_USER_OBJ r--`、`ACL_GROUP_OBJ ---`、`ACL_OTHER r--` 后，普通 ctf 进程即可 `open("/flag")` 读取。
- 该利用有概率：freelist 与跨 cache 复用窗口受启动状态影响；示例参数 `m=384 reserve=128 workers=160 delay_us=100`，命中 slot 48/32。

## 触发条件

- 内核模块存在“free 后不清指针 + 计数允许重复 free”的 double free 缺陷，且对象大小/缓存可被跨 cache 复用。
- 内核开启 `init_on_alloc`（或等效的分配清零），使复用对象内容被清零。
- io_uring 可用，普通用户可 `io_uring_setup`、`IORING_REGISTER_PERSONALITY`、提交 `IORING_OP_SETXATTR`；允许 `unshare(CLONE_NEWUSER)`（或已有足够 cred 引用）。
- 目标文件（如 `/flag`）所在文件系统支持 POSIX ACL，且空 cred 能通过 setxattr 权限检查。
- 攻击者已在目标上获得普通用户代码执行；模块设备可访问。

## 利用步骤

1. 审计模块：确认 ALLOC/FREE 的 cnt 逻辑与 free 后不清指针，计算对象大小（0x800）与私有 cache。
2. 喷射 cred：创建 io_uring ring；fork 一批 worker，每个 worker `unshare(CLONE_NEWUSER)` 后调用 `IORING_REGISTER_PERSONALITY`，把返回的 personality id 通过管道回传父进程并 pause 保持存活。
3. 制造 double free：对 M 个 slot 逐个 ALLOC，然后两次 FREE，使 M 个 0x800 对象各进入 freelist 两次（示例 M=384）。
4. 触发清零复用：执行 reserve 次 ALLOC（示例 128），让分配器从被污染 freelist 取对象并触发 `init_on_alloc` 清零；若命中 personality cred，该 cred 变为空 cred。
5. 逐个 personality 尝试 `IORING_OP_SETXATTR`：`addr`=`system.posix_acl_access`，`addr2`=ACL 字节，`addr3`=`/flag`，`len`=ACL 长度，`personality`=候选 id；返回 0 表示 ACL 设置成功。
6. 读取 flag：普通进程 `open("/flag", O_RDONLY)` 并 read；若失败，调整 M/reserve/workers/delay 重试。
7. 记录命中 slot/personality；清理 worker 与 ring。

## PoC

```c
// 模块命令：申请/释放同一 slot 两次
#define CMD_ALLOC 0x3361626eUL
#define CMD_FREE  0x74747261UL
for (i = 0; i < M; i++) ioctl(fd, CMD_ALLOC, &i);
for (i = 0; i < M; i++) ioctl(fd, CMD_FREE,  &i);
for (i = 0; i < M; i++) ioctl(fd, CMD_FREE,  &i);  // double free
```

```c
// worker：unshare userns 后注册 personality
unshare(CLONE_NEWUSER);
int p = syscall(__NR_io_uring_register, ring_fd,
                IORING_REGISTER_PERSONALITY, NULL, 0);
write(out_fd, &p, sizeof(p));
pause();
```

```c
// 用 personality 给 /flag 写 ACL：owner r--, group ---, other r--
static const unsigned char acl_value[] = {
    0x02, 0x00, 0x00, 0x00,                         // version 2
    0x01, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ r--
    0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ ---
    0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER r--
};
sqe->opcode = IORING_OP_SETXATTR;   // 42
sqe->addr = (uint64_t)"system.posix_acl_access";
sqe->addr2 = (uint64_t)acl_value;
sqe->addr3 = (uint64_t)"/flag";
sqe->len = sizeof(acl_value);
sqe->personality = p;
```

完整 EXP 见原文（io_uring 手工 mmap、SQE/CQE 环、worker/personality 管理、reserve 分配与 ACL 尝试）。PoC 未在本机执行；命中概率与参数需按环境调整。

## 变体与关联

- 变体：用其他持 cred 引用的对象（文件、socket、key）替代 io_uring personality；空 cred 也可用于其他权限检查（open、setuid、namespace 操作）。
- 变体：若 `init_on_alloc` 关闭，复用时内容不清零，需要其他“把对象字段置零/置可控值”的路径；可结合堆喷。
- 变体：ACL 只写 owner/group/other；named uid entry 会访问空 `user_ns` 导致 panic。
- 变体：d3kheap2pro-revenge 模块逻辑相同，仅命中 slot 不同（示例 slot 32），可复用同一利用。
- 关联卡片：[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（kmem_cache UAF 对象复用）、[[binary-pwn-kernel-splice-external-page-crc-commit-page-cache-write]]（同场 d3kbus 页缓存写）、[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（页缓存污染）。
- 注意：本例为 D^3 CTF 2026 自定义模块（0x800 私有 cache、init_on_alloc、io_uring 可用），不是公开 CVE；真实内核需确认 `init_on_alloc`、io_uring 与 unprivileged userns 配置。

## 检测与防御

- 防御：模块代码审计——free 后必须清空指针/置空 slot，计数不能允许对同一指针重复 free；使用 `kfree_sensitive`/引用计数/句柄表。
- 防御：不要把 `init_on_alloc` 当作安全边界（它只保证新分配清零，不能防 double free）；开启 KASAN/KFENCE 做测试。
- 防御：限制 unprivileged io_uring 与 unprivileged userns（sysctl `kernel.unprivileged_userns_clone`、io_uring 相关禁用/ seccomp），减少 personality cred 喷射面。
- 检测：KASAN/KFENCE 报 double free；监控异常 io_uring personality 注册数量、worker `unshare(CLONE_NEWUSER)` 与 `IORING_OP_SETXATTR` 组合；监控 `/flag` 等敏感文件 ACL 变更（auditd `setxattr`）。
- 检测：模块设备被高频 ALLOC/FREE 且同一 slot 重复释放；内核 freelist 异常。
- 响应：卸载模块、重启、恢复 ACL、检查其他敏感文件权限、修复模块并轮换相关凭据。
