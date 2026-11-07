---
id: code-analysis-dynamic-fuzzing-syzkaller-custom-proc-driver-syzlang
title: Syzkaller 定向 fuzz 自定义内核驱动：syzlang 描述 + KCOV/KASAN + syz-repro 最小化
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: syzkaller-custom-proc-driver-syzlang
aliases:
- Syzkaller 实战
- syzlang 自定义驱动
- 内核驱动堆溢出 fuzz
- KCOV KASAN
- syz-repro
- syz-crush
- /proc/test 驱动
tags:
- kernel
- fuzzing
- syzkaller
- syzlang
- kcov
- kasan
- qemu
- driver
- heap-overflow
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T22:37:32+08:00'
  notes: 已对照原文与14张截图核对：syzlang 流程、KCOV/KASAN、enable_syscalls、syz-crush 104/101=97.12%、KASAN slab-out-of-bounds proc_write 与 kmalloc-512 均与原文一致；无 sources 字段；未在本机复跑
---

## 一句话结论

对一个暴露 `/proc/<name>` 的自定义内核驱动，可以写一份最小 syzlang 描述（固定路径的 `open`、`read`、`write`、`close` 资源链），用 `syz-extract`/`syz-sysgen` 生成描述代码并重建 Syzkaller，在 `enable_syscalls` 中只放这四个调用，配合 KCOV 覆盖率和 KASAN，就能快速 fuzz 出驱动里的 `slab-out-of-bounds`；随后用 `syz-repro`/`syz-crush` 复现并最小化出 `repro.txt`/C repro。

## 原理

- **Syzkaller 架构**：`syz-manager` 跑在宿主机，负责生成/变异系统调用序列、管理 VM、收集覆盖率与崩溃；`syz-executor` 跑在 VM 内，接收程序、以临时子进程执行系统调用、通过 `ioctl(/sys/kernel/debug/kcov)` 收集 KCOV 边覆盖并上报。宿主机通过 SSH/SCP 下发程序，VM 崩溃后由 manager 重启（可配合快照）。
- **KCOV + KASAN 的作用**：KCOV 给内核插桩，记录每个输入执行到的边，作为覆盖率反馈引导变异；KASAN 检测越界/Use-After-Free 等内存错误，把普通“写坏内存但没崩”的 bug 变成可报告的 `slab-out-of-bounds`。没有这两个选项，fuzz 效率和可观测性都会大幅下降。
- **syzlang 是“接口模型”**：Syzkaller 不懂驱动的私有语义，必须用 syzlang 告诉它 syscall 名称、参数类型、路径常量、返回资源。资源类型（如 `fd`）会建立调用顺序依赖：`open$proc` 返回 `fd`，`write$proc`/`read$proc`/`close$proc` 消费同一个 `fd`，Syzkaller 因此能自动拼出合法调用链。
- **`$proc` 与固定路径**：`open$proc(file ptr[in, string["/proc/test"]], ...)` 是 `open` 的符号变种，把路径固定为 `/proc/test`，避免 fuzzer 去打开无关文件；`flags`/`mode` 用 `bitmask` 枚举合法取值。这样 fuzz 空间被压缩到目标驱动，命中率更高。
- **生成流程**：把 `vuln.txt` 放进 `syzkaller/sys/linux/`，先 `syz-extract -os linux -sourcedir <kernel> -arch amd64 vuln.txt` 生成 `.const`，再 `syz-sysgen` 把描述翻译成 Go 代码，最后 `make all` 重建 Syzkaller；不重建则新 syscall 不会生效。
- **`enable_syscalls` 收敛**：在 `test.cfg` 中只启用 `open$proc`、`read$proc`、`write$proc`、`close$proc`，Syzkaller 只变异这四个调用，避免把时间浪费在无关 syscall 上。这是“定向 fuzz”的关键。
- **崩溃与复现**：manager 检测到 KASAN `slab-out-of-bounds Write in proc_write` 后自动复现（默认 4 个 VM），把 prog 最小化并尝试生成 C repro；`syz-repro` 可单独对 `repro.prog` 复现并输出 `repro.txt`，`syz-crush` 可重复执行验证稳定性（原文 104 次执行复现 101 次，约 97.12%）。
- **示例 bug 的根因**：驱动 `proc_write` 里 `kmalloc(n + 512)` 只分配了 `n+512` 字节，却 `copy_from_user(c, user, n + 4096)` 复制 `n+4096` 字节；当用户写入长度使 `n+4096 > n+512` 时，内核缓冲区被越界写。KASAN 报告显示对象属于 `kmalloc-512`、越界发生在 `_copy_from_user`/`proc_write` 调用栈，正好验证了“分配长度与复制长度不一致”的模式。
- **为什么能 fuzz 出来**：`write$proc` 的 `count len[buf]` 让 Syzkaller 生成不同长度的缓冲区；fuzzer 不需要知道 `n+4096` 这个具体数字，只要变异出足够大的写入长度并命中 `proc_write`，KASAN 就会捕获越界。固定路径 + 资源链保证每次执行都能到达目标函数。

## 触发条件

- 目标是一个可编译/加载的内核驱动或模块，暴露 procfs、sysfs、ioctl、netlink 等用户态入口。
- 能在 QEMU/KVM 中启动被测内核，且内核开启 `CONFIG_KCOV`、`CONFIG_KASAN`（建议 `KASAN_INLINE`）、`CONFIG_DEBUG_INFO` 等选项。
- 已安装 Go、C 编译器、QEMU、debootstrap，能编译 Syzkaller 与内核、生成 VM 镜像。
- 能为目标接口写出 syzlang 描述（或能用 headerparser 自动生成结构体描述）。
- 驱动存在可被系统调用参数触发的内存安全 bug（越界、UAF、类型混淆等），且崩溃能被 KASAN/panic 捕获。

## 利用步骤

1. **搭建环境**：确认 CPU 虚拟化（`vmx`/`svm`）与 KVM 模块；编译 Syzkaller（`make all`）；用 `create-image.sh` 生成 Debian 根文件系统镜像；启动 QEMU 验证 SSH 登录。
2. **编译带插桩的内核**：`make defconfig && make kvm_guest.config`，用 `scripts/config` 开启 `CONFIG_KCOV`、`CONFIG_KASAN`、`CONFIG_KASAN_INLINE`、`CONFIG_DEBUG_INFO`、`CONFIG_KCOV_JIT` 等，`make olddefconfig && make -j$(nproc)`，得到 `bzImage` 与 `vmlinux`。
3. **定位目标接口**：确认驱动创建的设备节点/路径（示例 `/proc/test`）、支持的读写/ioctl 参数、资源生命周期。
4. **写 syzlang**：在 `syzkaller/sys/linux/vuln.txt` 中定义 `open$proc`（固定路径）、`read$proc`、`write$proc`、`close$proc` 及 flags/mode 枚举；资源返回 `fd`，读写消费 `fd`。
5. **生成描述代码**：`bin/syz-extract -os linux -sourcedir <kernel> -arch amd64 vuln.txt` 生成 `.const`；`bin/syz-sysgen` 生成 Go 描述；`make all` 重建 Syzkaller。
6. **配置并启动**：在 `test.cfg` 中设置 `target`、`kernel_obj`、`image`、`sshkey`、`vm`，并加 `"enable_syscalls": ["open$proc","read$proc","write$proc","close$proc"]`；`syz-manager -config test.cfg -vv 10`。
7. **观察覆盖率与崩溃**：打开 WebUI（`http://127.0.0.1:<port>`）看 stats/coverage/crashes；KCOV 页面用颜色标出已覆盖/部分覆盖/未覆盖；出现 KASAN 报告即记录 crash 目录。
8. **复现与最小化**：在 crash 目录查看 `description`/`log0`/`report0`/`repro.prog`；用 `bin/syz-repro -config test.cfg <crash>/repro.prog` 复现并生成 `repro.txt`/C repro；用 `bin/syz-crush -config test.cfg <crash>/repro.cprog` 反复执行验证稳定性。
9. **分析根因**：读 KASAN 头部（`slab-out-of-bounds Write`、cache 名、对象大小、越界偏移）与调用栈（`copy_from_user` → `proc_write` → `vfs_write`），对照驱动源码定位分配/复制长度不一致或索引越界；把最小化后的 `repro.txt` 作为 PoC。
10. **修复与回归**：修正长度校验（限制 `n`、按分配大小复制、使用 `memdup_user`/`strndup_user`），重新编译内核并重跑同一 syzlang/seed，确认 crash 不再出现。

## PoC

目标驱动的漏洞片段（原文示例）：

```c
static ssize_t proc_write(struct file *proc_file, const char __user *proc_user, size_t n, loff_t *loff)
{
    char *c = kmalloc(n + 512, GFP_KERNEL);
    // 分配 n+512，却复制 n+4096 -> 堆越界写
    size_t size = copy_from_user(c, proc_user, n + 4096);
    printk(DEBUG_FLAG ":into write %ld!\n", size);
    return 0;
}
```

syzlang 描述（`syzkaller/sys/linux/vuln.txt`）：

```text
include <linux/fs.h>

open$proc(file ptr[in, string["/proc/test"]], flags flags[proc_open_flags], mode flags[proc_open_mode]) fd
read$proc(fd fd, buf buffer[out], count len[buf])
write$proc(fd fd, buf buffer[in], count len[buf])
close$proc(fd fd)

proc_open_flags = O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_CREAT
proc_open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP
```

`syz-manager` 配置关键项：

```json
{
  "target": "linux/amd64",
  "kernel_obj": "/linux/",
  "image": "/linux/bullseye.img",
  "sshkey": "/linux/bullseye.id_rsa",
  "syzkaller": "/syzkaller/",
  "procs": 8,
  "type": "qemu",
  "enable_syscalls": ["open$proc", "read$proc", "write$proc", "close$proc"],
  "vm": {"count": 4, "kernel": "/linux/arch/x86/boot/bzImage", "cpu": 2, "mem": 2048}
}
```

最小化后的 `repro.txt`（原文）：

```text
r0 = open$proc(&(0x7f0000000580), 0x2, 0x24)
write$proc(r0, 0x0, 0x0)
```

KASAN 关键结论（原文截图）：`BUG: KASAN: slab-out-of-bounds in _copy_from_user` / `Write of size 4096 at addr ... by task syz.3.17`；对象属于 `kmalloc-512`，越界发生在 `proc_write` 分配的缓冲区。PoC 为 fuzz 配置与 crash 复现，不是内核提权 exploit；未在本机执行。

## 变体与关联

- **接口变体**：ioctl 驱动需要描述 `ioctl$cmd(fd, cmd const[...], arg ptr[in, struct])`；netlink/socket 驱动用 `socket`/`sendmsg`/`recvmsg`；sysfs 用固定路径的 open/read/write。
- **描述变体**：用 `no_generate` 禁止自动生成、`disabled` 暂时禁用、`timeout[N]` 调整超时；用 `headerparser` 从 C 头文件自动生成结构体字段。
- **架构变体**：交叉编译 `make CC=aarch64-linux-gnu-g++ TARGETARCH=arm64`，目标 `linux/arm64`；也可对 Android/Windows/OpenBSD 等目标使用对应 target。
- **复现变体**：`syz-repro` 生成 C repro，`syz-crush` 重复验证，`syz-execprog` 手动执行 prog；崩溃类型可能是 `no output from test machine`/`lost connection`（死锁/挂起）。
- **关联**：[[code-analysis-vuln-discovery-local-fuzzing-harness-function-extraction]]（用户态函数级 fuzz harness）、[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（QEMU 内核调试）、[[binary-pwn-kernel-ioctl-global-length-oob-read-flag]]（ioctl 长度越界读）。
- **边界**：syzlang 描述错误（路径/参数/资源不匹配）会导致 fuzzer 打不到目标函数；KCOV/KASAN 未开启会漏报或低效；驱动依赖特定时序/硬件时，纯 QEMU fuzz 可能无法触发；崩溃复现率不是 100%，需多 VM/多次验证。

## 检测与防御

- **驱动开发侧**：分配与复制长度必须使用同一上界；对用户传入的 `n` 做上限校验（如 `n > MAX_SIZE` 直接返回 `-EINVAL`）；优先用 `memdup_user`/`strndup_user`/`copy_from_user` 的返回值检查；避免 `kmalloc(n + 常量)` 后再用更大长度复制。
- **测试侧**：在 CI 中编译带 KCOV/KASAN 的内核，针对新驱动写 syzlang 并跑定向 fuzz；把 syzbot 的 crash 签名/复现纳入回归；对 ioctl/procfs 接口做参数长度/边界用例。
- **检测信号**：KASAN `slab-out-of-bounds`/`use-after-free` 报告、`copy_from_user` 调用栈、`kmalloc-*` cache 与对象大小不匹配、syz-manager crash 目录中同一 signature 反复出现。
- **防御加固**：开启 `CONFIG_KASAN`/`CONFIG_KFENCE`/`CONFIG_SLAB_FREELIST_HARDENED` 等测试/加固选项；限制未privileged用户对 procfs 设备的写权限；对驱动接口做最小权限与输入校验；上线前用 Syzkaller/syzbot 类持续 fuzz。
- **CTF/研究场景**：该流程用于发现内核 bug，不直接给出提权链；发现 crash 后仍需按内核利用方法（堆喷、信息泄露、ROP 等）验证可利用性，不能把 KASAN crash 直接等同于可提权漏洞。
