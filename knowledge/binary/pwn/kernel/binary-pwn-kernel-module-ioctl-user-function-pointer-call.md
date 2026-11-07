---
id: binary-pwn-kernel-module-ioctl-user-function-pointer-call
title: 内核模块 ioctl 直接调用用户函数指针：无 KASLR 固定模块基址调用 win 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-module-ioctl-user-function-pointer-call
aliases:
- 内核任意函数调用
- ioctl 函数指针
- 用户传入函数指针
- 无 KASLR 模块基址
- pwn.college level 5
tags:
- kernel
- pwn
- ioctl
- function-pointer
- privilege-escalation
- no-kaslr
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:50:38+08:00'
  notes: 已对照原文核对代码/地址/偏移与利用链，一致；原文为 pwn.college 教学环境，卡内已标注地址偏移依赖具体内核版本/配置，未复跑 PoC。
---

## 一句话结论

当内核模块的 `ioctl` 在处理 `cmd==1337` 时直接执行 `((void (*)(void *, file *))arg)(&unk_298, file)`，用户传入的 `arg` 就被当作内核函数指针调用；在未开启 KASLR 的题目里模块基址固定为 `0xffffffffc0000000`，把 `arg` 设为 `基址 + win 偏移（0x22d）` 即可调用模块内的 `prepare_kernel_cred(0) + commit_creds()` 提权。

## 原理

- **用户可控函数指针**：`device_ioctl(file, cmd, arg)` 只用 `cmd==1337` 做判断，没有校验 `arg` 是否在模块允许的函数表内，直接 `call arg`；内核态执行用户指定地址，等于“任意内核函数调用”。
- **控制参数有限**：调用约定把 `rdi=&unk_298`、`rsi=file` 传进去；本题不依赖参数，目标 `win()` 只做 `prepare_kernel_cred(0)`/`commit_creds()`。
- **无 KASLR 的固定布局**：`/proc/cmdline` 含 `nokaslr`；x86_64 的 `MODULES_VADDR` 为 `__START_KERNEL_map + KERNEL_IMAGE_SIZE`，通常 `0xffffffff80000000 + 0x40000000 = 0xffffffffc0000000`；题目只有一个模块，基址就是它。
- **偏移**：逆向得到 `win` 在模块内偏移 `0x22d`，所以地址 `0xffffffffc000022d`。
- **为什么危险**：SMEP/SMAP 只阻止内核执行/访问用户页，不阻止 `call` 到合法内核地址；只要模块加载且无 KASLR，攻击者就能调用任意内核函数（或模块内后门函数）。
- **本题**：`win()` 调 `prepare_kernel_cred(0)` 得到 root cred，再 `commit_creds`，返回用户态后 `system("/bin/sh")` 即 root。

## 触发条件

- 可加载/已加载的内核模块暴露 `/proc` 设备并实现 `ioctl`，把用户参数当函数指针调用。
- 内核未开启 KASLR（`nokaslr`），或能泄露模块/内核基址。
- 模块内存在可用的提权函数（`win`），或能调用 `commit_creds`/`run_cmd` 等已知内核函数并控制参数。
- 用户对设备有访问权限。

## 利用步骤

1. 逆向模块，确认 `device_ioctl` 在 `cmd==1337` 时 `call arg`，并找到 `win` 的偏移（本题 `0x22d`）。
2. 查看 `/proc/cmdline` 是否含 `nokaslr`；计算模块基址 `0xffffffffc0000000`。
3. 打开 `/proc/pwncollege`，调用 `ioctl(fd, 1337, 基址 + win 偏移)`。
4. `win()` 执行 `prepare_kernel_cred(0)`/`commit_creds`，当前进程获得 root。
5. `system("/bin/sh")` 或直接读 `/flag`。
6. 若 KASLR 开启，先通过 `/sys/module/<name>/sections/.text`、dmesg 泄露或已知内核符号相对偏移计算基址。

## PoC

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) return 1;
    ioctl(fd, 1337, 0xffffffffc000022dUL);  // 模块基址 + win 偏移
    system("/bin/sh");
    close(fd);
    return 0;
}
```

说明：地址/偏移来自原文的 pwn.college level 5 环境（nokaslr、单模块）；不同内核/模块需重新计算。PoC 未在本机复跑。

## 变体与关联

- **KASLR 开启**：用 `/sys/module/<name>/sections/.text`（需 root/权限）、`/proc/kallsyms`、dmesg 泄露、或模块内信息泄露获得基址。
- **调用其他内核函数**：`commit_creds`、`run_cmd`/`call_usermodehelper`、`modprobe_path` 写入等；注意控制 rdi/rsi 等参数。
- **函数指针在结构体**：ioctl 把用户结构体里的函数指针保存后调用，类似。
- **关联**：[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（UAF 回调劫持）、[[binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd]]（结构体函数指针覆盖）；用户态对应 [[binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc]]。

## 检测与防御

- **代码审计**：禁止把用户传入的地址/函数指针直接 `call`；ioctl 命令应只调用内部固定的函数表，参数做范围/类型校验。
- **KASLR**：开启 KASLR、隐藏 `/proc/kallsyms`、限制 `/sys/module/*/sections` 访问；SMEP/SMAP/CFI 可增加利用难度。
- **检测**：监控内核模块中的间接调用、异常 ioctl 参数（指向内核地址）、模块加载；对 `/proc/<device>` 的异常访问告警。
- **边界**：本卡是 CTF/教学模块的设计缺陷；真实内核模块应避免暴露任意函数调用原语。
