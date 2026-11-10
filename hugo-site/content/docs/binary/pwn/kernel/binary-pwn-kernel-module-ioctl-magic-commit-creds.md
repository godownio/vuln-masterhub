---
id: binary-pwn-kernel-module-ioctl-magic-commit-creds
title: 内核模块 ioctl 隐藏提权命令：objdump 还原命令码/魔数后 commit_creds(prepare_kernel_cred(0)) 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-module-ioctl-magic-commit-creds
tags:
- kernel
- pwn
- ioctl
- kernel-module
- privilege-escalation
- objdump
- reverse
- commit-creds
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V331-fix
  verified_at: '2026-11-08T18:10:21+08:00'
  notes: V331 核对发现 PoC 输出 uid 数字误用 seccomp 演示的 1234，原文实为 ctf uid=1000（图47/48）；主会话已修正两处为 1000，按 V331『修正后可转 verified』建议转 verified。其余机制、命令码/魔数、kASLR 说明均与原文一致。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-module-ioctl-magic-commit-creds/
draft: false
kb_aliases:
- 内核模块后门 ioctl
- make_root 内核模块
- pwn.college 内核提权
- ioctl 0x7001 0x13371337
- commit_creds prepare_kernel_cred 提权
- 逆向 .ko 找 ioctl 命令码
---

## 一句话结论

内核模块（教学/后门）在 ioctl 处理函数里把某个命令码加魔数作为提权开关，命中后执行 `commit_creds(prepare_kernel_cred(NULL))`；普通用户用 `objdump -M intel -d module.ko` 逆向出命令码（本例 0x7001）与魔数（0x13371337），open 对应 `/proc` 设备并调用 `ioctl(fd, 0x7001, 0x13371337)`，即可把当前进程 euid 改为 0 并拿到 root shell。

## 原理

- Linux 内核用 `task_struct` 记录每个进程，其中 `cred` 结构的 `euid` 决定权限检查结果；把当前进程的 euid 变成 0 就是提权。
- 内核提供两个凭证 API：`prepare_kernel_cred(struct task_struct *reference)` 创建 cred（传 NULL 时创建一个具有 root 全权限的 cred），`commit_creds(struct cred *)` 把新 cred 应用到当前进程。因此 `commit_creds(prepare_kernel_cred(NULL))` 是经典的内核提权原语。
- 本例的 `make_root.ko` 在 `/proc` 下创建 `pwn-college-root` 设备，注册 open/read/write/release/ioctl；ioctl 处理函数先比较 `ioctl_num` 是否等于模块内定义的 `PWN` 命令值，再比较 `ioctl_param` 是否等于魔数 `0x13371337`，两者都满足就调用 `commit_creds(prepare_kernel_cred(NULL))`。
- 命令码不一定在文档/源码中给出，需要反汇编 `.ko`：`objdump -M intel -d src/make_root.ko`，在 ioctl 分发的比较指令处读到立即数 `0x7001`；魔数 `0x13371337` 同理可在比较或调用点确认。
- 这是模块主动暴露的提权接口（教学模块/后门），不是内存破坏漏洞；能打开设备并能发出正确 ioctl 的普通用户都可利用。模块内部调用已解析的 `commit_creds`/`prepare_kernel_cred` 符号，因此即使内核开启 kASLR，也不影响这条调用路径；只有攻击者自己构造内核 shellcode/ROP 时才需要另行泄露内核基址。

## 触发条件

- 目标内核已加载暴露提权 ioctl 的模块（本例 pwn.college 的 `make_root.ko`，设备 `/proc/pwn-college-root`）。
- 普通用户对设备文件有 open/ioctl 权限。
- 能获取或读取 `.ko` 进行逆向，或已知命令码与魔数。
- 内核未通过 LSM/lockdown/模块签名等机制阻止该设备调用。

## 利用步骤

1. 确认模块与设备：`lsmod` 查看已加载模块，检查 `/proc`、`/dev` 下新增的设备文件（本例 `/proc/pwn-college-root`）。
2. 反汇编模块：`objdump -M intel -d src/make_root.ko`，定位 ioctl 处理函数，读出第一个比较的命令码（`0x7001`）与第二个比较的魔数（`0x13371337`）。
3. 编写利用程序：打开设备，调用 `ioctl(fd, 0x7001, 0x13371337)`；成功后 `getuid()` 应变为 0，再 `execl("/bin/sh","/bin/sh",NULL)` 获得 root shell。
4. 在无 libc 的 QEMU 环境静态编译：`gcc -o getroot -static getroot.c`。
5. 在 QEMU 内切换普通用户（原文为 ctf，uid=1000）执行，验证 uid 从 1000 变为 0，并可读取 `/flag`。
6. 若模块不直接调用凭证 API 而需要攻击者自行调用内核函数，则从 `/proc/kallsyms`（kASLR 关闭）或泄露地址计算 `commit_creds`/`prepare_kernel_cred`，再构造内核 shellcode/ROP 调用。

## PoC

```c
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int main(void) {
    int fd = open("/proc/pwn-college-root", 0);
    assert(fd > 0);

    printf("uid before: %d\n", getuid());
    ioctl(fd, 0x7001, 0x13371337);   // 命令码与魔数由 objdump 逆向得到
    printf("uid after: %d\n", getuid());

    execl("/bin/sh", "/bin/sh", NULL);
    return 0;
}
```

```bash
gcc -o getroot -static getroot.c
```

运行后依次输出 `uid before: 1000`、`uid after: 0`，并进入 root shell。PoC 未在本机执行（文章为不可信数据，未运行其中代码）。

## 变体与关联

- 命令码与魔数因模块而变，必须按目标 `.ko` 反汇编确认；参数也可能是用户结构体指针，需按 `copy_from_user` 的结构布局构造。
- 模块若把用户参数当函数指针直接 `call`，或允许覆盖结构体函数指针，利用方式不同：参见 [[binary-pwn-kernel-module-ioctl-user-function-pointer-call]]、[[binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd]]。
- 需要自行编写内核 shellcode 调 `commit_creds` 时，不能在内核态执行 `syscall`（会跳入假定来自用户态的 syscall_entry 导致崩溃）；应直接 `call` 内核 API，并用 `gs` 取 `current`：参见 [[binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec]]。
- seccomp 场景：同一教学模块还可提供清 `TIF_SECCOMP` 的 ioctl，先关闭 seccomp 再提权/读文件；该技术已有专门卡 [[binary-pwn-kernel-shellcode-clear-tif-seccomp]]。
- 边界：这是教学/后门模块场景，真实系统不存在该接口时不可用；kASLR 不影响模块内部已解析的符号调用。

## 检测与防御

- 检测：枚举已加载模块与新增 `/proc`/`/dev` 设备；审计模块 ioctl 中调用 `commit_creds`/`prepare_kernel_cred` 的代码；监控普通进程对字符设备的异常 ioctl 及随后的 uid 变化。
- 防御：不加载来源不明或调试用内核模块；启用模块签名与 kernel lockdown；设备文件仅 root 可读写；保持 kASLR/SMEP/SMAP；代码审计移除模块中的提权后门接口。
