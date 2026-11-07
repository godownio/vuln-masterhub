---
id: ctf-pwn-linux-module-lease-clone-uaf-commit-creds-kpti
title: Linux 内核模块租约克隆 UAF：对象复用泄露内核基址/通道字段 → 栈枢轴 ROP commit_creds
type: scenario
domain: ctf
path: ctf/pwn
technique: linux-module-lease-clone-uaf-commit-creds-kpti
tags:
- ctf
- pwn
- linux-kernel
- module
- uaf
- ioctl
- rop
- commit-creds
- kpti
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:00:00+08:00'
  notes: 已对照原文核对；note.ko 0x0e 克隆 UAF、0x0f/0x10 读写、gate/channel 泄露、0x4210 栈枢轴与 commit_creds+KPTI 链一致
url: /docs/ctf/pwn/ctf-pwn-linux-module-lease-clone-uaf-commit-creds-kpti/
draft: false
kb_aliases:
- note.ko 内核模块
- 租约克隆 UAF
- 自定义对象缓存复用
- 编织虚拟机 oracle
- 栈枢轴 gadget
- commit_creds(init_cred)
- KPTI trampoline
---

## 一句话结论

`note.ko` 是权限 0666 的 misc 字符设备，暴露约 40 个 ioctl；租约克隆 ioctl `0x0e` 释放旧缓冲区却不更新包装对象中的指针，留下悬空指针，`0x0f`/`0x10` 分别提供 UAF 读/写。用一个门对象回收该槽位即可泄露通道对象、通道随机字段与随机数函数地址，推出内核基址并覆写门对象关键字段；`0x1b` 把门字段复制进通道，控制通道属性。再解出编织对象的虚拟机预言机，用 `0x24-0x27` 创建通道并通过 `0x22` 泄露 secret；最后计算 `0x12` 号间接调用目标为模块 `endbr64; mov rsp,[rdi+0x28]; ret` 栈枢轴 gadget（模块基址+0x4210），把编织帧变成 ROP 栈，`commit_creds(init_cred)` 提权后经 KPTI 跳板返回用户态读 flag。

## 原理

- **设备与对象**：`note.ko` 是 misc 字符设备，权限 0666，暴露约 40 个 ioctl；每次打开设备都会维护一组自定义缓存对象，包括封条、租约、通道、帧与分片，以及一个内含四指令虚拟机预言机和四个随机表项的编织对象。
- **漏洞**：ioctl `0x0e` 克隆租约缓冲区时会释放旧缓冲区，却不更新包装对象中的指针，留下悬空指针；`0x0f` 是释放后使用读，`0x10` 是释放后使用写，作用域是控制与封条缓存。
- **对象复用泄露**：用一个门对象回收该槽位，可以泄露通道对象、通道中的随机字段以及随机数函数地址，从而推出内核基址；并可覆写门对象的关键字段。`0x1b` 会把门字段复制进通道，从而控制通道的关键属性。
- **编织虚拟机**：编织对象含四指令虚拟机预言机与四个随机表项；用命令 `0x24` 到 `0x27` 创建通道，并通过 `0x22` 预言机泄露每次打开设备的 secret。
- **控制流劫持**：计算 `0x12` 号间接调用的目标，设置为模块中的 `endbr64; mov rsp,[rdi+0x28]; ret` 栈枢轴 gadget，地址为模块基址加 `0x4210`。被编织的帧因此成为 ROP 栈：用 `commit_creds(init_cred)` 提权，再经 KPTI 跳板返回用户态，得到 root shell 读取 flag。
- **根因**：克隆操作先 `kfree` 旧对象再复制，没有把包装对象里的指针改成新对象或置空；释放后的槽位被其他类型对象复用，形成类型混淆/悬空引用。

## 触发条件

- 目标加载了存在租约克隆缺陷的内核模块，设备节点权限允许低权限用户打开并调用 ioctl。
- 模块使用自定义对象缓存（非 slab 直接分配），释放后的槽位可被其他类型对象复用。
- 模块暴露 UAF 读/写 ioctl，且能通过门对象/通道对象泄露内核地址。
- 模块内有可被间接调用/编织的虚拟机或函数指针，且存在可用的栈枢轴 gadget。
- 内核开启 KPTI，需要 KPTI trampoline 返回用户态；目标内核版本与模块偏移已知。

## 利用步骤

1. 打开 `/dev/note`，按 ioctl 序列创建 piece/journal/receipt，写入可控值；调用 `0x22` 预言机泄露 4 个 qword，逆转 8 轮混合得到 state0/state16/state2592。
2. 创建编织对象，`0x24` 泄露 loom 的 `0x128/0x130` 随机值；为 4 个槽位搜索满足 C0 flags/3A0 返回目标的程序，`0x25/0x26` 提交并校验，逆推得到 `loom_q[]`。
3. `0x27` 混合并校验；创建通道 `0x11`；创建 frame 并 clone 提高计数。
4. 创建 lease0 并 clone，触发 `0x0e` 的 UAF；创建 gate 对象回收槽位，`0x0f` 读 gate 泄露 `g32/g40/g48/g56/g64`；恢复 channel、v147、modbase、kbase。
5. 通过 `0x10` UAF 写把 gate 字段改成枢轴地址；`0x1b` 把 gate 字段复制进 channel，劫持 `channel[32]`。
6. `0x1c` 泄露 frame16，创建 weave，按 4 个 shard 写入 ROP 链（`pop rdi; init_cred; commit_creds; trampoline; 用户态 win`），`0x1e` flatten。
7. 创建 lease1/clone、seal42、`0x20/0x21` 刷新/finalize；`0x12` 触发间接调用，栈枢轴到编织帧，提权后返回用户态读 `/root/flag`。

## PoC

关键常量与 ROP（原文环境，模块/内核偏移需按目标复核）：

```c
u64 kbase    = leaked_random_fn - 0x6b0b20;
u64 modbase  = (g32 ^ g_v147) - 0x760;
u64 pivot    = modbase + 0x4210;      // endbr64; mov rsp,[rdi+0x28]; ret
u64 pop_rdi  = kbase + 0x142d79;
u64 commit_creds = kbase + 0xc19b0;
u64 init_cred    = kbase + 0x1a52fa0;
u64 tramp        = kbase + 0x10016b0 + 0x1b;

u64 chain[25] = {0};
chain[0] = pop_rdi; chain[1] = init_cred;
chain[2] = commit_creds; chain[3] = tramp;
chain[20] = (u64)&win; chain[21] = 0x33;
chain[22] = user_rflags; chain[23] = user_rsp; chain[24] = 0x2b;
```

UAF 关键序列：

```text
0x0d lease0 create -> 0x0e lease0 clone (frees old buffer, pointer stays)
0x19 gate create -> 0x0f gate read (leak channel/random/kbase)
0x10 gate write (pivot ^ v147) -> 0x1b push gate into channel
0x1c frame leak -> 0x17 weave create -> 0x1d shard0..3 -> 0x1e flatten
0x12 call (indirect target = pivot)
```

## 变体与关联

- 若没有门对象，可用其他同尺寸对象回收槽位，泄露不同字段；核心是“UAF + 对象类型复用 + 可控字段复制”。
- 栈枢轴 gadget 可换成 `xchg rsp, rax`、`push rdi; pop rsp`、`leave; ret` 等；若模块无合适 gadget，可先泄露内核基址再用内核 gadget。
- KPTI 关闭时可省去 trampoline；SMEP/SMAP 开启时需要 ROP 而不是直接跳用户态 shellcode。
- 关联：Linux 内核模块 UAF、自定义对象缓存类型混淆、commit_creds ROP、KPTI 返回卡。

## 检测与防御

- 克隆/复制操作必须在新对象分配成功后再释放旧对象，并更新包装指针；释放后置空，避免悬空引用。
- 自定义对象缓存加类型标签/魔数/引用计数，跨类型复用前清零并校验；ioctl 参数做完整边界检查。
- 模块内函数指针表/虚拟机入口做完整性校验（CFI/只读表），不要把用户可控字段直接作为间接调用目标。
- 内核开启 KPTI/SMEP/SMAP/CFI，限制模块加载权限；设备节点不要 0666。
- 检测：对 `/dev/note` 的异常 ioctl 序列（clone 后立即 create/read/write、0x1b 复制、0x12 调用）；内核日志中的 UAF/KASAN 报告；模块代码段异常执行流。
