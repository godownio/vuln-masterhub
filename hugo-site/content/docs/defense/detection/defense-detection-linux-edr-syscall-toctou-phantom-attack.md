---
id: defense-detection-linux-edr-syscall-toctou-phantom-attack
title: Linux EDR 系统调用参数 TOCTOU 欺骗（Phantom Attack v1）：userfaultfd 三线程改写 connect/openat 用户缓冲区
type: scenario
domain: defense
path: defense/detection
technique: linux-edr-syscall-toctou-telemetry-spoof
tags:
- linux
- edr
- evasion
- toctou
- userfaultfd
- syscall
- telemetry
- falco
- tracee
- defense-evasion
- ebpf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T12:03:08+08:00'
  notes: 已对照 content.md 与 img19-20 核对：DEF CON 29 Phantom Attack v1、connect/openat 用户指针 TOCTOU、三线程（mmap 不分配/userfaultfd/Page Fault 写真实值/Spoof 写伪造值）、userfaultfd 自 Linux 5.2 需 CAP_SYS_PTRACE、Falco/Tracee 因跟踪 syscall 而非内部内核函数易受影响、Outflank 修改 connect POC 对多种 EDR 有效，均与原文一致。未验证点：原文未给出完整 POC 代码，卡片为伪代码骨架；img20 中 EDR 记录实际为 1.2.3.4（真实连接到达 google），卡片示例把 1.2.3.4/80.80.80.80 标注为真/伪值仅为示意，方向不影响机制。
url: /docs/defense/detection/defense-detection-linux-edr-syscall-toctou-phantom-attack/
draft: false
kb_aliases:
- Phantom Attack
- 幻影攻击
- Phantom Attack v1
- userfaultfd EDR 欺骗
- 系统调用 TOCTOU
- EDR 遥测伪造
- Falco Tracee TOCTOU
- connect 参数欺骗
- openat 参数欺骗
---

## 一句话结论

基于系统调用 kprobe/tracepoint 的 Linux EDR（如 Falco、Tracee 及部分商业产品）会在系统调用路径上直接读取用户态指针（`connect` 的 `sockaddr`、`openat` 的路径名等）；攻击者用 `userfaultfd` 把参数所在页设为缺页，由缺页处理线程在系统调用真正取参前写入真实恶意数据、再由 spoof 线程在系统调用返回后把同一页改写为伪造的良性数据，就能让内核实际执行的行为与 EDR 记录的事件字段不一致（Phantom Attack v1）。

## 原理

- **遥测读取与内核取参存在时间差**：syscall tracepoint/kprobe 触发时，内核可能尚未 `copy_from_user`，EDR 往往在事件回调里直接解引用用户指针读取参数。若攻击者能在“内核读取参数”和“EDR 读取参数”之间改写同一用户页，就会出现真实行为与遥测字段不一致的 TOCTOU。
- **userfaultfd 制造可控缺页**：主线程 `mmap` 一页但故意不分配物理页，把该页注册到 `userfaultfd`；当目标系统调用访问该页时触发缺页，缺页处理线程收到 `UFFD_EVENT_PAGEFAULT`，此时分配页并写入真实恶意参数（例如 `connect` 的目标 IP `1.2.3.4`），随后唤醒系统调用继续执行。
- **三线程协作（原文示图）**：
  1. Main Thread：`mmap` 新页但不分配，创建 Page Fault Thread 与 Spoof Thread；Spoof Thread 先阻塞在 mutex 上；对 Page Fault Thread 注册 `userfaultfd`。
  2. Main Thread：执行目标系统调用（如 `connect`），参数指针指向缺页，触发 Page Fault Thread。
  3. Page Fault Thread：分配并写入真实恶意数据到原页，释放 mutex。
  4. Spoof Thread：获得 mutex 后把原页改写为伪造的良性数据（如 `80.80.80.80`）。
  5. EDR 在之后的遥测读取中看到的是伪造数据，而内核已经用真实数据完成了连接/文件操作。
- **为什么 Falco/Tracee 易受影响**：它们跟踪的是系统调用而不是内部内核函数，并直接评估用户态提供的参数指针；而内核内部函数（如 `security_file_open`、`tcp_v4_connect`）拿到的已是拷贝/解析后的内核数据，读取时不再受用户页改写影响。
- **权限与替代路径**：从 Linux 5.2 起 `userfaultfd` 需要 `CAP_SYS_PTRACE`（或系统允许非特权 userfaultfd）；原文提到也可通过其他方式延长 TOCTOU 窗口，以普通用户身份利用。Outflank 对 POC 的 `connect` 分支做过修改并在测试中对多种 EDR 产品有效。
- **影响**：可把恶意连接/文件访问伪造成访问无害 IP/文件，污染 EDR 告警与取证结论；对依赖用户态参数做阻断决策的 EDR，还可能影响其拦截判断。

## 触发条件

- 目标 Linux EDR 使用 syscall tracepoint/kprobe/fentry 并在事件回调中直接读取用户态指针参数（而非内部内核函数参数）；
- 攻击进程能使用 `userfaultfd`（具备 `CAP_SYS_PTRACE`，或系统 `vm.unprivileged_userfaultfd=1`），或能用其他方式扩大取参与遥测读取之间的时间窗；
- 攻击者控制目标系统调用的参数缓冲区（如 `connect` 的 `sockaddr`、`openat` 的路径名字符串）；
- EDR 的遥测读取发生在缺页处理完成之后（Falco/Tracee 等 syscall 探针的典型时序）。

## 利用步骤

1. 选择要欺骗的 syscall 及参数页（网络事件用 `connect` 的 `sockaddr`，文件事件用 `openat` 的 pathname）。
2. `mmap` 一页并保持未分配；创建 `userfaultfd`，`UFFDIO_REGISTER` 该页为 miss 模式。
3. 启动 Page Fault Thread 等待 `UFFD_EVENT_PAGEFAULT`；启动 Spoof Thread 并让其阻塞在 mutex 上。
4. 主线程以该页作为参数调用目标 syscall，触发缺页。
5. 缺页线程 `UFFDIO_COPY` 写入真实恶意参数，唤醒 syscall；syscall 用真实参数完成操作。
6. 缺页线程释放 mutex，spoof 线程把同一页覆盖为伪造的良性参数。
7. EDR 读取该用户页时得到伪造值；对照实际网络/文件结果（如实际连接了恶意 IP）即可验证欺骗成功。

## PoC

原文未给出完整代码，仅给出三线程示意与 EDR 查询结果；以下为按原理归纳的最小伪代码骨架（非可直接运行的完整 POC）：

```c
void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// 不触碰 page，保持未分配
int uffd = userfaultfd(O_CLOEXEC);
ioctl(uffd, UFFDIO_API, &api);
struct uffdio_register reg = { .range = { page, PAGE_SIZE },
                               .mode = UFFDIO_REGISTER_MODE_MISSING };
ioctl(uffd, UFFDIO_REGISTER, &reg);
// Page Fault Thread: 等待缺页 → 写入真实 sockaddr(1.2.3.4:80) → UFFDIO_COPY
// Spoof Thread: 等待 mutex → 覆盖为伪造 sockaddr(80.80.80.80:80)

struct sockaddr_in *sa = (struct sockaddr_in *)page;
sa->sin_family = AF_INET;          // 触发缺页
connect(sock, (struct sockaddr *)sa, sizeof(*sa));  // 内核用真实值连接
// EDR 之后读取该页，看到 spoof 线程写入的伪造值
```

## 变体与关联

- **变体**：`openat` 路径名欺骗（文件事件）；对 `sendmsg`/`recvmsg` 缓冲区、`execve` argv 等任何“EDR 直接读用户指针”的参数同样适用；后续研究可能针对更多 syscall。
- **关联**：`binary-pwn-kernel-double-fetch-user-pointer-race-flag` 讲内核 double-fetch 竞态，本卡是同一“用户内存两次读取”思想在 EDR 遥测层的应用；`web/generic/race-condition` 中的 TOCTOU 模式亦可对照。
- **反制关联**：EDR 若改用内部内核函数（`security_file_open`、`tcp_v4_connect`）或 LSM hook 读取已拷贝的数据，则不受用户页改写影响；部分商业产品已采用这种实现。
- **边界**：需要能制造并控制缺页时序；若 EDR 在 syscall 入口先拷贝参数再异步上报，或禁用非特权 userfaultfd，利用难度显著上升。

## 检测与防御

- **遥测完整性**：EDR 不应直接信任用户态指针；在 syscall 入口立即 `copy_from_user` 快照参数，或改挂钩内部内核函数/LSM hook（此时数据已在内核缓冲区）。
- **userfaultfd 监控**：审计 `userfaultfd` 系统调用、`UFFDIO_REGISTER` 与频繁缺页事件；对敏感 syscall 前后的异常缺页做关联告警；生产环境可设置 `vm.unprivileged_userfaultfd=0` 并限制 `CAP_SYS_PTRACE`。
- **交叉校验**：将 EDR 记录的用户态参数与内核侧真实状态（socket 五元组、文件 inode/path、审计日志）对比，发现不一致时以内核状态为准。
- **检测规则**：同一进程短时间内对同一页反复触发 userfaultfd 缺页并执行 `connect`/`openat`；EDR 事件中的目标 IP/路径与网络流量/文件系统审计不一致。
- **防御**：优先使用基于 eBPF LSM/fentry 内部函数的遥测；对 EDR 自身做完整性保护，防止用户态参数欺骗影响告警与阻断。
