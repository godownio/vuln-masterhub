---
id: binary-pwn-kernel-kernfs-pr-cont-buf-cgroup-path-data-placement
title: kernfs_pr_cont_buf 内核数据布置：iptables cgroup match 的 --path 把可控数据写进已知地址全局缓冲区
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernfs-pr-cont-buf-cgroup-path-data-placement
aliases:
- kernfs_pr_cont_buf
- cgroup match 布置数据
- iptables --path 内核写
- 已知内核地址布置伪造结构
- 全局缓冲区写原语
- 少泄露一次堆地址
tags:
- linux
- kernel
- pwn
- kernfs
- cgroup
- iptables
- xt-cgroup
- data-placement
- fake-object
- kaslr
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V593
  verified_at: '2026-11-12T15:34:15+08:00'
  notes: 已对照原文与 gdb dump 核对：kernfs_pr_cont_buf 为内核静态全局缓冲区、地址=内核基址+固定偏移；prepare_smap_bypass() 的 unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET)+setgroups/uid_map/gid_map+iptables -A OUTPUT -m cgroup --path <payload> -j LOG 代码与原文一致；原文 gdb x/400xg 显示填充字符 0x43/0x42、内部指针 0xffffffff81ffaee0/0xffffffff8391c588 与命令串 /usr/bin/chmod u+s /usr/bin/python3 落在缓冲区 +112~+272 偏移，卡片引用一致。修正：写入机制表述精确化为 xt_cgroup rev2 --path 在规则检查阶段 cgroup_get_from_path()→kernfs_walk_ns() strlcpy 整段路径进 kernfs_pr_cont_buf（原表述『路径匹配/格式化』不准确）。未验证点：原文未在本机复测，具体偏移需按目标 vmlinux 核对，卡片已注明。
---

## 一句话结论

`kernfs_pr_cont_buf` 是 kernfs 使用的全局静态缓冲区（内核 .data/.bss，地址 = 内核基址 + 固定偏移）；iptables `cgroup` match 在处理 `--path` 参数时会使用该缓冲区，攻击者通过 `iptables -A OUTPUT -m cgroup --path <payload> -j LOG` 把包含伪造结构/命令串的数据写进这个已知地址，从而在不泄露堆地址的情况下于内核固定地址布置可控数据，供 UAF/指针劫持利用（如伪造 `gsm->output` 函数指针）。

## 原理

- **全局缓冲区的位置可计算**：`kernfs_pr_cont_buf` 是内核镜像中的静态全局数组，KASLR 下其地址为 `kernel_base + 固定偏移`；只要泄露内核基址（如 `/sys/kernel/notes`），攻击者无需任何堆泄露就能知道它的绝对地址。
- **写入路径**：iptables 的 `cgroup` match（xt_cgroup rev2 的 `--path`）在规则检查阶段调用 `cgroup_get_from_path()` 解析用户路径，底层 `kernfs_walk_ns()` 会先用 `strlcpy` 把整段路径字符串拷进全局 `kernfs_pr_cont_buf` 再逐段解析。攻击者构造 `iptables -A OUTPUT -m cgroup --path <payload> -j LOG`，payload 中的字节（含伪造结构字段、函数指针、命令字符串）就落在该缓冲区内。文章在 gdb 中用 `x/400xg kernfs_pr_cont_buf` 验证：缓冲区中出现了攻击者的填充字符、内部指针（如 `0xffffffff8391c588`）与命令串 `/usr/bin/chmod +s /usr/bin/python`（image 03 / gdb dump）。
- **为什么有用**：内核 exploit 经常需要"在一个已知内核地址放一个伪对象"（fake `gsm`、fake `file`、fake ops 等）。传统做法要泄露堆地址或用 sprayed 页猜地址；本原语把"已知地址 + 可控内容"一次给到，减少一次堆地址泄露与堆布局依赖。
- **为什么需要用户命名空间**：普通用户默认不能改本命名空间的 iptables 规则；攻击者先 `unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET)` 获得新 user/net namespace 的 `CAP_NET_ADMIN`，在其中执行 iptables（`mount -t tmpfs tmpfs /run`、`/sbin/iptables ...`），内核仍写全局 `kernfs_pr_cont_buf`——缓冲区是全局的，不随 namespace 变化。
- **限制**：写入内容/长度受路径字符串解析与缓冲区大小限制，二进制/含 NUL 的布局需要用可接受字符与分段字段拼装（原文 payload 设计为固定偏移的字段+字符串）；不同内核版本的写入函数与偏移不同，必须按目标 vmlinux 核对。

## 触发条件

- 内核启用 kernfs/cgroup 且 iptables 可用 `cgroup` match（含对应内核模块）。
- 攻击者可创建 user+net namespace 并在其中执行 iptables（未禁用非特权 userns）。
- 已知内核基址（`/sys/kernel/notes` 等泄露），可计算 `kernfs_pr_cont_buf` 地址。
- 目标利用需要一个固定内核地址上的伪对象（如 `dlci->gsm` 指向的 fake `gsm`）。

## 利用步骤

1. 泄露内核基址，按目标 vmlinux 求 `kernfs_pr_cont_buf` 的偏移与绝对地址。
2. 设计 payload：在缓冲区目标偏移处放置伪结构字段（指针/函数地址）与命令字符串；其余用填充字符占位。
3. fork 子进程 `unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET)`，由父进程写 `setgroups`/`uid_map`/`gid_map` 完成映射；子进程 `mount -t tmpfs tmpfs /run` 后执行 `iptables -A OUTPUT -m cgroup --path <payload> -j LOG`。
4. 在 gdb/目标机用 `x/400xg kernfs_pr_cont_buf`（或间接行为）确认 payload 已落到预期地址与偏移。
5. 在 UAF/指针劫持利用中把目标对象指针（如 `dlci->gsm`）指向 `kernfs_pr_cont_buf + 目标偏移`，后续 `->output(...)`/`->ops->func(...)` 即使用伪结构与伪函数指针执行命令。

## PoC

原文 `prepare_smap_bypass()` 代码的核心（按原文整理，未在本机执行）：

```c
// 子进程：进入新 user/net namespace 并执行 iptables cgroup match
unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET);
write(a[1], &c, 1); read(b[0], &c, 1);         // 与父进程同步 uid_map 写入
system("mount -t tmpfs tmpfs /run");
fd = open("/dev/null", O_RDONLY); dup2(fd, 2); // 屏蔽 iptables 报错
execl("/sbin/iptables", "iptables", "-A", "OUTPUT", "-m", "cgroup",
      "--path", payload, "-j", "LOG", NULL);
```

```text
(gdb) x/400xg kernfs_pr_cont_buf
... kernfs_pr_cont_buf+112: 0x642f630062006100  0x4343434343434343
... kernfs_pr_cont_buf+144: 0xffffffff81ffaee0  0x0000000000000000
... kernfs_pr_cont_buf+224: 0xffffffff8391c588  0x6e69622f7273752f  ; /usr/bin/...
```

## 变体与关联

- 变体：其它"内核全局静态缓冲区 + 用户可控写入"的路径（日志缓冲区、sysfs/kernfs 打印路径、`modprobe_path` 类全局变量）；payload 可用分段多次写入拼装。
- 关联卡片：[[binary-pwn-kernel-sys-kernel-notes-kaslr-leak]]（定位该全局缓冲区所需的内核基址）、[[binary-pwn-kernel-cve-2023-6546-n-gsm-race-dlci-uaf-sched-window]]（本原语的实际使用场景：伪 `gsm`→`output` 劫持）。

## 检测与防御

- **缓解**：禁用非特权 user namespace 或限制其内 CAP_NET_ADMIN/iptables 使用；限制 `/sys/kernel/notes` 等基址泄露面；开启内核 CFG/CET 与 KASLR。
- **检测**：短时间创建 user/net namespace 并执行 iptables `-m cgroup --path` 且路径含大量异常字符/二进制填充；本地 exploit 时间线与 `kernfs_pr_cont_buf` 相关行为（需内核遥测/调试符号）；可疑的 `run_cmd`/usermodehelper 子进程。
