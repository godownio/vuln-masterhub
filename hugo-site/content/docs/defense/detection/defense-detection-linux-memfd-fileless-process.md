---
id: defense-detection-linux-memfd-fileless-process
title: Linux memfd 无文件进程检测：/proc exe/maps、bpftrace 与 auditd
type: scenario
domain: defense
path: defense/detection
technique: linux-memfd-fileless-detection
tags:
- linux
- detection
- memfd
- fileless
- bpftrace
- auditd
- procfs
- threat-hunting
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:47:49+08:00'
  notes: '已对照原文及16张图核对：/proc/*/exe遍历、/proc/*/maps的00:01+memfd特征、bpftrace memfd_create与execveat(AT_EMPTY_PATH=0x1000)、auditd规则/ausearch、合法memfd误报(pulseaudio/glycin-frame)、短命进程需提前布控均与原文/图15/16一致。修正：frontmatter别名''/proc/pid/exe /memfd: null''被YAML解析为映射，已改为带引号字符串。未验证点：bpftrace/auditd命令未在本机执行；tracepoint字段名随内核版本可能变化；无组件受影响版本，未设versions；frontmatter无sources/source_url。'
url: /docs/defense/detection/defense-detection-linux-memfd-fileless-process/
draft: false
kb_aliases:
- memfd 检测
- fileless 进程排查
- /proc/pid/exe /memfd
- /proc/pid/maps memfd
- bpftrace memfd_create
- auditd execveat AT_EMPTY_PATH
- 无文件恶意软件检测
---

## 一句话结论

用 memfd 执行的进程虽然磁盘上没有文件，但内核仍留下可查证据：`/proc/<pid>/exe` 指向 `/memfd: (deleted)`，`/proc/<pid>/maps` 出现 tmpfs 设备号 `00:01` 和 `/memfd:` 映射；快照式排查可以用 `/proc` 遍历，实时检测用 bpftrace 监控 `memfd_create` 与 `execveat(AT_EMPTY_PATH)`，持久化检测用 auditd 规则；对只运行几秒的 payload，必须提前开启审计/eBPF，事后快照来不及。

## 原理

- memfd 是匿名 tmpfs 文件：有 inode、可 mmap、可执行，但没有目录项；因此文件扫描、`rpm -Va`/`dpkg --verify`、`netstat`/`ss` 都无法定位它的二进制来源。
- `/proc/<pid>/exe` 对 memfd 进程解析为 `/memfd: (deleted)`：匿名 inode 没有可达 dentry，内核在生成链接时追加 `(deleted)`。正常进程指向磁盘路径（如 `/usr/bin/bash`、`/tmp/payload`）。
- `/proc/<pid>/maps` 中 memfd 映射的特征：设备号 `00:01`（tmpfs 虚拟设备）+ inode + 路径列 `/memfd: (deleted)`；正常磁盘可执行文件的设备号是真实分区（如 `00:2a`），路径是 `/tmp/payload` 等。
- 但仅靠 maps 有误报：桌面/服务进程也会用 memfd 做数据共享，原文的 grep 输出里出现 `pulseaudio`、`glycin-frame`、`xorg` 等合法 `/memfd:` 映射；要结合“该进程的 exe 是否指向 memfd”“是否可执行映射（r-xp）”“cmdline/comm”判断。
- 快照方法的窗口问题：`/proc` 只在进程存活时存在；一次性 payload（连入、读文件、外发、3 秒退出）可能赶不上扫描。bpftrace/auditd 在内核事件发生时记录，适合捕获短命进程。
- bpftrace：
  - `tracepoint:syscalls:sys_enter_memfd_create`：记录 pid、comm、`uname`（memfd 名字）、flags；正常服务器业务进程很少调用该 syscall。
  - `tracepoint:syscalls:sys_enter_execveat`：检查 `args->flags & 0x1000`（`AT_EMPTY_PATH`），这是“忽略路径、直接从 fd 执行”的标志；与 memfd fd 组合是 fileless 执行的强证据。
- auditd：`-a always,exit -F arch=b64 -S memfd_create -k memfd_watch` 与 `-S execveat -k execveat_watch`；日志记录 pid/uid/comm/参数，可用 `ausearch -k` 查询；规则写入 `/etc/audit/rules.d/` 持久化。审计必须提前开启，事后无法补录。
- `shm_open` 是另一条 fileless 路径，但文件在 `/dev/shm/` 有目录项，`ls` 可见，隐蔽性较弱；检测时也应关注 `/dev/shm` 下的可执行 ELF。

## 触发条件

- Linux 内核支持 memfd_create（3.17+）与 execveat；bpftrace 需要 root 和对应 tracepoint；auditd 需要安装并启用审计子系统。
- `/proc` 方法要求目标进程仍在运行、且取证方有权限读取 `/proc/<pid>/{exe,maps,cmdline,comm}`。
- bpftrace/auditd 规则需要在事件发生前挂载；对短命进程尤其关键。
- 需要区分合法 memfd 使用（图形栈、音频、数据库共享内存等）与恶意可执行映射；建立业务基线可降低误报。

## 利用步骤

1. **/proc exe 快照**：遍历 `/proc/[0-9]*/exe`，`readlink` 含 `memfd:` 即告警，并打印 cmdline：
   ```bash
   for pid in /proc/[0-9]*/; do
       p=$(basename "$pid")
       exe=$(readlink "/proc/$p/exe" 2>/dev/null)
       if echo "$exe" | grep -q "memfd:"; then
           cmdline=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
           echo "ALERT pid=$p exe=$exe cmdline=$cmdline"
       fi
   done
   ```
2. **/proc maps 指纹**：`grep -r "memfd:" /proc/[0-9]*/maps`，重点看设备号 `00:01`、`r-xp` 可执行映射和路径 `/memfd:`；与 exe/cmdline/comm 交叉验证，排除 `pulseaudio`/`glycin-frame` 等合法数据映射。
3. **bpftrace 实时监控 memfd_create**：
   ```bash
   bpftrace -e '
   tracepoint:syscalls:sys_enter_memfd_create {
       printf("memfd_create: pid=%d comm=%s name=%s flags=%d\n",
           pid, comm, str(args->uname), args->flags);
   }'
   ```
4. **bpftrace 监控 execveat + AT_EMPTY_PATH**：
   ```bash
   bpftrace -e '
   tracepoint:syscalls:sys_enter_execveat {
       if (args->flags & 0x1000) {
           printf("execveat(AT_EMPTY_PATH): pid=%d comm=%s fd=%d\n",
               pid, comm, args->fd);
       }
   }'
   ```
5. **auditd 持久化**：
   ```bash
   auditctl -a always,exit -F arch=b64 -S memfd_create -k memfd_watch
   auditctl -a always,exit -F arch=b64 -S execveat -k execveat_watch
   ausearch -k memfd_watch
   ausearch -k execveat_watch
   ```
   将规则写入 `/etc/audit/rules.d/` 并 `augenrules --load`。
6. **组合告警**：exe=memfd + 可执行 maps + 可疑 cmdline/comm（如自称 kworker 但 comm=memfd:）+ 网络连接；对一次性进程优先依赖 auditd/bpftrace。
7. **取证**：在进程退出前保存 `/proc/<pid>/{exe,maps,cmdline,comm,status,fd,net}` 与内存镜像；记录 loader 自删除留下的文件系统/审计线索。

## PoC

```bash
# 1) /proc/<pid>/exe 扫 memfd
for pid in /proc/[0-9]*/; do
    p=$(basename "$pid")
    exe=$(readlink "/proc/$p/exe" 2>/dev/null)
    if echo "$exe" | grep -q "memfd:"; then
        cmdline=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
        echo "ALERT pid=$p exe=$exe cmdline=$cmdline"
    fi
done

# 2) /proc/<pid>/maps 指纹
grep -r "memfd:" /proc/[0-9]*/maps 2>/dev/null

# 3) bpftrace 实时监控
bpftrace -e '
tracepoint:syscalls:sys_enter_memfd_create {
    printf("memfd_create: pid=%d comm=%s name=%s flags=%d\n",
        pid, comm, str(args->uname), args->flags);
}'

# 4) auditd 规则
auditctl -a always,exit -F arch=b64 -S memfd_create -k memfd_watch
auditctl -a always,exit -F arch=b64 -S execveat -k execveat_watch
ausearch -k memfd_watch
```

```text
# 预期告警示例：
# ALERT pid=211567 exe=/memfd: (deleted) cmdline=[migration/0]
# /proc/211567/maps: 00400000-00401000 r--p ... 00:01 7198 /memfd: (deleted)
# bpftrace: memfd_create called: pid=xxxx comm=ghost name= flags=1
```

## 变体与关联

- **变体：合法 memfd 误报**：图形/音频/数据库进程也可能使用 `/memfd:` 映射；优先看 `exe` 是否 memfd、是否有 `r-xp` 可执行映射、进程树与网络行为，建立白名单。
- **变体：短命进程**：快照法失效，必须提前部署 auditd/bpftrace；也可用 eBPF LSM/fanotify 等更底层监控。
- **变体：`shm_open`**：文件在 `/dev/shm/`，有路径，`ls` 可见；检测 `/dev/shm` 内 ELF/可执行文件。
- **关联卡片**：[[pentest-c2-linux-memfd-create-fileless-elf-execution]]（memfd 无文件执行与 PoC）、[[defense-forensics-linux-process-name-masquerade-comm-cmdline]]（comm/cmdline/exe 三源不一致）、[[web-java-classloader-memfd-fileless-agent-injection]]（Java Agent 场景的 memfd 注入）。
- **边界**：不同内核的 tracepoint 字段名可能变化；bpftrace 需要 root/内核支持；auditd 规则在高负载下可能丢事件；容器内 `/proc` 命名空间/权限会影响扫描结果。

## 检测与防御

- **检测**：部署 auditd `memfd_create`/`execveat` 规则并接入 SIEM；用 bpftrace/eBPF 实时告警；定期跑 `/proc/*/exe` 与 `/proc/*/maps` 巡检；对 `[kworker]` 等伪进程核对 comm/exe。
- **基线**：统计业务进程正常 memfd 使用（音频/图形/数据库），对新增 memfd_create 来源做白名单/告警；关注非 root 进程的 memfd 可执行映射。
- **加固**：对不需要 memfd 的服务用 seccomp 限制 `memfd_create`/`execveat`；启用 SELinux/AppArmor 限制可执行匿名映射；限制 `/proc` 访问（hidepid）与 ptrace；禁用不必要的 `/dev/shm` 执行。
- **响应**：发现 memfd 进程后先取证（exe/maps/cmdline/comm/fd/net/内存），再终止；检查 loader 自删除、父进程、网络连接与持久化；对一次性 payload 依赖审计回溯。
