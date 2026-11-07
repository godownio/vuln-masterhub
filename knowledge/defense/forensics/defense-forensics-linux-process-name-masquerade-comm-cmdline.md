---
id: defense-forensics-linux-process-name-masquerade-comm-cmdline
title: Linux 进程名伪装取证：comm/cmdline/exe 三源不一致与 15 字节上限
type: scenario
domain: defense
path: defense/forensics
technique: linux-process-name-masquerade-triage
aliases:
- comm vs cmdline
- 进程名伪装
- argv[0] 伪装
- PR_SET_NAME
- 'memfd: comm'
- kworker 伪装进程
- 进程名取证
tags:
- linux
- forensics
- process-masquerade
- comm
- cmdline
- prctl
- memfd
- anti-forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:47:47+08:00'
  notes: '已对照原文及16张图核对：comm=task_struct->comm/15字节上限、cmdline=argv[0]、memfd执行comm=memfd:、prctl(PR_SET_NAME)截断与exec重置、真实内核线程exe不可读、伪装进程exe=/memfd: (deleted)，与图10-12一致。修正：frontmatter别名''memfd: comm''未加引号被YAML解析为映射，已改为带引号字符串。未验证点：未本机复跑；不同内核/发行版comm命名可能有差异；无组件受影响版本，未设versions；frontmatter无sources/source_url。'
---

## 一句话结论

Linux 进程有两个“名字”：`comm`（内核 `task_struct->comm`，最多 15 个可见字符，看 `/proc/<pid>/comm` 或 `ps -o comm`）和 `cmdline`（用户态 `argv[0]` 起的参数字符串，看 `/proc/<pid>/cmdline` 或 `ps -o args`）；恶意样本可以用 `argv[0]` 把 cmdline 伪装成 `[kworker/0:1-events]`，用 `prctl(PR_SET_NAME)` 改 comm，但 comm 有 15 字节硬上限、且 `exec` 会重置，二者与 `/proc/<pid>/exe` 的不一致正是识别伪装进程的关键证据。

## 原理

- **comm**：内核维护在 `task_struct->comm`，长度 `TASK_COMM_LEN`（16 字节含结尾 NUL，即可见 15 字节）；`cat /proc/<pid>/comm`、`ps -o comm`、`ps -o comm=` 读取。内核线程的 comm 是完整的 `kworker/0:1-rcu` 之类名字。
- **cmdline**：用户态传给 `execve`/`fexecve` 的 `argv` 数组，`/proc/<pid>/cmdline` 用 NUL 分隔，`ps aux`/`ps -o args` 显示；长度没有固定 15 字节限制。`exec` 时传入的 `argv[0]` 只影响 cmdline，不会自动设置 comm。
- **memfd 执行的 comm**：`fexecve` 一个 memfd 时，comm 通常来自 `memfd_create` 的名字；原文传空字符串，comm 显示为 `memfd:`。因此进程可以同时拥有 cmdline `[kworker/0:1-events]` 和 comm `memfd:`。
- **`prctl(PR_SET_NAME)`**：可以设置 comm，但会被截断到 15 字节；如果在 loader 里、`fexecve` 之前调用，`exec` 会用新可执行文件名重新设置 comm，之前的设置丢失；要让 comm 生效，应由被执行后的 payload 自己调用，或通过写 `/proc/self/comm`（同样受长度限制）。原文示例中 comm 仍为 `memfd:`，也说明“只改 argv[0] 不够”。
- **三源不一致**：
  - `cmdline` 声称是 `[kworker/0:1-events]`，`comm` 却是 `memfd:` 或 15 字节截断的伪名；
  - **真正的内核线程** `/proc/<pid>/exe` 不可读（没有用户态可执行文件），而伪装进程返回 `/memfd: (deleted)`；
  - `ps aux` 的 COMMAND 列显示伪 cmdline，`ps -o comm` 显示真实 comm，二者对照即可发现异常。
- 进程名伪装的“天花板”在于内核同时保留 comm 和 cmdline 两个来源，且 `exec`/`fexecve` 的行为可预测；攻击者可以尽量让两者一致（payload 内 `prctl` + `<15` 字节名字），但仍难完全模仿真实内核线程的 exe/comm 组合。

## 触发条件

- Linux 进程能控制 `argv[0]`（自定义 `execve`/`fexecve` 参数）并可调用 `prctl(PR_SET_NAME)` 或写 `/proc/self/comm`。
- 目标名字不超过 15 字节（comm）或愿意接受截断；内核线程名字常带斜杠/连字符，容易被截断。
- 取证方有权限读取 `/proc/<pid>/comm`、`cmdline`、`exe`、`maps`（同用户或 root）。
- 需要先建立真实内核线程的基线（comm 形态、exe 不可读、cmdline 为空），才能判断伪装。

## 利用步骤

1. 攻击侧设置 cmdline：`execve`/`fexecve` 时传入 `argv[0] = "[kworker/0:1-events]"`；如需修改 comm，在 payload 启动后调用 `prctl(PR_SET_NAME, "[kworker/0:1]", 0, 0, 0)`，注意 15 字节截断。
2. 攻击侧检查效果：`cat /proc/<pid>/comm`、`tr '\0' ' ' < /proc/<pid>/cmdline`、`readlink /proc/<pid>/exe`，确认名字是否匹配预期。
3. 防守侧枚举：`ps -eo pid,user,comm,args` 对比 comm 与 args；对疑似内核线程的进程读取 `/proc/<pid>/exe`，真实内核线程 readlink 失败，伪装进程可能指向 `/memfd: (deleted)`。
4. 防守侧检查 `/proc/<pid>/maps`：memfd 映射显示 `00:01` + `/memfd:`；结合 comm/cmdline 判断。
5. 对 comm 与 cmdline 不一致、comm 为 `memfd:`、或自称 kworker 但 exe 可读的进程告警；保留证据后再终止。
6. 建立基线：记录常见内核线程 comm（`kworker/*`、`ksoftirqd/*`、`migration/*` 等）和它们“无用户 exe、无 cmdline”的特征；对业务进程记录正常 comm/cmdline 对应关系。

## PoC

```c
/* 在 payload 启动后设置 comm（注意 15 字节上限；在 fexecve 前设置会被 exec 重置） */
#include <sys/prctl.h>
prctl(PR_SET_NAME, "[kworker/0:1-events]", 0, 0, 0);
```

```bash
# 三源对照
pid=205081
cat /proc/$pid/comm
tr '\0' ' ' < /proc/$pid/cmdline; echo
readlink /proc/$pid/exe
# 典型伪装输出：
# memfd:
# [kworker/0:1-events]
# /memfd: (deleted)
```

```bash
# 找出 comm 与 cmdline 明显不一致的进程（示意）
for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    comm=$(cat "$p/comm" 2>/dev/null)
    args=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    exe=$(readlink "$p/exe" 2>/dev/null)
    case "$args" in
        *kworker*|*ksoftirqd*|*migration*)
            echo "pid=$pid comm=$comm args=$args exe=$exe" ;;
    esac
done
```

```text
# 真实内核线程 vs 伪装进程：
# 真实 kworker: comm=kworker/0:1-rcu, cmdline 空, readlink exe 失败
# 伪装进程:     comm=memfd:, cmdline=[kworker/0:1-events], exe=/memfd: (deleted)
```

## 变体与关联

- **变体：argv 内存覆写/setproctitle**：程序启动后改写 argv 所在内存，使 cmdline 看起来像别的进程；comm 仍可能暴露。
- **变体：写 `/proc/self/comm`**：与 `prctl(PR_SET_NAME)` 等价，同样受 15 字节限制；需在 exec 之后执行。
- **变体：短名伪装**：攻击者选择 `sshd`、`nginx` 等 15 字节以内的名字，comm 与 cmdline 可以一致，但仍可通过 exe/maps/网络行为/父子进程关系识别。
- **关联卡片**：[[pentest-c2-linux-memfd-create-fileless-elf-execution]]（memfd 无文件执行与 argv 伪装）、[[defense-detection-linux-memfd-fileless-process]]（memfd 检测）、[[pentest-c2-linux-implant-anti-forensics-masquerade-node-id]]（Linux 植入体文件名/节点 ID 反取证）、[[defense-forensics-proc-environ-startup-view-split]]（/proc 视图差异）。
- **边界**：不同内核/发行版对 memfd 的 comm 命名可能略有差异；`ps` 版本/选项影响显示列；只有 root/同用户能读部分 `/proc` 字段；短名伪装可让 comm/cmdline 一致，需要更多行为证据。

## 检测与防御

- **三源对照**：始终同时看 `comm`、`cmdline`、`exe`（必要时加 `maps`、`status`、`cwd`、父子进程），不要只信 `ps aux` 的 COMMAND 列。
- **基线**：维护内核线程 comm 白名单/形态基线；真实内核线程无用户 exe、cmdline 为空；对“自称 kworker 但有 memfd exe”的进程立即告警。
- **监控**：auditd 记录 `execve`/`execveat`/`prctl`（如可）与 `/proc` 读取；EDR 监控 memfd_create/execveat；对 comm 变更（`prctl(PR_SET_NAME)`）做异常检测。
- **加固**：限制非特权用户对 `/proc/<pid>` 的访问（hidepid）、启用 YAMA ptrace_scope、监控 memfd 执行；对业务进程固定 comm/cmdline 基线，发现突变告警。
- **响应**：发现伪装进程后先保存 `/proc/<pid>/{comm,cmdline,exe,maps,status,fd}` 与内存镜像，再终止；检查 loader 自删除/父进程/网络连接，防止遗漏。
