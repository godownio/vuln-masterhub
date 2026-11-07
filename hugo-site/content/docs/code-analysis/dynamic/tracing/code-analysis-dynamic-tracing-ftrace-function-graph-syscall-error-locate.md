---
id: code-analysis-dynamic-tracing-ftrace-function-graph-syscall-error-locate
title: ftrace function_graph 定位 syscall 内核错误返回点：strace→函数图追踪→gdb 断点
type: scenario
domain: code-analysis
path: code-analysis/dynamic/tracing
technique: ftrace-function-graph-syscall-error-locate
tags:
- linux
- kernel
- debugging
- ftrace
- function-graph
- funcgraph-retval
- strace
- gdb
- syscall
- tracing
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T20:09:32+08:00'
  notes: 已对照原文与17张图核对：strace EINVAL（图4）、function_graph/funcgraph-retval 显示 genl_rcv_msg=-22（图5）、gdb 定位 net/netlink/genetlink.c:1173 nlmsg_len<nlmsg_msg_size(hdrlen) 返回 -EINVAL（图6）、TIPCv2 命令6 can dumpit（图7）、脚本与按 BASHPID 过滤均与卡片一致。未验证点：本环境无 tracefs，未实际运行；frontmatter 无 sources/source_url。
url: /docs/code-analysis/dynamic/tracing/code-analysis-dynamic-tracing-ftrace-function-graph-syscall-error-locate/
draft: false
kb_aliases:
- ftrace function_graph
- funcgraph-retval
- 定位 EINVAL 来源
- syscall 错误返回点
- 内核调用图跟踪
- tracefs 调试
- genl_rcv_msg 排查
---

## 一句话结论

用户态 PoC 的系统调用只返回一个 `errno`（如 `EINVAL`/`EOPNOTSUPP`）时，`strace` 只能看到错误码，无法知道内核里是哪一层返回的；在 tracefs 上启用 `function_graph` 并打开 `options/funcgraph-retval`，按 PoC 的 PID 过滤，就能在内核函数调用图里直接看到每个函数的返回值，定位到返回该错误的函数，再用 gdb 在该函数下断点查看具体分支。

## 原理

- `strace` 停在用户态/系统调用边界，只显示 `sendto(...) = -1 EINVAL`；`perror` 更只有一行字符串。一个 syscall 内核路径可能有几十层函数都能返回 `-EINVAL`，盲目单步代价很高。
- ftrace 的 `function_graph` tracer 记录函数进入/退出（带缩进和耗时），形成调用图；打开 `options/funcgraph-retval` 后，每个函数退出时会把返回值附加到 trace 行，例如 `} /* genl_rcv_msg = -22 */`。
- 错误码会沿调用栈向上传播；在 trace 中从外层往内看，**第一个返回目标错误码的函数**就是错误产生点（或至少是最近的、可下断点的候选）。之后用 gdb 在该函数入口下断点，单步到返回 `-EINVAL` 的源码行即可确认条件。
- 用 `set_ftrace_pid` 只跟踪目标进程（`echo $BASHPID > set_ftrace_pid` 写在子 shell 里，确保记录的是执行 `exec /exp` 的那个 PID），避免全系统 trace 被噪声淹没。
- `funcgraph-retval` 不是所有内核都有；没有该文件时仍可用 `function_graph` 看调用路径，或改用 kprobe/kretprobe 抓返回值。
- 该方法是通用的内核 PoC 调试技巧：先定位“哪个函数返回错误”，再定位“函数里哪个条件返回错误”，把原本需要遍历长调用链的排错压缩成两步。

## 触发条件

- 能挂载/访问 tracefs（通常需要 root；路径可能是 `/sys/kernel/debug/tracing` 或 `/sys/kernel/tracing`）。
- 内核启用了 `CONFIG_FUNCTION_TRACER`、`CONFIG_FUNCTION_GRAPH_TRACER`，且存在 `options/funcgraph-retval`（较新内核）。
- 目标 PoC 能在该环境运行，且能复现目标 `errno`；trace 期间最好固定 CPU/减少其他负载，避免环形缓冲区被覆盖。
- 需要内核符号（`vmlinux`/`/proc/kallsyms`）来在 gdb 中按函数名下断点；无符号时可用 trace 里的函数地址 + `add-symbol-file`/`vmlinux-to-elf` 还原。

## 利用步骤

1. 先用 `strace -f ./exp` 或程序内 `perror` 确认失败的系统调用与 `errno`（例如 netlink dump 返回 `EINVAL`）。
2. 挂载 tracefs 并复位 tracer：
   ```bash
   TRACE_DIR=/sys/kernel/debug/tracing
   [ -d "$TRACE_DIR" ] || mount -t tracefs nodev /sys/kernel/debug
   echo 0 > "$TRACE_DIR/tracing_on"
   echo nop > "$TRACE_DIR/current_tracer"
   echo > "$TRACE_DIR/set_ftrace_filter"
   echo > "$TRACE_DIR/set_ftrace_pid"
   echo > "$TRACE_DIR/set_graph_function"
   [ -f "$TRACE_DIR/options/funcgraph-retval" ] && echo 1 > "$TRACE_DIR/options/funcgraph-retval"
   echo function_graph > "$TRACE_DIR/current_tracer"
   ```
3. 只跟踪目标进程并运行 PoC（子 shell 里写 `$BASHPID` 再 `exec`，保证 PID 正确）：
   ```bash
   (
       echo $BASHPID > "$TRACE_DIR/set_ftrace_pid"
       echo 1 > "$TRACE_DIR/tracing_on"
       exec /exp
   ) &
   wait $!
   echo 0 > "$TRACE_DIR/tracing_on"
   cat "$TRACE_DIR/trace" > /tmp/trace.txt
   ```
4. 在 trace 中搜索错误码的十进制/符号，找到返回它的函数：
   ```bash
   grep -n -- '-22\|EINVAL' /tmp/trace.txt | head
   # 例：} /* genl_rcv_msg = -22 */
   ```
5. 用 gdb 在定位到的函数下断点，重新运行 PoC，单步到返回错误的源码行：
   ```bash
   gdb -q vmlinux
   (gdb) b genl_rcv_msg
   (gdb) run
   (gdb) bt
   (gdb) list
   ```
   原文示例最终定位到 `net/netlink/genetlink.c` 中 `nlmsg_len < nlmsg_msg_size(hdrlen)` 的 `return -EINVAL`；修复后又出现 `EOPNOTSUPP`，进一步发现 TIPC 有旧 `TIPC` 与 `TIPCv2` 两个 family，只有 `TIPCv2` 的命令 6 支持 dumpit。
6. 根据源码条件修正 PoC 的报文/参数；若还有新错误，重复步骤 3–5。对已知函数范围可加 `set_graph_function` 限制调用图，降低噪声和开销。

## PoC

```bash
#!/bin/bash
# strace 先确认 errno，例如: sendto(...) = -1 EINVAL
TRACE_DIR="/sys/kernel/debug/tracing"
[ ! -d "$TRACE_DIR" ] && mount -t tracefs nodev /sys/kernel/debug

echo 0 > "$TRACE_DIR/tracing_on"
echo nop > "$TRACE_DIR/current_tracer"
echo > "$TRACE_DIR/set_ftrace_filter"
echo > "$TRACE_DIR/set_ftrace_pid"
echo > "$TRACE_DIR/set_graph_function"
[ -f "$TRACE_DIR/options/funcgraph-retval" ] && echo 1 > "$TRACE_DIR/options/funcgraph-retval"
echo function_graph > "$TRACE_DIR/current_tracer"

(
    echo $BASHPID > "$TRACE_DIR/set_ftrace_pid"
    echo 1 > "$TRACE_DIR/tracing_on"
    exec /exp
) &
wait $!

echo 0 > "$TRACE_DIR/tracing_on"
cat "$TRACE_DIR/trace" > /tmp/trace.txt
grep -n -- '-22\|EINVAL' /tmp/trace.txt | head
```

预期 trace 片段形如：

```text
0)               |  genl_rcv_msg() {
0)   0.088 us    |    mutex_lock();
...
0)   0.661 us    |  }
0)               | } /* genl_rcv_msg = -22 */
```

## 变体与关联

- **无 `funcgraph-retval`**：用 `function_graph` 只看调用路径，再在可疑函数上用 kprobe/kretprobe 抓返回值；或直接对 syscall 入口下 gdb 断点逐层返回。
- **限定范围**：`set_graph_function <func>` 只画某个函数以下的调用图；`set_ftrace_filter` 限定函数名通配；`trace-cmd record -p function_graph` 便于保存和查看。
- **eBPF 替代**：`bpftrace` 的 `kretprobe:<func> { printf("%d", retval); }` 可在不挂 tracefs 的情况下抓返回值，适合容器/权限受限环境。
- **其他错误码**：同样适用于 `EOPNOTSUPP`、`ENOENT`、`EPERM` 等；先 `strace` 拿到 errno，再在 trace 中搜对应负值。
- **关联卡片**：[[binary-pwn-kernel-cve-2026-64563-rhashtable-stale-iter-p-tipc-uaf-lpe]]（原文用该方法调试 TIPC netlink dump 的 `EINVAL`/`EOPNOTSUPP`）、[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（QEMU + GDB 内核调试环境）、[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（另一种动态分析流程）。
- **边界**：生产内核可能关闭 ftrace/tracefs、`funcgraph-retval` 不存在、或 `perf_event_paranoid`/安全策略禁止跟踪；容器内需要挂载 tracefs 并具备相应 capability。`function_graph` 有开销，可能改变竞态时序，分析稳定复现的错误时最合适。

## 检测与防御

- **权限**：tracefs/ftrace 是强力的内核观测接口，默认只允许 root；生产环境应卸载 tracefs 或限制 mount/capability，避免普通用户读取内核函数执行与地址信息。
- **加固**：开启 `CONFIG_SECURITY_LOCKDOWN`（限制 debugfs/tracefs 与 kprobe）、`kernel.perf_event_paranoid` 高值、`kernel.kptr_restrict`，并限制容器内的 `CAP_SYS_ADMIN`/`CAP_PERFMON`。
- **检测**：监控 `tracing_on`、`current_tracer`、`set_ftrace_pid`、`kprobe_events` 等 tracefs 文件的写入；非运维时段出现 `function_graph`/`kprobe` 跟踪、或进程读取 `/sys/kernel/debug/tracing/trace`，可作为调试/侦察行为告警。
- **注意**：本卡是调试方法论，不是攻击面本身；防御重点在于限制谁能使用跟踪设施，而不是阻止程序返回错误码。
