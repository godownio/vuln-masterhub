---
id: defense-forensics-proc-environ-startup-view-split
title: 进程环境取证：/proc/pid/environ 只是启动视图，getenv 才是当前状态
type: scenario
domain: defense
path: defense/forensics
technique: proc-environ-startup-view-split
aliases:
- /proc/self/environ 不同步
- 环境变量视图分裂
- setenv 不出现在 proc
- unsetenv 残留
- envp 不是启动快照
- 环境取证盲区
tags:
- linux
- forensics
- elf
- constructor
- environment-variable
- procfs
- incident-response
- detection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T19:38:16+08:00'
  notes: 已对照原文与17张图核对：内核 mm_struct env_start/env_end 启动视图、glibc setenv/unsetenv 维护独立 environ、PROC_ENV 三态实验、envp==environ 迁移、dlopen/LD_PRELOAD 行为与图7/12/14/15/16 一致；PoC 可复现。未验证点：未实际编译执行 PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

进程启动后由 ELF 构造器或运行期代码 `setenv`/`unsetenv`/改写环境时，`getenv`/`environ` 反映当前值，而 `/proc/<pid>/environ` 仍读取 exec 时记录的环境内存区：新增项不出现、删除项不消失、改写值不变；因此环境取证不能只依赖 `/proc`，也不能把 `main` 的 `envp` 当成启动快照。

## 原理

- exec 时内核把环境字符串放在用户栈，并在 `mm_struct` 中记录 `env_start`/`env_end`；`/proc/<pid>/environ` 读取的正是这段启动区域。
- glibc 的 `setenv`/`unsetenv` 维护独立的 `environ` 指针数组：新增或改写时通常在堆上分配新字符串与数组，并更新 `environ`；这些修改不会写回内核记录的启动区域，所以 `/proc` 与当前 `environ` 分裂。
- 地址变化可以直接观察：被改写的变量字符串与 `environ` 数组迁到堆附近（`0x55...`/`0x56...`），未被改写的变量（如 `PATH`）仍指向栈上的启动字符串（`0x7ffc...`）。
- `main` 的第三个参数 `envp` 由 `__libc_start_main` 传入，通常就是当前的 `environ`；构造器在 `main` 之前运行，因此只要前置构造器改过环境，`main` 拿到的就是已经处理过的数组，不是 exec 时的原始 `envp`。
- `dlopen` 加载的新对象的构造器同样在加载时执行，会继承并继续改写当前环境；运行期环境不是冻结的启动参数。
- 于是“启动时是否存在”“当前值是什么”“哪个对象已经加载”成为三个不同事实，任何一个来源单独都不能代表完整状态。

## 触发条件

- Linux 进程，使用 glibc 等通过 `environ` 维护运行期环境的 libc。
- 构造器、`LD_PRELOAD` 对象或 `dlopen` 库在 `main` 前后调用了 `setenv`/`unsetenv`/`putenv`，或业务代码运行期修改环境。
- 取证/检测方通过 `/proc/<pid>/environ`、程序日志里的 `envp`、或外部采集的环境快照判断“当前环境”。
- 读取 `/proc/<pid>/environ` 需要对该进程具备 ptrace 访问权限（同用户或 root）；容器与 PID namespace 会影响可见范围。

## 利用步骤

1. 采集 `/proc/<pid>/environ` 时标注其为“启动环境视图”：文件以 NUL 分隔，不是按行文本，需按 `name=value\0` 解析。
2. 需要当前环境时，不要只读 `/proc`：在进程内读取 `environ`/`getenv`，或用 gdb attach 后 `p environ`、`p (char*)getenv("NAME")`；外部只能看到启动视图。
3. 做三态核对：启动时有该变量但运行期被删（`getenv` 为空、`/proc` 仍在）；启动时没有但运行期新增（`getenv` 可见、`/proc` 无）；启动时有但值被改（`/proc` 仍是旧值）。
4. 检查 `environ` 指针与变量字符串地址（栈 vs 堆）判断是否发生迁移；`main` 的 `envp == environ` 不能证明它等于启动快照。
5. 在取证报告中同时保留 auditd/execve 记录里的启动环境、`/proc` 视图与进程内当前值，避免把过期视图当作实时状态。

## PoC

```c
/* gcc -D_GNU_SOURCE -O0 -g envsplit.c -o envsplit */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

__attribute__((constructor))
static void ctor_modify_env(void) {
    setenv("CTOR_NEW", "new-from-ctor", 1);  /* 运行期新增 */
    unsetenv("CTOR_OLD");                    /* 运行期删除 */
    setenv("CTOR_TOKEN", "ctor-value", 1);   /* 运行期改写 */
}

static int proc_has(const char *name) {
    FILE *f = fopen("/proc/self/environ", "rb");
    if (!f) return -1;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    size_t len = strlen(name);
    for (size_t i = 0; i + len + 1 <= n; i++) {
        if (memcmp(buf + i, name, len) == 0 && buf[i + len] == '=') return 1;
    }
    return 0;
}

int main(int argc, char **argv, char **envp) {
    printf("getenv NEW=%s OLD=%s TOKEN=%s\n",
           getenv("CTOR_NEW"), getenv("CTOR_OLD"), getenv("CTOR_TOKEN"));
    printf("proc   NEW=%d OLD=%d TOKEN=%d\n",
           proc_has("CTOR_NEW"), proc_has("CTOR_OLD"), proc_has("CTOR_TOKEN"));
    printf("envp==environ: %s\n", envp == environ ? "yes" : "no");
    return 0;
}
```

```bash
CTOR_OLD=start CTOR_TOKEN=start ./envsplit
# 预期：getenv NEW=new-from-ctor / OLD=(null) / TOKEN=ctor-value
#       proc   NEW=0 / OLD=1 / TOKEN=1（TOKEN 值仍是 start 的启动视图）
#       envp==environ: yes
```

## 变体与关联

- 变体：`putenv` 直接放入调用者提供的字符串，`clearenv` 清空 `environ`；两者同样不会同步改写内核记录的启动区域，表现仍是 `/proc` 保留启动痕迹。
- 变体：`LD_PRELOAD` 对象在启动时进入进程，其构造器若 `unsetenv("LD_PRELOAD")`，当前 `getenv` 已为空而 `/proc` 仍显示该变量，且预加载对象的代码仍已加载并继续执行。
- 变体：`execve` 启动的新进程会重新生成启动区域，此前的分裂不会跨 exec 继承；容器内读取 `/proc` 还要考虑 PID namespace 与宿主视角。
- 关联：[[defense-forensics-elf-constructor-order-dt-needed]]（同一实验的构造器顺序结论）、[[defense-forensics-elf-symbol-interposition-triage]]（ELF 加载期取证）、[[pentest-privilege-escalation-ld-preload-symbol-interposition-downgrade]]（LD_PRELOAD 构造器代码执行）。
- 边界：不同 libc/`setenv` 实现可能在特定情况下复用或修改原区域，结论需在目标 libc 上验证；`/proc/<pid>/environ` 的读取还受 ptrace 权限与内核版本影响。

## 检测与防御

- 检测：不要用 `/proc/<pid>/environ` 单独判断当前环境或“是否存在恶意变量”。结合 auditd `execve` 记录的启动环境、进程内 `environ` 采样、`/proc/<pid>/maps` 的加载对象与业务日志交叉验证。
- 取证：在报告中明确区分“启动痕迹”和“运行期当前值”；对新增/删除/改写三类分别记录证据，避免把 `/proc` 命中当作变量仍生效，或把 `/proc` 缺失当作运行期不存在。
- 防御：安全决策应在使用点读取当前值或使用显式配置，不要依赖 `/proc` 或 `main` 的 `envp` 作为可信快照；若必须校验环境是否被篡改，应在进程内多次采样并记录 `environ` 地址/字符串地址变化。
