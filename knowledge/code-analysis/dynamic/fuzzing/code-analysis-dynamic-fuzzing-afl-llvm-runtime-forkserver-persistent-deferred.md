---
id: code-analysis-dynamic-fuzzing-afl-llvm-runtime-forkserver-persistent-deferred
title: AFL LLVM 插桩运行时：shmat 覆盖率共享内存 + forkserver 管道协议 + persistent/deferred 模式 + SanitizerCoverage trace-pc-guard
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: afl-llvm-runtime-forkserver-persistent-sanitizercoverage
aliases:
- AFL forkserver
- aflgo-runtime.o
- __afl_start_forkserver
- __AFL_LOOP persistent 模式
- __AFL_INIT deferred 模式
- SanitizerCoverage trace-pc-guard
- __sanitizer_cov_trace_pc_guard
- shmat 共享内存
tags:
- fuzzing
- afl
- aflgo
- llvm
- forkserver
- persistent-mode
- deferred-mode
- sanitizercoverage
- shared-memory
- runtime
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T21:23:44+08:00'
  notes: 已对照原文核对：__afl_map_shm/shmat、__afl_start_forkserver 4字节管道协议、__afl_persistent_loop/SIGSTOP-SIGCONT、__afl_manual_init/deferred、__afl_auto_init、SanitizerCoverage trace-pc-guard、AFLGO_TRACING 均与 content.md 一致，原理/触发条件/PoC/函数名齐全，路径合法，dedup 非同链、dup-scan 无 pair；未验证点：未在本机编译运行（PoC 为源码语义整理），该批次卡按 KB 现状均不含 sources/source_url 溯源字段（与同目录已 verified 卡一致）。
---

## 一句话结论

基于 LLVM 的 AFL 系 fuzzer 把传统汇编插桩搬进高级语言写的 runtime：`__afl_map_shm` 用 `shmat` 挂接覆盖率共享内存，`__afl_start_forkserver` 用 `FORKSRV_FD`/`FORKSRV_FD+1` 两根管道与 fuzzer 做 4 字节握手并派发 fork，persistent 模式用 `__AFL_LOOP` + SIGSTOP/SIGCONT 在一次 fork 内重复执行，deferred 模式用 `__AFL_INIT` 手动推迟 forkserver 启动，覆盖率可由 SanitizerCoverage 的 `__sanitizer_cov_trace_pc_guard` 回调按 guard ID 累加 hit。

## 原理

- 初始化入口：`__attribute__((constructor(CONST_PRIO))) __afl_auto_init` 在 main 之前执行，读 `PERSIST_ENV_VAR` 置 `is_persistent`；若设了 `DEFER_ENV_VAR` 则直接返回、不自动启动 forkserver，否则调 `__afl_manual_init`（= `__afl_map_shm` + `__afl_start_forkserver`），并用 static `init_done` 保证只做一次。
- 共享内存：`__afl_map_shm` 从 `SHM_ENV_VAR`（fuzzer 传来的 shm id）`atoi` 后 `shmat`，把 `__afl_area_ptr` 指向该区并写 `__afl_area_ptr[0] = 1`，让父进程即使在低 `AFL_INST_RATIO` 下也不放弃该子进程——这是覆盖率 bitmap 与 fuzzer 之间的物理通道。
- forkserver 协议：先向 `FORKSRV_FD+1` 写 4 字节确认父进程存在（写失败则退化成普通单次执行），随后循环 `read(FORKSRV_FD, &was_killed, 4)` 等启动信号 → `fork()` → 子进程关闭两个 fd 后 `return` 继续执行目标，父进程把 `child_pid` 写回 `FORKSRV_FD+1` → `waitpid` 等子进程 → 把 `status` 写回管道 → 下一轮。字节数与读写顺序就是 AFL 与 forkserver 的契约，自定义 fuzzer 只要遵守即可复用该 runtime。
- persistent：`__afl_persistent_loop(max_cnt)` 首轮清空 bitmap（memset + `__afl_area_ptr[0]=1`、`__afl_prev_loc=0`）并置 `cycle_cnt`；后续每轮 `--cycle_cnt` 后 `raise(SIGSTOP)` 自挂，forkserver 的 `waitpid(..., WUNTRACED)` 收到 `WIFSTOPPED` 就置 `child_stopped=1`，下一轮改用 `kill(child_pid, SIGCONT)` 唤醒而不再 fork，把 fork 开销摊薄到 N 次执行；达到次数后把 `__afl_area_ptr` 指回 `__afl_area_initial` dummy 区，避免记录循环体外代码。`child_stopped && was_killed` 分支处理「子进程已挂起但 fuzzer 因超时发出 SIGKILL」的竞态。
- deferred：`__AFL_INIT()`/`__afl_manual_init` 让 forkserver 在昂贵初始化（数据库、大量网络连接）之后才启动，避免每次 fork 都重做初始化。宏 `__AFL_LOOP`/`__AFL_INIT` 用 `static volatile char* __attribute__((used))` 内联签名字符串，配合 `__asm__` 别名绑定到 `__afl_persistent_loop`/`__afl_manual_init`，既防编译器优化掉签名又能在 C++ 类内声明全局函数。
- SanitizerCoverage：编译加 `-fsanitize-coverage=trace-pc-guard` 后 LLVM 在每条边插 `__sanitizer_cov_trace_pc_guard(&guard_var)`；runtime 的 `..._init(start, stop)` 给每个 guard 分配 `1..MAP_SIZE-1` 的随机 ID（受 `AFL_INST_RATIO` 控制，未插桩置 0，首元素恒置非零以防重复初始化），回调里 `__afl_area_ptr[*guard]++` 即完成「按边 ID 累加 hit」，无需手写 cur_loc/prev_loc 边插桩 IR。

## 触发条件

- 目标由支持 LLVM 插桩的编译器（afl-clang-fast/aflgo-clang）编译并链入对应 `*-runtime.o`。
- 运行环境由 AFL 系 fuzzer 启动，设置了 `SHM_ENV_VAR`（shm id）与 `FORKSRV_FD`/`FORKSRV_FD+1` 文件描述符。
- persistent 需要 fuzzer 侧识别 `PERSIST_SIG`/`DEFER_SIG` 签名；deferred 需要在目标 driver 里显式调用 `__AFL_INIT()`。
- SanitizerCoverage 路径需要编译加 `-fsanitize-coverage=trace-pc-guard`。

## 利用步骤

（以复用该 runtime 接入自定义 fuzzer 为例）

1. 编译目标并链入 `aflgo-runtime.o`，编译时注入 `__AFL_LOOP`/`__AFL_INIT` 宏及 persistent/deferred 签名。
2. fuzzer 侧创建共享内存、把 shm id 放入 `SHM_ENV_VAR`，准备好 `FORKSRV_FD`/`FORKSRV_FD+1` 管道后 exec 目标。
3. 目标 constructor 自动执行 `__afl_auto_init`：挂接 shm、启动 forkserver（deferred 时推迟到 `__AFL_INIT()`）。
4. fuzzer 按 4 字节协议驱动 forkserver：写启动信号 → 读 child_pid → 读 status；persistent 模式下对挂起的子进程发 SIGCONT 复用。
5. 边执行时 trace-pc-guard 回调把 hit 累加进共享内存，fuzzer 据此更新覆盖率、挑选种子变异。

## PoC

forkserver 协议骨架（runtime 侧）：

```c
static u8 tmp[4];
if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;      // 握手：告诉父进程 OK
while (read(FORKSRV_FD, &was_killed, 4) == 4) {
    if (child_stopped && was_killed) { waitpid(child_pid, &status, 0); child_stopped = 0; }
    if (!child_stopped) {
        child_pid = fork();
        if (!child_pid) { close(FORKSRV_FD); close(FORKSRV_FD+1); return; }  // 子进程执行目标
    } else { kill(child_pid, SIGCONT); child_stopped = 0; }                 // persistent 复用
    write(FORKSRV_FD + 1, &child_pid, 4);
    waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0);
    if (WIFSTOPPED(status)) child_stopped = 1;
    write(FORKSRV_FD + 1, &status, 4);
}
```

SanitizerCoverage 回调骨架：

```c
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) { __afl_area_ptr[*guard]++; }
void __sanitizer_cov_trace_pc_guard_init(uint32_t *s, uint32_t *e) {
    if (s == e || *s) return;
    *(s++) = R(MAP_SIZE - 1) + 1;                 // 首元素恒非零
    for (; s < e; ++s) *s = (R(100) < inst_ratio) ? R(MAP_SIZE - 1) + 1 : 0;
}
```

persistent 使用侧：

```c
while (__AFL_LOOP(1000)) { /* 读输入、调用目标接口、复位状态 */ }
```

（按源码语义最小化整理，未在本机编译运行。）

## 变体与关联

- 变体：persistent 循环次数由 `__AFL_LOOP(N)` 指定；`child_stopped && was_killed` 处理超时竞态，避免把已终止的挂起进程再次 SIGCONT。
- 变体：deferred 用 `__AFL_INIT()` 把 forkserver 启动点后移；`__attribute__((constructor))` 与 `DEFER_ENV_VAR` 决定自动/手动初始化。
- 变体：覆盖率可由传统 `cur_loc/prev_loc` 边插桩或 SanitizerCoverage trace-pc-guard 二选一提供；`AFL_INST_RATIO`（1-100）控制插桩密度。
- 关联：[[code-analysis-dynamic-fuzzing-aflgo-directed-distance-instrumentation]]（距离插桩与 shm[MAP_SIZE] 距离字段）、[[code-analysis-dynamic-fuzzing-libfuzzer-engineering-corpus-parallel-dict-coverage]]（libFuzzer 的 trace-pc-guard 与覆盖率工程化）；本卡聚焦 AFL 系 runtime 的进程/内存/管道机制，与距离算法无关。
- 局限：这是本地 fuzzer 基础设施，不是漏洞利用链；forkserver 协议与 fd 编号是 AFL 系列约定，其他 fuzzer 需自行适配。

## 检测与防御

- 本地构建/测试组件，不暴露网络攻击面；防守方关注点是二进制健壮性，而非检测本 runtime。
- 使用方：确认 `SHM_ENV_VAR`/`FORKSRV_FD` 正确传递（否则 `__afl_map_shm` 拿不到 shm、握手失败会退化成单次普通执行）；persistent 循环内必须复位全局状态，否则跨轮污染导致假崩溃；`__afl_area_ptr` 在循环外要指回 dummy 区避免误记覆盖；ASAN/MSAN 与 AFL_HARDEN/FORTIFY_SOURCE 互斥，编译选项需按标志位取舍。
- 防御方：发布版本移除 fuzzing 宏与 runtime、不携带调试/插桩信息；用 sanitizer 与输入校验降低可被 fuzz 发现的 sink。
