---
id: code-analysis-dynamic-fuzzing-afl-stdin-qemu-modes-ui-metrics
title: AFL 首次上手：afl-gcc 插桩跑 stdin 目标、无源码用 -Q，并用面板的 stability/map density/uniq crashes 判断这轮 fuzz 是否有效
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: afl-stdin-fuzz-instrumented-vs-qemu-mode-ui-metrics-triage
aliases:
- afl-gcc 插桩
- afl-fuzz -Q qemu 模式
- AFL 面板字段解读
- stability 100%
- map density
- uniq crashes
- core_pattern 报错
tags:
- afl
- fuzzing
- instrumented
- qemu-mode
- stdin
- coverage-guided
- triage
- core-pattern
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:34:56+08:00'
  notes: 已对照原文核对；本次核对未读取图片（本篇原文无图片）；afl-gcc 编译、afl-fuzz -i fuzz_in -o fuzz_out ./afl_test、无源码加 -Q、echo core > /proc/sys/kernel/core_pattern 及面板数值（2.57b、stability 100.00%、map density 0.05%/0.06%、uniq crashes 6、total 3140、exec 403.6/sec）均与原文一致。小瑕疵：原文编译器 wrapper 为 afl-gcc/afl-clang，卡中写成 afl-clang-fast（AFL++ 命名），不影响用法；面板指标判读方法属通用语义归纳，卡内已声明。未验证点：未在本机编译运行 AFL
---

## 一句话结论

有源码时用 `afl-gcc`/`afl-clang-fast` 编译出带插桩的目标、准备一个小而有效的种子目录，`afl-fuzz -i <in> -o <out> ./target` 让它从 stdin 读输入；没有源码就在同一条命令上加 `-Q` 走 qemu 模式的二进制插桩。跑起来之后判断这轮 fuzz 是否可信，不看“有没有崩”，而看面板的 `stability`（必须 100%）、`map density`（覆盖是否被真正打开）、`uniq crashes`（去重后的可复现样本）和 `exec speed`（吞吐）；一开始报 `Pipe at the beginning of 'core_pattern'` 是环境问题，先把 core_pattern 改回 `core` 再重跑。

## 原理

- **覆盖率引导**：插桩在每个基本块入口更新共享内存里的 64KB trace bitmap，`afl-fuzz` 读 bitmap 判断某个变异输入是否走到了新边（新路径）；只有带来新边的输入才进 queue 继续变异，所以“盲变异”被替换成“朝未探索代码走”。
- **两种插桩形态的差别**：`afl-gcc` 是编译器 wrapper，在源码编译期插入插桩代码，粒度是基本块，速度最快；`-Q` 让 `afl-fuzz` 通过 `afl-qemu-trace` 在用户态模拟执行无源码二进制，靠 QEMU 的基本块翻译做边缘覆盖，速度慢一个量级但能覆盖闭源 target。
- **stability 的意义**：它衡量“同一份输入重复执行时覆盖位图是否一致”。目标若含时间、随机数、ASLR 相关的分支、多线程调度或未初始化内存，位图会抖动，AFL 会把同一输入不断当成“新路径”，queue 爆炸、crash 信号被淹没。`stability` 掉到 100% 以下时先修非确定性（固定随机种子、关 ASLR、单线程复跑），否则后续所有统计都不可信。
- **map density 的意义**：插桩位图被命中的比例。长期停在个位数百分比通常说明种子覆盖不到目标主要逻辑（种子选错、需要字典/前置参数），此时应补种子或加 `-x` 字典，而不是加大运行时长；接近饱和时新路径几乎不再出现，说明该配置的探索能力到顶。
- **uniq crashes 与 total crashes**：同一个崩溃地址会被反复触发，`total crashes` 是次数、`uniq crashes` 是按信号/位置去重后的样本数；只有 `out/crashes/` 目录里的样本才值得用 GDB/ASan 复现，且要按 stack 再人工去重。
- **core_pattern 报错的原因**：AFL 需要把崩溃现场交给它自己的 handler，若系统的 core dump 管道被设成以 `|` 开头（如交给 apport/systemd-coredump），AFL 检测到后主动退出，避免崩溃被外部程序吞掉。

## 触发条件

- Linux 环境；目标从 stdin（或 `@@` 指定的文件）读取待测输入。
- 有源码：编译器可用 afl 的 wrapper；无源码：已构建 qemu 模式（老版本 AFL 需要先给 `build_qemu_support.sh` 换 QEMU 下载地址，并补 `syscall.diff` 的 `<linux/sockios.h>`、新增 `gettid.diff` 把 `_syscall0(int, gettid)` 改名，否则在新内核/QEMU 上编译失败）。
- 种子目录里至少有一个“能进业务逻辑”的有效小样本；输出目录需可写。
- 需要 root 或 docker 权限修改 `/proc/sys/kernel/core_pattern`，否则 AFL 拒绝启动。

## 利用步骤

1. 写一个最小可测目标（示例：从 stdin `gets` 读入，做首字符/长度判断后主动 `raise(SIGSEGV)`，便于验证“崩溃确实被抓到”）。
2. 用插桩编译器产出目标：`afl-gcc test.c -o afl_test`；确认编译日志里出现插桩提示，`afl-showmap -o /dev/null -q ./afl_test < seed` 能看到非空覆盖。
3. 建 `fuzz_in/` 放种子（内容尽量小、但必须是有效输入），`fuzz_out/` 留空。
4. 有源码：`afl-fuzz -i fuzz_in -o fuzz_out ./afl_test`；无源码：同一目标加 `-Q`，`afl-fuzz -i fuzz_in -o fuzz_out -Q ./afl_test`（复用前先清空 `fuzz_out`，否则会续跑旧状态）。
5. 等 1~3 分钟后读面板：`stability` 是否 100%、`map density` 是否在涨、`cycles done` 是否在推进、`uniq crashes`/`uniq hangs` 是否出现。
6. 有崩溃就取 `fuzz_out/crashes/id:*`，用 `afl-showmap` 确认覆盖差异、用 GDB/ASan 复现并定位到具体分支；挂起样本单独看 `hangs/`，超时不是崩溃。
7. 若报 core_pattern 错误：`echo core > /proc/sys/kernel/core_pattern` 后重跑（注意这会影响主机上其他程序的 core 处理策略，做完应评估是否恢复）。

## PoC

```bash
# 1) 插桩编译（有源码）
afl-gcc test.c -o afl_test

# 2) 种子与输出目录
mkdir -p fuzz_in fuzz_out
printf 'abc' > fuzz_in/seed

# 3) 覆盖率引导 fuzz（stdin 模式）
afl-fuzz -i fuzz_in -o fuzz_out ./afl_test

# 4) 无源码：多一个 -Q
afl-fuzz -i fuzz_in -o fuzz_out -Q ./afl_test

# 5) core_pattern 拦路时
echo core | sudo tee /proc/sys/kernel/core_pattern
```

```text
关键面板字段（判读用）：
stability       -> 必须 100.00%，否则先修非确定性
map density     -> 长期个位数 = 种子/字典不足；接近饱和 = 探索到顶
uniq crashes    -> 去重后可复现的候选，去 out/crashes/ 取样
exec speed      -> 吞吐，qemu 模式通常只有插桩模式的 1/10 量级
```

## 变体与关联

- **多实例并行**：`-M master` / `-S slave` 共享同一输出目录做同步，把 CPU 核数用满；单机多核优先并行而非调大变异轮次。
- **命令行参数目标**：AFL 默认只变异 stdin，argv 固定的程序要先在 `main` 里 `AFL_INIT_ARGV()`（见 [[code-analysis-dynamic-fuzzing-afl-argv-fuzz-inl-argv-override]]）。
- **语料工程**：`afl-cmin` 精简语料、`afl-tmin` 最小化单样本、`-x` 字典把协议关键字/magic 值喂进去，能显著提高 map density 增长率。
- **更强的崩溃发现**：同一目标用 ASan/UBSan 重编译（内存错误立即崩），或用 libFuzzer/`-fsanitize=fuzzer` 复跑（见 [[code-analysis-dynamic-fuzzing-libfuzzer-cpp-harness-crash-repro]]）。
- **边界**：目标有强非确定性（时间戳参与分支、大量随机）时 stability 难到 100%；qemu 模式对多线程、`fork` 密集、依赖内核行为的程序覆盖失真；只跑几十分钟得出的“无崩溃”不构成安全性结论。

## 检测与防御

- **看结论前先看配置**：判读任何 fuzz 结果都要同时看 `stability`、`exec speed`、种子数量与运行时长，缺一项就可能把“没跑到”当成“没有漏洞”。
- **去重与复现**：把 `crashes/` 里的样本按崩溃栈/信号去重，逐个在 ASan 构建上复现；只有能稳定复现的才算候选漏洞（`hangs` 单独归类为拒绝服务）。
- **工程化**：CI 里固定种子与 `-x` 字典、把每轮最小崩溃样本回灌成回归语料；对被测程序开启 ASan/UBSan、关闭调试符号剥离，便于定位。
- **环境隔离**：qemu 模式与 `core_pattern` 修改会影响宿主，fuzz 一律放在容器/专用机器上跑，避免污染生产主机的崩溃处理与内核参数。
