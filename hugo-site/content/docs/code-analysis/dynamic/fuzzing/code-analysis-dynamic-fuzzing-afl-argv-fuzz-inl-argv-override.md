---
id: code-analysis-dynamic-fuzzing-afl-argv-fuzz-inl-argv-override
title: AFL++ 命令行参数模糊测试：argv-fuzz-inl.h 覆盖 argv、NUL 分隔种子与 afl-clang-fast 静态插桩
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: afl-argv-fuzz-inl-argv-override
tags:
- aflplusplus
- fuzzing
- argv
- argv-fuzz-inl
- instrumentation
- afl-clang-fast
- corpus
- crash
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:46:32+08:00'
  notes: 已对照原文核对：AFL++默认只fuzz stdin、argv-fuzz-inl.h的AFL_INIT_ARGV()覆盖argv、afl_init_argv按空白切分/NUL结尾种子、CC=afl-clang-fast(--disable-shared)静态插桩、afl-fuzz -i/-o/-M/-S、core_pattern提示与total crashes/tmouts均与正文及img01-22一致；img06-12为头文件源码，img17-20为fuzz运行界面，img21-22为插桩对比。原文为工具教程但给出了完整可复用的argv fuzz方法，非纯安装步骤。未复跑原文fuzz。
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-afl-argv-fuzz-inl-argv-override/
draft: false
kb_aliases:
- AFL++ argv fuzzing
- argv-fuzz-inl.h
- AFL_INIT_ARGV
- 命令行参数模糊测试
- afl-fuzz argv
- nmap 参数 fuzz
---

## 一句话结论

AFL++ 默认只对程序的标准输入做变异，命令行参数保持启动时固定值；若目标逻辑依赖 argv（如 `nmap -iL <file>`），需在 `main` 开头调用 `argv-fuzz-inl.h` 的 `AFL_INIT_ARGV()`，让 `afl_init_argv()` 从 stdin 读取字节并按空白切分成伪造的 `argv`，再用 NUL 终止的种子（如 `echo -en "-iL\x00"`）启动 `afl-fuzz`，即可让 AFL++ 变异命令行参数；配合 `CC=afl-clang-fast`/`afl-gcc` 插桩、`-M/-S` 多实例并行可提升效率。

## 原理

- **默认行为**：AFL++ 的 forkserver 把变异后的输入接到目标 stdin；目标程序原有 `argv` 来自启动命令，不参与变异。因此只测 stdin 的解析逻辑，测不到 argc/argv 驱动的分支。
- **argv 覆盖机制**：`argv-fuzz-inl.h` 定义 `AFL_INIT_ARGV()` → `argv = afl_init_argv(&argc)`。`afl_init_argv` 用 `static char in_buf[MAX_CMDLINE_LEN]` 保存 `read(0, ...)` 读到的 stdin 数据，`static char* ret[MAX_CMDLINE_PAR]` 保存切分后的参数指针；`rc` 从 1 开始（保留 `argv[0]`），循环中把每个参数起点写入 `ret[rc]`，跳过连续非空白字符后在首个空白处写 `'\0'`、再跳过空白，`rc++`；最终 `*argc=rc` 并返回伪造的 `ret`。宏在 `main` 入口执行后，原 `argv` 被替换为 AFL 变异出的参数。
- **保留/指定 argv[0]**：`AFL_INIT_SET0("prog_name")` 在覆盖后把 `argv[0]` 设为指定值，避免程序因 `argv[0]` 为畸形数据而提前退出。
- **语料格式**：种子是无换行的字节串，参数之间用空白分隔，末尾用 `\x00`（NUL）终止，例如 `-iL\x00`；AFL 会变异这些字节（包括分隔符/NUL），从而探索不同参数组合。
- **插桩**：`CC=afl-clang-fast ./configure --disable-shared`（或 `afl-gcc`）让编译器在每个分支插入 `afl_maybe_log` 调用与校准指令；AFL 通过共享内存 bitmap 记录边覆盖，发现新路径的输入进入队列。`--disable-shared` 静态链接可避免动态库未插桩导致的覆盖遗漏。
- **多实例**：`afl-fuzz -i in -o out -M f1 ./target` 为主实例，`-S f2/-S f3` 为从实例，共享同一输出目录、同步语料，利用多核加速。
- **crash 判定**：`total crashes` 增加时 AFL 将触发崩溃的输入写入输出目录的 `crashes/`，可配合 GDB/ASAN 复现定位；`total tmouts` 是超时输入，需区分崩溃与挂起。

## 触发条件

- 目标为可编译的开源二进制，且待测逻辑由命令行参数控制（不是仅从 stdin 读数据）。
- 能修改目标源码并在 `main` 开头加入 `#include "argv-fuzz-inl.h"` 与 `AFL_INIT_ARGV()`（或 `AFL_INIT_SET0`）。
- 使用 AFL++ 的编译器包装器（`afl-clang-fast`/`afl-gcc`）重新编译，插桩生效；静态链接以覆盖全部代码。
- 种子格式正确（参数以空白分隔、NUL 结尾），且 `afl-fuzz` 能正常运行（必要时设置 `core_pattern`）。

## 利用步骤

1. 下载并按 `make && make install` 安装 AFL++；确认 `afl-fuzz`、`afl-clang-fast`、`afl-gcc` 可用。
2. 获取目标源码，在 `main` 入口加入 `#include "argv-fuzz-inl.h"` 和 `AFL_INIT_ARGV();`（需要固定 argv[0] 时用 `AFL_INIT_SET0("prog")`）。
3. `CC=afl-clang-fast ./configure --disable-shared && make` 重新编译（失败可退回 `afl-gcc`）。
4. 创建 `in/out` 目录，写入 NUL 终止的参数种子（如 `echo -en "-iL\x00" > in/1`）。
5. 运行 `afl-fuzz -i in -o out ./target`；若提示 core_pattern 问题，`echo core >/proc/sys/kernel/core_pattern` 后重跑。
6. 观察 `findings in depth` 的 `total crashes/total tmouts`，到 `out/crashes/` 取样本，用 GDB/ASAN 复现分析。
7. 需要加速时启动 `-M` 主实例与多个 `-S` 从实例共享 `out`。

## PoC

```c
/* 目标 main 入口（以 nmap 为例） */
#include "argv-fuzz-inl.h"
int nmap_main(int argc, char *argv[]) {
    AFL_INIT_ARGV();
    ...
}
```

```bash
# 用 AFL++ 编译器插桩并静态编译
CC=afl-clang-fast ./configure --disable-shared && make

# NUL 结尾的参数种子：测试 -iL 参数
mkdir -p /tmp/in /tmp/out
echo -en "-iL\x00" > /tmp/in/1

# 运行 fuzz
afl-fuzz -i /tmp/in -o /tmp/out ./nmap

# 多实例并行
afl-fuzz -i /tmp/in -o /tmp/out -M f1 ./nmap
afl-fuzz -i /tmp/in -o /tmp/out -S f2 ./nmap
```

## 变体与关联

- 若只想 fuzz 固定参数后的 stdin 数据，无需 argv 覆盖，直接把数据喂给 stdin 即可。
- `AFL_INIT_SET0("prog")` 适用于程序强依赖 `argv[0]` 的场景；也可直接改 `argv-fuzz-inl.h` 的 `int rc = 0` 让 `argv[0]` 也参与变异。
- 框架/目标不同：libFuzzer、AFLGo、cargo-fuzz 各有自己的 harness/入口；argv fuzzing 是 AFL++ 对 CLI 程序的适配方式。
- 插桩原理与 forkserver/persistent 模式：见 [[code-analysis-dynamic-fuzzing-afl-llvm-runtime-forkserver-persistent-deferred]]；本卡只讲 argv 覆盖与语料格式。

## 检测与防御

- 这是测试/研究技术，不是攻击链；对被测程序应在隔离环境（容器/虚拟机、快照）中运行，避免崩溃影响宿主。
- 生产环境不要用被 fuzz 过且带调试插桩的二进制；对发现崩溃的输入做最小化与根因修复。
- 若目标是第三方闭源程序，需遵守授权与漏洞披露流程；不要在生产系统上直接 fuzz。
