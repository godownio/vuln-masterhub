# 模糊测试

## 这层是什么

覆盖率引导、语料、变异与崩溃分析。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AFL LLVM 插桩运行时：shmat 覆盖率共享内存 + forkserver 管道协议 + persistent/deferred 模式 + SanitizerCoverage trace-pc-guard](code-analysis-dynamic-fuzzing-afl-llvm-runtime-forkserver-persistent-deferred.md) | verified | medium | 2026-11-07 |
| [AFL 二次开发扩展：POST_LIBRARY 后处理钩子、自定义 havoc 算子与 virgin_bits 可视化](code-analysis-dynamic-fuzzing-afl-post-library-havoc-virgin-map-extension.md) | verified | high | 2026-11-07 |
| [AFL 首次上手：afl-gcc 插桩跑 stdin 目标、无源码用 -Q，并用面板的 stability/map density/uniq crashes 判断这轮 fuzz 是否有效](code-analysis-dynamic-fuzzing-afl-stdin-qemu-modes-ui-metrics.md) | verified | high | 2026-11-08 |
| [AFL++ Frida 模式 Android 原生库灰盒 fuzz：NDK 构建、afl.js 持久化入口与 aarch64 参数注入](code-analysis-dynamic-fuzzing-afl-frida-android-native-persistent-hook.md) | verified | high | 2026-11-11 |
| [AFL++ 命令行参数模糊测试：argv-fuzz-inl.h 覆盖 argv、NUL 分隔种子与 afl-clang-fast 静态插桩](code-analysis-dynamic-fuzzing-afl-argv-fuzz-inl-argv-override.md) | verified | high | 2026-11-07 |
| [AFLGo 定向模糊测试的编译包装与距离生成链：aflgo-clang(-mllvm/-Xclang -load) + gold/LTO .bc + opt -dot-callgraph + distance.py](code-analysis-dynamic-fuzzing-aflgo-clang-wrapper-distance-build-pipeline.md) | verified | medium | 2026-11-07 |
| [AFLGo 定向模糊测试距离插桩：targets/BBnames 预处理 + CG/CFG Dijkstra 距离 + shm[MAP_SIZE] 累加](code-analysis-dynamic-fuzzing-aflgo-directed-distance-instrumentation.md) | verified | high | 2026-11-07 |
| [Android JNI 函数真机灰盒 fuzz：native harness 经 libandroid_runtime 初始化真实 ART JVM，jbyteArray 包装输入](code-analysis-dynamic-fuzzing-android-jni-real-art-harness-afl-frida.md) | verified | high | 2026-11-11 |
| [Android JNI 原生库内存安全模糊测试：调用序列捕获 + 自动 C harness + JNIEnv 模拟 + AFL++](code-analysis-dynamic-fuzzing-android-jni-env-emulation-harness.md) | verified | medium | 2026-11-07 |
| [boofuzz 内置原语的生成策略集合：特殊值表、长串边界扩展、group 组合与 s_update 运行时改字段](code-analysis-dynamic-fuzzing-boofuzz-primitive-generation-strategy-library.md) | verified | medium | 2026-11-09 |
| [boofuzz 变异粒度：默认一次只变异一个原语，靠 group 与组合变异（max_depth）把覆盖扩展到多字段组合](code-analysis-dynamic-fuzzing-boofuzz-mutation-single-primitive-maxdepth-group.md) | verified | high | 2026-11-09 |
| [boofuzz 有状态序列模糊测试：用 connect 的 callback 与 session_variables 把上一个请求的响应喂进下一个请求](code-analysis-dynamic-fuzzing-boofuzz-stateful-path-callback-session-variables.md) | verified | high | 2026-11-09 |
| [C/C++ libFuzzer 实战：LLVMFuzzerTestOneInput harness、Sanitizer 编译、语料字典与 crash 复现最小化](code-analysis-dynamic-fuzzing-libfuzzer-cpp-harness-crash-repro.md) | verified | high | 2026-11-07 |
| [Go 原生 go test -fuzz 复现 CVE：脆弱 commit 回退、超时隔离无限循环与崩溃输入最小化](code-analysis-dynamic-fuzzing-go-native-fuzz-cve-repro.md) | verified | high | 2026-11-07 |
| [go-fuzz 覆盖率引导模糊测试工作流：go-fuzz-build 插桩、Fuzz(data []byte) int 接口与 crasher 复现](code-analysis-dynamic-fuzzing-go-fuzz-instrumentation-crasher-workflow.md) | verified | high | 2026-11-07 |
| [Jackalope + TinyInst 黑盒覆盖率引导 fuzz Windows 闭源模块：调试器式动态插桩、shmem 交付与 gdiplus harness](code-analysis-dynamic-fuzzing-jackalope-tinyinst-windows-coverage-fuzz.md) | verified | medium | 2026-11-11 |
| [libFuzzer 大规模工程化调优：语料合并/断点续传、jobs/fork 分层并行、分层字典与覆盖率热点分析](code-analysis-dynamic-fuzzing-libfuzzer-engineering-corpus-parallel-dict-coverage.md) | verified | high | 2026-11-07 |
| [MALintent：闭源 Android 应用 Intent 灰盒模糊测试——jadx 静态规范 + JVMTI 覆盖率插桩 + LibAFL 变异](code-analysis-dynamic-fuzzing-malintent-jvmti-intent-greybox.md) | verified | medium | 2026-11-07 |
| [Rust 模糊测试实战：cargo-fuzz、afl.rs 与 honggfuzz 的 harness、语料、sanitizer 与 crash 复现](code-analysis-dynamic-fuzzing-rust-cargo-fuzz-afl-honggfuzz.md) | verified | high | 2026-11-07 |
| [Syzkaller 定向 fuzz 自定义内核驱动：syzlang 描述 + KCOV/KASAN + syz-repro 最小化](code-analysis-dynamic-fuzzing-syzkaller-custom-proc-driver-syzlang.md) | verified | high | 2026-11-06 |
| [Windows 驱动自动化漏洞挖掘流水线：攻击面三元组枚举 + IDA 批量提取 ControlCode + kAFL Special Pool 模糊测试与崩溃复现](code-analysis-dynamic-fuzzing-windows-driver-attacksurface-triplet-kafl-pipeline.md) | verified | medium | 2026-11-10 |
| [基于 QEMU 全系统模拟的通用化 fuzzing：Lua 插桩统计覆盖率、guest 内选点 fork、PGD 区分进程、Lua 覆盖内存注入输入](code-analysis-dynamic-fuzzing-qemu-fullsystem-lua-instrument-forkserver.md) | verified | medium | 2026-11-12 |
| [强加固 Android 应用的 Intent-aware 灰盒 fuzzer：eBPF 对象布局恢复 + Key-Value 反馈 + 选择性覆盖](code-analysis-dynamic-fuzzing-android-ebpf-intent-aware.md) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
