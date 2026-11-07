---
id: code-analysis-dynamic-fuzzing-rust-cargo-fuzz-afl-honggfuzz
title: Rust 模糊测试实战：cargo-fuzz、afl.rs 与 honggfuzz 的 harness、语料、sanitizer 与 crash 复现
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: rust-fuzzing-cargo-afl-honggfuzz
aliases:
- Rust 模糊测试
- cargo-fuzz
- afl.rs
- honggfuzz
- libFuzzer Rust
- fuzz_target!
- Rust sanitizer
- Rust 覆盖率
tags:
- rust
- fuzzing
- cargo-fuzz
- afl
- honggfuzz
- libfuzzer
- sanitizer
- coverage
- vulnerability-discovery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:38+08:00'
  notes: 已对照原文核对；cargo-fuzz/afl.rs/honggfuzz 配置与 CVE 案例一致；未复跑 fuzz
---

## 一句话结论

Rust 项目可用 nightly 工具链 + 三个主流 fuzzer 做覆盖率引导测试：`cargo-fuzz` 以 `fuzz_target!` 包装 libFuzzer，`afl.rs` 以 `fuzz!` 读取 stdin 并 `catch_unwind`，`honggfuzz` 支持软件插桩与 Intel PT 硬件反馈；配合种子语料、ASan、crash 最小化与覆盖率报告，可复现 rust-url 整数下溢、zlib-rs 栈溢出、Cap'n Proto 越界读等真实问题。

## 原理

- **nightly + sanitizer**：Rust 的 libFuzzer/AFL 插桩与 `-Z sanitizer=address` 依赖 nightly 的实验特性；稳定版缺少编译期插桩与 sanitizer 支持，因此三个工具都要求 nightly。
- **cargo-fuzz**：本身不是 fuzzer，而是调用 libFuzzer 的包装器（通过 `libfuzzer-sys`）。`fuzz_target!(|data: &[u8]| { ... })` 定义入口，libFuzzer 持续变异输入并调用闭包；crash 输入保存在 `artifacts/<target>/`。支持 `-max_len`、`-only_ascii`、`-dict`、`-max_total_time` 等 libFuzzer 参数。
- **afl.rs**：把 AFL/AFL++ 引擎移植到 Rust；`fuzz!` 宏从 AFL 运行时提供的 stdin 读输入，并用 `catch_unwind` 捕获 panic，避免 fuzzer 进程退出。`cargo afl build` 编译插桩目标，`cargo afl fuzz -i in -o out` 运行，支持 `-M/-S` 并行主从、`cmin/tmin` 语料/crash 最小化、`RUSTFLAGS="-Z sanitizer=address"`。
- **honggfuzz**：多平台 fuzzer，支持软件插桩与 Intel PT 硬件分支跟踪（`--linux_perf_ipt_block --linux_perf_instr --linux_perf_branch`），可无插桩运行；`hfuzz::fuzz!` 从共享内存读输入，`cargo hfuzz run` 自动编译与执行，`-n` 并行、`-D` 字典。
- **为什么能发现深层问题**：fuzzer 以覆盖率反馈引导字节级变异，能探索人工难以构造的输入组合；sanitizer 把 release 下静默的整数下溢、栈溢出、越界读写变成可捕获的崩溃。
- **案例映射**：rust-url 在解析特定 URL 时触发 `attempt to subtract with overflow`（ASan 捕获）；zlib-rs `<=0.3.1` 因 LLVM 尾调用优化缺失导致栈溢出（RUSTSEC-2024-0401，0.4.0 修复）；Cap'n Proto Rust 实现 list-of-pointer 边界检查不一致导致越界读（CVE-2022-46149，可泄露最多 512 KiB 缓冲区后内存）；Rust regex `<=1.5.4` 的 ReDoS（CVE-2022-24713，1.5.5 修复）由 cargo-fuzz 在约 20 秒内发现执行时间异常。
- **覆盖率与闭环**：`cargo fuzz coverage` + `cargo cov -- show` 生成 HTML/终端报告；覆盖率用于判断语料与字典是否充分，而不是安全性的直接证明。

## 触发条件

- 目标为 Rust crate/二进制，能在本地用 nightly 工具链编译。
- 有可直接调用的解析/转换/边界处理函数作为 fuzz 入口，且能提供基本合法种子（URL、压缩流、序列化消息等）。
- 有足够 CPU/时间运行覆盖率引导 fuzz；AFL/honggfuzz 的并行与硬件反馈需要相应资源（Intel PT 需支持的 CPU）。
- 分析 crash 需要 sanitizer/调试符号与 `RUST_BACKTRACE`。

## 利用步骤

1. 安装 Rust 与 nightly：`curl ... | sh`、`rustup install nightly`、`rustup default nightly`。
2. 选择工具：快速集成/覆盖率分析用 cargo-fuzz；大规模并行/精细控制用 afl.rs；硬件反馈/无插桩用 honggfuzz。
3. cargo-fuzz：`cargo install cargo-fuzz` → `cargo fuzz init` → 编辑 `fuzz/fuzz_targets/fuzz_target_1.rs`，在 `fuzz_target!` 中把 `data` 转 UTF-8 后调用目标函数。
4. 准备语料：`fuzz/corpus/fuzz_target_1/` 放入合法样本；运行 `cargo fuzz run fuzz_target_1 -- -max_len=512 -only_ascii=1`。
5. afl.rs：`cargo install cargo-afl` → 新建项目、加入 `afl` 与目标 crate → `fuzz!` 宏 → `cargo afl build` → `cargo afl fuzz -i in -o out target/debug/url-fuzz`；必要时 `cargo afl config --build` 构建 LLVM runtime。
6. honggfuzz：`cargo install honggfuzz` → `hfuzz::fuzz!` → `cargo hfuzz run url-fuzz`；需要硬件反馈时加 `HFUZZ_RUN_ARGS="--linux_perf_ipt_block ..."`。
7. 分析 crash：用 `RUST_BACKTRACE=full` 复现，结合 ASan 报告定位栈帧；用 `cargo fuzz tmin`/`cargo afl tmin` 最小化输入，再对照修复 commit/根因。
8. 覆盖率：`cargo fuzz coverage fuzz_target_1` → `cargo cov -- show ... --format=html --Xdemangler=rustfilt`；根据未覆盖路径补充种子/字典。
9. 在 CI 中固定 nightly 版本与语料哈希，避免工具链变化导致不可复现。

## PoC

```rust
// cargo-fuzz: fuzz/fuzz_targets/fuzz_target_1.rs
#![no_main]
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = url::Url::parse(s);
    }
});
```

```rust
// afl.rs: src/main.rs
#[macro_use]
extern crate afl;
extern crate url;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = url::Url::parse(&s);
        }
    });
}
```

```rust
// honggfuzz: src/main.rs
use honggfuzz::fuzz;
use url::Url;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            if let Ok(s) = std::str::from_utf8(data) {
                let _ = Url::parse(s);
            }
        });
    }
}
```

```bash
# 运行与复现
cargo fuzz run fuzz_target_1 -- -max_len=512 -only_ascii=1
cargo fuzz run fuzz_target_1 artifacts/fuzz_target_1/crash-<hash>
RUST_BACKTRACE=full cargo run < out/default/crashes/id:000000
RUST_BACKTRACE=1 cargo hfuzz run hfuzz_workspace/url-fuzz/SIGABRT.PC....fuzz

# ASan 与覆盖率
RUSTFLAGS="-Z sanitizer=address" cargo afl build
cargo fuzz coverage fuzz_target_1
cargo cov -- show fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_1 \
  --format=html --Xdemangler=rustfilt \
  --instr-profile=fuzz/coverage/fuzz_target_1/coverage.profdata > coverage.html
```

## 变体与关联

- 变体：结构化 fuzz（`Arbitrary` trait、protobuf/序列化消息）比纯 `&[u8]` 更容易进入深层逻辑；也可用字典/语法生成器。
- 变体：AFL 持久模式（`afl::read_stdio_into` 循环）与延迟插桩（`afl::afl_manual_init`）提高吞吐。
- 变体：对库的旧 commit 做 fuzz 复现 CVE 时，要回退到修复 commit 的父提交并本地化依赖，避免加载已修复版本。
- 关联：[[code-analysis-dynamic-fuzzing-go-native-fuzz-cve-repro]]（Go 原生 fuzz 的 CVE 复现与超时 harness）、[[code-analysis-dynamic-fuzzing-syzkaller-custom-proc-driver-syzlang]]（内核 syscall fuzz）、[[binary-pwn-heap-quickjs-put-var-double-pop-uaf-jsruntime-hijack]]（fuzz 发现的引擎漏洞利用）。

## 检测与防御

- 防御：把 fuzz 纳入 CI（固定 nightly、语料缓存、超时/内存限制），对解析器/序列化/编解码等边界处理模块持续 fuzz。
- 防御：开启 ASan/UBSan、`-Z sanitizer` 与 `RUST_BACKTRACE`，对 crash 做去重、最小化与根因归档。
- 防御：维护高质量种子与字典，定期看覆盖率报告，避免只跑“容易路径”。
- 检测（供应链）：对第三方 crate 的 fuzz 结果、RUSTSEC 公告与修复版本做依赖审计；对 regex/zlib/序列化库等高风险依赖优先升级。
- 边界：fuzzer 只能证明“存在触发输入”，不能证明不存在漏洞；覆盖率不等于安全性，需结合代码审计与人工验证。
