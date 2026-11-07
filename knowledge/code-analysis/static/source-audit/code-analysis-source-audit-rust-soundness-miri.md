---
id: code-analysis-source-audit-rust-soundness-miri
title: Rust soundness 缺陷审计：四类失效机理与 Miri 验证零 unsafe 代码的 UB
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: rust-soundness-audit-miri
aliases:
- Rust 内存安全审计
- Rust soundness 缺陷
- 安全 API 触发 UB
- Miri Stacked Borrows
- auto trait 约束遗漏
- 生命周期签名缺失
- Drop 线程语义
tags:
- rust
- soundness
- undefined-behavior
- memory-safety
- unsafe
- miri
- code-audit
- static-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:34:17+08:00'
  notes: 已对照原文核对；四类失效机理、anyhow 1.0.102/1.0.104 与 bumpalo 3.11.0/3.11.1 的 Miri 对照输出、命令与退出码均与正文及截图一致。该卡定位为 Rust crate 源码审计方法，未声称 UB 可直接远程利用，边界已在卡内注明；未在本机复跑 Miri。
---

## 一句话结论

Rust 的借用检查只覆盖安全代码的调用点，管不到三件事：`unsafe` 块内的手写内存操作、类型签名是否忠实表达了实现的真实约束、以及 trait bound / Drop 的线程语义是否完整；审计 Rust crate 时应按这四类失效机理逐项检查，并用 Miri 对“完全不含 `unsafe` 的触发代码”在受影响版本与修复版本上做对照，确认 UB 是否真实存在。

## 原理

Rust 的安全承诺是“只要不写 `unsafe`，编译器保证不出现内存安全问题”，但这句话有三个缺口：

1. **`unsafe` 块不受借用检查保护**。标准库、分配器、容器、异步运行时大量使用 `unsafe` 实现所有权模型难以表达的结构。块内算错一个加法、少校验一次容量，错误与 C 相同。
   - 典型：`bytes` 的 `reserve` 用 `new_cap + offset` 做未检查加法，release 构建下 `usize` 静默回绕，容量被设成超过实际分配值，后续构造越界切片。
   - 典型：`smallvec::insert_many` 按迭代器 `size_hint()` 的下界分配，迭代器实际产出更多元素时堆溢出。
   - 同类：`bitvec` 转换时双重释放、`bumpalo::realloc` 复制 `new_size` 而非 `old_size` 字节导致越界读。
2. **类型签名可能没有表达真实约束**。代码通过借用检查，是因为签名内部自洽；但签名没有告诉编译器“这个返回值依赖哪个对象”“这个迭代器不能活得比分配器久”。
   - 典型：`bumpalo::collections::Vec::into_iter()` 返回的迭代器类型不携带“依赖哪个 `Bump`”的信息。先 `drop(bump)` 再遍历迭代器，编译器全程放行，运行时访问已释放内存（UAF）。
   - 典型：`openssl::ssl::select_next_proto` 返回的切片实际指向 `server` 缓冲区，生命周期却绑定到 `client`；`server` 先释放时产生 UAF，可能把任意内存返回给客户端。
   - 典型：`anyhow::Error::context()` 后再 `downcast_mut()`，构造可变引用的过程把共享引用带进借用链，违反别名规则，产生 UB。
3. **auto trait 约束可能写漏**。`Send`/`Sync` 是 Rust 自己的线程安全抽象，C 语言没有对应物；bound 少写一个，编译器的全部检查就建立在错误前提上。
   - 典型：`tokio::sync::broadcast` 接收时并行对值调用 `clone`，只要求 `T: Send` 而不要求 `T: Sync`；传入 `Send` 但 `!Sync` 的类型，其 `clone` 若依赖“不会被并发调用”的前提，就会产生数据竞争/UB。
   - 同类：`crossbeam-deque` 数据竞争导致任务被 pop 两次、`tokio::sync::oneshot` 关闭后并发 send/try_recv、`borsh` 反序列化 ZST 产生 UB。
4. **类型系统不追踪值在哪个线程被析构**。`Drop` 语义与运行时线程归属脱节。
   - 典型：`tokio` 的 `JoinHandle::abort` 在任务未执行时，会在调用 abort 的线程上 drop future；`LocalSet` 任务里常用的 `Rc`/`RefCell` 不是 `Send`，跨线程 drop 破坏内部不变量。
   - 典型：`time`/`chrono` 在多线程程序中不加同步地设置环境变量，另一个线程读取时可能解引用悬垂指针。

这四类中，只有第一类是 C 语言里也有的老问题；后三类是 Rust 安全模型自身引入的新失效形态。它们的共同点是：**使用者写的是安全代码，编译器不会给出任何警告，缺陷发生在库内部的安全抽象实现里。**

Miri 是 Rust 官方 MIR 解释器，内置 Stacked Borrows 别名规则检查器，可以在不依赖真实崩溃的情况下检出 UB。验证方法是：对同一段**不含 `unsafe`** 的触发代码，分别在“受影响的最后一个版本”和“修复版本”上运行 `cargo +nightly miri run`，对比退出码与诊断。

## 触发条件

- 目标 crate 提供容器、分配器、并发原语、错误处理、加密/网络封装等安全抽象，内部含 `unsafe`。
- crate 的安全 API 存在生命周期、别名、`Send`/`Sync`、Drop 线程归属方面的隐含契约，但类型签名没有表达。
- 审计者能获取受影响版本与修复版本的源码，并能在本地构建、运行 Miri（需要 nightly 工具链）。
- 触发路径只需要正常的调用顺序（例如先 `context()` 再 `downcast_mut()`，先取迭代器再 `drop` 分配器），不需要调用方写 `unsafe`。

## 利用步骤

1. **盘点 `unsafe` 面**：用 `cargo-geiger` 或源码搜索列出 crate 及其依赖的 `unsafe` 块，优先审计分配器、容器、并发、FFI、自定义 Drop。
2. **按四类机理逐一核对**：
   - 手写内存：容量计算、整数加减、指针偏移、`set_len`、`realloc`、双重释放；
   - 类型表达：返回引用/迭代器/切片的生命周期是否绑定到正确的所有者；是否存在“调用者必须保证某条件”但签名未表达；
   - auto trait：并发 API 的 `Send`/`Sync` bound 是否与内部实际并发访问一致；
   - Drop/线程：future、`Rc`/`RefCell`、`LocalSet`、abort、环境变量等跨线程析构与共享。
3. **构造最小安全代码触发**：只用公开安全 API，按正常顺序调用，不写 `unsafe`；目标是让 UB 在 Miri 下稳定出现。
4. **版本对照**：在受影响版本与修复版本上运行同一段代码和同一条 `cargo +nightly miri run`，记录退出码、分配点/释放点/UB 点。
5. **判断修复路线**：改内部实现只修掉当前 bug，类型不变则同类错误可能再犯；改类型签名（增加生命周期参数、补 `Sync` bound）能让编译器从此拒绝同类用法，但可能破坏下游兼容。
6. **结合公告分级**：`cargo-audit` 的 `memory-corruption` 标签混装“有 CVE 的可利用漏洞”和“无 CVE 的 soundness 债务”；有 CVE/CVSS 的优先处理，unsound 类按触发条件与是否可达评估。

## PoC

案例 A：`anyhow` 的 `downcast_mut` UB（触发代码不含 `unsafe`）：

```rust
use anyhow::Error;
use std::fmt;

#[derive(Debug)]
struct ErrorContext(&'static str);

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

fn main() {
    let mut error = Error::msg("inner error").context(ErrorContext("old context"));
    let context: &mut ErrorContext = error.downcast_mut().unwrap();
    context.0 = "new context";
    println!("{:?}", error);
}
```

```text
cargo +nightly miri run
# anyhow 1.0.102: Undefined Behavior: trying to retag ... for Unique permission,
#                 but that tag only grants SharedReadOnly permission
#                 at anyhow-1.0.102/src/ptr.rs:170  (exit 1)
# anyhow 1.0.104: 正常输出，无 Miri 诊断 (exit 0)
```

案例 B：`bumpalo` 的 `IntoIter` UAF（同样不含 `unsafe`）：

```rust
use bumpalo::{collections::Vec, Bump};

fn main() {
    let bump = Bump::new();
    let mut vec = Vec::new_in(&bump);
    vec.extend([0x01u8; 32]);
    let into_iter = vec.into_iter();
    drop(bump);
    for _ in 0..100 {
        let reuse_bump = Bump::new();
        let _reuse_alloc = reuse_bump.alloc([0x41u8; 10]);
    }
    for x in into_iter {
        print!("0x{:02x} ", x);
    }
    println!();
}
```

```text
# bumpalo 3.11.0: Undefined Behavior: in-bounds pointer arithmetic failed:
#                  alloc is freed, so this pointer is dangling
#                  at bumpalo-3.11.0/src/collections/vec.rs:2300 (exit 1)
# bumpalo 3.11.1: 编译失败 E0505（cannot move out of `bump` because it is borrowed）
```

说明：以上是 UB 的可复现证据，不是可对外利用的 RCE/信息泄露 PoC；原文未演示如何把 UB 转化为实际危害。

## 变体与关联

- 变体：把 `bumpalo` 的修复方式与 `anyhow` 对比——前者给 `IntoIter` 增加生命周期参数，编译器从此拒绝同一段代码；后者只改内部实现，签名不变，同类错误仍可能再出现。
- 变体：同一审计框架可套用到自研容器、arena 分配器、零拷贝网络库、异步运行时、FFI 封装。
- 变体：用 AddressSanitizer/ThreadSanitizer、`cargo miri test`、fuzzing 补充 Miri 覆盖不到的运行时代码。
- 关联：[[code-analysis-sast-codeql-custom-taint-steps]]（静态污点建模，另一种代码审计手段）。
- 边界：Miri 只能执行被解释到的路径，依赖真实系统调用、FFI、平台相关代码时可能无法运行；Miri 报告 UB 也不等于外部可利用，需进一步评估触发条件与影响。

## 检测与防御

- 审计：优先审查提供安全抽象的 crate 的 `unsafe` 块、生命周期签名、`Send`/`Sync` bound、`Drop` 实现和线程归属。
- 修复：给类型补上缺失的生命周期/所有权信息，让编译器而非运行期检查来保证契约；并发 API 按实际访问补全 `Send`/`Sync`；减少 `unsafe` 面积并把“为什么 sound”写成文档。
- 验证：CI 中加入 Miri（至少覆盖单元测试与最小复现）、ASan/TSan；对修复版本确认同一触发代码要么不再 UB，要么直接编译失败。
- 依赖管理：`cargo-audit`/`cargo-deny` 告警按“有 CVE / 自称 unsound / 无评分”分层处理；不要因为“无 CVE”就忽略 soundness 公告。
- 边界：这类缺陷通常不产生直接的远程可利用原语；只有在能证明 UB 可被外部输入触发并造成泄露/破坏时，才升级为漏洞。
