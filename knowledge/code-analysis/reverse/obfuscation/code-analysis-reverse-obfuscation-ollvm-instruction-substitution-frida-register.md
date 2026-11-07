---
id: code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register
title: Frida 辅助 OLLVM 指令替换分析：Hook memcpy/寄存器提取运算结果
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ollvm-instruction-substitution-frida-register-extraction
aliases:
- 指令替换
- SUB
- OLLVM substitution
- memcpy hook
- STURB W8
- 2*len
- 寄存器提取
tags:
- reverse
- obfuscation
- ollvm
- instruction-substitution
- frida
- android
- arm64
- register
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:14:23+08:00'
  notes: 已对照原文与截图核对：STURB W8,[X29,#var_60] 对应 LOBYTE(v156)=2*len、memcpy hook 读取 X8=0x1e/X23=0xf/LR=0xf638、2*15 与输入长度一致均与图文相符。未验证点：未复跑 Frida hook。
---

## 一句话结论

OLLVM 指令替换把 `a+b`、`a-b`、`a&b`、`a|b`、`a^b` 等简单运算改写成等价的复杂指令序列；不必手工化简这些表达式，Hook 目标函数下游的 `memcpy`（或关键指令地址），直接读取寄存器（如 `X8 = 2*len`）即可提取替换运算的真实结果。

## 原理

- **指令替换（SUB）**：OLLVM 用等价但更复杂的序列替换原始运算，例如 `a+b` → `a-(-b)` 或插入随机数 `r` 的加减组合，`a^b` → `(~a&b)|(a&~b)`；单条替换看似可读，但多层嵌套后伪代码会变成大量位运算，手工化简容易出错。
- **寄存器仍保存真实结果**：无论表达式多复杂，编译器最终会把结果放进某个寄存器/栈槽；在关键指令或下游调用处观察寄存器，就能绕过代数化简。
- **定位关键指令**：在 IDA 中找到替换块后的 `STURB W8, [X29,#var_60]`，它对应源码 `LOBYTE(v156) = 2 * len;`；说明 `W8` 保存的就是 `2*len`。
- **Hook 下游调用**：如果直接 hook 该指令地址不方便，可 hook 紧随其后的 `memcpy`，在 `onEnter` 读取 `this.context.x8`（长度/结果）、`x23`（其他参数）与 `lr`；用 `lr - 模块基址` 确认调用来自目标 `.so`，过滤其他模块的噪声。
- **为什么可行**：指令替换只改变计算形式，不改变数据流；运行时寄存器/内存中的值就是原始语义的结果，动态观测比静态化简更可靠。
- **边界**：若结果只在寄存器中短暂存在且没有下游调用，需要在目标指令地址用 `Interceptor.attach` 读 `context`；若被内联/优化掉，需要结合 IDA 反汇编定位实际指令。

## 触发条件

- Android native 库使用 OLLVM 指令替换（`-mllvm -sub` 或类似）。
- 关键计算块后有可观测的下游调用（`memcpy`、`strlen`、`malloc`、自定义函数）或可定位的存储指令。
- 测试设备可运行 Frida，目标未启用强反调试/反 Frida。
- 有 IDA/Ghidra 可定位替换块与寄存器/栈槽。

## 利用步骤

1. 在 IDA 中定位被替换的计算块，找到结果落点（如 `STURB W8, [X29,#var_60]`）及对应的源码语义（如 `2*len`）。
2. 找紧随其后的下游调用（如 `memcpy(dst, src, len)`）或函数入口，确定要读的寄存器（x0–x7 参数、x8 返回值/临时值）。
3. Hook `memcpy`（`Module.findExportByName(null, "memcpy")`），在 `onEnter` 读取 `this.context.x8`/`x23` 与 `this.context.lr`。
4. 用 `Process.findModuleByAddress(lr)` 过滤 `libhello-jni.so` 的调用，打印 `LR - base` 映射回 IDA 地址。
5. 多次运行/固定输入，验证 `X8` 与预期 `2*len` 一致；若不一致，回到 IDA 检查是否读错寄存器/栈槽。
6. 把提取到的值代回算法，继续分析后续变换。

## PoC

```javascript
function hook_native() {
    var base = Module.findBaseAddress("libhello-jni.so");
    var memcpy = Module.findExportByName(null, "memcpy");
    Interceptor.attach(memcpy, {
        onEnter: function (args) {
            var lr = ptr(this.context.lr);
            var module = Process.findModuleByAddress(lr);
            if (module && module.name === "libhello-jni.so") {
                console.log("memcpy X8:", this.context.x8,
                            "X23:", this.context.x23,
                            "LR:", lr.sub(base));
            }
        }
    });
}
setImmediate(hook_native);
```

```text
# 典型日志
# memcpy X8: 0x1e X23: 0xf LR: 0xf638
# 0x1e = 30 = 2 * 15（输入字符串长度 15）
# 对应 IDA: LOBYTE(v156) = 2 * len;
```

```text
# 也可直接 hook 指令地址读寄存器
# Interceptor.attach(base.add(0xF61C), {
#   onEnter: function(args) { console.log(this.context.x8, this.context.x23); }
# });
```

## 变体与关联

- Hook 点变体：`memcpy` 可换成 `strlen`、`malloc`、`free`、`pthread_create`、自定义函数；也可 hook 目标指令地址直接读 `context`。
- 提取对象变体：寄存器、栈槽（`[X29,#var_60]`）、返回值（`x0`）、结构体字段；按 IDA 反汇编确定。
- 静态辅助：用 IDA microcode/Hex-Rays、Triton 符号执行化简替换表达式；动态提取用于验证。
- 关联：[[code-analysis-reverse-obfuscation-ollvm-cff-frida-trace]]（CFF 动态追踪）、[[code-analysis-reverse-obfuscation-ollvm-string-decrypt-frida]]（字符串解密）、[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]（OLLVM 原理）。

## 检测与防御

- 检测：`memcpy`/`strlen` 等导出函数被 Interceptor hook；Frida/Xposed 特征；进程中出现异常线程/内存扫描；关键函数被高频调用。
- 防御：反调试/反 Frida（端口、线程、maps、inline hook 检测）；strip 符号；关键计算 native 化并做完整性校验；对结果做服务端校验。
- 加固：CFF + 指令替换 + 字符串加密多层叠加；减少可观测的下游调用（内联/自定义内存操作）；检测 Hook 框架并拒绝运行。
