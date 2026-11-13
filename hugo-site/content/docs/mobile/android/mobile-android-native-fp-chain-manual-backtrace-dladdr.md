---
id: mobile-android-native-fp-chain-manual-backtrace-dladdr
title: Android Native 手动栈回溯：__builtin_frame_address 沿 FP 链遍历 + dladdr 符号化，及 ART/JNI 帧 FP/LR 对位于 SP+0x20 与 -fomit-frame-pointer 断链
type: scenario
domain: mobile
path: mobile/android
technique: android-native-fp-chain-manual-backtrace
tags:
- android
- native
- reverse
- arm64
- backtrace
- stack-unwind
- frame-pointer
- anti-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V659
  verified_at: '2026-11-13T07:04:23+08:00'
  notes: 已对照原文与 img/01-06 核对：FP 链循环代码与原文逐行一致（__builtin_frame_address/return_address、*(fp+8) 取 LR、dladdr+dli_fname 判空、fp=*(fp) 上溯）；logcat 实测 func2v→func1v→stringFromJNI→libart symbol=(null) 与 img/04 一致；libart art_quick_invoke_stub 的 STP X29,X30,[SP,#0x30+var_10]/MOV X29,SP 与 img/05 一致（已修正表述：var_10=-0x10 使 FP/LR 对落在 SP+0x20、LR 在 SP+0x28，原文口语化写作 lr 在 sp+0x20，需先 fp+0x20 再按 +8 取 LR）；-fomit-frame-pointer 只留当前帧与原文及 img/06 一致；libcorkscrew 4.1-4.4W/libunwind 5.0-7.1.1/libunwindstack 8.0+ 版本线与 _Unwind_Backtrace/_Unwind_Context 描述一致。两个 wikilink 目标均存在（tools-frida-native-hook-export-unexport-retval-constructor、mobile-android-jni-native-unicorn-emulation-constant-extraction）；非组件类未设 affected_versions 合理；severity low/confidence high 合理（逆向辅助技术、代码与 logcat 均来自原文）。dedup 复跑 top 候选均为 Frida/Unidbg/Unicorn 类，new 成立。未复跑 PoC。
url: /docs/mobile/android/mobile-android-native-fp-chain-manual-backtrace-dladdr/
draft: false
kb_aliases:
- 手动 stacktrace
- FP 链回溯
- frame pointer 栈回溯
- dladdr 符号化
- __builtin_frame_address
- art_quick_invoke_stub 断链
---

# 一句话结论

Android Native 层可以不用系统 backtrace 库，直接用 `__builtin_frame_address(0)`/`__builtin_return_address(0)` 从当前 FP 开始沿"栈上保存的上层 FP"逐帧迭代、用帧内 LR 槽取返回地址并经 `dladdr` 符号化成模块名，实现最小手动栈回溯；但该 FP 链在进入 ART/JNI 系统帧时会断（`art_quick_invoke_stub` 里 X29 实际指向 SP，FP/LR 对位于 SP+0x20、LR 在 SP+0x28，需先 fp+0x20 再按 +8 取 LR，而非常规的 [X29]/[X29+8]），且被 `-fomit-frame-pointer` 编译的函数只留下当前帧。

# 原理

- **ARM64 栈帧约定**：函数入口 `STP X29, X30, [SP,#0x40]` + `ADD X29, SP, #0x40` 把调用者的 FP(X29) 与 LR(X30) 存到当前栈帧，X29 指向这块保存区；函数出口 `LDP X29, X30, [SP,#0x40]` 恢复。于是"当前 FP 指向的内存"依次是 caller 的 FP 与返回地址（LR），逐层解引用即可向上遍历整条调用链。
- **遍历条件**：循环在 `fp != 0`、`*(fp) != 0`、`fp != *(fp)`（自环）时继续；每轮 `lr = *(fp + sizeof(char*))`，再用 `dladdr(lr)` 取 `dli_fname` 模块路径（可选 `dli_sname` 符号名）。任何一环取不到就停止，避免非法地址崩溃。
- **为什么不能穿透 ART/JNI**：系统库并不遵循同一套 prologue 约定。反编译 `libart.so` 的 `art_quick_invoke_stub` 可见 `STP X29, X30, [SP,#0x30+var_10]`（var_10=-0x10，FP/LR 对落在 SP+0x20，LR 在 SP+0x28）后 `MOV X29, SP`——此时 X29 等于 SP，若仍按"FP+8 取 LR"会取到 [S+8] 处的无关值，导致手动遍历到该帧后中断；需先把 fp 加 0x20 得到常规 FP 再按 +8 取 LR（现象：`module=/apex/com.android.runtime/lib64/libart.so, symbol=(null)` 为止）。
- **为什么 -fomit-frame-pointer 断链**：开启该优化后编译器不再保存/维护 X29 链，任何一帧被优化掉 FP 保存都会让遍历在该层终止，只能拿到当前函数自身的 LR。
- **与系统库的对照**：AOSP 自带 backtrace 按版本演进——libcorkscrew（Android 4.1–4.4W）、libunwind（5.0–7.1.1）、libunwindstack（8.0+）；C++ 侧底层是 `_Unwind_Backtrace(_Unwind_Trace_Fn, void*)`，对每个栈帧回调 `_Unwind_Context`（含 reg[]/cfa/ra 等），但这些接口并不适合在业务代码里手工逐帧取数，因此才有基于 FP 的自实现。

# 触发条件

- 目标为 Android Native（JNI）代码，测试/分析者能编译或注入 so 并拿到 logcat 输出。
- 目标库未被 `-fomit-frame-pointer` 编译（或只需回溯纯业务帧、不要求穿透系统库）。
- 需要基础符号化能力：`dladdr` 可解析模块路径（符号名在 strip 后常为 null，可配合本地符号表/IDA 基址换算）。

# 利用步骤

1. 在 JNI 函数或待观察函数中调用一个 dump 函数，先取 `lr = __builtin_return_address(0)`、`fp = __builtin_frame_address(0)` 作为起点。
2. 循环：用 `*(uint64_t*)fp` 读 caller FP、`*(uint64_t*)(fp + 8)` 读本帧保存的 LR（即返回地址）；`dladdr` 解析后打印 `pc/module/symbol`，然后 `fp = caller FP`。
3. 遇到 `fp==0`、`*(fp)==0` 或自环即停止（进入系统库后实际会先遇到 libart 帧）。
4. 若需要穿透 ART/JNI 帧：对 `art_quick_invoke_stub` 这一层按 `X29=SP`、FP/LR 对位于 SP+0x20（LR 在 SP+0x28）的特例修正取址（先 `fp+0x20` 得到 FP/LR 对，再按 +8 取 LR），但原文仅给出该观察，未实现完整穿透。
5. 对照验证：与 crash 堆栈/debuggerd 输出比对，确认业务帧（func2→func1→JNI 函数）齐全，系统帧缺失属预期。

# PoC

```cpp
// 最小 FP 链手动回溯（ARM64，logcat 输出 pc/module）
auto lr = (uint64_t) __builtin_return_address(0);
auto fp = (uint64_t) __builtin_frame_address(0);
while ((0 != fp) && (0 != *(unsigned long *) fp) &&
       (fp != *(unsigned long *) fp)) {
    lr = *(uint64_t *) (fp + sizeof(char *));
    Dl_info info;
    if (!dladdr((void *) lr, &info)) break;
    if (!info.dli_fname) break;
    LOG("backtrace pc = %p,module = %s", lr, info.dli_fname);
    fp = *((uint64_t *) fp);
}
```

```text
# logcat 实测（示例）：
backtrace pc = 0x6ecb4d7680,module = /data/app/com.huawei.stacktraceunwnd-.../lib/arm64/libstacktraceunwnd.so,symbol = _Z5func2v
backtrace pc = 0x6ecb4d7694,module = ...libstacktraceunwnd.so,symbol = _Z5func1v
backtrace pc = 0x6ecb4d76c0,module = ...libstacktraceunwnd.so,symbol = Java_com_huawei_stacktraceunwnd_MainActivity_stringFromJNI
backtrace pc = 0x6f32759354,module = /apex/com.android.runtime/lib64/libart.so,symbol = (null)   # 到这里 FP 链断开
```

# 变体与关联

- 变体：配合本地符号表把 `pc - base` 换算成函数偏移（`dladdr` 返回的 `dli_fbase` 即模块基址），strip 后仍可符号化。
- 变体：系统侧标准做法用 `_Unwind_Backtrace`/libunwindstack（8.0+），可作对照基线；业务侧自实现的价值在于不依赖私有系统接口。
- 对抗面：`-fomit-frame-pointer`（GCC/Clang 优化或显式 `target_compile_options`）会让任何 FP 链回溯只拿到当前帧；加固方案可据此干扰逆向者的栈打印。
- 关联：[[tools-frida-native-hook-export-unexport-retval-constructor]]（native Hook 基础）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（JNI 模拟执行分析）。

# 检测与防御

- 检测：逆向分析场景无服务端检测点；防御方可对敏感逻辑使用 `-fomit-frame-pointer`、strip 符号、SO 加固，降低攻击者/逆向者获取调用上下文的能力。
- 防御视角的局限：省略帧指针不能阻止 crash 级 unwind（系统依赖 .eh_frame/.debug_frame 表），只干扰基于 FP 链的手工回溯。
- 说明：本文为逆向分析辅助技术（系列第一篇，未给出完整穿透 ART 的实现），severity 记为 low，confidence high（代码与 logcat 实测均来自原文）。
