---
id: code-analysis-reverse-obfuscation-ollvm-cff-frida-trace
title: Frida 辅助 OLLVM 控制流平坦化分析：NewStringUTF/LR 追踪 + base64/MD5 识别
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ollvm-cff-frida-newstringutf-lr-trace
aliases:
- 控制流平坦化
- CFF
- NewStringUTF
- GetStringUTFChars
- LR 追踪
- sub_15F1C
- base64
- MD5 0xD76AA478
tags:
- reverse
- obfuscation
- ollvm
- control-flow-flattening
- frida
- android
- jni
- md5
- base64
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:14:20+08:00'
  notes: 已对照原文与截图核对：NewStringUTF/GetStringUTFChars hook、固定 sign2 输入、sub_15F1C/sub_162B8 base64/sub_154D4/sub_158AC/sub_14844 MD5 常量 0xD76AA478/0xE8C7B756、最终 32 位 hex 结果均一致。未验证点：未复跑 Frida 脚本与算法复现。
---

## 一句话结论

面对 OLLVM 控制流平坦化（CFF）的 native 函数，先 hook `libart.so` 的 `NewStringUTF`/`GetStringUTFChars` 拿到 native 与 Java 之间的字符串，固定 Java 层随机输入，再用 IDA 交叉引用 + Frida hook 关键函数（记录参数、返回值与 LR）逐步定位 base64 与 MD5，最后复现算法。

## 原理

- **CFF 形态**：OLLVM 把函数的基本块拆散，用一个状态变量 + `while`/`switch` 分发器串起来；IDA 的 CFG 会变成“蜘蛛网”，直接读伪代码很难看出原逻辑。
- **动态观测优先**：CFF 只改变控制流，不改变数据流；在关键函数入口/出口 hook，打印参数、返回值和调用者 LR，就能从数据变化反推算法，而不必先还原 CFG。
- **JNI 字符串边界**：`NewStringUTF` 是 native 返回给 Java 的字符串（可看到最终密文/结果），`GetStringUTFChars` 是 Java 传给 native 的字符串（可看到输入）；两者都在 `libart.so` 中，按符号名过滤 `CheckJNI` 后 hook。
- **固定随机输入**：Java 层用 `RandomStringUtils.randomAscii(16)` 生成随机参数会干扰分析；用 Frida Java Hook 替换 `sign2` 实现，固定为已知字符串，保证每次调用输入一致。
- **交叉引用 + LR**：在 IDA 中从 `NewStringUTF` 的 `result` 反查赋值（如 `v49` → `sub_15F1C`），再 hook `sub_15F1C` 看 `arg0/arg1/arg2/retval`；把 `this.context.lr` 减去模块基址，就能把调用点映射回 IDA 地址，继续向上/向下追踪。
- **算法识别**：`sub_162B8` 把两个输入拼接后返回可打印字符串，手动/CyberChef 验证为 base64；`sub_14844` 中出现 MD5 常量 `0xD76AA478`、`0xE8C7B756` 等，且输出 32 位十六进制，可判定为 MD5；`sub_158AC` 对结果做进一步变换，最终与界面一致。
- **为什么可行**：CFF 让静态 CFG 复杂，但运行时数据流仍按原语义执行；Frida 的 Interceptor 能在不修改二进制的情况下捕获真实参数与返回值。

## 触发条件

- Android native 库使用 OLLVM CFF（或类似平坦化）混淆。
- 关键逻辑通过 JNI 调用，输入/输出经过 `NewStringUTF`/`GetStringUTFChars`。
- 测试设备可运行 Frida，目标未启用强反调试/反 Frida。
- 有 IDA/Ghidra 可做交叉引用，且能定位关键函数地址。
- Java 层输入可被 Hook 固定，或可重复复现。

## 利用步骤

1. Hook `libart.so` 的 `NewStringUTF`/`GetStringUTFChars`，确认 native 返回的密文/结果与界面一致。
2. 用 Java Hook 固定 `sign2`/`sign1` 的随机参数（如 `adkliowpwkklsap`、`0987654321adksoi`），保证输入稳定。
3. 在 IDA 中从 `NewStringUTF` 的 `result` 反查赋值，定位 `sub_15F1C(input,len,&result)` 等关键函数。
4. Hook `sub_15F1C`，打印 `arg0/arg1/arg2/retval` 与 `LR`；用 `LR - 模块基址` 映射回 IDA 调用点。
5. 继续向上追踪输入来源（如 `sub_162B8` 拼接 + base64），向下追踪结果变换（如 `sub_154D4`/`sub_158AC`）。
6. 用常量/输出特征识别算法：`0xD76AA478` 等 MD5 常量、32 位十六进制输出；用 CyberChef/本地脚本验证 base64、MD5 输入拼接与 salt。
7. 复现完整算法，用固定输入验证输出与 App 界面一致。

## PoC

```javascript
// Hook NewStringUTF / GetStringUTFChars
function hook_libart() {
    var libart = Process.findModuleByName("libart.so");
    var addrNew = null, addrGet = null;
    libart.enumerateSymbols().forEach(function (s) {
        if (s.name.indexOf("CheckJNI") === -1 && s.name.indexOf("JNI") > 0) {
            if (s.name.indexOf("NewStringUTF") > 0) addrNew = s.address;
            if (s.name.indexOf("GetStringUTFChars") > 0) addrGet = s.address;
        }
    });
    if (addrNew) Interceptor.attach(addrNew, {
        onEnter: function (args) { console.log("[NewStringUTF]", ptr(args[1]).readCString()); }
    });
    if (addrGet) Interceptor.attach(addrGet, {
        onLeave: function (retval) { console.log("[GetStringUTFChars]", ptr(retval).readCString()); }
    });
}
```

```javascript
// 固定 Java 层随机输入
Java.perform(function () {
    var HelloJni = Java.use("com.example.hellojni.HelloJni");
    HelloJni.sign2.implementation = function (arg0) {
        var r = this.sign2("adkliowpwkklsap", "0987654321adksoi");
        console.log("[result]", r);
        return r;
    };
});
```

```javascript
// Hook 关键 native 函数，记录参数/返回值/LR
function hook_native_addr(addr) {
    var base = Module.findBaseAddress("libhello-jni.so");
    var idb = addr.sub(base);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.arg0 = args[0]; this.arg1 = args[1];
            this.arg2 = args[2]; this.arg3 = args[3];
            this.lr = this.context.lr;
        },
        onLeave: function (retval) {
            console.log("ptr:" + ptr(addr) + " idb:" + ptr(idb)
                + " LR:" + ptr(this.lr).sub(base));
            console.log("arg0:", hexdump(this.arg0), "arg1:", hexdump(this.arg1),
                        "arg2:", hexdump(this.arg2), "retval:", hexdump(retval));
        }
    });
}
```

```text
# 关键观测
# sub_162B8("adkliowpwkklsap","0987654321adksoi") -> base64
# sub_15F1C 的 arg0 = "++++++++++salt0+" + base64
# sub_14844 中出现 0xD76AA478/0xE8C7B756 -> MD5
# 最终 result 为 32 位十六进制，与界面一致
```

## 变体与关联

- 静态还原变体：用 Angr/Triton/符号执行处理 CFF，或写 IDA 脚本做 dispatcher 状态变量分析；动态 hook 与其互补。
- Hook 点变体：`NewStringUTF`/`GetStringUTFChars` 可换成 `strcmp`、`memcmp`、`memcpy`、`malloc`、`pthread_create`；LR 追踪通用。
- 算法识别变体：base64 可用 CyberChef 验证；MD5 可搜 `0xD76AA478`/`0x67452301`；也可用已知输入输出做差分。
- 关联：[[code-analysis-reverse-obfuscation-ollvm-string-decrypt-frida]]（字符串解密）、[[code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register]]（指令替换）、[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]（OLLVM 原理）。

## 检测与防御

- 检测：`libart.so` 的 `NewStringUTF`/`GetStringUTFChars` 被 Interceptor hook；Frida/Xposed 特征；进程中出现异常线程/内存扫描；native 函数被频繁调用。
- 防御：反调试/反 Frida（检测端口、线程、maps、inline hook）；strip 符号与字符串加密；关键算法 native 化并做完整性校验；服务端校验结果。
- 加固：CFF + 指令替换 + 字符串加密多层叠加；对 JNI 调用做参数校验；检测 Hook 框架并拒绝运行。
