---
id: tools-frida-arm64writer-nop-conditional-branch
title: Frida Arm64Writer 动态 NOP 掉 B.NE：绕过 native 分支暴露隐藏逻辑
type: scenario
domain: tools
path: tools/frida
technique: frida-arm64writer-nop-bne-branch-patch
tags:
- frida
- arm64
- native
- patch
- arm64writer
- branch
- reverse
- android
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:08:42+08:00'
  notes: 已对照原文及24张图核对：B.NE→NOP、Arm64Writer、0x15248、loc_1532C返回路径均一致；已修正PoC中误写的0xA flag FRIDA{DONT_CALL_ME}为0xB实际flag FRIDA{NATIVE_HACKER}；原文Memory.protect(基址,0x1000)与目标偏移0x15248不在同一页，PoC按原文保留，未本机执行
url: /docs/tools/frida/tools-frida-arm64writer-nop-conditional-branch/
draft: false
kb_aliases:
- Frida 0xB
- Arm64Writer
- putNop
- B.NE
- Memory.protect
- 4 字节指令
- 修改汇编
---

## 一句话结论

当 native 函数用 `B.NE` 等条件跳转跳过核心逻辑时，可用 Frida 的 `Memory.protect` 给代码段临时写权限，再用 `Arm64Writer.putNop()` 把 4 字节的 `B.NE` 覆盖成 4 字节 NOP，强制走真实路径，从而暴露被跳过的解密/flag 逻辑。

## 原理

- **ARM64 定长指令**：ARM64 每条指令固定 4 字节，`B.NE`（条件分支）与 `NOP`（空操作）都是 4 字节，因此可以用 1 条 NOP 精确覆盖原分支，不会破坏后续指令边界。
- **B.NE 的跳过逻辑**：案例中 `MOV W8,#0xDEADBEEF; STUR W8,[X29,#var_24]; LDUR W8,[X29,#var_24]; SUBS W8,W8,#0x539; B.NE loc_1532C`；`0xDEADBEEF - 0x539 != 0` 恒成立，`B.NE` 永远跳到 `loc_1532C`，而该标签只有 `LDP; ADD SP; RET`，直接返回，核心解密逻辑（`loc_15250` 的 XOR/日志）永远不执行。
- **NOP 掉分支**：把 `B.NE` 改成 NOP 后，执行流落到下一条 `B loc_15250`，进入真实逻辑，IDA 重新反编译即可看到 `getFlag` 的字符串异或与 `__android_log_print` 输出。
- **Frida 写代码段**：`Memory.protect(addr, 0x1000, "rwx")` 临时赋予读写执行权限；`new Arm64Writer(target)` 在目标地址写入 `putNop()`；`flush()` 刷新指令缓存；`dispose()` 释放 writer。
- **为什么可行**：Frida 在用户态修改目标进程内存，绕过静态补丁；条件跳转被 NOP 后，原本不可达的路径变为可达，配合 Hook/日志即可观察隐藏逻辑。
- **边界**：若代码段有 W^X/完整性校验/反调试，`Memory.protect` 可能失败或被检测；若分支是多条指令组成的复杂条件，需要逐条 patch 或改寄存器。

## 触发条件

- 目标为 ARM64 Android native 库，关键逻辑被条件跳转保护/跳过。
- 测试设备可运行 Frida，目标未启用强反调试/反 Frida/代码段完整性校验。
- 能在 IDA 中定位 `B.NE`/`B.EQ`/`CBZ` 等分支及其目标标签。
- 分支指令为 4 字节且可被 NOP 等长覆盖。

## 利用步骤

1. 在 IDA 中定位被跳过的核心逻辑（如 `loc_15250` 的字符串异或/日志），找到保护它的条件跳转（如 `B.NE loc_1532C`）。
2. 计算 `B.NE` 的运行时地址：`Module.findBaseAddress("libfrida0xb.so").add(0x15248)`。
3. Frida 脚本中 `Memory.protect(base, 0x1000, "rwx")` 给代码页写权限。
4. `new Arm64Writer(target)`，`putNop()`，`flush()`，`dispose()`。
5. 触发目标函数（点击按钮/调用 `getFlag`），观察 logcat/Frida 输出中是否出现被隐藏的 flag。
6. 若 patch 后崩溃，检查是否覆盖了错误地址/指令边界；必要时只 patch 条件跳转本身，不要动后续指令。

## PoC

```javascript
function hook() {
    var adr = Module.getBaseAddress("libfrida0xb.so");
    var target = adr.add(0x15248);          // B.NE 指令地址
    console.log("function address:", target);

    Memory.protect(adr, 0x1000, "rwx");     // 代码段临时可写
    var writer = new Arm64Writer(target);
    try {
        writer.putNop();                    // 用 NOP 覆盖 B.NE
        writer.flush();
        console.log("Success!!");
    } finally {
        writer.dispose();
    }
}

function main() {
    Java.perform(function () { hook(); });
}
setImmediate(main);
```

```text
# Patch 前：
# MOV W8,#0xDEADBEEF; ...; SUBS W8,W8,#0x539; B.NE loc_1532C
# loc_1532C: LDP X29,X30; ADD SP,SP,#0x60; RET  -> 直接返回，跳过核心逻辑
#
# Patch 后（B.NE -> NOP）：
# 执行落到 B loc_15250 -> 字符串异或 + __android_log_print
# logcat: FLAG : FRIDA{NATIVE_HACKER}
```

## 变体与关联

- 分支变体：`B.EQ`、`CBZ`、`CBNZ`、`TBZ`、`TBNZ` 都可用 NOP 覆盖；条件组合复杂时逐条 patch。
- 指令变体：除 NOP 外，可写 `RET` 提前返回、`MOV` 改寄存器、`B` 改跳转目标；`Arm64Writer` 提供 `putNop`/`putRet`/`putBytes` 等。
- 动态替代：`Interceptor.attach` 在分支前改寄存器/`context.pc`，或 `Interceptor.replace` 整个函数；不改代码段，隐蔽性更好。
- 关联：[[tools-frida-native-hook-export-unexport-retval-constructor]]（Native Hook 基础）、[[tools-frida-source-patch-anti-detection]]（Frida 反检测）、[[code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register]]（指令级动态分析）。

## 检测与防御

- 检测：代码段被 `mprotect` 改为可写/可执行；`B.NE`/`CBZ` 等分支被改写为 NOP；Frida 特征；函数行为与静态逻辑不一致。
- 防御：代码段 W^X、SELinux 强制、完整性校验（对 .text 做哈希/签名）；反调试/反 Frida；关键逻辑多路径校验并服务端验证。
- 加固：OLLVM/控制流平坦化增加 patch 难度；检测 `mprotect`/`memcpy` 到代码段的行为；定期校验指令字节。
