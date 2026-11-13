---
id: code-analysis-dynamic-fuzzing-afl-frida-android-native-persistent-hook
title: AFL++ Frida 模式 Android 原生库灰盒 fuzz：NDK 构建、afl.js 持久化入口与 aarch64 参数注入
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: afl-frida-android-native-persistent-hook
aliases:
- AFL++ Frida 模式
- afl-frida-trace.so
- Android 灰盒模糊测试
- afl.js 持久化钩子
- Afl.setPersistentAddress
- CModule persistent hook
- GumCpuContext 参数写入
- AFL_FRIDA_JS_SCRIPT
tags:
- android
- fuzzing
- afl
- frida
- native
- persistent-loop
- cmake
- ndk
- aarch64
- coverage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502-fix
  verified_at: '2026-11-11T03:40:33+08:00'
  notes: V502 修正：Afl.addExcludedRange 第二参数改为 m.size（AFL++ 4.06c API 为 address,size）；性能描述改为约 1 万 exec/s（原文图03 10.8k）。
---

## 一句话结论

在没有源码插桩条件（或不想改包）的 Android 原生库上，可以用 AFL++ 的 Frida 模式做覆盖率引导的灰盒 fuzz：用 NDK 和精简 CMake 把 AFL++ 交叉编译成设备上的 `afl-fuzz` 与 `afl-frida-trace.so`，在 `afl.js` 里用 `DebugSymbol` 定位 harness 的 `fuzz_one_input` 并设为持久化入口，再用 Frida `CModule` 编译一段 C 持久化钩子，在每轮迭代前把 fuzzer 输入写入 aarch64 的 `x0`（缓冲区）与 `x1`（长度），即可在真机上以接近原生的速度跑持久化 fuzz。

## 原理

- **Frida 模式为什么可行**：AFL++ 的 Frida 模式通过注入 `afl-frida-trace.so` 在目标进程内做动态插桩，按基本块/边收集覆盖率并写回 AFL 共享内存；无需重新编译目标，适用于只有 APK 中 `.so` 的场景（闭源/第三方库）。
- **交叉编译**：用 Android NDK 工具链 + Quarkslab 的精简 `CMakeLists.txt` 构建 AFL++，指定 `ANDROID_PLATFORM=31`、`ANDROID_ABI=arm64-v8a`，产出的 `afl-fuzz` 与 `afl-frida-trace.so` 通过 adb 推到 `/data/local/tmp`；设备需 root（共享内存与注入权限）。
- **持久化循环**：AFL 默认每轮 fork/exec 一个新进程，放大了 Android 上 JVM/动态链接的启动成本。`afl.js` 中 `const pStartAddr = DebugSymbol.fromName("fuzz_one_input").address; Afl.setPersistentAddress(pStartAddr); Afl.setEntryPoint(pStartAddr);` 把 `fuzz_one_input` 设为入口与持久化返回点，进程只启动一次，循环调用。
- **每轮上下文修复**：持久化循环每轮开始时寄存器上下文会恢复，但函数参数仍需按本轮输入重设。用 `CModule` 内联编译 C 钩子 `afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len)`，`memcpy((void*)regs->x[0], input_buf, length)` 把输入复制进 harness 缓冲区，`regs->x[1] = length` 设置长度——符合 aarch64 调用约定（x0=第一参数缓冲区指针、x1=第二参数长度）。`memcpy` 通过 `Module.getExportByName(null, "memcpy")` 从宿主模块解析。
- **过滤插桩范围**：Frida 模式默认会插桩进程中所有模块，Android 运行时体量巨大，必须排除。示例用模块白名单 `["fuzz","libblogfuzz.so"]`，先 `Module.load("libandroid_runtime.so")` 保证它出现在模块列表，再遍历 `new ModuleMap().values()` 对非白名单模块调用 `Afl.addExcludedRange(m.base, m.size)`；持久化迭代次数用 `Afl.setPersistentCount(10000)`。
- **运行与配置**：`./afl-fuzz -O -G 256 -i in -o out ./fuzz`；`-O` 选择 Frida 模式，`-G 256` 限制生成输入最大 256 字节（与 harness 缓冲区一致）。默认读取当前目录 `afl.js`，可用环境变量 `AFL_FRIDA_JS_SCRIPT` 指定其他脚本；设备上先把 CPU governor 设为 `performance`（或运行 `afl-system-config`）。
- **为什么快**：持久化 + 进程内插桩避免了每轮启动代价，纯原生函数场景可达约 1 万 exec/s（原文图03 显示 10.8k exec/s）；代价是目标状态需要可重置，若库内有全局状态/缓存，持久化会导致跨轮污染，需要每轮重置或退回 fork 模式。

## 触发条件

- Android 设备/模拟器已 root，可 adb 推送并执行二进制（aarch64，对应 NDK ABI）。
- 目标原生库可在独立 harness 进程中加载调用（依赖齐全），或 harness 内自行 dlopen。
- 能编写一个接收 `(const uint8_t*, size_t)` 的 `fuzz_one_input` 并链接目标函数。
- AFL++ 已按目标平台交叉编译出 Frida 模式产物；设备 CPU governor 可调。

## 利用步骤

1. 环境：Ubuntu x86_64 安装 cmake/curl/unzip/xxd，下载 AFL++ 4.06c、Android NDK r25c 与精简 `CMakeLists.txt`。
2. 交叉编译：`cmake -DANDROID_PLATFORM=31 -DCMAKE_TOOLCHAIN_FILE=<ndk>/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a .. && make`，得到 `afl-fuzz` 与 `afl-frida-trace.so`。
3. `adb push afl-fuzz afl-frida-trace.so fuzz afl.js libtarget.so /data/local/tmp`；设备上 `echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`（root）。
4. 准备种子目录与输出目录：`mkdir in out; dd if=/dev/urandom of=in/sample.bin bs=1 count=16`（大小不超过 `-G` 限制）。
5. 编写 harness：`fuzz_one_input(buf,len)` 调用目标函数；编译为可执行 `fuzz` 并链接/加载目标 `.so`。
6. 编写 `afl.js`：定位 `fuzz_one_input` 地址并设入口/持久化地址；用 `CModule` 注册持久化钩子写入 `x0/x1`；按白名单排除运行时模块；设置持久化迭代次数。
7. 运行：`./afl-fuzz -O -G 256 -i in -o out ./fuzz`；观察 UI 的 stability、map density、exec speed；崩溃样本在 `out/default/crashes/`。
8. 对 crash 做最小化与复现（ASan/真机），确认是目标库缺陷而非 harness/持久化状态问题。

## PoC

```bash
# 交叉编译（环境变量按实际 NDK 路径替换）
mkdir build && cd build
cmake -DANDROID_PLATFORM=31 \
  -DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk-r25c/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a ..
make
adb push afl-fuzz afl-frida-trace.so /data/local/tmp
```

```javascript
// afl.js（核心片段）
const pStartAddr = DebugSymbol.fromName("fuzz_one_input").address;
Afl.setPersistentAddress(pStartAddr);
Afl.setEntryPoint(pStartAddr);

const cm = new CModule(`
#include <string.h>
#include <gum/gumdefs.h>
#define BUF_LEN 256
void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len) {
  uint32_t length = (input_buf_len > BUF_LEN) ? BUF_LEN : input_buf_len;
  memcpy((void *)regs->x[0], input_buf, length);
  regs->x[1] = length;
}
`, { memcpy: Module.getExportByName(null, "memcpy") });
Afl.setPersistentHook(cm.afl_persistent_hook);
Afl.setPersistentCount(10000);

const MODULE_WHITELIST = ["fuzz", "libtarget.so"];
Module.load("libandroid_runtime.so");
new ModuleMap().values().forEach(m => {
  if (!MODULE_WHITELIST.includes(m.name)) {
    Afl.addExcludedRange(m.base, m.size);
  }
});
```

```bash
# 设备上运行（Frida 模式 + 最大输入 256）
./afl-fuzz -O -G 256 -i in -o out ./fuzz
```

说明：示例基于原文环境（AFL++ 4.06c、Frida 16、NDK r25c、Android 12 aarch64）；不同 Frida/AFL++ 版本的 GumJS API 可能有差异，需按版本文档核对。

## 变体与关联

- 关联：无源码二进制的另一种选择是 QEMU 模式与基础 AFL 用法，见 [[code-analysis-dynamic-fuzzing-afl-stdin-qemu-modes-ui-metrics]]；本卡是 Frida 模式在 Android 上的工程化配置。
- 关联：把 JNI 函数作为 fuzz 入口（真实 ART 环境）见 [[code-analysis-dynamic-fuzzing-android-jni-real-art-harness-afl-frida]]；用假 JNIEnv 模拟脱离 Android 运行时见 [[code-analysis-dynamic-fuzzing-android-jni-env-emulation-harness]]。
- 变体：`afl-frida-trace.so` 也可通过环境变量配置（`AFL_FRIDA_*`），与 JS 配置混用；持久化地址也可用导出符号或偏移固定。
- 变体：无 root 设备可改用模拟器/自编译 AOSP 或在应用进程内 fuzz；加固/反调试会阻止注入。
- 边界：持久化要求目标每轮可重置；全局状态、JNI 全局引用、线程池会跨轮污染；Frida 注入可能被反调试/完整性校验发现。

## 检测与防御

- 测试侧：fuzz 仅限授权目标；对每个 crash 在独立进程/真机复现，区分持久化状态导致的假崩溃；为 harness 设置超时与内存上限。
- 防护侧（被测应用）：root/越狱检测、Frida 端口与注入特征检测、`/data/local/tmp` 可执行文件监控、APK 完整性校验可提高在真机上运行 fuzz 的成本。
- 工程化：把 Frida 模式 fuzz 放进专用测试机/容器，固定 CPU governor 与种子，记录 AFL++/Frida/NDK 版本以保证结果可复现。
