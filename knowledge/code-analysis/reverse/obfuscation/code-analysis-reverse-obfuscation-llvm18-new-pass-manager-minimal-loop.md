---
id: code-analysis-reverse-obfuscation-llvm18-new-pass-manager-minimal-loop
title: LLVM 18 新版 PassManager 最小闭环：PassInfoMixin 写 run()、PassRegistry.def 注册 encode、ninja opt 后以 -O3 生成的 .ll 验证
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: llvm18-new-pass-manager-pass-registration-build
aliases:
- 新版 PassManager
- PassInfoMixin
- FUNCTION_PASS 注册
- llvm 18 pass 编写
- opt -passes 加载
- new pass manager
tags:
- llvm
- pass
- new-pass-manager
- obfuscation
- toolchain
- cmake
- opt
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:34:51+08:00'
  notes: 已对照原文核对；本次核对未读取图片；LLVM 18 新版 PassManager 的 PassInfoMixin/run 签名、PassRegistry.def 的 FUNCTION_PASS 注册、PassBuilder.cpp include、ninja opt 单目标、-O3 必需、BLAKE3 误加目标导致循环依赖均与正文一致。另修正卡内一处失效关联链接。未验证点：未编译 LLVM、未运行 opt，CLion 截图未核对
---

## 一句话结论

在 LLVM 18 的新版 PassManager 下写一个自定义 pass，不再是继承 `FunctionPass` 并实现 `runOnFunction`，而是继承 CRTP 混入 `PassInfoMixin<YourPass>` 并实现 `PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM)`；要能用 `opt` 的名字直接调起，还需要在 `PassRegistry.def` 里加一行 `FUNCTION_PASS("encode", EncodePass())` 并在 `PassBuilder.cpp` 引入头文件，最后用 `ninja opt` 只编 opt 目标验证。

## 原理

- 旧版 PassManager 通过继承 `FunctionPass`/`ModulePass` 并覆写 `runOnFunction` 定义接口；新版改为**基于概念的多态**：没有显式接口类，所有 pass 继承 CRTP 混入 `PassInfoMixin<PassT>`，框架靠 `PassT::run` 的签名（返回 `PreservedAnalyses`、接收 IR 单元 + `AnalysisManager`）来识别它属于哪一级（Function/Module/CGSCC）。
- `PreservedAnalyses` 是返回值而不是副产物：它声明「本次变换之后哪些分析结果仍然有效」，全量返回 `PreservedAnalyses::all()` 表示未破坏任何分析；若改了 CFG 却仍返回 `all()`，下游分析会拿到过期结果，表现为优化行为异常而非编译报错。
- 名字注册走两条路：`PassRegistry.def` 里的 `FUNCTION_PASS("encode", EncodePass())` 让 `-passes=encode` 可用（官方为便于扩展把 pass 列表做成宏定义文件）；`PassBuilder.cpp` 里 include 新头文件是为了让该宏展开处能看到 `EncodePass` 的完整类型。
- 新版资料远少于旧版，官方文档的 helloworld 示例已存在同名文件，直接照它加一个 `Encode.h`/`Encode.cpp` 是最小可编译路径；`run` 在头文件里声明后 IDE 标红属正常（实现尚未参与索引），不影响编译。
- 必须对目标 C 文件加 `-O3` 再 `-emit-llvm`：不开优化时函数体可能保留为 `available_externally`/被内联前的形态，`F.getName()` 拿不到预期函数名（表现为 pass「什么都没打印」），这是最常见的「代码明明对却没输出」原因。
- 编译收敛到 `ninja -j<N> opt` 单目标：全量 `ninja` 编 LLVM 耗时极长，而 pass 只被 `opt` 使用；CLion 新建 `.cpp` 时默认把它挂到 `lib/Support/BLAKE3/` 目标下会产生循环依赖报错，需删掉那条误加的 CMakeLists 条目。

## 触发条件

- 本地已获取 LLVM 源码（18.1.8 系列）并可用 CMake + Ninja 构建；`-DLLVM_ENABLE_PROJECTS="clang"` 且需要动态库时加 `-DBUILD_SHARED_LIBS=ON`。
- 需要以 **pass 名字**（而非 `.so` 插件路径）在 `opt` 里调用，因此必须改 `PassRegistry.def` + `PassBuilder.cpp` 并重新编译 `opt`。
- 目标代码为 C/C++，且用 `clang -O3 -emit-llvm -S` 生成 `.ll` 供 `opt` 处理。
- 只做单机实验时无需全量构建，编 `opt` 目标即可。

## 利用步骤

1. 在 `llvm/include/llvm/Transforms/Utils/` 下新建 `Encode.h`，声明 `class EncodePass : public PassInfoMixin<EncodePass>` 与 `PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);`。
2. 在 `llvm/lib/Transforms/Utils/` 下新建 `Encode.cpp`，实现 `run`（如 `errs() << F.getName() << "\n";`）并 `return PreservedAnalyses::all();`。
3. 把 `Encode.cpp` 加入 `llvm/lib/Transforms/Utils/CMakeLists.txt` 的源文件列表。
4. 在 `llvm/lib/Passes/PassRegistry.def` 增加 `FUNCTION_PASS("encode", EncodePass())`；在 `PassBuilder.cpp` 增加 `#include "llvm/Transforms/Utils/Encode.h"`。
5. `cmake -S llvm -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang"` 后 `cd build && ninja -j8 opt`；若报循环依赖，检查是否有新 `.cpp` 被误加进其他子目录的 CMakeLists（如 `lib/Support/BLAKE3/`）并删除。
6. `clang -O3 -emit-llvm hello.c -S -o hello.ll`，再 `./build/bin/opt -passes=encode -disable-output hello.ll`（或 `-passes=encode hello.ll -S -o -`）观察输出。
7. 需要不重编 LLVM 时改用插件路线：把 pass 编成 `.so`，`opt -load-pass-plugin=./Encode.so -passes=encode ...`。

## PoC

```cpp
// Encode.h
namespace llvm {
class EncodePass : public PassInfoMixin<EncodePass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};
}
```

```cpp
// Encode.cpp
#include "llvm/Transforms/Utils/Encode.h"
using namespace llvm;
PreservedAnalyses EncodePass::run(Function &F, FunctionAnalysisManager &AM) {
  errs() << F.getName() << "\n";
  return PreservedAnalyses::all();
}
```

```text
FUNCTION_PASS("encode", EncodePass())          # llvm/lib/Passes/PassRegistry.def
#include "llvm/Transforms/Utils/Encode.h"      # llvm/lib/Passes/PassBuilder.cpp

clang -O3 -emit-llvm hello.c -S -o hello.ll    # -O3 必须加
./build/bin/opt -passes=encode -disable-output hello.ll
```

判定：`opt` 逐行打印 `main`/`test_hello1`/`test_hello2` 等函数名即闭环成功；若一行不打印，先确认是否漏了 `-O3`（函数被优化掉的形态拿不到名字）。

## 变体与关联

- 变体：模块级改 `MODULE_PASS`，循环级改 `LOOP_PASS` 等，宏名与 `run` 签名随之变化。
- 变体：不侵入 LLVM 源码时用 `-fpass-plugin`（clang 直接加载 pass 插件）或 `opt -load-pass-plugin`，适合快速迭代。
- 关联：[[code-analysis-reverse-obfuscation-llvm-pass-implementation]]（同一工具链下**实现**基本块分割/控制流平坦化/虚假控制流/指令与常量替换的 OLLVM 风格 pass，本卡是它的新版 PassManager 前置脚手架）。
- 关联：[[code-analysis-reverse-obfuscation-ollvm-triton-ast-ai-z3-mba]]（混淆效果与还原视角：CFF/BCF/MBA 的符号执行化简）。

## 检测与防御

- 说明：本卡是分析/构建环境搭建，防御侧对应「识别自定义 pass 产生的混淆特征」。
- 检测：二进制中出现 LLVM 版本戳、`opt` 风格控制流（dispatch switch + 状态变量）或异常均匀的基本块规模，提示经过自定义 pass 处理。
- 加固：发布前用 `strip` 与 `-fno-ident` 去除版本痕迹，避免分析者据 LLVM 版本直接复现 pass 行为。
