---
id: code-analysis-dynamic-fuzzing-libfuzzer-cpp-harness-crash-repro
title: C/C++ libFuzzer 实战：LLVMFuzzerTestOneInput harness、Sanitizer 编译、语料字典与 crash 复现最小化
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: libfuzzer-cpp-coverage-guided-harness
aliases:
- libFuzzer 入门
- LLVMFuzzerTestOneInput
- -fsanitize=fuzzer
- libFuzzer crash 复现
- libFuzzer 字典
- 覆盖率引导模糊测试
tags:
- fuzzing
- libfuzzer
- clang
- sanitizer
- addresssanitizer
- ubsan
- coverage
- corpus
- crash
- cpp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:52:13+08:00'
  notes: 已对照原文与 img/01、02 核对：crash 文件 FUZ#、ASan heap-buffer-overflow、harness 与复现命令一致；保留。
---

## 一句话结论

对 C/C++ 目标实现 `LLVMFuzzerTestOneInput(const uint8_t*, size_t)` harness，用 Clang 的 `-fsanitize=fuzzer,address,undefined` 编译，libFuzzer 就会以覆盖率反馈持续变异输入、把新覆盖样本加入语料库；配合种子语料、字典、crash 文件复现与 `-minimize_crash`，可以把内存错误稳定转成可复现的最小测试用例。

## 原理

- libFuzzer 是“库链接式”的进程内 fuzzer：LLVM 的 SanitizerCoverage 在编译期插桩，记录基本块/边覆盖；每次执行后按覆盖增量决定是否保留输入，并对高价值语料做插入、删除、替换、拼接等变异。
- 用户只需实现 `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`；libFuzzer 反复调用它并传入变异后的数据。返回值必须为 0，非 0 会被当作崩溃。
- harness 应满足：确定性（同输入同行为）、无副作用（不写文件、不发网络请求、不改全局状态）、快速执行（单次尽量在 1 秒内）。
- AddressSanitizer/UBSan 把栈/堆越界、UAF、整数溢出等原本可能静默的内存错误转成可捕获的崩溃；`-fno-omit-frame-pointer -g -O1` 保留可读的调用栈与调试信息。
- crash 输入会保存为 `crash-<sha1>` 文件（可用 `-artifact_prefix` 指定目录），可单独喂回 fuzzer 复现；`-minimize_crash=1` 用 delta debugging 找出仍能触发崩溃的最小输入。
- 运行日志中的 `cov`（覆盖的基本块）、`ft`（features）、`corp`（语料数量/体积）、`exec/s`、`rss` 用于判断覆盖率是否停滞、语料是否有效、性能是否受 sanitizer 影响。

## 触发条件

- 目标是 C/C++ 库、解析器、协议实现或格式处理代码，存在可直接调用的入口函数；
- 能构造少量基本合法的种子输入（空输入、边界值、特殊字符、真实样本）；
- 本地有支持 `-fsanitize=fuzzer` 的 Clang/LLVM 工具链与足够 CPU/时间；
- harness 不依赖网络、文件系统或不可控全局状态；若目标有副作用，需要 mock 或隔离。

## 利用步骤

1. 安装 Clang/LLVM 并验证 fuzzer 支持：
   ```bash
   echo 'int main(){return 0;}' | clang++ -fsanitize=fuzzer -x c++ -
   ```
2. 编写目标函数与 harness，限制输入大小并复制为以 NUL 结尾的缓冲区，调用目标函数。
3. 编译：
   ```bash
   clang++ -fsanitize=fuzzer,address,undefined \
           -fno-omit-frame-pointer -g -O1 target.cpp harness.cpp -o fuzzer
   ```
4. 准备语料与字典：语料放合法/边界样本；字典放协议关键字、魔数、常见字段值。
5. 运行并调参：
   ```bash
   ./fuzzer corpus/ -dict=target.dict -max_total_time=600 -max_len=1024 \
            -artifact_prefix=crashes/ -print_final_stats=1
   ```
6. crash 复现与符号化：
   ```bash
   ./fuzzer crashes/crash-<sha1>
   ASAN_OPTIONS=symbolize=1 ./fuzzer crashes/crash-<sha1>
   ```
7. 最小化 crash 输入：
   ```bash
   ./fuzzer -minimize_crash=1 -exact_artifact_path=min.crash crashes/crash-<sha1>
   ```
8. 修复后用同一语料/字典回归，确认原 crash 不再出现且覆盖率未下降；把固定运行时间/次数的 fuzz 加入 CI，并归档 crash 文件。

## PoC

```cpp
#include <cstdint>
#include <cstring>
#include <cstdlib>

// 故意包含栈溢出的目标函数
bool ProcessInput(const char* input, size_t len) {
    char buffer[32];
    if (len >= 4 && memcmp(input, "FUZZ", 4) == 0) {
        strcpy(buffer, input);           // 输入超过 32 字节即溢出
        return true;
    }
    if (len > 10 && input[len - 1] == '!') {
        memcpy(buffer, input, len);      // len 可能大于 32
        return true;
    }
    return false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 1000) return 0;
    char* s = static_cast<char*>(malloc(size + 1));
    memcpy(s, data, size);
    s[size] = '\0';
    ProcessInput(s, size);
    free(s);
    return 0;
}
```

```bash
clang++ -fsanitize=fuzzer,address -g -O1 poC.cpp -o demo_fuzzer
mkdir corpus && echo "FUZZ" > corpus/seed
./demo_fuzzer corpus/
# AddressSanitizer 报 stack-buffer-overflow 后：
./demo_fuzzer crash-<sha1>
./demo_fuzzer -minimize_crash=1 -exact_artifact_path=min.crash crash-<sha1>
```

## 变体与关联

- 结构化 fuzzing：用 libprotobuf-mutator 生成符合协议结构的输入，提高深层路径命中率；也可用自定义 `LLVMFuzzerCustomMutator`。
- 其它引擎：AFL/AFL++（进程级/持久模式）、honggfuzz（硬件分支反馈）、OSS-Fuzz（托管式持续 fuzzing）；C/C++ 下常与 libFuzzer 互补。
- 语料优化：`-merge=1` 合并去重语料、`-reduce_inputs=1` 精简输入、按覆盖率挑选种子。
- 关联：[[code-analysis-dynamic-fuzzing-rust-cargo-fuzz-afl-honggfuzz]]（Rust 侧 cargo-fuzz 对 libFuzzer 的封装）、[[code-analysis-dynamic-fuzzing-go-native-fuzz-cve-repro]]（Go 原生 fuzz 复现 CVE）、[[code-analysis-dynamic-fuzzing-syzkaller-custom-proc-driver-syzlang]]（内核 syzkaller）。
- 边界：harness 非确定性、有副作用或过慢会显著降低效果；fuzzing 主要发现崩溃类内存问题，难以覆盖逻辑漏洞与设计缺陷。

## 检测与防御

- 开发侧：把 fuzzing 作为日常测试与 CI 环节，固定运行时间/次数并归档 crash artifacts；修复后用原 crash 做回归。
- 安全编码：对长度做边界检查，优先使用 `snprintf`/`strncpy`/`strncat` 等有界函数；对解析器的转义、Unicode、整数运算做专项测试。
- 检测侧：主机上出现长时间高 CPU 的 fuzzer 进程、`corpus/` 目录与 `crash-*` 文件属于测试行为特征；生产容器中若出现类似进程需排查是否为异常工具投放。
- 注意：libFuzzer 本身是安全测试工具，不是攻击 payload；本卡只描述测试流程与 crash 闭环。
