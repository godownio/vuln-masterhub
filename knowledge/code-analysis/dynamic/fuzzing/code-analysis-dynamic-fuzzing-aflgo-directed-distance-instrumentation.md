---
id: code-analysis-dynamic-fuzzing-aflgo-directed-distance-instrumentation
title: AFLGo 定向模糊测试距离插桩：targets/BBnames 预处理 + CG/CFG Dijkstra 距离 + shm[MAP_SIZE] 累加
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: aflgo-directed-fuzzing-distance-instrumentation
aliases:
- AFLGo
- 定向模糊测试
- directed fuzzing
- 距离插桩
- distance.py
- shm[MAP_SIZE]
- BBnames.txt
- 模拟退火能量分配
- CG/CFG 距离
tags:
- fuzzing
- aflgo
- afl
- llvm
- instrumentation
- directed-fuzzing
- distance
- call-graph
- coverage
- vulnerability-discovery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:41:36+08:00'
  notes: 已对照原文核对：pass 参数互斥、getDebugLoc/BB 命名、BBnames/BBcalls/Fnames/Ftargets/dot-files、CG/CFG networkx Dijkstra 距离公式与 i/d 输出、shm[MAP_SIZE]/[MAP_SIZE+8] 累加均一致；修正了卡片两处“输出 10*distance”的表述（一般路径输出 distance=i/d，仅已在 bb_distance 的 BB 输出 10*bb_distance）；未在本机编译运行 AFLGo。
---

## 一句话结论

AFLGo 在 AFL 的边覆盖率插桩之外，用 LLVM Pass 给每个基本块记录“到目标代码行号的距离”：预处理阶段把每个基本块按 `文件名:行号` 命名，输出 `BBnames.txt`、`BBcalls.txt`、`Fnames.txt`、`Ftargets.txt` 和每个函数的 CFG dot；`distance.py` 在函数调用图/CFG 上用 Dijkstra 计算距离并写回距离文件；插桩阶段把命中的基本块距离累加到共享内存 `shm[MAP_SIZE]`、把累加次数写到 `shm[MAP_SIZE+8]`（32 位平台为 +4），fuzzer 据此计算每次执行的平均距离，用模拟退火把变异能量导向目标点。

## 原理

- **两个互斥模式**：Pass 的 `-targets <file>` 与 `-distance <file>` 不能同时给出；`-targets` 进入预处理（`is_aflgo_preprocessing`），`-distance` 进入距离插桩（`is_aflgo`），两者都需要 `-outdir`。另有 `AFL_INST_RATIO`（传统插桩率 1–100）、`AFLGO_INST_RATIO`（距离插桩率）、`AFLGO_SELECTIVE`（是否只插桩预处理记录过的 BB）。
- **预处理阶段**：遍历模块内所有函数（跳过 blacklist 和 `/usr/` 系统库路径），对每条 IR 指令调用 `getDebugLoc` 取 `DILocation` 的 `filename`/`line`；遇到内联丢失 filename 时回退到 `getInlinedAt`。基本块名取该块第一条有效指令的 `file:line`（去掉路径）；若 `setName` 失败则用 `setValueName` 底层设置。随后：
  - `BBnames.txt`：所有基本块名；
  - `BBcalls.txt`：`bb_name,callee_func`，记录基本块内的函数调用（`dyn_cast<CallInst>` + `getCalledFunction`）；
  - `Fnames.txt`/`Ftargets.txt`：含基本块的函数名/是否命中目标；
  - `dot-files/cfg.<func>.dot`：`WriteGraph` 输出每个函数的 CFG；
  - `AFLGO_TRACING` 定义时还会在每个基本块末尾插入 `llvm_profiling_call(bb_name)`。
- **distance.py 的 CG/CFG 距离**：用 `networkx` 读 dot 图（DiGraph）。若图字符串含 `Call graph` 则是 CG 模式，否则 CFG 模式。
  - CG 模式：对每个函数节点到每个目标函数求 `nx.dijkstra_path_length`，把 `1/(1+shortest)` 累加；目标是让“离目标函数越近”的函数得分越高。
  - CFG 模式：先读 `-c` 给出的 CG 距离文件和 `-s` 给出的 BB→被调函数映射；若某 BB 调用的函数在 CG 距离里，则把该函数距离作为该 BB 的 `bb_distance`（多个调用取最小值）；目标 BB 的 `bb_distance = 0`。对每个 BB 到每个目标 BB 求 CFG 内 Dijkstra 距离，累加 `1/(1+10*bb_d+shortest)`——`10*bb_d` 是跨函数调用路径的惩罚项；同一目标 BB 多个实例取平均，最后取所有目标中的最小距离。
  - 输出：一般路径写 `bb_name,distance`（`distance = i/d`，即各目标得分 `1/(1+10*bb_d+shortest)` 的调和平均）；若 BB 已在 `bb_distance` 中（目标 BB 或调用了 CG 可达函数的 BB）则写 `bb_name,10*bb_distance[name]`。距离插桩 pass 读回时再乘 100 并转 int，形成按百分比的整数距离。
- **传统 AFL 边覆盖率插桩**：在每个基本块的 `getFirstInsertionPt()` 插入 `cur_loc = AFL_R(MAP_SIZE)`；`prev_loc = load __afl_prev_loc`；`map[prev_loc ^ cur_loc]++`；`__afl_prev_loc = cur_loc >> 1`。所有插桩 IR 带 `nosanitize` 元数据，避免 sanitizer 误报。
- **AFLGo 距离累加**：若该 BB 在距离文件中有值（`distance >= 0`），额外：
  - `shm[MAP_SIZE] += distance`（x86_64 用 i64，32 位用 i32）；
  - `shm[MAP_SIZE + 8] += 1`（32 位为 `+4`），作为距离累加次数计数器。
  fuzzer 用 `总距离 / 次数` 得到本次执行的平均距离；平均距离越小说明路径越接近目标，模拟退火据此提高该种子的能量/变异概率。只有预处理记录过的 BB 且随机数 `< dinst_ratio` 时才取距离，`AFLGO_SELECTIVE=1` 时非 BBnames 的块直接跳过。
- **为什么有效**：覆盖率反馈只告诉 fuzzer“走到了新边”，定向模糊需要“离目标更近”的梯度；把 Dijkstra 距离编码进共享内存后，任意一次执行都能得到一个可比较的标量，退火算法就能在“探索新路径”和“靠近目标”之间调度。

## 触发条件

- 目标程序为 C/C++ 等可编译到 LLVM IR 的项目，使用 AFLGo 的 LLVM Pass（`aflgo-pass.so.cc`）和配套 `distance.py`；编译时保留调试信息（`-g`），否则 `getDebugLoc` 取不到 `file:line`。
- 明确给出目标位置文件（每行 `源文件:行号`，如 `parser.c:123`），且目标行在 CFG 中可达；目标不能只落在 `/usr/` 系统库或被 blacklist 的函数里。
- 能接受两阶段编译：预处理（`-targets`）→ `distance.py` → 距离插桩（`-distance`）；`-outdir` 可写。
- 使用 AFLGo 的 `afl-fuzz` 版本（需要读取 `shm[MAP_SIZE]` 的距离字段）；普通 AFL/AFL++ 不会使用该字段，距离插桩不会生效。

## 利用步骤

1. **写 targets 文件**：每行一个 `源文件:行号`（如 `vuln.c:42`），对应想要定向到达的代码位置。
2. **预处理编译**：用 AFLGo 的编译器/Pass 带 `-targets <targets.txt> -outdir <out>` 编译目标，生成 `BBnames.txt`、`BBcalls.txt`、`Fnames.txt`、`Ftargets.txt`、`dot-files/*.dot`。
3. **计算距离**：
   - CG：`python distance.py -d <callgraph.dot> -t targets.txt -o cg_distance.txt -n Fnames.txt`；
   - CFG：`python distance.py -d <cfg.func.dot> -t targets.txt -o bb_distance.txt -n BBnames.txt -c cg_distance.txt -s BBcalls.txt`。
   多函数时对每个 CFG 分别跑，或合并 dot；一般路径输出 `bb_name,distance`（`i/d` 调和平均），已在 `bb_distance` 中的 BB 输出 `bb_name,10*bb_distance[name]`。
4. **距离插桩编译**：用 `-distance <bb_distance.txt> -outdir <out>` 重新编译目标，插桩传统边覆盖率 + `shm[MAP_SIZE]` 距离/计数。
5. **运行 AFLGo fuzzer**：用 AFLGo 的 `afl-fuzz` 跑目标；fuzzer 读取平均距离做模拟退火调度，种子能量向目标附近倾斜。
6. **调参**：`AFLGO_INST_RATIO` 控制距离插桩比例（默认 100）、`AFLGO_SELECTIVE=1` 只插桩预处理记录过的块、`AFL_INST_RATIO` 控制传统插桩率；`AFL_QUIET` 控制 banner。
7. **验证**：在目标 BB 下断点/加日志确认 fuzzer 能到达；检查 `shm[MAP_SIZE]`/`shm[MAP_SIZE+8]` 是否随执行变化；如果距离一直是 0/不变，检查 targets 行号、调试信息、`distance.py` 的 CG/CFG 参数与 `BBnames` 命名是否一致。

## PoC

Pass 参数定义（LLVM `cl::opt`）：

```cpp
cl::opt<std::string> DistanceFile("distance", cl::desc("Distance file ..."));
cl::opt<std::string> TargetsFile("targets", cl::desc("Input file containing target lines of code."));
cl::opt<std::string> OutDirectory("outdir", cl::desc("Output directory ..."));
```

预处理阶段的基本块命名与调用记录（核心逻辑）：

```cpp
getDebugLoc(&I, filename, line);              // 取 file:line
if (auto *c = dyn_cast<CallInst>(&I)) {
  if (auto *CalledF = c->getCalledFunction())
    bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
}
BB.setName(bb_name + ":");                     // file:line:
bbnames << BB.getName().str() << "\n";
```

距离插桩的核心 IR 语义（等价 C 伪代码）：

```c
uint8_t *map = __afl_area_ptr;
uint32_t cur = rand() % MAP_SIZE;
map[__afl_prev_loc ^ cur]++;
__afl_prev_loc = cur >> 1;

if (distance >= 0) {                // 该 BB 在 distance 文件中有值
    *(uint64_t *)(map + MAP_SIZE) += distance;      // 64 位平台
    *(uint64_t *)(map + MAP_SIZE + 8) += 1;         // 距离累加次数
}
```

distance.py 的 CFG 距离公式：

```python
d += 1.0 / (1.0 + 10 * bb_d + shortest)   # bb_d 为调用函数到目标的 CG 距离，10 倍为跨函数惩罚
# 最终 distance = i / d（各目标得分的平均倒数），输出 10 * distance
```

原文未给出完整 README 式命令行，以上步骤按文章中的 pass 选项、脚本参数与源码逻辑整理，未在本机编译运行 AFLGo。

## 变体与关联

- **关闭选择性插桩**：默认 `AFLGO_SELECTIVE=0` 时所有基本块都插传统边覆盖率，只有 distance 命中的块累加距离；设为 1 时只插预处理记录的 BB，可减小体积但可能丢失部分覆盖反馈。
- **CG/CFG 混合**：`distance.py` 的 CFG 模式必须同时给 `-c`（CG 距离）和 `-s`（BB→函数调用映射），否则退出；这是“函数间可达性 + 函数内路径”两级距离的关键。
- **目标选择**：targets 行号越靠近 sink（如危险函数调用点）越有效；目标在不可达分支或黑名单函数中会导致 distance 为空、退化为普通 AFL。
- **关联**：`[[code-analysis-dynamic-fuzzing-libfuzzer-engineering-corpus-parallel-dict-coverage]]`（覆盖率引导 fuzz 的语料/并行/字典工程化）、`[[code-analysis-dynamic-fuzzing-rust-cargo-fuzz-afl-honggfuzz]]`（AFL/多 fuzzer 使用）、`[[code-analysis-dynamic-fuzzing-go-fuzz-instrumentation-crasher-workflow]]`（插桩与 crasher 流程）；本卡聚焦“定向”所需的距离插桩与距离计算。
- **其他定向 fuzzer**：AFL++ 的 directed mode、Hawkeye、Beacon、ParmeSan 等也使用目标距离/可达性调度，但实现不同；原文只分析 AFLGo，不外推。

## 检测与防御

- **对使用方（漏洞挖掘）**：先用 `distance.py` 的距离分布确认目标可达、距离梯度存在；用 `AFLGO_SELECTIVE`/`AFLGO_INST_RATIO` 控制插桩体积；对目标行设置断点或日志验证 fuzzer 确实到达；距离不变时检查调试信息（`-g`）与 `file:line` 格式。
- **对防守方**：定向模糊测试本身不是攻击流量，无法从网络侧检测；它针对的是本地/可执行目标。防御重点是提高目标代码的健壮性（sanitizer/静态分析/代码审计）、减少可利用的 sink、对解析器/协议入口做输入校验与隔离。
- **代码审计提示**：AFLGo 的 pass 依赖 debug 信息完成 BB 命名，发布构建 strip 调试信息会让定向距离失效；若目标二进制无调试信息，需要其他定向信号（函数名、覆盖率哈希、调用图）替代。
- **局限**：距离基于静态 CG/CFG 的 Dijkstra，间接调用、虚函数、内联与异常边可能不准；模拟退火参数与距离缩放（×10/×100）影响效果；不是所有目标都适合定向 fuzzing。
