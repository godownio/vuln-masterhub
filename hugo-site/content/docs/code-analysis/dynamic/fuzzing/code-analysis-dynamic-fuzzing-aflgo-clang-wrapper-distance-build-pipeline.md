---
id: code-analysis-dynamic-fuzzing-aflgo-clang-wrapper-distance-build-pipeline
title: AFLGo 定向模糊测试的编译包装与距离生成链：aflgo-clang(-mllvm/-Xclang -load) + gold/LTO .bc + opt -dot-callgraph + distance.py
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: aflgo-clang-wrapper-distance-build-pipeline
tags:
- fuzzing
- aflgo
- afl
- llvm
- lto
- gold-plugin
- callgraph
- distance
- instrumentation
- build-pipeline
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T21:23:39+08:00'
  notes: 已对照原文核对：aflgo-clang 的 -mllvm/-Xclang -load、find_obj/edit_params、maybe_linking、gold+LTO .bc、gen_distance_orig.sh(opt -dot-callgraph/merge_callgraphs.py/distance.py) 与 content.md 一致，原理/触发条件/PoC/命令齐全，路径合法，dedup 非同链、dup-scan 无 pair；未验证点：未在本机编译运行 AFLGo（PoC 为源码语义整理），该批次卡按 KB 现状均不含 sources/source_url 溯源字段（与同目录已 verified 卡一致）。
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-aflgo-clang-wrapper-distance-build-pipeline/
draft: false
kb_aliases:
- AFLGo 编译流程
- aflgo-clang 包装器
- gen_distance_orig.sh
- 距离文件生成
- gold 插件 LTO 保存 bc
- opt -dot-callgraph
- merge_callgraphs.py
---

## 一句话结论

用 AFLGo 给第三方 C/C++ 项目做定向模糊测试时，编译期先用 gold 插件 + LTO 把每个模块保存成 `.bc`，再由外围脚本 `opt -dot-callgraph` 生成调用图、`merge_callgraphs.py` 合并、`distance.py` 在 CG/CFG 上算出每个基本块到目标的距离文件；`aflgo-clang` 包装器负责把 `-targets/-distance/-outdir` 经 `-mllvm` 送进 `aflgo-pass.so` 并注入运行时库与持久化/延迟 forkserver 宏，二者配合才把「目标距离」编译进目标二进制。

## 原理

- `aflgo-clang` 是 drop-in 编译器包装：`find_obj` 定位 `aflgo-pass.so`/`aflgo-runtime.o`，`edit_params` 组装真正的 clang 命令，核心是 `-Xclang -load -Xclang <path>/aflgo-pass.so` 加载自定义 LLVM Pass，并用 `-Qunused-arguments` 避免因 pass 参数「未被使用」而报错。
- 自定义选项 `-distance/-targets/-outdir` 不是 clang 标准选项，必须在前面补 `-mllvm` 才能原样透传给 LLVM 后端 pass；pass 据此区分「预处理记录 BB/函数/调用」与「读距离文件插桩」两种互斥模式。bit_mode（-m32/-m64）决定链接 `aflgo-runtime(-32/-64).o`，`-c/-S/-E/-shared` 等会把 maybe_linking 置 0 从而不链运行时。
- 距离文件不在 pass 内计算，而在外围脚本 `gen_distance_orig.sh`：目标项目须用 `-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps` 编译，让 gold 插件把各模块 LLVM bitcode 落成 `<bin>.0.0.*.bc`；脚本对每个 .bc 调 `opt -dot-callgraph` 生成 `.callgraph.dot`，`awk '!a[$0]++'` 去重后用基于 networkx 的 `merge_callgraphs.py -o callgraph.dot` 把多模块 CG 合成一张图。
- 随后 `distance.py` 先在 CG 上算函数级到目标函数距离（`-d callgraph.dot -t Ftargets.txt -n Fnames.txt -o distance.callgraph.txt`），再对每个 CFG dot 结合该 CG 距离与 BBtargets/BBnames/BBcalls 算基本块级距离（`-s BBcalls.txt -c distance.callgraph.txt`），合并为 `distance.cfg.txt`。函数名未出现在 CG 中的 CFG 会被跳过（不可达），避免对不相关函数浪费计算；脚本还清理 CFG dot 的重复行、转义引号与异常标签以修复 Pydotplus 的格式 bug。
- 为什么成立：LLVM Pass 只能看到单个模块的 IR，无法自行得到「跨模块调用图 + 到目标行的距离」；把距离计算外置到脚本、结果通过文件回灌给 pass，是 LTO 分模块编译下取得全程序视图的必要做法；`-g` 保留的调试行号则是把源码目标行映射到基本块的桥梁。

## 触发条件

- C/C++ 项目可用 clang + LLVM gold 插件 + LTO 编译，且能产出 `.0.0.*.bc` 形态的 bitcode。
- 有明确的目标源文件行号（Ftargets/BBtargets），且目标函数在全程序调用图中可达。
- 编译保留调试信息 `-g`；`TMP_DIR`/`-outdir` 可写，用于存放 BBnames、BBcalls、dot-files 与距离文件。
- 系统具备 python3、LLVM `opt`，以及 merge_callgraphs.py/distance.py 依赖的 networkx、pydotplus。

## 利用步骤

1. 设置编译环境：`CC/CXX=$AFLGO/instrument/aflgo-clang(++)`，`ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"`，给 configure 传 `-g -Wno-error $ADDITIONAL`（`-Wno-error` 防止 warning 升级为 error，`-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer` 为可选的内存保护项）。
2. 第一次编译：aflgo-clang 注入 pass 与 runtime，gold 插件保存各模块 `.bc`；pass 在预处理模式输出 BBnames/BBcalls/Fnames/Ftargets 与 `dot-files/cfg.*.dot`。
3. 运行 `gen_distance_orig.sh <binaries-dir> <tmp-dir>`：对每个 .bc 调 `opt -dot-callgraph` 生成 CG dot，去重后 `merge_callgraphs.py -o callgraph.dot` 合并；清理 CFG dot 后调 `distance.py` 算 CG 距离与每个 CFG 的 BB 距离，最后 `cat *.distances.txt > distance.cfg.txt`。脚本用 `TMPDIR/state` 记录 STEP 支持断点续跑，某步失败会 `tail -n30 stepN.log` 并提示重跑命令。
4. 第二次编译：把 `-targets` 换成 `-distance=$TMP_DIR/distance.cfg.txt`，pass 读取距离文件把「到目标距离」累加逻辑插进基本块。
5. 用 AFLGo 的 afl-fuzz 运行，fuzzer 依据平均距离做模拟退火调度（距离公式与 shm 累加见关联卡）。

## PoC

编译包装注入的关键参数（aflgo-clang 组装）：

```
-Xclang -load -Xclang /path/aflgo-pass.so -Qunused-arguments
-mllvm -targets <BBtargets.txt> -mllvm -outdir <TMP_DIR>   # 预处理模式
-mllvm -distance <distance.cfg.txt> -mllvm -outdir <TMP_DIR> # 距离插桩模式
```

距离生成脚本核心命令骨架：

```
opt -dot-callgraph <bin>.0.0.*.bc -callgraph-dot-filename-prefix <prefix>
awk '!a[$0]++' <bin>.callgraph.dot > callgraph.<bin>.dot
merge_callgraphs.py -o callgraph.dot $(ls callgraph.*)
distance.py -d callgraph.dot -t Ftargets.txt -n Fnames.txt -o distance.callgraph.txt
distance.py -d cfg.<func>.dot -t BBtargets.txt -n BBnames.txt -s BBcalls.txt \
            -c distance.callgraph.txt -o cfg.<func>.dot.distances.txt
cat *.distances.txt > distance.cfg.txt
```

（编译选项与脚本片段按源码逻辑最小化整理，未在本机编译运行 AFLGo。）

## 变体与关联

- 变体：给脚本传第三个参数 `fuzzer-name` 时，只针对该 fuzzer 的 .bc 生成单张 CG，不合并多模块 CG。
- 变体：AFLGO_TRACING 模式下，runtime 用 `llvm_profiling_call`/`writeBB` 把执行过的基本块名以 `[BB]: <name>` 写入 `AFLGO_PROFILER_FILE`，用 hashset 与 `edgeStr` 路径哈希（hash32）去重，可导出动态 BB 轨迹辅助距离验证。
- 关联：[[code-analysis-dynamic-fuzzing-aflgo-directed-distance-instrumentation]] 讲 pass 内部与 distance.py 的 Dijkstra/调和平均公式、shm[MAP_SIZE] 累加；本卡补的是「距离文件如何被算出来、参数如何送进 pass」的编译期工程链，二者是同一工具的前后段，不重复。
- 局限：依赖 gold+LTO 特定的 `.0.0.*.bc` 命名，现代构建系统不一定产出该形态；`-targets`/`-distance` 互斥，同时给出会导致 pass 模式冲突；脚本靠 RESUME/STEP 状态文件续跑，TMPDIR 残留状态可能跳过步骤。

## 检测与防御

- 这是本地构建/漏洞挖掘工具链，不产生网络攻击流量，防守方无法从流量侧检测。
- 使用方：确认 `-g` 未丢失（strip 后调试行号缺失会让目标映射失败）；确认目标函数出现在 callgraph.dot，否则 distance.py 跳过该函数、退化为普通覆盖率 fuzz；校验 distance.cfg.txt 非空再进入第二次编译；核对 BBnames 命名与 BBtargets 行号格式一致。
- 防御方：发布二进制移除调试信息会削弱此类定向 fuzz 的目标定位能力；提高输入解析健壮性、启用 sanitizer 与代码审计仍是根本。
