---
title: 逆向工程
weight: 1
---

# 逆向工程

## 这层是什么

二进制/应用逆向、脱壳、反调试、混淆与虚拟机保护。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- [脱壳](unpacking/) —— 壳识别、手动/自动脱壳、内存 dump 与重建。
- [反调试](anti-debug/) —— 反调试检测与绕过、反反调试。
- [混淆](obfuscation/) —— 控制流平坦化、字符串加密、指令替换与还原。
- [虚拟机保护](vm/) —— VMProtect/Themida 等 VM 保护的分析与还原。
- [固件逆向](firmware/) —— 固件提取、文件系统、启动链、模拟/仿真与漏洞分析（含 IoT 固件）。
- [Windows 逆向](windows/) —— PE、驱动、系统机制与调试。
- [Linux 逆向](linux/) —— ELF、内核模块、系统调用与调试。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Cython pyd 双层交叉引用定位：对 "<模块>.<函数>" 取 xref 得两处，第二处 __pyx_pf_* 才是实现体](code-analysis-reverse-cython-pyd-wrapper-vs-impl-xref/) | verified | high | 2026-11-07 |
| [Cython pyd 校验函数静态还原链：实现体定位 → PyObject 布局 → 常量槽回溯 → PyNumber 翻译 → 差分验证](code-analysis-reverse-cython-pyd-check-function-recovery-chain/) | verified | high | 2026-11-07 |
| [Cython pyd 的 PyNumber_* 调用序列翻译：按实参顺序还原运算符，识别移位辅助函数、in-place 末参与 32 位收窄](code-analysis-reverse-cython-pyd-py-number-api-translation/) | draft | high | 2026-11-08 |
| [DES/3DES 逆向识别与解密：8 个 S 盒/IP/PC 表与 OpenSSL DES_* API 指纹、key 派生陷阱、ECB/CBC 试解与 3DES EDE 组合](code-analysis-reverse-des-3des-identification-decrypt/) | verified | high | 2026-11-13 |
| [Go 二进制逆向基础：string/slice/map 内存布局、调用约定与 stripped 符号恢复](code-analysis-reverse-go-binary-layout-symbol-recovery/) | verified | high | 2026-11-06 |
| [Go 接口与 SwissMap 反汇编识别：eface/iface/itab、slice interface 与 runtime.mapassign/mapaccess](code-analysis-reverse-go-interface-swissmap-disassembly/) | verified | medium | 2026-11-06 |
| [macOS Movist Pro（Paddle SDK）试用期/授权校验的多面绕过：本地立即数、服务端 duration、activated 分支、弹窗 NOP 与客户端缓存](code-analysis-reverse-macos-movist-paddle-trial-bypass-surfaces/) | verified | high | 2026-11-08 |
| [macOS 应用签名与 Entitlements 审计：codesign 标志位/授权映射到 Dylib 注入、调试附加与内存破坏攻击面](code-analysis-reverse-macos-codesign-entitlements-attack-surface-audit/) | verified | high | 2026-11-13 |
| [PHP 字节码反编译：VLD 导出 OPCode 后交给 LLM 还原源码结构](code-analysis-reverse-php-vld-opcode-llm-decompile/) | verified | medium | 2026-11-09 |
| [pyd 内 CPython 对象布局识别：按 dq 标志/类型/长度/数据 展开，用 PyLong_Type 区分小整数快速路径](code-analysis-reverse-cython-pyd-pyobject-layout-dq/) | draft | high | 2026-11-08 |
| [pyd 常量槽回溯：对 off_XXX[k] 取 xref 回到初始化函数的 PyLong_FromLongLong/FromString 实参](code-analysis-reverse-cython-pyd-constant-slot-xref/) | draft | high | 2026-11-08 |
| [Unity IL2CPP CTF 链：CE 改内存触发内嵌资源释放 + 十六进制 PE 还原与凯撒/XOR 逆推](code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe/) | verified | high | 2026-11-06 |
| [Unity IL2CPP 逆向：GameAssembly/libil2cpp + global-metadata 经 Il2CppDumper 恢复符号并导入 IDA/Ghidra](code-analysis-reverse-unity-il2cpp-dumper-symbol-recovery/) | verified | high | 2026-11-06 |
| [WebAssembly 逆向双路径：wabt/IDA/JEB 静态反编译 + 浏览器 devtools 调 wat 并注入内存辅助函数](code-analysis-reverse-wasm-browser-debug-memory-helpers/) | verified | high | 2026-11-11 |
| [Zig ELF 逆向快速识别与取舍：clang/LLD 构建、符号清晰、comptime 导致 main 膨胀且 SIMD 展开时优先黑盒/动态](code-analysis-reverse-zig-elf-identification-analysis-triage/) | verified | medium | 2026-11-12 |
| [二进制中识别 ChaCha20：魔数常量、状态布局与 32 次 ARX 特征](code-analysis-reverse-chacha20-binary-identification-features/) | verified | high | 2026-11-07 |
| [二进制层面代码复用：把目标函数机器码字节编译成共享库，用 ctypes 跨位数调用](code-analysis-reverse-machine-code-so-reuse-cross-bitness/) | verified | medium | 2026-11-08 |
| [样本通信算法对比识别改版 RC6：key schedule 常量/算子差异 + GDB 提取 rk 重构 Go 解密器](code-analysis-reverse-modified-rc6-key-schedule-gdb-rk-decrypt/) | verified | high | 2026-11-13 |
| [逆向中加密算法与编码识别：从常量/S 盒/轮数/密钥索引特征定位算法并提取密钥解密](code-analysis-reverse-crypto-encoding-identification-decrypt/) | verified | medium | 2026-11-07 |
| [逆向中复用目标程序汇编代码：给纯寄存器算法补函数包装（参数/初始化/返回值），nasm 编译 .o 后 gcc -m32 链接进 C 注册机](code-analysis-reverse-assembly-function-reuse-nasm-object-gcc-link-keygen/) | verified | high | 2026-11-08 |
| [逆向卷积型线性加密：把 des[i+j]+=flag[i]*key[j] 建模为 Toeplitz 方程组用最小二乘还原输入](code-analysis-reverse-convolution-linear-cipher-least-squares/) | draft | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
