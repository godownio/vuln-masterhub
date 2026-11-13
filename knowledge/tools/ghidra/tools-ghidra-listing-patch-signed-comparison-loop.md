---
id: tools-ghidra-listing-patch-signed-comparison-loop
title: Ghidra 列表视图定位并指令级修补有符号比较死循环（阶乘 INT_MAX 示例）
type: scenario
domain: tools
path: tools/ghidra
technique: ghidra-listing-patch-signed-comparison-loop
aliases:
- Ghidra 列表视图补丁
- Patch Instruction
- 有符号比较死循环
- JLE 改 JNC
- 阶乘 INT_MAX 死循环
- Ghidra 导出 ELF
- Ghidra 汇编补丁
tags:
- ghidra
- reverse
- patch
- assembly
- listing
- signed-comparison
- elf
- linux
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-13'
updated: '2026-11-13'
---

## 一句话结论

在 Ghidra 列表视图（不使用反编译器）中，通过 `__libc_start_main` 的调用交叉引用定位 main，识别出循环终止条件使用有符号比较 `JLE`、在计数器达到 `INT_MAX` 后回绕为负数导致循环永不退出的缺陷，再用 `Patch Instruction` 交换 `CMP` 操作数并把 `JLE` 改为无符号 `JNC`，即可仅凭两条指令的字节修改修复该 hang，并导出新的 ELF。

## 原理

- **列表视图定位入口**：ELF 导入摘要显示依赖 `libc.so.6`，说明程序经 `__libc_start_main` 启动 main。在列表视图按 `G` 跳到该符号的 thunk，`XREF[2]` 列出两个引用：`(c)` 调用点与 `(*)` 指针引用；进入调用点可见其前一条 `LEA RDI,[FUN_xxx]`，该地址就是 main。
- **重命名降低阅读成本**：Ghidra 已识别栈帧变量 `local_10`、`local_14`；用 `L` 键重命名（如 `input`、`factorial_subtotal`、循环索引 `i`），并将 `FUN_xxx` 重命名为 `factorial`，后续列表可读性显著提高。`printf`/`scanf` 的参数可悬停 thunk 显示（如格式串 `%d`、`The factorial of %d is %lu.\n`）。
- **循环结构**：输入为 0 时直接返回 1；否则 `i=1`、`subtotal=1`，循环体先把 `i` 符号扩展（`CDQE`）后与 64 位 `subtotal` 相乘（`IMUL`），`i++` 后回到比较块：`MOV EAX,i` → `CMP EAX,input` → `JLE` 回循环体。即"`i <= input` 时继续"。
- **缺陷根因**：`JLE` 是**有符号**比较，而 `i` 是会溢出的 32 位有符号计数器。当输入恰为 `INT_MAX`（2147483647）时，`i` 在最后一轮加一后回绕为 `0x80000000`（负数），有符号解释下仍"小于等于"输入，比较永远成立，循环永不退出。main 里的负数检查只校验用户输入，不覆盖循环计数器溢出。
- **修复方式**：把比较改为无符号语义——`CMP EAX,[input]` 交换操作数为 `CMP [input],EAX`（减法方向反转，保持 3 字节编码 `3b 45 ec` → `39 45 ec`），再把 `JLE`（`7e`）改为 `JNC`（`73`，无进位则跳转）。无符号比较下，`i` 回绕后 `input < i` 产生借位（CF=1），`JNC` 不再跳回循环，函数得以返回。
- **为什么必须交换操作数**：`JNC` 判断的是"`[input] - i` 无借位"，即 `input >= i` 时继续；若只把 `JLE` 换成 `JNC` 而不交换 `CMP` 操作数，减法方向是 `i - input`，语义变成 `i >= input` 时继续，条件反向，会立即退出循环。
- **修复边界**：该补丁只解决"不终止"，不解决"结果正确"——64 位累乘仍会溢出，示例中 `INT_MAX` 的阶乘打印为 1。补丁前要明确目标是修 hang 还是修语义；完整修复还需加入乘法溢出检查或改用更大宽度/任意精度。

## 触发条件

- 拿到可被 Ghidra 加载的 ELF（或其他架构目标），能通过导入表/符号定位 `__libc_start_main` 与 main；完全 strip 时可改从入口点手工跟到 main。
- 循环上界来自用户输入且使用有符号 32 位比较，输入可取到 `INT_MAX` 附近触发计数器回绕。
- 目标文件可写、可导出，且无签名/完整性校验阻止修改后的二进制运行。
- 修复者能识别比较指令的有符号/无符号差别（`JLE/JG` vs `JBE/JA`、`JNC`）。

## 利用步骤

1. Ghidra 导入目标，查看 Import Results 摘要确认依赖库；在列表视图按 `G` 输入 `__libc_start_main` 跳转。
2. 在 thunk 处查看 `XREF[2]`，点击 `(c)` 调用引用；其前一条 `LEA RDI,[FUN_xxx]` 即 main 地址，跳转过去。
3. 用 `L` 键重命名栈变量（`input`、`i`、`factorial_subtotal`）与函数（`factorial`）；用光标高亮变量快速查看所有使用点。
4. 顺调用进入计算函数，定位循环比较块（示例地址 `00101193`）：`MOV EAX,i` → `CMP EAX,[input]` → `JLE LAB_loop`。
5. 右键 `CMP` 指令 → `Patch Instruction`（Ctrl+Shift+G），输入交换操作数后的写法 `CMP dword ptr [RBP + -0x14], EAX`，确认对话框仍为 3 字节编码（`39 45 ec`）。
6. 右键 `JLE` → `Patch Instruction`，改为 `JNC 0x0010117e`（字节 `7e e3` → `73 e3`）。
7. `File → Export Program`，Format 选 ELF，导出为新文件；分别运行原版与补丁版对比：原版输入 2147483647 挂起，补丁版正常返回。

## PoC

原文未给出源码，只提供示例 ELF 与截图。缺陷模式的最小复现（等价 C 代码，非原文样本）：

```c
#include <limits.h>
unsigned long factorial(int n) {
    unsigned long r = 1;
    for (int i = 1; i <= n; i++)   /* n = INT_MAX 时 i 回绕为负，循环不退出 */
        r *= i;
    return r;
}
```

指令级补丁（x86-64，地址与字节来自原文示例）：

| 位置 | 原始 | 补丁后 | 语义 |
|---|---|---|---|
| `00101196` | `3b 45 ec` = `CMP EAX,[RBP-0x14]` | `39 45 ec` = `CMP [RBP-0x14],EAX` | 反转减法方向 |
| `00101199` | `7e e3` = `JLE 0010117e`（有符号） | `73 e3` = `JNC 0010117e`（无符号） | 无借位（input>=i）才继续 |

验证结果：原版输入 2147483647 后不返回（需 Ctrl-C）；补丁版输出 `The factorial of 2147483647 is 1.` 并退出——循环终止成立，结果仍因累乘溢出而不正确。

## 变体与关联

- **有符号/无符号比较错误的通用识别**：`JLE/JGE/JL/JG` 为有符号，`JBE/JAE/JB/JA` 为无符号；循环计数器、长度字段、索引与 `size_t` 混用时常见同类缺陷。修复方向一致：改用无符号比较或增加边界/溢出检查。
- **Ghidra 其他补丁手段**：`Patch Data`/`Patch Bytes` 直接改字节、`Assemble` 重写指令、GhidraScript 批量修改；导出时可选原始格式或仅导出选区。
- **IDA 对应操作**：`Patch program → Assemble/Change byte`，思路相同；本库另有 IDA 双进程 fork 补丁调试卡可组合使用（[[tools-ida-fork-child-loop-patch-attach]]）。
- **与漏洞研究的边界**：本卡是二进制修补/逆向阅读技能；同一模式在真实程序中可能表现为整数溢出导致的循环不终止或边界判断失效，但示例程序仅构成 hang（可用性影响），不构成提权/RCE 链。
- **正确修复**：源码层把循环索引与上界改为 `unsigned`/64 位，或在乘法前检查 `r > ULONG_MAX / i`；仅改比较符属于"止血"，会留下错误结果。

## 检测与防御

- **补丁检测**：对关键二进制做哈希/签名校验（Authenticode、IMA、TPM 度量），或与基线反汇编对比；仅 2 字节的代码段修改即可被字节级完整性检查发现。
- **开发侧**：编译器开启溢出检查（`-ftrapv`、UBSan 的 `signed-integer-overflow`）、静态分析规则拦截有符号循环计数器与不可信上界的组合；对用户输入做范围限制（远小于 `INT_MAX`）。
- **修复流程**：优先从源码重编译并回归测试，而不是直接 patch 生产二进制；补丁后必须验证边界输入（`INT_MAX`、`INT_MAX-1`、负数、0）与结果正确性。
- **逆向侧自检**：Patch Instruction 时注意指令长度必须保持不变（否则后续地址错位），Ghidra 对话框会显示编码字节与长度，导出后应在反汇编器/运行环境中复核。
