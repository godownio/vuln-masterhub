---
id: code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore
title: 银狐强混淆 VM 调用还原：IDAPython 识别 call r11 模式并常量折叠 patch
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: silverfox-vm-call-idapython-constant-folding
aliases:
- 银狐 VM 混淆
- call r11 常量折叠
- IDAPython 去混淆
- 虚表分发混淆
- 常量函数 patch
- .fish 段壳
- VM 函数调用还原
tags:
- malware-analysis
- silverfox
- obfuscation
- idapython
- ida
- vm
- deobfuscation
- windows
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V96
  verified_at: '2026-11-05T19:59:37+08:00'
  notes: 已对照原文与16张图片核对；.fish段、全局字符串XOR、虚表分发、hash反断点sub_7FF70F8C4DA0、常量函数、call r11扫描、158模式/145调用/45 patch/99 skip、PoolParty与SetIoCompletion均有正文或截图支撑；脚本未在本机复跑。
---

## 一句话结论

银狐强混淆样本外层是 `.fish` 段壳，脱壳后把功能函数放进虚表、用大量无参常量函数和 `off_xxx((int)&dword_xxx, len, key, a4, a5)` 形式的 VM 函数把常量运算层层嵌套；用 IDAPython 扫描 `lea rcx, dword_xxx; mov r11, cs:off_xxx; ...; call r11` 模式，结合 Hex-Rays 伪代码解析参数、对参数已确定的调用做常量折叠并以 `mov eax, imm`/等价短指令 patch 掉 `call r11`，反复执行即可恢复大部分可读逻辑。

## 原理

- **外层壳**：样本入口在名为 `.fish` 的段中，IDA 对入口的自动分析会失败（`sp-analysis failed`）；需要先脱壳/在 OEP dump，再加载到 IDA。壳本身不是本文重点，但不去掉会让后续函数不可达。
- **字符串层**：脱壳后先对全局字符串做单字节 XOR 解密；随后出现一张 API 名称/函数指针表，例如 `off_7FF70F91D580(&a_ntdll_dll, 10LL, 33LL, v4)`、`off_7FF70F91D9F0(&aNtOpenProcess, 14LL, 4294967199LL, v4)`，以及 `a_kernel32_dll`、`a_Sleep`、`a_VirtualQueryEx`、`a_ReadProcessMemory`、`a_DuplicateHandle`、`a_SetIoCompletion` 等名称；这些是后续行为分析的关键线索。
- **虚表分发**：功能函数以类方法方式调用，`off_7FF70F92EB80` 处是一张函数指针表；还原后代码形如 `a1->field_0->Privilege_7FF70F87522C(...)`、`a1->field_0->VirtualQueryEx_WriteShell(...)`、`a1->field_0->SetIoCompletion_7FF70F87C66E(...)`。先恢复虚表项与实际函数的对应关系，才能看懂调用语义。
- **反 IDA 代码**：函数中混入重叠/无效指令（如 `xor rax, rax; jz ...; db 0`、`rep retn`、跳进指令中间的花指令），使 IDA 反编译出现 `JUMPOUT`、`sp-analysis failed` 或错误指令边界；处理办法是对可疑区域 `undefine` 后 `make code`，把明显的数据/花指令剔除，恢复真实指令流。
- **反软件断点**：代码中大量 `sub_7FF70F8C4DA0(&off_xxx)` 调用，函数体对目标做 hash 运算后比较结果，属于针对软件断点（INT3 会改写代码字节）的检测；直接 patch 掉/NOP 掉不影响静态分析（运行时要避免触发其反调试分支）。
- **常量函数**：`sub_7FF70F87EFE9() { return 7LL; }` 这类无参数函数只返回一个常量；调用点形如 `v93 = off_7FF70F8E87D0();`。把这些 `call` 替换成 `mov eax, imm` 后，后续 VM 调用的参数才可能变成常量。
- **VM 函数**：形如 `off_7FF70F8E8808((int)&dword_7FF70F9285D0, 7, -97, 9, 7LL)`；被调用函数按传入的 opcode/参数在一个 `switch` 中选择运算，操作对象是栈上的数组，支持 `+=`、`-=`、`*`、`/=`、`^`、`&` 等（原文截图为 case 0x10–0x15）。各个算式相互嵌套，外层结果又作为内层参数。
- **汇编特征**：调用点先 `lea rcx, dword_xxx` 取数据地址，再 `mov r11, cs:off_xxx` 取 VM 函数指针，压栈保存 volatile 寄存器、`sub rsp, 20h`、若干 `nop`，最后 `call r11`；IDA 可能把 `dword_xxx` 识别成 qword/byte/word/dword，统一强制为 dword 才能稳定匹配。
- **常量折叠可行性**：VM 函数是纯函数，只依赖参数和固定数据；当一次调用的 5 个参数都能确定为常量时，就可以离线算出返回值，把 `call r11` 改成返回该常量的指令。一次 patch 会让更外层的调用参数变成常量，因此需要反复扫描、解析、patch，直到不再变化。
- **最终可读性**：原文脚本在目标函数中找到 158 个 VM 调用模式、145 个可解析的 VM 调用，首轮 patch 45 个、因参数非确定跳过 99 个；多次运行后代码虽未完全清理，但已能人工/AI 分析虚表调用与样本行为。

## 触发条件

- 目标为 Windows PE 恶意样本（银狐名单类），外层为自定义壳/`.fish` 段，IDA 自动分析在入口失败；需要先脱壳到 OEP。
- 使用 IDA + Hex-Rays（脚本依赖反编译伪代码文本）；IDA 版本不同会导致伪代码语法、变量命名和类型推断差异，需要调整正则/解析。
- VM 调用的参数中至少有一部分是常量；如果全部依赖运行时变量，静态常量折叠无法完成，需要改用动态调试或符号执行。
- 脚本需要能定位 `lea rcx, dword_xxx`/`mov r11, cs:off_xxx`/`call r11` 三段模式；样本若改变寄存器分配、调用约定或内联 VM，需要改匹配规则。
- 输入样本不可信：脱壳、调试、运行都应在隔离虚拟机中进行，禁止在分析主机直接执行样本。

## 利用步骤

1. 在隔离环境确认壳类型与入口段（`.fish`），在调试器中运行到 OEP 并 dump 内存镜像；修复 IAT/节表后加载到 IDA，确认关键函数可达。
2. 处理入口/花指令：对 `sp-analysis failed` 的区域按实际指令边界 `undefine` 再 `make code`；删除明显的重叠/无效字节，恢复函数。
3. 定位全局字符串单字节 XOR 解密循环，在解密完成后 dump 字符串，或直接根据 XOR key 静态还原；整理 API 名称表（`a_kernel32_dll`、`a_Sleep`、`aNtOpenProcess`、`a_SeDebugPrivilege` 等）。
4. 找到 hash 校验函数（原文为 `sub_7FF70F8C4DA0`）及其调用点，patch/NOP 掉，避免其反软件断点逻辑干扰调试与后续 patch。
5. 找到无参常量函数（返回 0/7/指针等），用 IDAPython 把调用点替换成 `mov eax, imm`（返回值是指针时用 `lea rax, [addr]`）；重新反编译，让常量传播。
6. 用 `scan_vm_patterns` 扫描目标函数，收集 `(lea_ea, data_ea, mov_r11_ea, call_ea)`；必要时把 `dword_xxx` 强制为 dword 类型，便于按名称/地址匹配。
7. 反编译目标函数，解析形如 `off_xxx((int)&dword_xxx, len, key, a4, a5)` 的调用；对 5 个参数均为常量的调用，按 VM 的 switch 语义计算返回值。
8. 将 `call r11` patch 成返回常量的指令（原文用 `mov eax, imm`；空间不足时可用 `push imm8; pop eax` 等等价短指令），记录 PATCH/SKIP；重新反编译并重复步骤 6–8，直到不再产生新的常量调用。
9. 对仍无法折叠的调用（参数为变量）保留，转人工分析/动态调试；结合虚表调用还原样本行为：获取 `SeDebugPrivilege`、查询目标进程内存、写入 shellcode 与跳板、失败时退回 `NtAllocate/Write` 注入，成功时用线程池（PoolParty，`SetIoCompletion`）启动 shellcode，之后下载后续载荷并在 `C:\Program Files (x86)\Internet Explorer` 释放白加黑文件。

## PoC

```python
# IDAPython 简化版：扫描 lea rcx, dword_xxx -> mov r11, cs:off_xxx -> call r11
import ida_funcs, idc

def scan_vm_patterns(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return []
    out = []
    ea = f.start_ea
    while ea < f.end_ea:
        if (idc.print_insn_mnem(ea) == 'lea'
                and 'rcx' in idc.print_operand(ea, 0)
                and 'dword_' in idc.print_operand(ea, 1)):
            data_ea = idc.get_operand_value(ea, 1)
            s = ea + idc.get_item_size(ea)
            mov_ea = None
            while s < f.end_ea:
                m = idc.print_insn_mnem(s)
                o0 = idc.print_operand(s, 0)
                o1 = idc.print_operand(s, 1)
                if m == 'lea' and 'rcx' in o0:
                    break
                if m == 'mov' and 'r11' in o0 and 'off_' in o1.lower():
                    mov_ea = s
                    break
                if m == 'call' and 'r11' in o0:
                    break
                s += idc.get_item_size(s)
            if mov_ea is not None:
                s = mov_ea + idc.get_item_size(mov_ea)
                while s < f.end_ea:
                    m = idc.print_insn_mnem(s)
                    o0 = idc.print_operand(s, 0)
                    if m == 'call' and 'r11' in o0:
                        out.append((ea, data_ea, mov_ea, s))
                        break
                    if (m == 'mov' and 'r11' in o0) or (m == 'lea' and 'rcx' in o0):
                        break
                    s += idc.get_item_size(s)
        ea += idc.get_item_size(ea)
    return out

# 使用：对目标函数地址调用，先打印模式，再按伪代码解析参数并计算常量
for lea_ea, data_ea, mov_ea, call_ea in scan_vm_patterns(0x7FF70F855A3C):
    print("data=0x%x lea=0x%x mov_r11=0x%x call=0x%x" %
          (data_ea, lea_ea, mov_ea, call_ea))
```

```python
# patch 示意：把参数已确定的 call r11 改成返回常量（需先解析参数并算出 value）
# value 在 0..255 时可使用 3 字节 push imm8; pop eax；其余情况按原文脚本用 5 字节 mov eax, imm32
def patch_const(call_ea, value):
    import ida_bytes
    if 0 <= value <= 0xFF:
        ida_bytes.patch_bytes(call_ea, bytes([0x6A, value, 0x58]))
    else:
        ida_bytes.patch_bytes(call_ea, b'\xB8' + (value & 0xFFFFFFFF).to_bytes(4, 'little'))
```

原文首轮输出示例：158 个汇编模式、145 个 VM 调用；`[PATCH] 0x7ff70f859a0b: call r11 -> mov eax, 16`、`[PATCH] 0x7ff70f859ac0: call r11 -> mov eax, 0`，以及多条 `[SKIP] ... 参数非确定值 (a4=v5)`；总计 patch 45 个，跳过 99 个参数非确定值。多次运行后代码可读性明显提升。

## 变体与关联

- **变体：VM 调用内联/寄存器分配变化**：若 `lea rcx` 被换成 `mov rcx, imm` 或使用其他寄存器，需要扩展模式匹配；可先定位 `call r11`，再回溯最近的 `mov r11, off_xxx` 与数据引用。
- **变体：常量函数返回字符串/指针**：把 `call` patch 成 `lea rax, [addr]` 或写入字符串地址，而不是 `mov eax, imm`。
- **变体：参数依赖变量**：改用 Unicorn 模拟执行 VM 函数、angr/Triton 符号执行，或在调试器中运行到调用点读取真实参数后动态 patch/dump。
- **变体：花指令/指令重叠**：结合 [[code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream]] 的识别与修复方法；VMProtect 等商业虚拟化则参考 [[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]，它不是本文这种轻量 VM 函数。
- **关联卡片**：[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（同一样本的字符串/API 轻量混淆）、[[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]（另一种常量数组还原思路）、[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（运行时解密后重建函数）。
- **边界**：脚本强依赖 IDA/Hex-Rays 的伪代码格式和样本的固定模式；脱壳失败、VM 调用参数全部依赖运行时、或样本使用更复杂的字节码解释器时，需要改用动态/符号执行，不能仅靠静态 patch。

## 检测与防御

- **样本识别**：YARA/PE 结构规则匹配 `.fish` 段、周期性 `@` 字符串、`call r11` 密集模式、虚表式函数指针表；对银狐常见诱饵文件名（裁员名单/补偿方案）和压缩包内可执行文件提高警惕。
- **行为检测**：还原后关注 `SeDebugPrivilege`、`VirtualQueryEx`/`ReadProcessMemory`/`WriteProcessMemory`、`DuplicateHandle`、`SetIoCompletion`（PoolParty 线程池执行）、向 `C:\Program Files (x86)\Internet Explorer` 释放文件、进程内网络下载等行为链；这些比单一字符串更稳定。
- **加固**：终端启用 AMSI/ETW、内存扫描与行为阻断；限制普通用户对浏览器安装目录的写入；对 WPS/Office 文档和压缩包执行隔离/沙箱打开；及时更新 AV/EDR 的银狐家族规则。
- **分析安全**：样本、脱壳镜像、字符串均视为不可信数据；在隔离虚拟机中分析，禁止在主机运行或让脚本自动执行样本；patch 前备份 IDA 数据库。
