---
id: code-analysis-reverse-vm-binary-ninja-custom-isa-architecture-plugin
title: 自定义 ISA/VM 字节码逆向：Binary Ninja 加载器 + 架构插件三回调还原反编译视图
type: scenario
domain: code-analysis
path: code-analysis/reverse/vm
technique: binary-ninja-custom-isa-architecture-plugin
tags:
- reverse-engineering
- binary-ninja
- custom-isa
- vm
- bytecode
- disassembler
- decompiler
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T03:28:18+08:00'
  notes: 已对照原文与图02-08核对：switch(opcode) 分发与 VM 结构（regs[8]/sp/lr/pc/fl/mem/handle_syscall）、UNICORN blob 段表（图03，段0数据+段1栈）、POTLUCKView 加载后段映射 r-x 0-0x14e5 与 .synthetic_builtins（图04）、图形视图与反汇编（图05）、sub_3cc 伪 C/低位 IL 显示 xor 常量校验（图06/07）均一致；三回调（text/info/low_level_il）、自定义 syscall calling convention（ID/R0/R1）、返回 None 而非 0、address_size=4 的坑均为原文要点。PoC 为按原文整理的最小骨架（加载器+架构），未执行。dedup 候选为自定义栈式 VM/VMC2/ARX 逆向题，均为不同解题场景、无 BN 插件卡，非同链；dup-scan.json 早于建卡不涉及本卡；frontmatter 无 sources/source_url；分析工具类无版本。
url: /docs/code-analysis/reverse/vm/code-analysis-reverse-vm-binary-ninja-custom-isa-architecture-plugin/
draft: false
kb_aliases:
- Binary Ninja 架构插件
- 自定义 ISA 反编译器
- BinaryView 加载器
- UNICORN blob 格式
- get_instruction_low_level_il
- 自定义系统调用约定
- Pot of Gold
---

## 一句话结论

面对一个用 `switch-case` 解释自定义指令集、字节码封装在私有 blob 格式里的 VM 时，可以给 Binary Ninja 写一个 `BinaryView` 加载器自动识别并映射段，再实现 `Architecture` 插件的三个回调——`get_instruction_text`（反汇编文本）、`get_instruction_info`（分支/调用/系统调用元数据，决定函数边界）、`get_instruction_low_level_il`（把每条指令翻译成 LLIL）——就能在图形视图和伪 C 反编译里分析 VM 字节码；再注册自定义系统调用约定，还能把 `syscall()` 显示成带 `ID/R0/R1` 参数的可读调用。

## 原理

- **先逆 VM 宿主**：目标是一个去符号的 x86-64 ELF，内部实现 VM；`exec_one_instruction` 的大 `switch(opcode)` 很快暴露指令分发，初始化函数暴露 VM 结构（`regs[8]`、`sp`、`lr`、`pc`、`fl`、内存映射链表、`handle_syscall` 函数指针、`stopped`、`is_master`）和操作码编码（1 字节 opcode + 参数，部分指令用参数高 4 位选寄存器）。
- **私有 blob 格式**：字节码文件以 `UNICORN` magic 开头（与 Unicorn 引擎无关），头部为 `char magic[8]; uint16 nb_segments;`，随后每个段 `{uint16 virtual_base; uint16 size; uint16 protection}`，最后是各段数据；只有第一个段有数据，第二个段是零填充的 VM 栈。加载器按该结构解析并建立可执行段。
- **加载器（BinaryView）**：继承 `BinaryView`，`is_valid_for_data` 检查 magic，`init` 里解析段表并 `add_auto_segment(base, size, file_offset, size, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)`，`perform_get_address_size`/`perform_get_entry_point`/`perform_is_executable` 返回 VM 的地址宽度与入口；这样打开 blob 即自动识别格式，不必每次手动选架构/偏移。
- **架构插件三回调**：
  - `get_instruction_text(data, addr)`：按 opcode/参数生成 `InstructionTextToken`（文本/寄存器 token），返回 (tokens, 指令长度)；用于线性反汇编。
  - `get_instruction_info(data, addr)`：返回 `InstructionInfo` 并 `add_branch`：系统调用 `BranchType.SystemCall`、条件分支同时加 `TrueBranch`/`FalseBranch`、直接调用 `CallDestination`、寄存器调用 `IndirectBranch`、返回 `FunctionReturn`；这是 Binary Ninja 识别函数边界与 CFG 的关键，没有它只能看到孤立的指令块。
  - `get_instruction_low_level_il(data, addr, il)`：用 LLIL 表达式树描述语义，如 `il.set_reg(4, dst, il.xor_expr(4, il.reg(4, src), il.const(4, imm)))` 表示 `xor rX, imm`；`il.append(op)` 挂到函数上。LLIL 让 BN 的优化与反编译流程生成伪 C。
- **系统调用可读化**：默认 `il.system_call()` 无参数，反编译只显示 `syscall()`；注册虚拟寄存器 `ID` 并在 IL 中 `set_reg('ID', 常量)`，再定义 `CallingConvention`（`int_arg_regs=['ID','R0','R1']`、`int_return_reg='R0'`、`eligible_for_heuristics=False` 强制显示参数），把 `platform.system_call_convention` 指向它，伪 C 里即可看到 `syscall(ID, R0, R1)` 形式。
- **两个关键坑**：`get_instruction_text`/`get_instruction_low_level_il` 失败时必须返回 `None` 而不是 0（返回值是消耗字节数，0 会导致死循环）；开发期可先实现一个 `get_instruction_info` 桩（固定 `length=4`）拿线性反汇编，再逐步补全分支信息。64 位寄存器但 `address_size=4` 时反编译结果通常更干净。
- **收益**：原本难以阅读的 VM 字节码获得图形化 CFG 与伪 C，字符串解密、输入校验、命令分发等逻辑可以直接读；本例据此还原了挑战口令校验与两段 VM 的通信协议。

## 触发条件

- 目标为自定义 ISA/VM（私有字节码格式、`switch` 分发、未公开指令编码），静态分析工具原生不支持。
- 使用 Binary Ninja（含 Python 插件 API）；有至少一个样本可迭代调试插件。
- 已能逆出 VM 结构、操作码表与基本指令语义；样本非强反调试/壳导致宿主无法分析。

## 利用步骤

1. 逆宿主 ELF：定位 `exec_one_instruction` 的 switch 分发、VM 初始化、blob 解析循环与 syscall 处理函数；记录 VM 结构布局、寄存器数量、指令长度与参数编码。
2. 写 `BinaryView` 加载器：识别 magic、解析段表、映射代码/数据段、设置地址宽度与入口。
3. 写 `Architecture` 类：声明 `address_size`、`default_int_size`、`instr_alignment`、`max_instr_length`、`regs`（含 SP/LR）、`stack_pointer`、`link_reg`；注册架构。
4. 实现 `get_instruction_text`：覆盖全部 opcode 与 ALU 子操作码，生成 token。
5. 实现 `get_instruction_info`：为 syscall/branch/call/ret 添加 `BranchType`，无效指令返回 None；用图形视图检查函数边界。
6. 实现 `get_instruction_low_level_il`：把每条指令翻译成 LLIL（算术、访存、分支、调用、syscall），处理标志位与条件分支。
7. 注册自定义 syscall calling convention，让伪 C 显示参数；按需要调整 `address_size` 与寄存器宽度。
8. 用反编译视图分析目标 blob：定位输入校验、字符串解密（本例按 `0xf00dcafe ^ ((addr+i)*0x10001)` 生成密钥逐字节异或）、命令分发与漏洞点。

## PoC

```python
# 加载器骨架：识别 UNICORN blob 并映射第一段
class POTLUCKView(BinaryView):
    name = "POTLUCKView"
    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0, 7) == b"UNICORN"
    def init(self):
        n = unpack("<H", self.data.read(8, 2))[0]
        base, size = unpack("<HH", self.data.read(0xA, 4))
        self.add_auto_segment(base, size, 0xA + 6 * n, size,
                              SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        return True
```

```python
# 架构骨架：三个回调，注意失败返回 None 而不是 0
class POTLUCK(Architecture):
    name = "POTLUCK"
    address_size = 4
    default_int_size = 4
    instr_alignment = 4
    max_instr_length = 4
    regs = {f"R{i}": RegisterInfo(f"R{i}", 4) for i in range(8)}
    regs.update({"SP": RegisterInfo("SP", 4), "LR": RegisterInfo("LR", 4)})
    stack_pointer = "SP"; link_reg = "LR"
    def get_instruction_info(self, data, addr):
        info = InstructionInfo(); info.length = 4
        if data[0] == 5: info.add_branch(BranchType.SystemCall, data[1])
        return info
    def get_instruction_text(self, data, addr):
        # 例：xor rX, imm -> set_reg(dst, xor(reg(src), const))
        return [InstructionTextToken(InstructionTextTokenType.TextToken, "xor")], 4
    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, RegisterName("R0"),
                             il.xor_expr(4, il.reg(4, RegisterName("R0")), il.const(4, 0x42))))
        return 4
```

说明：以上为按原文思路整理的最小骨架，完整插件需覆盖全部 opcode/ALU 子操作码；示例寄存器名与指令编码取自原文自定义 ISA。

## 变体与关联

- 变体：Ghidra Processor 模块、IDA processor module 提供同类能力；也可用 Unicorn/Qiling 动态模拟辅助验证指令语义。
- 关联：其他自定义 VM/字节码逆向场景见 [[code-analysis-reverse-vm-unity-compute-shader-bytecode-il2cpp]]、[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]。
- 关联：本例后续利用（VM 越界寄存器索引劫持 syscall 处理器）见 [[ctf-pwn-custom-vm-oob-register-index-handle-syscall-hijack]]。
- 边界：插件需随样本迭代；遇到自修改字节码、运行时解密或强反调试时，静态 IL 不足以还原，需要动态 dump 解码后的字节码。

## 检测与防御

- 分析侧：把 ISA 插件与样本一起版本化，记录 opcode 表与 VM 结构偏移；对未见过的 blob 先用加载器验证段表与入口。
- 防御侧（VM 实现者）：不要在字节码中暴露可直接映射到宿主控制流的语义；对寄存器索引、栈指针、跳转目标做边界检查；不要把控制字段与寄存器数组紧邻放置（本例 OOB 索引可直接改写函数指针）。
- 通用：反编译视图只是分析加速器，最终结论仍需动态调试验证。
