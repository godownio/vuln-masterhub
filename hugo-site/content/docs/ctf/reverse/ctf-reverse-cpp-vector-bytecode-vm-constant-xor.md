---
id: ctf-reverse-cpp-vector-bytecode-vm-constant-xor
title: C++ 向量构造字节码的自定义 VM 逆向：4 条指令解释器与常量表异或
type: scenario
domain: ctf
path: ctf/reverse
technique: cpp-vector-bytecode-vm-constant-xor
tags:
- ctf
- reverse
- vm
- bytecode
- cpp
- ida
- struct-recovery
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:53:42+08:00'
  notes: 已对照原文Ez_VM核对：0x10/0x11/0x20/0x30/0xFF指令语义、每字符10 00 20 00 11 30 00 i字节码、regs[4]上下文偏移、27字节常量表及^0x11 PoC一致；未验证点：PoC未本机执行；标题'4条指令'与正文'五条(含0xFF停机)'口径不同，属轻微。
url: /docs/ctf/reverse/ctf-reverse-cpp-vector-bytecode-vm-constant-xor/
draft: false
kb_aliases:
- Ez_VM
- 自定义 VM
- push_back 字节码
- vm_ctx_t
- regs 上下文
- 指令长度解码
---

## 一句话结论

C++ crackme 的 main 并不直接校验输入，而是用 `std::vector::push_back` 现场拼出一段固定字节码，再交给 `verify` 的寄存器 VM 解释；VM 只有 `0x10/0x11/0x20/0x30/0xFF` 五条指令，每字符实际执行“读入 → 异或 0x11 → 查表比较”，因此恢复常量表后直接异或即可得到 flag，无需完整模拟 VM。

## 原理

- `verify` 接收一个 VM 上下文结构，字段布局可从反编译恢复：
  - `+0x00 code_ptr`：字节码指针；
  - `+0x08 ip`：指令指针；
  - `+0x0C regs[4]`：4 个 8 位寄存器；
  - `+0x10 input_ptr`：用户输入指针；
  - `+0x18 in_pos`：输入位置；
  - `+0x1C ok`：校验标志位；
  - `+0x1D` 起 3 字节填充。
  IDA 中没有 `ida_struct` 模块时，可用 `idc.set_local_type` 定义本地类型，并显式加入填充数组，或直接按 `ctx+reg+12` 的偏移访问寄存器。
- 主循环取 `op = code[ip++]`，按 opcode 分派；实际语义为：
  - `0x10 reg`：`regs[reg] = input[in_pos++]`；若当前输入字节为 0，直接置 `ok=0`，所以输入不能含 NUL，长度由外部 `strlen` 检查（该题为 27）。
  - `0x11 reg imm`：`regs[reg] = imm`。
  - `0x20 reg imm`：`regs[reg] ^= imm`。
  - `0x30 reg idx`：若 `idx > 0x1A` 或 `regs[reg] != table[idx]`，置 `ok=0`。
  - `0xFF`：正常返回。
  - 其他字节：置 `ok=0` 并返回。
- main 的字节码构造循环每轮追加 8 字节：`10 00 | 20 00 11 | 30 00 i`，循环 27 次后追加 `FF`。其中 `0x20` 后的 `11` 不是独立 opcode，而是异或立即数 `0x11`；必须按 opcode 的操作数长度解码，不能按字节值逐字节猜指令。这是本题最容易误判的点。
- 因此每个字符的约束就是 `input[i] ^ 0x11 == table[i]`，而 `table` 是 `.data/.rdata` 中的 27 字节常量数组（含 `0x27`、`0x22` 等不可打印字节）。XOR 自逆，`input[i] = table[i] ^ 0x11`。
- 常量表在源码中由多段字符串与单字节拼接而成，用 Python `bytes` 重建时要注意引号转义与连续空格，避免长度或内容错位（该表长度为 27）。

## 触发条件

- C++ 二进制中存在大量 `std::vector` 扩容/`push_back` 调用，main 反复追加常量字节。
- 存在一个接收上下文结构指针的 `verify`/`check` 函数，结构含 `code_ptr`、`ip`、小寄存器数组、`input_ptr`、`in_pos`、`ok`。
- 输入长度被固定（如 27），校验由“读入、异或、查表比较、停机”几类 opcode 组成。
- 常量比较表在二进制中可见，且没有不可逆哈希/加密。

## 利用步骤

1. 在 IDA 中定位 `main` 的字节码构造循环：识别 `push_back` 的目标 vector 与每次追加的立即数，按顺序还原字节流；也可以在该 vector 构造完成后动态 dump。
2. 从 `verify` 的字段访问恢复上下文结构偏移，定义本地类型，确认 `regs` 数组大小（该题为 4）。
3. 逐条分析 `verify` 的 switch/if 分派，写出 opcode 长度与语义表：`0x10 reg`、`0x11 reg imm`、`0x20 reg imm`、`0x30 reg idx`、`0xFF`。
4. 按指令长度反汇编 main 构造的字节码，确认每字符模板为 `10 00 20 00 11 30 00 i`，最后的比较表下标 `i` 递增。
5. 从二进制提取 27 字节常量表，计算 `table[i] ^ 0x11`。
6. 将结果作为输入重新运行程序，或按上述 ISA 写一个最小解释器正向验证 `ok` 保持为 1。

## PoC

```python
# 27 字节常量表：由 "w}pvj" + 0x27 + b'#&(<(#)!<"#&' + 0x27 + b"<  %$ %l" 重建
table = bytes([
    0x77, 0x7d, 0x70, 0x76, 0x6a, 0x27, 0x23, 0x26, 0x28, 0x3c,
    0x28, 0x23, 0x29, 0x21, 0x3c, 0x22, 0x23, 0x26, 0x27, 0x3c,
    0x20, 0x20, 0x25, 0x24, 0x20, 0x25, 0x6c,
])
assert len(table) == 27
flag = bytes(b ^ 0x11 for b in table)
print(flag)          # 输出应为可打印的 27 字节 flag
```

```python
# 最小 VM 解释器，按上述 ISA 正向验证
def run(code, inp):
    regs = [0] * 4
    ip = pos = 0
    ok = 1
    while True:
        op = code[ip]
        ip += 1
        if op == 0x10:
            reg = code[ip]; ip += 1
            if pos >= len(inp) or inp[pos] == 0:
                ok = 0
            else:
                regs[reg] = inp[pos]; pos += 1
        elif op == 0x11:
            reg, imm = code[ip], code[ip + 1]; ip += 2
            regs[reg] = imm
        elif op == 0x20:
            reg, imm = code[ip], code[ip + 1]; ip += 2
            regs[reg] ^= imm
        elif op == 0x30:
            reg, idx = code[ip], code[ip + 1]; ip += 2
            if idx > 0x1A or regs[reg] != table[idx]:
                ok = 0
        elif op == 0xFF:
            return ok
        else:
            return 0
```

说明：以上为按反编译语义重写的结构化 PoC，未在本机执行；常量表与脚本中的 27 字节一致即可复现。

## 变体与关联

- **操作数别名陷阱**：立即数/操作数与 opcode 取值相同（如本题 `0x11` 既是 `MOV imm` opcode，又作为 `XOR` 的立即数），必须按「操作码 + 固定长度操作数」解码，不能把操作数当指令。
- **VM 变体**：寄存器 VM、栈式 VM、掩码 opcode、运行时解密字节码；先恢复 ISA 与操作数编码，再决定反汇编或符号执行。
- **结构恢复变体**：没有 IDA 结构体模块时，用本地类型 + 显式填充；或按偏移在脚本中模拟。
- **关联卡片**：[[ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse]]（VM 上下文/ISA + 可逆变换）、[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]（栈式 VM 与逐字符约束）、[[ctf-reverse-custom-python-vm-bytecode-disassembler]]（自定义 VM 反汇编器）。
- **边界**：若字节码在运行时才解密、opcode 被掩码，或比较使用不可逆哈希，则不能只静态提取常量表，需要动态 dump 或符号执行。

## 检测与防御

- **CTF/验证**：用恢复的 flag 运行原程序应输出成功；或用最小解释器正向执行，确认所有 `0x30` 比较通过且 `ok` 保持为 1。
- **检测信号**：C++ 程序中 vector 反复 `push_back` 常量字节、紧随其后的 `verify(ctx)` 调用、上下文中 `code_ptr/ip/regs/input_ptr/ok` 的连续偏移访问、switch 分派与固定比较表。
- **防御视角**：客户端校验不能作为安全边界；把校验搬进自定义 VM 只提高逆向成本，VM 语义最终仍可恢复。关键授权/许可判断应放服务端，并使用签名或不可逆承诺保护常量。
- **加固边界**：字节码加密、opcode 掩码、控制流平坦化只能延缓分析；对高价值逻辑应配合完整性校验与服务端裁决。
