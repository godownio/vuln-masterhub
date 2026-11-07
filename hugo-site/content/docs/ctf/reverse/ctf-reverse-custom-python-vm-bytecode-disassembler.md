---
id: ctf-reverse-custom-python-vm-bytecode-disassembler
title: 自定义 Python VM 字节码逆向：反汇编器与多轮变换逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-python-vm-bytecode-disassembly
tags:
- ctf
- reverse
- vm
- bytecode
- disassembler
- python
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:13:58+08:00'
  notes: 已对照原文核对：main.pyc/kernelVM.pyc/opcode.bin 结构、R0/R1/PC/heap 与 opcode 语义、第一段 27 字节 XOR 0x55 后 +7+3i 及逆变换、ntbase.pyd 非 MZ 的第二段 VM 指令流、+10/前缀异或/偶数位 +0x10/奇数位 +0x31 均一致。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-custom-python-vm-bytecode-disassembler/
draft: false
kb_aliases:
- FunPyVM
- 自定义 VM
- 字节码反汇编
- opcode.bin
- Python VM
- 隐藏字节码
---

## 一句话结论

`main.pyc` 只是加载器，真正的校验在 `kernelVM.pyc` 实现的自定义 VM 中；先按 opcode 语义写反汇编器解析 `opcode.bin`，再识别“异或 0x55 + 加 7+3i”的变换并逆推；同一 VM 还藏在 `ntbase.pyd`（开头不是 MZ 而是 VM 指令流）中，需对第二段字节码再做“加 10、前缀异或、奇偶加 0x10/0x31”的逆变换。

## 原理

- VM 状态：`R0` 当前堆块指针、`R1` 通用寄存器、`PC` 程序计数器、`heap` 字典；指令长度 1 或 2 字节（带 imm）。
- 常用 opcode：`0x10 ALLOC imm`、`0x11 LOAD imm`、`0x12 STORE imm`、`0x20 MOVI imm`、`0x30 ADDI imm`、`0x31 XORI imm`、`0x35 XOR_MEM imm`、`0x40 CMPEQ imm`、`0x42 JZ imm`、`0x43 JNZ imm`、`0x51 SWAP`、`0x52 SYSCALL`（0x01 读输入、0x02 打印）。
- 反汇编器按 `LEN2_OPS` 判断指令长度，遇到 JZ/JNZ 计算 `target = pc + imm` 并标注标签，即可恢复控制流。
- 第一段校验：对前 27 字节，若 `input[i] != 0` 则 `input[i] ^= 0x55`，再 `input[i] += 7 + 3*i`，最后与常量表比较；逆运算为 `((target[i] - (7+3*i)) & 0xFF) ^ 0x55`。
- 第二段藏在 `ntbase.pyd`：文件头不是 `MZ`，而是 `10 64 10 32 ...` 的 VM 指令流；反汇编后可见 `+10`、前缀异或（`s[i] ^= s[i-1]`）、偶数位 `+0x10`、奇数位 `+0x31`，逆序还原。
- 关键点：自定义 VM 的“安全性”来自指令集不公开；一旦从 `kernelVM.pyc` 恢复 opcode 语义，字节码就是可读程序。

## 触发条件

- 附件包含 `.pyc` 加载器、`opcode.bin`/`.pyd` 等自定义字节码。
- `.pyd`/数据文件开头不是标准 PE/ELF 魔数，而是疑似指令流。
- 加载器调用 `CustomVM().run(bytecode)` 或等价解释器。
- 校验逻辑由多条算术/跳转指令组成，变换可逆。

## 利用步骤

1. 反编译 `main.pyc`，确认字节码文件路径与 VM 类。
2. 反编译/逆向 `kernelVM.pyc`，提取 opcode 表、指令长度、寄存器/堆语义、syscall。
3. 写反汇编器：逐条解码、标注跳转目标、打印 `PC/opcode/arg/name`。
4. 阅读反汇编，识别输入变换与目标常量表；按逆序实现逆变换。
5. 对 `ntbase.pyd` 等隐藏文件重复反汇编；若开头不是标准格式，直接按 VM 指令流处理。
6. 还原所有阶段明文，拼接 flag；用格式/长度校验。

## PoC

```python
from pathlib import Path

LEN2 = {0x10,0x11,0x12,0x20,0x30,0x31,0x32,0x33,0x34,0x35,
        0x36,0x37,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x50,0x52}
NAMES = {0x10:"ALLOC",0x11:"LOAD",0x12:"STORE",0x13:"FREE",0x20:"MOVI",
         0x30:"ADDI",0x31:"XORI",0x35:"XOR_MEM",0x40:"CMPEQ",
         0x42:"JZ",0x43:"JNZ",0x51:"SWAP",0x52:"SYSCALL"}

def disasm(data: bytes):
    pc = 0
    while pc < len(data):
        op = data[pc]
        ln = 2 if op in LEN2 else 1
        arg = data[pc+1] if ln == 2 and pc+1 < len(data) else None
        name = NAMES.get(op, f"DB_{op:02X}")
        extra = ""
        if name in ("JZ","JNZ") and arg is not None:
            extra = f" -> 0x{pc+arg:04X}"
        print(f"0x{pc:04X}: {op:02X} {arg if arg is not None else '':>2}  {name}{extra}")
        pc += ln

disasm(Path("opcode.bin").read_bytes())
```

```python
# 第一段逆变换
target = [41,71,57,26,63,80,57,38,64,95,97,99,105,56,82,113,
          115,96,71,124,105,80,106,115,111,130,191]
plain = bytes(((v - (7 + 3*i)) & 0xFF) ^ 0x55 for i, v in enumerate(target))
print(plain)
```

## 变体与关联

- 变体：栈式 VM、寄存器 VM、变长指令、加密 opcode 表；反汇编器需按实际语义调整。
- 变体：隐藏字节码可能放在 `.pyd`、资源段、图片附加数据、注册表等；按 VM 指令特征搜索。
- 变体：多轮变换可能包含前缀异或、奇偶位不同常量、查表；逆序处理即可。
- 关联：[[ctf-reverse-lua53-bytecode-xor-rc4]]（Lua 字节码）、[[ctf-reverse-multistage-pe-vm-modified-sm4]]（x86 VM）、[[ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse]]（自定义 VM ISA）。

## 检测与防御

- 检测：`.pyc` 加载器、非标准魔数的数据文件、`CustomVM`/`run(bytecode)` 等符号。
- 防御：不要把敏感校验放在客户端 VM；使用服务端校验、代码签名与完整性保护。
- 响应：确认字节码可提取后，视为逻辑泄露，轮换相关密钥并审计客户端。
