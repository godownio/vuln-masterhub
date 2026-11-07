---
id: code-analysis-reverse-obfuscation-silverfox-const-func-global-dce-bcf
title: 银狐 BCF 不透明谓词静态还原：常量函数内联 + 只读全局常量化触发 IDA DCE
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ida-constant-function-inline-readonly-global-const-dce
tags:
- malware-analysis
- silverfox
- obfuscation
- bogus-control-flow
- opaque-predicate
- idapython
- ida
- hex-rays
- deobfuscation
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:04:32+08:00'
  notes: 已对照原文与10张截图核对：BCF不透明谓词、sub_14008E740返回6、byte_1400BE9C0全部只读xref、IDAPython patch mov al imm+NOP、const化后DCE简化、a+b-2(a&b)=a^b字符串解密均一致；未验证点：未实际运行IDA脚本/样本。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-silverfox-const-func-global-dce-bcf/
draft: false
kb_aliases:
- 常量函数 patch
- 只读全局变常量
- BCF 不透明谓词去混淆
- 死代码消除去混淆
- 银狐名单样本去混淆
---

## 一句话结论

面对大量 `if (常量函数() != 常量)` 形式的不透明谓词把 CFG 糊成一团时，先用 IDAPython 把所有“只返回常量的小函数”的直接调用点 patch 成 `mov al/eax, imm`，再把“有初值且全部交叉引用为读”的全局变量强制声明为 `const`，Hex-Rays 就能常量折叠并用死代码消除（DCE）自动删掉永不执行的假分支，恢复可读伪代码。

## 原理

- BCF（Bogus Control Flow，虚假控制流）插入的假分支由不透明谓词保护。理想情况下谓词两边都是编译期常量，IDA 可以算出来；但样本故意把常量藏进两种位置，让反编译器无法计算：
  1. 无参小函数只返回常量：`char sub_14008E740() { return 6; }` 编译为 `mov al, 6; retn`；零值常量常被编译成 `xor al, al; retn`，而不是 `mov al, 0`。
  2. 有初值的全局变量（如 `char byte_1400BE9C0`）。查交叉引用全部是 `movzx ecx, cs:byte_1400BE9C0` 一类读取，没有任何写入，语义上就是常量；但 Hex-Rays 按可变全局处理，不会参与折叠。
- 把 `call sub_14008E740` 改成等价的 `mov al, 6`（剩余字节填 `nop`）后，调用结果在反编译层面变成字面量；把全局变量类型改成 `const char` 后，Hex-Rays 把它当常量参与运算。
- 一旦谓词两边都能求值，`if (a != a)` 或 `if (24 * 1 + x != x)` 就变成恒真/恒假；IDA 的 DCE 在展示伪代码时删除不可达分支，原本挤在一起的基本块随之消失。对多层嵌套的谓词需要反复 patch、重新反编译，直到常量传播稳定。
- 去混淆后的算术还会暴露字符串解密公式。例如伪代码出现 `v13[i] = (i - 111) + v13[i] - 2 * ((i - 111) & v13[i])`，利用恒等式 `a + b - 2*(a & b) == a ^ b` 可识别为 `密文[i] ^ (i - 111)`；每个字符串的 key 是 `i + 随机常量` 的形式，按位置逐字节异或即可还原。
- 本文样本的常量函数返回值多为 0–9（`mov al, imm`），用于参与 `24 * byte_1400BE9C0 + ...` 一类运算；常量的“隐藏”并不改变语义，只是阻止反编译器的常量传播。把它们还原后，垃圾代码块失去存在的意义，DCE 才能生效。

## 触发条件

- 目标是 Windows PE（本文样本为 x64），使用 BCF 式虚假控制流：函数图出现大量并排/糊在一起的小基本块，伪代码充满 `double` 运算、`(double)7 - (double)3 * 2.0` 这类实际等于 1 的表达式。
- 常量被放在“直接 call 的无参常量函数”或“有初值、只读的全局变量”里；若常量通过函数指针/VM 间接调用，或全局在运行时有写入，本方法不适用。
- 使用 IDA + Hex-Rays；脚本依赖 `idc.print_insn_mnem`/`idc.print_operand` 的文本格式，IDA 版本差异可能需要调整。
- 只能改 IDB 中的字节/类型，不执行样本；样本可能带 `IsDebuggerPresent`/PEB 检测和 `.text` 段运行时解密，需先静态定位或动态 dump 解密后的代码，且全程在隔离虚拟机中进行。

## 利用步骤

1. 隔离环境中静态加载样本；先定位反调试（如 `GetModuleHandleA` + `GetProcAddress("IsDebuggerPresent")` 后 `test eax, eax; je exit`），分析时 patch 掉该分支即可，不要运行样本。
2. 处理外层 `.text` 自解密：定位 `ZwProtectVirtualMemory(..., 64, ...)`（`64 = PAGE_EXECUTE_READWRITE`）及其后的 `xor_decrypt` 循环；入口表项常为 20 字节（目标 RVA、长度、标志等），目标地址为 `0x140000000 + RVA`。若无法静态还原 key，在调试器中让解密循环跑完后 dump 内存，再重新载入 IDA。
3. 识别常量函数：遍历函数指令，匹配“2 条指令、`mov al/eax/ax, 0..9; ret`”或“`xor al, al; ret`”，记录函数地址与返回值；返回宽度按调用点实际使用（al/ax/eax）选择。
4. 扫描对这些函数的直接 `call`，patch 为 `mov al, imm`（`B0 imm`）或 `mov eax, imm32`（`B8 imm32`），多余字节填 `0x90`；加注释便于回滚，重新反编译让常量传播。
5. 查可疑全局变量的交叉引用：若有初值且全部为读取，用 IDAPython 将其类型改为 `const char`/`const unsigned char`（`idc.set_type` 或 IDA 的 SetType），再反编译。
6. 重复 4–5 步并重新按 F5；DCE 会删除恒假分支，直到函数 CFG 和伪代码稳定、可读。
7. 在简化后的代码中定位关键调用（进程/服务枚举、内存分配、注入、字符串解密）；对 `a + b - 2*(a & b)` 形式按 XOR 还原字符串：`plain[i] = cipher[i] ^ ((i + k) & 0xff)`，k 从每个字符串的常量项读取。

## PoC

```python
# IDAPython：扫描并 patch 直接调用的常量函数（简化自样本分析脚本）
import ida_ua, ida_bytes, idc, ida_funcs

def const_func(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    insns, cur = [], f.start_ea
    while cur < f.end_ea:
        insn = ida_ua.insn_t()
        n = ida_ua.decode_insn(insn, cur)
        if not n:
            break
        insns.append((idc.print_insn_mnem(cur),
                      idc.print_operand(cur, 0),
                      idc.print_operand(cur, 1), n))
        cur += n
    if len(insns) != 2 or insns[1][0] not in ("ret", "retn"):
        return None
    m0, o0, o1, _ = insns[0]
    if m0 == "mov" and o0.lower() in ("al", "ax", "eax") and o1.isdigit():
        return int(o1)
    if m0 == "xor" and o0.lower() == o1.lower() and o0.lower() in ("al", "ax", "eax"):
        return 0
    return None

def patch_calls():
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        for ea in range(f.start_ea, f.end_ea):
            if idc.print_insn_mnem(ea) != "call":
                continue
            v = const_func(idc.get_operand_value(ea, 0))
            if v is None:
                continue
            old_len = idc.get_item_size(ea)
            new = bytes([0xB0, v]) if v <= 0xFF else b"\xB8" + v.to_bytes(4, "little")
            ida_bytes.patch_bytes(ea, new + b"\x90" * (old_len - len(new)))
            idc.set_cmt(ea, f"inline const {v}", 0)
```

```python
# 字符串还原：a + b - 2*(a & b) == a ^ b
def decrypt(cipher: bytes, k: int) -> bytes:
    return bytes(c ^ ((i + k) & 0xFF) for i, c in enumerate(cipher))
```

## 变体与关联

- 变体：常量函数返回指针/字符串地址时，patch 成 `lea rax, [addr]`，而不是 `mov eax, imm`。
- 变体：`mov al, 0` 被编译为 `xor al, al`、`sub al, al` 等零值习语，需单独匹配；返回值被当作 64 位使用时要把 `eax` 写零扩展到 `rax`。
- 变体：常量通过函数指针、虚表或 VM 间接调用时，本方法失效；可参考 [[code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore]] 的 `call r11` 扫描与常量折叠。
- 变体：全局变量在初始化时才写入，静态常量化会算错；应在初始化完成后下断点 dump，或把写入点也 patch 成常量。
- 关联卡片：[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]（BCF 原理）、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（花指令修复）、[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（运行时解密后重建代码）、[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（同家族字符串/API 混淆）。
- 边界：DCE 只能删除“可证明恒假”的路径；如果谓词依赖运行期值，或常量藏在间接调用后面，仍需动态调试/符号执行。

## 检测与防御

- 静态检测：大量 2 条指令的 `mov al, imm; ret`/`xor al, al; ret` 小函数、只读但有初值的全局变量、`(double)7 - (double)3 * 2.0` 之类恒为 1 的浮点表达式、以及谓词两边来自同一常量源的 `if`，都是 BCF 混淆及此类反分析手法的强特征。
- 动态检测：监控对自身 `.text` 段调用 `ZwProtectVirtualMemory`/`VirtualProtect` 改为 RWX 后写入的行为；监控 `IsDebuggerPresent`/PEB 读取；这些常出现在解密/反调试前置阶段。
- 防御/加固：分析侧用脚本批量常量化 + DCE、符号执行或 Unicorn 模拟；检测侧不要依赖单点字符串签名，应结合 CFG 形态、段权限变化与后续行为链（服务枚举、跨进程写入、ALPC/线程池）综合判定。
- 分析安全：样本是不可信数据，patch 只写 IDB，不执行样本；动态阶段必须在隔离虚拟机、无凭据、无共享目录的环境中进行。
