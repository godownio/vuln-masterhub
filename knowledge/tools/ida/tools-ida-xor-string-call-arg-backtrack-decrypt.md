---
id: tools-ida-xor-string-call-arg-backtrack-decrypt
title: IDAPython 批量解密调用点 XOR 字符串：回溯 mov r8d/lea rdx 参数并自动注释
type: scenario
domain: tools
path: tools/ida
technique: idapython-xor-string-call-arg-backtrack
aliases:
- IDA 批量字符串解密
- XOR 0x5A 字符串
- XrefsTo 解密函数
- 调用点参数回溯
- 恶意样本字符串还原
tags:
- ida
- idapython
- reverse
- malware-analysis
- string-decryption
- xor
- obfuscation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V134
  verified_at: '2026-11-06T05:40:20+08:00'
  notes: 已对照原文与47张图核对：FUN_decode2 为逐字节 XOR 0x5A、参数 rdx=密文/r8d=长度，XrefsTo 回溯脚本与原文一致，图23显示49处调用批量解密结果；标题/原理/步骤/PoC/变体与图文相符。未验证点：脚本未在本机 IDA 复跑；属分析工具技巧卡，无受影响版本。
---

## 一句话结论

当样本把字符串 XOR 加密后通过 `decode(ptr, len)` 一类函数在运行时解密时，用 IDAPython 枚举该函数的全部 `XrefsTo`，在每个 `call` 前向上回溯 `lea rdx, <密文地址>` 与 `mov r8d, <长度>`，按同一 XOR 密钥逐字节解密并写回注释，即可一次性还原所有隐藏字符串，而不必逐个跟进调用。

## 原理

- 恶意样本常把 URL、注册表路径、进程名、服务名等字符串以密文形式放在数据段，运行时调用一个轻量解密函数（如逐字节 `xor 0x5A`、加减常量、简单循环）还原到栈/堆；IDA 的字符串窗口只能看到密文，静态分析容易漏掉关键 IOC。
- 解密函数的调用约定通常很固定：`lea rdx, <ciphertext>` 传密文指针，`mov r8d, <length>` 传长度（x64）；x86 下可能是 `push <len>; push offset <ciphertext>` 或 `mov edx/ecx`。
- 因此不需要理解每个调用点的上下文：只要找到解密函数地址，枚举所有交叉引用，回溯最近的参数赋值指令，就能批量拿到 `(密文地址, 长度)`。
- 用与样本相同的 XOR 密钥解密后，把结果打印出来并写入 IDA 注释（`set_cmt`），后续反编译/交叉引用时可直接看到明文，显著降低分析成本。
- 该方法的边界：参数可能经过寄存器中转、被内联、长度是运行时计算、或解密算法不是简单 XOR；此时需要按实际汇编调整回溯规则，或改用模拟执行/动态调试。

## 触发条件

- 样本中存在一个被多处调用的字符串解密函数，参数为密文指针与长度。
- 字符串在静态数据段中以密文形式存在，IDA 字符串窗口看不到明文。
- 解密算法是简单 XOR/加减/循环异或，密钥可从函数体或调用点读出。
- 使用 IDA 7.x/8.x，具备 IDAPython（`idaapi`、`idc`、`idautils`）环境。

## 利用步骤

1. 在 IDA 中定位解密函数：从字符串比较、API 调用前的 `call sub_xxx` 跟进，或搜索逐字节 XOR 循环；记录函数地址与 XOR 密钥。
2. 用 `idautils.XrefsTo(decode_func_addr)` 枚举所有调用点。
3. 对每个 `call` 地址，用 `idc.prev_head` 向上回溯最多 20 条指令，匹配 `mov r8d, imm`（长度）与 `lea rdx, <addr>`（密文指针）；x86 样本改为匹配 `push`/`mov edx`/`mov ecx`。
4. 用 `idaapi.get_byte(addr+i)` 读取密文字节，按 `b ^ key` 解密，拼成字符串。
5. 打印 `(调用地址, 密文地址, 长度, 明文)`；确认可读后，用 `idc.set_cmt` 把明文写到调用点或密文地址。
6. 对未提取到参数的调用，检查寄存器中转/内联/长度计算，必要时手动跟进或改用动态解密。

## PoC

```python
import idaapi
import idc
import idautils

XOR_KEY = 0x5A
DECODE_FUNC_ADDR = 0x00007FF6E0875350  # 替换为实际解密函数地址

def decode_str(addr, length):
    return ''.join(chr(idaapi.get_byte(addr + i) ^ XOR_KEY) for i in range(length))

def find_and_decode_all_calls():
    count = 0
    for xref in idautils.XrefsTo(DECODE_FUNC_ADDR):
        call_ea = xref.frm
        cur_ea = call_ea
        r8d_len = None
        rdx_addr = None

        # 向上回溯最多 20 条指令，找参数赋值
        for _ in range(20):
            cur_ea = idc.prev_head(cur_ea)
            mnemonic = idc.print_insn_mnem(cur_ea)
            if mnemonic == "mov" and idc.print_operand(cur_ea, 0) == "r8d":
                r8d_len = idc.get_operand_value(cur_ea, 1)
            if mnemonic == "lea" and idc.print_operand(cur_ea, 0) == "rdx":
                rdx_addr = idc.get_operand_value(cur_ea, 1)
            if r8d_len is not None and rdx_addr is not None:
                break

        if rdx_addr and r8d_len:
            dec = decode_str(rdx_addr, r8d_len)
            print(f"[+] call 0x{call_ea:X} str 0x{rdx_addr:X} len {r8d_len}: {dec!r}")
            idc.set_cmt(call_ea, f"decoded: {dec}", 0)
            count += 1
        else:
            print(f"[-] call 0x{call_ea:X}: 未提取到参数，跳过")

    print(f"[*] 完成，解密 {count} 个字符串")

find_and_decode_all_calls()
```

## 变体与关联

- 变体（x86）：参数常用 `push <len>` + `push offset <ciphertext>`，或 `mov edx, len` + `mov ecx, offset`；回溯时匹配 `push`/`mov` 而不是 `r8d/rdx`。
- 变体（寄存器中转）：`lea rax, str; mov rdx, rax` 或长度由 `strlen` 计算；需要多跳一层数据流或改用 IDA microcode/模拟执行。
- 变体（算法不同）：多字节 XOR、加减常量、RC4/XXTEA、逐字符变换；把 `decode_str` 换成对应算法即可。
- 变体（内联/混淆）：解密函数被内联到调用点或经 VM 执行；改用动态调试在解密后 dump 内存，或按 VM 调用还原。
- 关联：[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（@ 隔字符/栈上字符串/API wrapper 还原）、[[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]（API 哈希与 XOR Key 还原）、[[code-analysis-reverse-obfuscation-ollvm-string-decrypt-frida]]（Frida 动态字符串解密）。

## 检测与防御

- 检测（分析侧）：样本数据段存在大量高熵短字节串、被同一函数反复引用；调用点前固定出现 `lea`+`mov imm` 参数模式；函数体是逐字节 XOR/加减循环。
- 检测（防守侧）：字符串加密只是提高静态分析成本，不构成安全边界；EDR 应关注解密函数执行后的内存字符串、API 调用与网络外联。
- 防御：对恶意样本分析，结合静态脚本与动态 dump 交叉验证；对自身软件，不要用硬编码 XOR 保护敏感字符串/密钥。
- 边界：脚本依赖固定调用约定与密钥；换编译器/架构/混淆后需调整回溯规则，不能盲目套用。
