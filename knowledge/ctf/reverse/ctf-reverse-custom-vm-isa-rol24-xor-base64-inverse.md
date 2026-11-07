---
id: ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse
title: 自定义 VM 字节码逆向：VM 上下文/ISA 恢复 + rol24 XOR 混淆 Base64 求逆
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-vm-isa-rol24-xor-base64-inverse
aliases:
- vm-encryptor
- code.bin
- VM 指令集
- 自定义虚拟机
- rol24 0x55757d
- Base64 表 0x10e3
- 字节码反汇编
tags:
- reverse
- vm
- bytecode
- isa
- base64
- rol24
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:13:00+08:00'
  notes: 已对照原文核对：VM 上下文结构、opcode 表、0x1000/0x102b/0x1064/0x109d 地址、rol24 5/11/20 各 XOR 0x55757d、XOR 0x63、逆序求逆均一致；原文无图片；未实际运行。
---

## 一句话结论

`vm-encryptor.exe` 把校验逻辑放在 `code.bin` 的自定义 VM 字节码里：主程序只负责加载字节码、把输入复制到 VM 内存 `0x1000`、调用 `vm_exec`；逆出 VM 上下文结构与 switch/jumptable 指令集后，把字节码反汇编成“3 字节→24 位→rol24 5/11/20 各 XOR 0x55757d→标准 Base64 表映射”“逐字节 XOR 0x63”“56 字节比较”三段，再按逆序求逆即可还原 flag。

## 原理

- 主程序从命令行读取 `code.bin`，把字节码加载到 VM 内存 `mem[0]`；从 stdin 读取 Flag，复制到 `mem[0x1000]`（最多 0x2a 字节），然后调用 `vm_exec`。所以字节码中的 `0x1000`、`0x102b`、`0x1064` 等地址分别对应输入、第一段输出、第二段输出。
- VM 上下文结构可从 `vm_exec`/`load_program` 恢复：
  ```text
  uint32_t ip;            // 0x0000
  uint32_t sp;            // 0x0004
  uint8_t  mem[0x10000];  // 0x000c
  uint32_t stack[0x1000]; // 0x1000c
  uint32_t running;       // 0x1400c
  uint32_t err;           // 0x14010
  ```
- 解释器是典型 switch/jumptable；梳理跳转表后得到指令集：`jmp/jz/jnz`、`push8/push32`、`ld8/ld32`、`pop`、`st8/st32`、`add/sub/mul/div/mod`、`and/or/not/xor`、`shl/shr`、`eq/ne/lt/gt/le/ge`、`dup/swap`、`call/ret`、`printstr`、`halt`。
- 字节码入口（0x0000）三次调用：
  1. `call 0x004f`：输入 `0x1000` → 输出 `0x102b`，长度 0x2a=42；
  2. `call 0x0368`：`0x102b` → `0x1064`，长度 0x38=56；
  3. `call 0x0471`：比较 `0x1064` 与目标 `0x109d`，长度 56。
- `sub_004f`：每 3 字节组成 24 位整数 `v`，依次 `v = rol24(v,5) ^ 0x55757d`、`rol24(v,11) ^ 0x55757d`、`rol24(v,20) ^ 0x55757d`，再按标准 Base64 表（`0x10e3` 处的 `A-Za-z0-9+/`）取 4 个 6 位字符。42 字节刚好 14 组，输出 56 字节。
- `sub_0368`：对 56 字节逐字节 XOR `0x63`。
- `sub_0471`：逐字节比较，全部相等返回 1，主程序打印 `Right!`。
- 求逆：从 `code.bin` 取 `0x109d` 起 56 字节，先 XOR `0x63` 得到自定义 Base64 串；每 4 字符映射回 24 位整数，依次逆第三轮（`^0x55757d` 后 `ror24(20)`）、第二轮（`^0x55757d` 后 `ror24(11)`）、第一轮（`^0x55757d` 后 `ror24(5)`），再拆成 3 字节。
- 根因是“VM 只是把逻辑搬进字节码”，VM 本身没有不可逆的密码学保护；只要恢复 ISA 与字节码，就能像普通程序一样反汇编、求逆。

## 触发条件

- 目标为“解释器 + 字节码”结构的 crackme/程序，字节码文件与 VM 解释器分离或内嵌。
- VM 指令集由 switch/jumptable 实现，语义可从 handler 恢复。
- 字节码中的校验算法是可逆的逐字节/分组变换（ARX、异或、Base64 换表），没有不可逆哈希/签名。
- 允许静态分析解释器与字节码（CTF/授权逆向场景）。

## 利用步骤

1. 从主程序字符串（`usage: ... <program.bin>`、`Input Flag:`、`Right!`/`Wrong!`）定位 `load_program`、`vm_exec` 与输入复制逻辑。
2. 恢复 VM 上下文结构（ip/sp/mem/stack/running/err）与字节码加载地址；确认输入在 `mem[0x1000]`。
3. 分析 `vm_exec` 的 switch/jumptable，整理 opcode → 语义、立即数字节序、栈行为；写一个简单的反汇编器。
4. 从入口 `0x0000` 递归反汇编，识别函数调用与参数（push32 顺序）、输出/比较地址。
5. 对每个 VM 函数提炼高层算法；本题得到“24 位 rol24/XOR + Base64 表”“XOR 0x63”“memcmp”。
6. 提取目标常量，按逆序求逆；用正向算法验证结果与目标一致。
7. 输出 flag。

## PoC

```python
from pathlib import Path

code = Path("code.bin").read_bytes()
alphabet = code[0x10E3:0x10E3 + 64]
target = code[0x109D:0x109D + 56]
inv = {c: i for i, c in enumerate(alphabet)}
MASK = (1 << 24) - 1

def ror24(x, n):
    return ((x >> n) | (x << (24 - n))) & MASK

enc = bytes([b ^ 0x63 for b in target])   # 逆第二段 XOR 0x63
flag = bytearray()

for i in range(0, len(enc), 4):
    c0, c1, c2, c3 = enc[i:i+4]
    x = (inv[c0] << 18) | (inv[c1] << 12) | (inv[c2] << 6) | inv[c3]

    x ^= 0x55757d; x = ror24(x, 20)   # 逆第三轮
    x ^= 0x55757d; x = ror24(x, 11)   # 逆第二轮
    x ^= 0x55757d; x = ror24(x, 5)    # 逆第一轮

    flag.extend([(x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff])

print(flag.decode())
```

## 变体与关联

- **VM 变体**：寄存器 VM、栈式 VM、基于文件的地图 VM、自修改字节码、掩码 opcode；先恢复 ISA 再决定反汇编/符号执行。
- **编码变体**：自定义 Base64 表、输出顺序置换、rol/ror 轮数、XOR 常量、LCG 掩码；逆序时注意“先逆最后一轮”。
- **工具变体**：手写反汇编器、IDA/Ghidra 处理器模块、Unicorn 仿真、angr/Z3 符号执行。
- **关联**：[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（掩码 opcode + 反向执行）；[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（VMC2 寄存器 VM 与 ARX 求逆）；[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（rol/xor/ror 求逆的另一 VM 场景）。
- **边界**：若字节码使用不可逆哈希、服务端校验或反调试/自修改导致静态字节码不完整，需要动态 dump 或符号执行。

## 检测与防御

- **检测**：程序出现 `usage: ... <program.bin>`、`Input Flag:`、`vm error`、`Right!`/`Wrong!`；存在 `ip/sp/mem/stack` 结构与大型 switch/jumptable；字节码文件与解释器分离。
- **防御**：CTF 场景外，不要把关键校验放在客户端字节码；使用服务端校验、代码签名与完整性校验。
- **加固**：VM 混淆、字节码加密、opcode 掩码只能提高成本；解释器最终要执行语义，逻辑仍可被恢复。
