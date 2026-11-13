---
id: ctf-reverse-nor-machine-single-instruction-vm-emulate-bruteforce
title: NOR-Machine 单指令虚拟机逆向：从 PE 提取 16 位 NOR 字节码，按 mem[mem[IP+2]]=NOR(mem[mem[IP]],mem[mem[IP+1]]) 用 Python 仿真并逐字符爆破 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: nor-machine-one-instruction-vm-emulation
aliases:
- NOR-CPU
- 单指令 CPU
- NOR 虚拟机逆向
- OISC 逆向
- NOR-Machine 爆破
- mem[IP+2]=NOR(mem[IP],mem[IP+1])
tags:
- ctf
- reverse
- vm
- nor-cpu
- oisc
- bytecode
- emulation
- bruteforce
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V562
  verified_at: '2026-11-12T07:41:27+08:00'
  notes: 已对照原文与全部21张截图核对：NOR单指令语义mem[mem[IP+2]]=NOR(mem[mem[IP]],mem[mem[IP+1]])、IP+3、SHIFT_REG=ROL1、mem[4]/mem[6]打印/读入端口、sub_4010AD的VirtualAlloc+memcpy(v0+300,unk_404018,0x3246)+mem[0]=300、16位小端字节码、逐字符256次重放爆破得flag{WE1rd_v1R7UaL_M@chINE_Ev3R}均与原文/图20/21一致。修正两处表述：原文爆破脚本是在id=0x43f处检查mem[0x1a0d]（校验位在0x1ee/0x1a0d附近，原卡误作'写mem[0x1a0d]'）；26个输入字符为去掉flag{}后的主体。dedup候选(自定义VM TEA-like/VMC2/栈式VM/Python VM等)均为多指令ISA VM，非同链。未验证点：无原题样本复跑。
---

# 一句话结论

NOR-CPU 用一条指令实现全部逻辑：`mem[mem[IP+2]] = NOR(mem[mem[IP+0]], mem[mem[IP+1]])`，IP 每次加 3，`SHIFT_REG` 保存结果的循环左移一位，`mem[4]`/`mem[6]` 为打印/读入端口；逆向时按 16 位小端从 PE 中提取字节码，用 Python 按同一语义仿真，定位校验单元后对每个输入字符做 256 次重放爆破，即可恢复 `flag{WE1rd_v1R7UaL_M@chINE_Ev3R}`。

# 原理

- **单指令完备性**：NOR 是功能完备位运算，`NOT(a)=NOR(a,a)`、`OR(a,b)=NOT(NOR(a,b))`、`AND(a,b)=NOT(OR(NOT(a),NOT(b)))`、`XOR` 可由 OR/AND/NOT 组合；因此一条 NOR 就能表达所有运算，计数器、循环、比较都由软件在内存中模拟。
- **内存布局**：16 位线性地址空间（0x0000–0xFFFF），对象文件布局与运行时内存布局完全一致；`mem[0]=IP`、`mem[1]=SHIFT_REG`（每次 NOR 结果的 ROL1）、`mem[2]=REG0`，其后为代码段与数据段。
- **指令语义**：取 `id=mem[IP]`，三个参数是**地址**：`arg0=mem[id]`、`arg1=mem[id+1]`、`arg2=mem[id+2]`，执行 `mem[arg2]=NOR(mem[arg0],mem[arg1])`，`mem[IP]=id+3`，`mem[1]=ROL16(result,1)`。
- **I/O**：VM 的 `sub_401000` 每轮检查 `mem[4]==1` 时打印 `mem[3]` 并清零；`mem[6]==1` 时把 `scanf` 读入的字符写入 `mem[5]` 并清零。输入 26 个字符时，校验程序把某个内存单元（文章为 `mem[0x1ee]`/`mem[0x1a0d]` 附近）置 0/非 0 表示该字符是否正确。
- **为什么能爆破**：VM 是确定性的，单个输入字符只影响其后的状态；修改仿真脚本在每条指令后检查校验单元，若为 0 则该字符正确。对 26 个位置逐一枚举 0–255、每次重置内存重放，复杂度只有 26×256×指令数，远低于符号执行。
- **字节码提取**：`main`（`sub_4010AD`）`VirtualAlloc(0, 0x20000, 0x1000, 4)` 后 `memcpy(v0+300, unk_404018, 0x3246)` 并把 `mem[0]` 置 300；`unk_404018` 即 16 位小端字节码，按两字节拼成一个 word 后接在内存偏移 300 处仿真即可。

# 触发条件

- CTF RE 题目使用 NOR-CPU（或同类 OISC 单指令 VM）实现校验，样本可在本地运行/调试。
- 能从 PE 中定位字节码数组与 VM 初始化函数（如 `VirtualAlloc`+`memcpy` 模式）。
- 已知输入长度（本题 26）与输出格式；有 Python 环境。
- 校验单元可通过跟踪 I/O 或对比正确/错误输入定位；无须完整的符号执行工具。

# 利用步骤

1. 逆 `main`：找到 `VirtualAlloc` 分配的 VM 内存、`memcpy(dst,unk_404018,0x3246)` 与 `mem[0]=300`，确认字节码源地址与长度。
2. 提取字节码：按 `a[i] | (a[i+1]<<8)` 拼成 16 位 word 列表，内存布局为 `mem[0:300]` 系统区 + 字节码。
3. 写 Python 仿真器：实现 `id=mem[0]`、三地址 NOR、`mem[0]=id+3`、`mem[1]=rol1(result)`，并处理 `mem[4]` 打印/`mem[6]` 读入端口。
4. 先用 26 个 `a` 跑一遍，观察输出与校验单元；在每条指令后打印 `id` 与写入地址，定位"把校验结果写到固定单元"的那条指令（文章在 `id=0x43f` 处检查校验单元 `mem[0x1a0d]`，校验位保存在 `mem[0x1ee]`/`mem[0x1a0d]` 附近）。
5. 逐字符爆破：对位置 `k`（0..25）枚举 `t`（0..255），每次重置 `mem`、设置输入数组第 `k` 位为 `t`，运行到校验指令，若校验单元为 0 则记录该字符。
6. 拼接 26 个字符（即去掉 `flag{}` 包裹后的主体）得到 `flag{WE1rd_v1R7UaL_M@chINE_Ev3R}`，回填程序验证。

# PoC

```python
# NOR-CPU 仿真器骨架（对照文章 sub_401000）
def nor(a, b): return (~(a | b)) & 0xFFFF
def rol1(x):   return ((x << 1) + (((1 << 15) & x) >> 15)) & 0xFFFF

def run(code_words, inp, trace_check_id=None):
    mem = [0] * 300
    mem[0] = 300                      # IP 指向字节码起始
    mem += code_words
    mem += [0] * 100000
    num = 0
    pc = 0
    while mem[0] != 0xFFFF:
        if mem[4] == 1:               # 打印端口
            mem[4] = 0
            print(chr(mem[3]), end='')
        if mem[6] == 1:               # 读入端口
            mem[6] = 0
            mem[5] = ord(inp[num]); num += 1
        id_ = mem[0]
        a0, a1, a2 = mem[id_], mem[id_+1], mem[id_+2]
        mem[0] = id_ + 3
        r = nor(mem[a0], mem[a1])
        mem[a2] = r
        mem[1] = rol1(r)
        if trace_check_id is not None and id_ == trace_check_id:
            return mem[0x1a0d]        # 校验单元（按题目实际地址调整）
    return None

# 逐字符爆破（每次重置内存）
known = 'flag{WE1rd_v1R7UaL_M@chINE_Ev3R}'
inp = ['a'] * 26
for k in range(26):
    for t in range(256):
        inp[k] = chr(t)
        if run(code_words, ''.join(inp), trace_check_id=0x43f) == 0:
            print(t, chr(t)); break
print(''.join(inp))
```

```text
文章实测：字节码从 unk_404018 取出（长度 0x3246），按 16 位小端拼接；
用 'a'*26 作输入，在指令 id=0x43f 后检查 mem[0x1a0d]；逐字符命中后得到
flag{WE1rd_v1R7UaL_M@chINE_Ev3R}。
```

# 变体与关联

- 变体：同类 OISC 还有 subleq、RISC 单指令等，逆向方法一致——先还原指令语义（参数是地址还是立即数）、I/O 约定，再写仿真器。
- 关联：`ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution`（自修改 VM + z3）、`ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse`（自定义 VM ISA 还原）、`ctf-reverse-cpp-vector-bytecode-vm-constant-xor`（C++ vector 字节码 VM）；本卡差异是单指令 OISC + 仿真爆破，不需要恢复复杂 ISA。
- 参考实现：NOR-CPU（yuan-xy）GitHub 项目中的 `norcpu.rb`、`assembler.rb`，可用其汇编器/反汇编思路辅助验证。
- 边界：字节码提取偏移、内存系统区（寄存器/端口地址）与校验单元位置随题目实现变化；VM 若有输入长度/时序校验需先满足。

# 检测与防御

- CTF 场景无防护语义；对出题方：可在字节码中加入依赖输入长度/环境的时间校验、或在 NOR 程序层做多层自校验，增加仿真与爆破成本；对解题方：OISC 的关键是还原语义与内存约定，仿真器 + 局部爆破通常比通用符号执行更快、更稳。
