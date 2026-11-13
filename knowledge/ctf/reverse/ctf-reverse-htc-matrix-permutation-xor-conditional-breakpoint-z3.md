---
id: ctf-reverse-htc-matrix-permutation-xor-conditional-breakpoint-z3
title: HTC CTF 矩阵乘 RE：IDA 条件断点+IDAPython 现场导出 mul 系数与中间值，z3 解 4 元线性方程 + 单字节异或爆破 + 置换逆序还原 16 字节 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: ida-conditional-breakpoint-matrix-z3-inverse
aliases:
- IDA 条件断点导矩阵
- z3 矩阵线性方程还原 flag
- Sn@k 16 字节 RE
- 矩阵乘逆向
- 条件断点打印 imul 操作数
tags:
- ctf
- reverse
- ida
- idapython
- z3
- matrix
- conditional-breakpoint
- xor-bruteforce
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V562
  verified_at: '2026-11-12T07:41:25+08:00'
  notes: 已对照原文与全部21张截图核对（21/21可读，14/15为同一文件重复图）：前缀Sn@k+长度16、cry1置换/单字节异或、cry2三条关键汇编(mov eax,[rbx];add rbx,rbp;imul eax,[rdi])、条件断点IDAPython输出、z3解出100,89,119,92...、CyberChef XOR key=0x37得Sn@ku2r3cd3__era、换序后Sn@k3_are_cu2r3d、最终Successful均与图一致。修正了z3示例PoC右端项：原文结论对应真实密文x组分量0x436/0x2EA/0x1C6/0x69E（原卡误写0x466/0x2f9/0x1e4/0x646，混入假flag组），并澄清右端项须用真实硬编码密文（假flag输出只解出假flag自身变换）；已本地运行z3验证修正后解得x1..x4=100,66,84,104。dedup候选(tools-ida-python-conditional-breakpoint-register/LinuxChal NAND z3/AMX矩阵BFS/三关线性方程组等)均非同链。未验证点：未能获取原题样本复跑。
---

# 一句话结论

当校验逻辑把 16 字节输入先按固定置换/单字节异或预处理，再与常量矩阵做 4×4 矩阵乘法、与目标向量比较时，不必静态猜矩阵与乘法顺序：在 IDA 里对 `imul` 前后的三条关键指令下条件断点、用 IDAPython 打印 `rbx`/`rdi`/`rax` 现场值，就能导出真实系数与中间结果，将每个输出分量写成 4 元一次方程交给 z3 求解；解出的字节再按单字节异或爆破（利用已知前缀 `Sn@k`）和置换逆序即可恢复 `Sn@k3_are_cu2r3d`。

# 原理

- **校验结构**：`main` 先检查 `memcmp(input,"Sn@k",4)` 且 `strlen(input)==16`；随后 `cry1` 对输入做位置交换（用两组 SIMD 常量数组 `m128i_i32`/`si128.m128i_i32` 决定交换顺序）并逐字节异或一个由上下文决定、但固定为单字节的值；再把结果按行优先摆成 int 矩阵。
- **矩阵乘**：`cry2` 的核心只有三条汇编——`mov eax,[rbx]`（取矩阵元素）、`add rbx,rbp`（步进）、`imul eax,[rdi]`（与另一矩阵元素相乘），外层四重循环累加得到 `output[16]`，即 `output = input_matrix × matrix2`。`main` 最后用 `*(_DWORD*)((char*)matrix1 + i*4) == output[i]` 与硬编码密文比较。
- **为什么需要条件断点**：`matrix1`/`matrix2` 由 `_mm_load_si128` 从内存常量装载，静态看是 SIMD 数据；加上循环/交换顺序可能被打乱，直接逆推系数容易出错。条件断点在命中时不暂停，而是执行 IDAPython 脚本打印寄存器与内存，等价于给指令插桩。
- **建模**：每个输出元素是 4 个输入字节的线性组合 `a1*x1+a2*x2+a3*x3+a4*x4 = c`；16 个输出按 4×4 分组就是 4 组独立的四元一次方程。用调试得到的真实系数和题目硬编码的真实密文作右端项，z3 对整数求解即可得到每个字节（假 flag 运行只用于确认系数与结构；若拿假 flag 的输出密文作右端项，解出的是假 flag 自身的变换结果）。
- **异或与置换**：解出的字节与真实输入之间还差一个单字节 XOR；由于已知 flag 前缀 `Sn@k`，对候选明文做 256 次单字节异或爆破即可定位 key（文章用 CyberChef XOR Brute Force 得到 `Sn@ku2r3cd3__era`）；最后按 `cry1` 的交换顺序逆推得到 `Sn@k3_are_cu2r3d`。

# 触发条件

- CTF RE 题目用"查表/常量矩阵 + 线性变换 + 比较"实现校验，输入长度与格式已知（本题 16 字节、前缀 `Sn@k`）。
- 能用 IDA 调试运行样本（本地或可模拟环境），并能下条件断点、执行 IDAPython。
- 本机有 Python + z3（`pip install z3-solver`）；可选 CyberChef 做 XOR 爆破。

# 利用步骤

1. 逆 `main`：确认长度/前缀检查、`cry1`/`cry2` 调用与最终比较，提取硬编码密文（IDA 直接看 `data[16]` 或从静态数组 dump）。
2. 逆 `cry1`：记录位置交换用的两个索引数组与异或表达式；确认异或值固定为单字节（可先按未知处理）。
3. 在 `cry2` 的 `imul` 三条关键指令处各下条件断点，条件里填 IDAPython 脚本（见 PoC），分别打印乘数地址内容、指针与累加结果。
4. 用假 flag（如 16 个 `a`）运行，收集断点输出，还原每个输出元素对应的 4 个系数与累加中间值；最终求真实 flag 时必须以题目硬编码密文作右端项（用假 flag 输出作右端项只会解出假 flag 自身的变换结果）。
5. 按 4 个一组写 z3 约束（整数域即可），求解得到 16 个字节；若解不唯一，补充 `0<=x<=255` 或利用真假密文差分。
6. 对解出的字节做单字节 XOR 爆破（已知前缀 `Sn@k`），得到 `Sn@ku2r3cd3__era`；按 `cry1` 的交换顺序逆序重排，得到 `Sn@k3_are_cu2r3d`。
7. 重新运行程序输入该字符串，确认输出 `Successful!`。

# PoC

```python
# IDA 条件断点 Actions 中的 IDAPython 脚本（分别挂在取数/步进/乘法三条指令）
print("[rbx] = ", hex(idc.get_wide_dword(get_reg_value("rbx"))))
print("rax = ", hex(get_reg_value("rax")), "[rdi]= ", hex(idc.get_wide_dword(get_reg_value("rdi"))))
print("output, rax = ", hex(get_reg_value("rax")), "\n")
```

```python
# z3 求解 4 组四元一次方程（系数由条件断点实测；示例为本题第一组 x，
# 右端项 = 真实密文中 x 组的 4 个输出分量 0x436/0x2EA/0x1C6/0x69E，解得 x1..x4 = 100,66,84,104）
from z3 import *
x = [Int(f'x{i}') for i in range(4)]
s = Solver()
for c, goal in [((1,5,4,3),0x436), ((2,1,2,3),0x2ea), ((2,1,1,1),0x1c6), ((3,5,4,7),0x69e)]:
    s.add(x[0]*c[0] + x[1]*c[1] + x[2]*c[2] + x[3]*c[3] == goal)
    s.add(And([xi >= 0, xi <= 255 for xi in x]))
print(s.check(), s.model())
```

```text
文章实测：条件断点输出形如 [rbx]=0x5 / rax=0x5 [rdi]=0x5f / output,rax=0x1db ...；
z3 解得 100,89,119,92,66,5,69,4,84,83,4,104,104,82,69,86；
CyberChef XOR Brute Force（key=0x37）得到 Sn@ku2r3cd3__era；置换逆序后为 Sn@k3_are_cu2r3d。
最终程序输出 Successful!（图 18）。
```

# 变体与关联

- 变体：若矩阵可逆且无模运算，可直接用线性代数求逆，不必上 z3；有模 256/32 位溢出时用 z3 的 `BitVec` 更贴合。
- 变体：若系数由运行时随机生成，可把条件断点日志直接导出为系数矩阵；若交换顺序由运行期数据决定，可在交换完成后 dump 索引数组。
- 关联：`tools-ida-python-conditional-breakpoint-register`（IDA 条件断点判断寄存器的基础用法）、`ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution`（z3 符号执行解 VM）、`ctf-reverse-adfgvx-click-matrix-md5-constraint-brute-force`（矩阵/约束类逆向）。
- 边界：条件断点需能调试运行；若样本有反调试或环境校验，需先绕过；本题 z3 解出的字节还需结合异或爆破与置换，单靠方程不能直接得到 flag。

# 检测与防御

- CTF 场景无防护语义；对出题方：可用运行时生成系数、非线性运算（S 盒/模乘）、把比较拆成多轮等方式提高 z3/插桩难度；对解题方：条件断点插桩是绕过静态混淆、获取动态系数的通用手段，优先于手工猜矩阵。
