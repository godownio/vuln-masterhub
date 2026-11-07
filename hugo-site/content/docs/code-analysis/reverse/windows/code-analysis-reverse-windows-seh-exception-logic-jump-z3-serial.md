---
id: code-analysis-reverse-windows-seh-exception-logic-jump-z3-serial
title: SEH 除零异常隐藏校验分支：在 __except 块下断点 + Z3 还原序列号
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: seh-exception-logic-jump-z3-serial
tags:
- reverse
- windows
- seh
- exception-handling
- ida
- z3
- crackme
- ctf
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V226
  verified_at: '2026-11-07T06:56:19+08:00'
  notes: 已对照原文与15张图逐项核对序列号逻辑：v7[3..5]==0x33/0x35/0x33、前三位和==0x95、fold=esi*16+(c-0x30)==0x401353；图04/10/11/12与Z3约束一致，按约束穷举仅 401353/3A!353 两解；已修正卡内“call指令最后一个字节”为“返回地址指向call后下一条指令起始字节（0x401354为其中间字节、被解析为pop eax）”；原文未在程序中验证候选序列号，未复跑。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-seh-exception-logic-jump-z3-serial/
draft: false
kb_aliases:
- 基于异常处理的逻辑跳转
- SEH 隐藏校验
- try/except 逆向
- 除零异常触发
- 异常块下断点
- Z3 解序列号
---

## 一句话结论

MSVC x86 程序把真正的序列号校验藏在 `__try/__except` 的 except 块里，用 `div` 除零异常实现隐藏跳转：`call` 压入的返回地址 `0x401353` 被被调函数的 `pop eax` 取出，`sub esi,eax` 把输入折叠值 esi 与 `0x401353` 比较，相等时 `div esi` 触发 `0xC0000094` 进入 `__except` 并打印 success；因此不要在 `div` 上单步（调试器会卡在异常），直接在 except 块首 `loc_401379` 下断点、让程序自己派发异常，再按折叠公式 `esi = esi*16 + (c - 0x30)` 用 Z3 约束 `esi == 0x401353`，即可解出 `401353` 与 `3A!353` 两个候选序列号。

## 原理

- **MSVC SEH 的数据结构**：x86 `__try/__except` 在栈上维护 `CPPEH_RECORD`（IDA 里显示为 `ms_exc`），其中 `ms_exc.registration.TryLevel` 标记当前 try 层级。`mov [ebp+ms_exc.registration.TryLevel], 0` 表示进入最外层 try；`ms_exc.old_esp` 保存异常发生前的栈指针。异常产生后系统沿 SEH 链调用 filter（本例 `loc_401373` 执行 `mov eax,1; retn`，返回 `EXCEPTION_EXECUTE_HANDLER`），然后跳入 except 块；except 块首的 `mov esp,[ebp+ms_exc.old_esp]` 恢复异常前的栈，避免异常现场导致的栈错乱。
- **隐藏跳转的关键**：try 块内是 `test esi,esi; jz loc_40135D; push eax; call loc_401354`。被调函数 `loc_401354` 的第一条指令是 `pop eax`，它弹出的不是前面 `push eax` 压入的值，而是 `call` 指令压入的返回地址 `0x401353`——该地址是 `call` 之后下一条指令的起始字节（IDA 在 0x401353 处显示 `db 0E8h`，而 `call` 目标 0x401354 落在该指令内部、被解析为 `pop eax`），所以容易被忽略。随后 `sub eax,0` 是冗余指令，`sub esi,eax` 计算 `esi = esi - 0x401353`，最后 `div esi`：当且仅当 esi 等于 `0x401353` 时除数为 0，触发整数除零异常，控制流被异常派发“跳”到 except 块；不等时除法正常执行，程序沿被隐藏的失败路径继续。
- **为什么 IDA/Hex-Rays 容易看漏**：Hex-Rays 对 MSVC SEH 恢复不完整，F5 得到的 main 伪代码会把 except 块的控制流错误折叠，看不到真正的判断；需要在汇编/图视图里识别 `TryLevel`、`__except filter // owned by`、`__except(...)` 三类注释和 `old_esp` 恢复，才能把 try、filter、except 三块分开。
- **输入约束**：main 先做长度与字符检查——长度小于 7（即 6 字节）、`v7[3]=='3'`、`v7[4]=='5'`、`v7[5]=='3'`、`v7[0]+v7[1]+v7[2]==0x95`（149）。随后循环 `movzx eax,[ebp+ecx+inputflag]; shl esi,4; add esi,0FFFFFFD0h; add esi,eax`，等价于 `esi = esi*16 + (c - 0x30)`，把 6 个字符折叠成一个 32 位值；折叠值等于 `0x401353` 才会触发上面的除零并进入 except 打印 `success!`。
- **Z3 求解**：把“前三位字符和 == 0x95”“后三位固定为 `353`”“折叠值 == 0x401353”“前三位 >= 33（可打印下界，原文额外加的限制）”交给 Z3，得到 `401` 与 `3A!` 两组前三位；两者折叠值都等于 `0x401353`，拼上固定后缀即 `401353`、`3A!353`。原文只打印这两个模型，未截图在程序中验证哪一个（或两个都）能输出 success，属于本卡的待验证点。

## 触发条件

- 目标为 MSVC 编译的 Windows PE32（x86）程序，使用 `__try/__except`，且真正的分支判断/校验逻辑被放在 except 块或由异常跳转决定。
- 异常触发点是一个可预期的故障指令（本例 `div` 除零，异常码 `0xC0000094`），并且触发条件由输入或运行时值控制。
- 分析者能用 IDA 加载并调试该程序，能看到或手动识别 `ms_exc.registration.TryLevel`、`__except filter`、`__except` 块。
- 需要恢复的输入空间足够小，约束可以表达为整数/位向量公式并交给 Z3 等 SMT 求解器。

## 利用步骤

1. 识别文件与编译器（PE32、I386、MSVC 2015 控制台程序）；在 IDA 中把字符串编码设为 GBK，正确读出“请输入序列号:”“success!”“error”等提示，先还原程序交互。
2. 在函数图/汇编中搜索 `mov [ebp+ms_exc.registration.TryLevel], 0`、`__except filter // owned by ...`、`__except(...)` 注释，标出 try 块 `loc_401342`、filter `loc_401373`、except 块 `loc_401379`。
3. 分析 try 块：`test esi,esi; jz ...; push eax; call loc_401354`。进入 `loc_401354`，识别 `pop eax` 取的是 `call` 返回地址 `0x401353`，`sub esi,eax` 后 `div esi` 的除零条件为 `esi == 0x401353`。
4. 在 except 块首地址（`loc_401379`）下断点，F9 运行程序并触发异常；IDA 弹出 “Integer divide by zero (exc.code c0000094)” 后点确定，程序会自行把控制流交给 except，断点命中。不要在 `div` 指令上单步或让调试器反复接管异常，否则会卡在异常处理循环里。
5. 在 except 块内跟完：`mov esp,[ebp+ms_exc.old_esp]` 恢复栈、循环计算输入长度、逐字节 `add ax,9; mov word_41F300[ecx*2],ax` 变换，最后 `push offset aSuccess; call sub_401410` 输出成功提示；确认成功条件就是异常被触发。
6. 回到输入检查：记录长度 < 7、后三位固定为 `3`、`5`、`3`、前三位字符和 == 0x95，以及折叠循环的 `esi*16 + (c - 0x30)` 公式。
7. 把约束写成 Z3/SMT：`v4=0x33, v5=0x35, v6=0x33`，`v1+v2+v3==0x95`，`fold(v1..v6)==0x401353`，再加可打印下界 `v1,v2,v3>=33`；枚举模型得到 `401353`、`3A!353`。
8. 将候选序列号输入程序，确认输出 `success!`（原文未展示该验证步骤，需自行复跑）。

## PoC

原文 Z3 脚本（整理后）：

```python
from z3 import *

v1, v2, v3 = Int('m1'), Int('m2'), Int('m3')
v4, v5, v6 = 0x33, 0x35, 0x33  # '3', '5', '3'

s = Solver()
s.add(And(
    v1 + v2 + v3 == 0x95,
    v6 + 0x10*(v5 + 0x10*(v4 + 0x10*(v3 + 0x10*(v2 + 0x10*(v1 + 0x10*0 - 0x30) - 0x30) - 0x30) - 0x30) - 0x30) - 0x30 == 0x401353,
    v1 >= 33, v2 >= 33, v3 >= 33,
))

while s.check() == sat:
    m = s.model()
    chars = [m[v1], m[v2], m[v3], v4, v5, v6]
    print("".join(chr(int(str(c))) for c in chars))
    s.add(Or(v1 != m[v1], v2 != m[v2], v3 != m[v3]))
```

输出：

```text
401353
3A!353
```

等价的折叠函数可直接验证两个候选：

```python
def fold(s: str) -> int:
    x = 0
    for ch in s.encode():
        x = (x * 16 + (ch - 0x30)) & 0xffffffff
    return x

assert fold("401353") == 0x401353
assert fold("3A!353") == 0x401353
```

## 变体与关联

- **变体：异常类型不同**。除零 `div` 之外，也可用非法内存访问、`int 3`、非法指令等触发 SEH；分析方法相同——找到 `TryLevel`/filter/except，分析异常触发条件，再在 except 块下断点。
- **变体：VEH 或自定义异常处理**。如果隐藏逻辑在 `AddVectoredExceptionHandler` 注册的 VEH 中，异常先于 SEH 派发；可在 VEH 回调或异常处理器上下断点，参考 [[code-analysis-dynamic-debugging-veh-invisible-breakpoint-dynamic-patch]] 与 [[code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack]]。
- **关联：其他隐藏校验分支**。API inline hook 把校验放进 hook 函数、TLS callback 在 OEP 前执行、VM/花指令隐藏控制流，都属于“表面逻辑是诱饵、真逻辑在别处”的同一类反分析手法，可参考 [[code-analysis-reverse-windows-api-hook-hidden-aes-branch]]、[[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]。
- **求解替代**：输入空间较小可直接穷举；公式复杂时可用 angr/Triton 做符号执行，或按 `esi = esi*16 + (c-0x30)` 的线性递推手算；Z3 适合本例这种“字符和 + 折叠值”的多约束组合。

## 检测与防御

- **识别信号（分析侧）**：PE 中出现 `ms_exc.registration.TryLevel`、`__except filter`、`old_esp` 恢复序列；`call` 目标落在指令中间（`db 0E8h`）；`pop` 后立即用返回值参与减法和 `div`/内存访问；正常路径只做表面检查、成功/失败输出却在异常块内。这些组合强烈提示“异常驱动隐藏分支”。
- **调试要点**：在异常处理器（except 块/VEH 回调）下断点，而不是在故障指令上单步；让被测程序自己派发异常，避免调试器接管后反复停在 `0xC0000094`。必要时在 IDA 的异常选项中把除零/访问违规交给程序处理。
- **防御/设计侧**：这种异常跳转只是提高逆向成本，不构成安全边界；客户端序列号校验无论怎么藏都能被静态还原，真正的许可/授权应在服务端做签名校验或使用不可离线复用的凭证。恶意样本若用同样手法隐藏 C2/配置，可按上述断点法定位异常处理器后 dump 解密结果。
- **与反调试区分**：本例的 SEH 是“隐藏正常逻辑”，不是 `SetUnhandledExceptionFilter`/`INT 2D` 那类检测调试器的反调试；后者可参考 [[code-analysis-reverse-anti-debug-exception-timing-checksum-bypass]]，两者异常码与行为不同。
