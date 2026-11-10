---
id: ctf-pwn-awdp-stack-overflow-length-compare-binary-patch
title: AWDP fix：栈溢出/整数比较/输入长度类漏洞的二进制补丁（push 立即数缩长度、jle→jbe 修符号、.eh_frame 注入 read）
type: scenario
domain: ctf
path: ctf/pwn
technique: awdp-stack-overflow-length-compare-binary-patch
aliases:
- AWDP 栈溢出修复
- AwdPwnPatcher 脚本补丁
- patch_origin 改 push 长度
- JLE 改 JBE 负数绕过
- .eh_frame 注入 syscall read
- add_constant_in_ehframe
- evilPatcher 沙箱
tags:
- ctf
- pwn
- awdp
- binary-patching
- stack-overflow
- assembly
- eh-frame
- ida
- python
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:46:39+08:00'
  notes: 已对照原文核对：patch_origin(0x8048476,end=0x804847b,assembly=push 0x20)、patch_by_jmp(0x706,jmp_to=0x712) 配合 add_constant_in_ehframe 的 64 位格式串用法、.eh_frame 0x400F7D 处 syscall read stub（rax=0/rdi=0/lea rsi,[rbp+buf]/rdx=90h/syscall/jmp）、cmp eax,20h 的 jle 改 jbe 修负数绕过、evilPatcher 加沙箱与 IDA Apply patches 步骤均与原文一致；卡内只保留第三类补丁（长度/比较/输入函数），未重复既有的格式化字符串与 UAF 卡。未验证点：未在本地对样例二进制执行该补丁脚本，地址需按实际目标重算。
---

## 一句话结论

AWDP fix 阶段没有源码、只能交二进制补丁时，除了改 `printf`/`free` 这类调用点，还可以按漏洞类型直接改“长度/比较/输入函数”本身：把 `push 0x100` 之类的缓冲区尺寸立即数改小（`patch_origin`），把有符号比较 `jle` 改成无符号 `jbe` 堵住负数绕过，或在 `gets` 这类无法控制长度的场景把流程劫持到 `.eh_frame` 代码洞里用 `syscall` 自建 `read`；用 `AwdPwnPatcher` 把每一种补丁固化成可复现的 Python 脚本，比手工在 IDA 里改字节更稳。

## 原理

- **长度立即数是最省事的补丁点**：栈溢出题的 `main` 里常见 `mov/push` 一个尺寸常量再 `read`/`fgets`。把这个常量改小（如 `push 0x20` 替代原 `push 0x100`）就同时缩小了可写入长度，不需要动调用链、不破坏栈平衡（`push` 与后续 `pop`/`add rsp` 的配对照原序列调整时需核对）。
- **比较指令的符号性决定绕过**：`cmp eax, 20h; jle loc` 用的是有符号“小于等于”，输入 `-1` 满足条件从而跳过长度检查；改成 `jbe`（无符号）后负数被视作极大值，检查生效。这是“只看操作数不看符号”的常见修复缺口。
- **`gets` 无法限长时改输入通道**：`gets` 本身没有长度参数，补丁思路是让流程跳到一段自己写的代码（`.eh_frame` 段可写可执行、通常有足够空位），用 `mov rax,0; mov rdi,0; lea rsi,[rbp+buf]; mov rdx,0x90; syscall` 实现定长 `read`，再 `jmp` 回主流程。
- **字符串/常量注入到代码洞**：`add_constant_in_ehframe` 把 `"%s"` 之类的常量追加进 `.eh_frame`，再在 `patch_by_jmp` 里用 `lea rdi,[rip+off]` 引用，等价于“给二进制加一个只读字符串池”，解决 64 位下“想改成 `printf("%s", buf)` 但原指令空间/常量都没有”的问题。
- **脚本化的价值**：`patch_origin(start, end, assembly)` 按“原指令区间”整段替换、`patch_by_jmp(from, jmp_to, assembly)` 在空闲区写入汇编并跳转、`patch_by_call` 只改调用目标；补丁位置、机器码与注释都在脚本里，重打/换版本/复核都快，也便于团队共享。
- **沙箱通防**：`evilPatcher` 一类工具配合 IDA 的 `Edit -> Patch program -> Apply patches to input file` 可以直接改可执行文件；防守方也可以在 `sandboxs` 里改禁用规则，配合沙箱做“通防”（限制危险调用）。

## 触发条件

- AWDP/CTF 修复环节，只能提交二进制补丁（`update.tar` 里的可执行文件），无源码或不允许重编译。
- 目标漏洞属于“长度常量可改/比较符号可改/输入函数无长度参数”三类之一，且能定位到具体指令地址。
- 有 IDA（或等效反汇编器）+ `AwdPwnPatcher`（Python）或 KeyPatch/evilPatcher 等补丁工具。
- 目标段表里有可执行代码洞（如 `.eh_frame`）可用于注入自定义 stub；或原指令区间足够容纳替换序列。
- 能本地跑原 PoC 做回归，确认补丁后攻击失效且正常功能未坏。

## 利用步骤

1. 定位漏洞点：栈溢出看 `read/fgets/gets` 前的长度常量；整数绕过看 `cmp/jle/jge` 组合；`gets` 场景确认栈上缓冲区与返回地址布局。
2. 选择补丁形态：
   - 改长度：`patch_origin(addr, end=<下一条指令地址>, assembly="push 0x20")`，核对后续 `pop`/`add rsp` 是否仍配平；
   - 改符号：把 `jle` 的机器码换成 `jbe`（同长度、仅条件码不同，最安全的一类单字节替换）；
   - `gets` 场景：在 `.eh_frame` 写入 `read` stub，把 `call gets` 改成 `jmp` 到 stub，stub 末尾 `jmp` 回原流程；
   - 需要固定格式串：先 `add_constant_in_ehframe("%s\x00\x00")` 得到偏移，再在跳转补丁里 `lea rdi, [rip+off]`。
3. 用脚本落地：每个补丁一段 `AwdPwnPatcher` 代码（`patch_origin`/`patch_by_jmp`/`patch_by_call` + `save()`），保持地址与原文一致并注释用途。
4. IDA 里 `Edit -> Patch program -> Apply patches to input file` 复核字节是否与脚本一致，避免脚本偏移算错。
5. 回归：用原 exp 打补丁后的二进制，确认溢出/负数绕过/超长输入都被拦住；再跑正常功能路径（合法长度、边界长度、空输入）。
6. 打包 `update.tar` 前检查文件权限与大小，提交后保留补丁脚本与回归记录。

## PoC

```python
# 1) 栈溢出：把输入长度常量改小（patch_origin 覆盖原 push 指令区间）
from AwdPwnPatcher import *
p = AwdPwnPatcher("pwn")
p.patch_origin(0x8048476, end=0x804847b, assembly="push 0x20")
p.save("pwn_patched")
```

```asm
; 2) 整数比较：把有符号 jle 改成无符号 jbe（同长度条件码替换）
cmp     eax, 20h
jbe     short loc_safe        ; 原为 jle，输入 -1 不再绕过
```

```asm
; 3) gets 无法限长：跳到 .eh_frame 里的自建 read 再回主流程
; .eh_frame:0x400F7D
mov     rax, 0                ; __NR_read
mov     rdi, 0                ; fd = 0
lea     rsi, [rbp+buf]        ; 目标缓冲区
mov     rdx, 90h              ; 固定长度
syscall
jmp     loc_main_continue
```

```python
# 4) 64 位下需要固定格式串：在 .eh_frame 注入 "%s"，再用 lea 引用
p = AwdPwnPatcher("pwn64")
off = p.add_constant_in_ehframe("%s\x00\x00")
asm_str = f"""
mov rsi, qword ptr [rbp-0x8]
lea rdi, qword ptr [rip+{hex(off)}]
"""
p.patch_by_jmp(0x706, jmp_to=0x712, assembly=asm_str)
p.save()
```

说明：地址与偏移取自原文示例，实际必须按目标二进制重新计算；`patch_origin` 的 `end` 是原指令区间的“下一条指令地址”，覆盖长度与替换汇编的机器码长度之间会由工具补 `nop`/调整，需用 IDA 复核。本条未在本地复跑。

## 变体与关联

- 变体：把 `push 长度` 改成“`cmp` 上限 + 提前返回”的组合补丁，比单纯缩小缓冲更不易被绕过。
- 变体：`jle→jbe` 之外，`jg/jge` 与 `ja/jae` 的互换同样用于修正符号性错误；也可改成对输入做 `and eax,0x7fffffff` 之类的钳制。
- 变体：`.eh_frame` 不可用时，选 `.init_array`、`.fini_array` 尾部或段间空隙作为代码洞；也可直接在 `.text` 尾部追加新段（需同步段表）。
- 关联：[[ctf-pwn-awdp-format-string-patch]]（改 `call printf` 为 `puts`/固定格式串，同属“改调用点”类补丁）、[[ctf-pwn-awdp-uaf-free-patch]]（释放点清指针，属“改数据流”类补丁）；本条补的是“改长度常量/比较符号/输入函数”第三类，且给出 64 位 `add_constant_in_ehframe` 用法。
- 边界：换编译优化级别或不同版本时指令序列全变，脚本里的硬编码地址失效；原地汇编若语义不成立（工具补 `nop` 破坏上下文）必须改用 jmp 代码洞方案。

## 检测与防御

- 检测（作为攻击方复盘/出题方校验）：对比补丁前后二进制，`.text` 中长度立即数变化、条件码字节变化（`0x7e`↔`0x76` 等）、`.eh_frame` 出现 `syscall`/新增可执行 stub，都是补丁痕迹。
- 防御（开发侧）：不要用固定长度常量作为唯一防线，输入长度应与缓冲区尺寸绑定校验；比较用无符号/显式范围判断；禁用 `gets`，改用 `fgets/read` 并检查返回值。
- 修复侧纪律：补丁要覆盖所有同类输入点（不止一处 `read`），并保留原 PoC 回归用例；补丁脚本入库便于复核与回滚。
