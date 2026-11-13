---
id: ctf-reverse-angr-constraints-avoid-path-explosion
title: angr 约束表达式替代逐字符比较：explore 到比较点后 add_constraints 防路径爆炸
type: scenario
domain: ctf
path: ctf/reverse
technique: angr-constraints-avoid-path-explosion
tags:
- ctf
- reverse
- angr
- symbolic-execution
- constraints
- path-explosion
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V693
  verified_at: '2026-11-13T17:54:13+08:00'
  notes: 已对照原文及图05/06核对：08 题 qmemcpy 密码常量 AUPDNNPROEZRJWKB、check_equals_AUPDNNPROEZRJWKB 逐字节比较 16 字节，explore 到比较函数入口 0x08048565 后 memory.load(0x804a050,0x10) 加载已变换缓冲区并加等式约束，思路与原文一致（等价于把 2^16 分支交给 SMT）。原文脚本 project 误写成 07_angr_symbolic_file（图06 warning 也指向 07），卡片 PoC 已按题号更正为 08_angr_constraints，并把期望字符串改为 bytes 适配现代 angr；图06 仅见 exit 状态过多 warning，未本地复现。
url: /docs/ctf/reverse/ctf-reverse-angr-constraints-avoid-path-explosion/
draft: false
kb_aliases:
- 08_angr_constraints
- angr 路径爆炸
- angr add_constraints
- 构建表达式防路径爆炸
- angr strcmp 循环
---

## 一句话结论

当程序用 for 循环逐字节比较输入（如 `check_equals_*` 比较 16 字节）时，angr 会按每个字节的相等/不等分叉出 2^N 条路径导致路径爆炸或 exit 状态过多；正确做法是让 `simgr.explore(find=比较函数入口地址)` 只走到比较前，然后从解状态内存中 load 出待比较的符号向量，直接 `state.solver.add(loaded == 期望字符串)`，再 eval 原始符号变量得到输入。

## 原理

- 逐字节比较循环在符号执行中每轮都会产生"该字节相等/不等"两个分支；16 字节即最多 2^16 条路径，angr 会报 `Exit state has over N possible solutions` 或直接超时。
- 约束法把"比较过程"从符号执行中移除：先 explore 到比较函数的入口（此时内存中已有符号化的输入缓冲区），`solution_state.memory.load(addr, size)` 取出该缓冲区的位向量，再对"缓冲区位向量 == 期望常量字符串"添加单一约束——等价于把比较循环的语义直接交给 SMT 求解器，一步约束出所有字节。
- `solver.eval(password, cast_to=bytes)` 求原始 BVS；注意 `add_constraints` 的参数是相等表达式而非布尔值，期望字符串需按内存字节序书写。

## 触发条件

- 输入缓冲区地址固定（无 PIE 或已知基址）、以符号向量形式存在于内存；
- 能定位逐字节比较函数入口地址与待比较缓冲区地址/长度；
- 比较目标常量字符串在二进制中可见（或可推）。

## 利用步骤

1. IDA 定位：输入写入地址（如 0x804a050）、比较函数入口（0x08048565）、比较长度 0x10、期望字符串（'AUPDNNPROEZRJWKB'）。
2. `blank_state(addr=0x8048625)` 后把 `claripy.BVS('password', 128)` store 到输入地址。
3. `simgr.explore(find=0x08048565)` 只走到比较前，避免进入循环。
4. 从 found 状态 `memory.load(0x804a050, 0x10)` 取位向量，`solver.add(bv == b'AUPDNNPROEZRJWKB')`。
5. `solver.eval(password, cast_to=bytes)` 输出答案。

## PoC

```python
import angr, claripy
p = angr.Project('08_angr_constraints')
st = p.factory.blank_state(addr=0x8048625)
password = claripy.BVS('password', 128)
st.memory.store(0x804a050, password)
sm = p.factory.simgr(st)
sm.explore(find=0x08048565)
if sm.found:
    s = sm.found[0]
    bv = s.memory.load(0x804a050, 0x10)
    s.solver.add(bv == b'AUPDNNPROEZRJWKB')
    print(s.solver.eval(password, cast_to=bytes))
```

## 变体与关联

- 也可用 `simgr.explore(find=..., avoid=...)` 配合 `state.posix.dumps` 判定输出，但比较点多时约束法更稳。
- 需要绕过比较函数时可用 SimProcedure hook 直接返回 1（原文第 9 节只给概念与同一 constraints 脚本，未给出实际 hook 实现）。
- 与 z3 直接建模等价：angr 约束本质就是 SMT 求解。

## 检测与防御

CTF 场景无防御；工程上可把比较改成带副作用的混淆（如哈希后比较、分块加密）提高符号求解成本。
