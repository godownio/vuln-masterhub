---
id: ctf-reverse-angr-symbolic-dynamic-memory-fake-pointer
title: angr 符号化动态内存输入：blank_state 后把 malloc 指针改成伪地址再写入符号向量
type: scenario
domain: ctf
path: ctf/reverse
technique: angr-symbolic-dynamic-memory-fake-pointer
tags:
- ctf
- reverse
- angr
- symbolic-execution
- claripy
- linux
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V693
  verified_at: '2026-11-13T17:54:08+08:00'
  notes: 已对照原文及 8 图核对：blank_state(0x08048699) 跳过 scanf、向 0x0abcc8a4/0x0abcc8ac 两个 i386 4 字节指针写入伪地址 0x12345678/0x12345678-100、再 store BVS v1/v2、explore 按 Good Job/Try again 判定，与原文脚本一致；图02 终端输出 UBDKLMBV UNOERNS。已修正草稿中“两个 8 字节指针”的笔误与一句话结论中“先读进栈再 scanf 进堆”的错误描述（该题 scanf 直接写入 malloc 堆）。未本地复现。
url: /docs/ctf/reverse/ctf-reverse-angr-symbolic-dynamic-memory-fake-pointer/
draft: false
kb_aliases:
- 06_angr_symbolic_dynamic_memory
- angr 符号向量保存在内存
- angr malloc 输入符号化
- angr fake address
---

## 一句话结论

当目标程序把输入读入 `malloc` 堆缓冲区、而缓冲区地址保存在全局指针变量里（符号执行中真实堆地址未知）时，可从读入后的指令地址 `blank_state` 起步（跳过 scanf），把保存 malloc 返回值的全局指针变量改写为任意伪地址（如 0x12345678），再把 claripy 符号向量写到这些伪地址，程序后续按指针取输入时即读到符号值，`simgr.explore` 命中 "Good Job" 后 `solver.eval` 还原输入。

## 原理

- `p.factory.blank_state(addr=start_addr)` 跳过程序前半段（含真实输入），直接从指定指令开始符号执行；未初始化的寄存器/内存只产生 warning，不影响求解。
- 程序把 `malloc` 返回值存在指针变量中（如 0x0abcc8a4/0x0abcc8ac，i386 下各 4 字节），后续 `strncmp(buffer0, "UODXLZBI", 8)` 通过该指针读取用户输入。直接在真实堆地址写符号向量不可行（堆地址在符号执行中未知），所以先用 `state.memory.store(buffer1, fake_addr1, endness=p.arch.memory_endness)` 把指针变量改成伪地址——大小端必须按 `p.arch.memory_endness` 处理。
- 再 `state.memory.store(fake_addr1, v1)` 把 64 位符号向量落到伪地址；程序解引用指针时读到的就是符号值。
- 两个输入对应两个指针变量与两个伪地址（如 0x12345678 与 0x12345678-100），分别约束；explore 以 stdout 是否含 "Good Job"/"Try again" 区分成功与失败路径。
- 符号向量本身不需要关心大小端（claripy 位向量），需要处理的只是内存存储顺序。

## 触发条件

- 目标为无 PIE 的 x86/x64 ELF，输入经指针间接存放（malloc 堆缓冲区），且能从输入读取后的固定地址 blank_state；
- 已知两个输入缓冲区的指针变量地址、比较成功/失败的输出字符串；
- 输入长度固定、比较函数可被 angr 正常符号执行（无复杂反调试/系统调用副作用）。

## 利用步骤

1. IDA 定位读入完成后的指令地址（如 0x08048699），确认两个输入缓冲区指针变量的地址（0x0abcc8a4/0x0abcc8ac）。
2. `blank_state(addr=start_addr)`，向两个指针变量地址写入自选伪地址（注意 endness）。
3. 创建 `claripy.BVS('v1', 64)`、`v2` 并 store 到两个伪地址。
4. `simgr.explore(find=is_good, avoid=is_bad)`，is_good/is_bad 用 `state.posix.dumps(1)` 匹配 "Good Job"/"Try again"。
5. `solver.eval(v1, cast_to=bytes)` 输出两个输入字符串。

## PoC

```python
import angr, claripy
p = angr.Project('06_angr_symbolic_dynamic_memory')
init_state = p.factory.blank_state(addr=0x08048699)
fake_addr1, fake_addr2 = 0x12345678, 0x12345678 - 100
buffer1, buffer2 = 0x0abcc8a4, 0x0abcc8ac
init_state.memory.store(buffer1, fake_addr1, endness=p.arch.memory_endness)
init_state.memory.store(buffer2, fake_addr2, endness=p.arch.memory_endness)
v1 = claripy.BVS('v1', 64); v2 = claripy.BVS('v2', 64)
init_state.memory.store(fake_addr1, v1); init_state.memory.store(fake_addr2, v2)
simgr = p.factory.simgr(init_state)
simgr.explore(find=lambda s: b"Good Job" in s.posix.dumps(1),
               avoid=lambda s: b"Try again" in s.posix.dumps(1))
if simgr.found:
    print(simgr.found[0].solver.eval(v1, cast_to=bytes),
          simgr.found[0].solver.eval(v2, cast_to=bytes))
```

## 变体与关联

- 单输入同法：只改一个指针变量。
- 输入在全局数组而非堆：可直接在全局地址 store 符号向量，无需伪指针。
- 文件输入见 SimFile 卡；逐字符比较引起路径爆炸时改用约束表达式 card。

## 检测与防御

CTF 场景无防御；工程上可加反符号执行（环境检测、复杂外部调用、超长比较循环造成路径爆炸）提高求解成本。
