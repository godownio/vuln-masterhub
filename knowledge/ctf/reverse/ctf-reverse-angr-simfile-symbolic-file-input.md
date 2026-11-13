---
id: ctf-reverse-angr-simfile-symbolic-file-input
title: angr 符号化文件输入：SimFile 模拟文件内容并把符号向量插入 state.fs
type: scenario
domain: ctf
path: ctf/reverse
technique: angr-simfile-symbolic-file-input
aliases:
- 07_angr_symbolic_file
- angr SimFile
- angr 文件输入符号化
- OJKSQYDP.txt
tags:
- ctf
- reverse
- angr
- symbolic-execution
- simfile
- linux
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V693
  verified_at: '2026-11-13T17:54:10+08:00'
  notes: 已对照原文及图03/04核对：fopen OJKSQYDP.txt、fread 0x40、blank_state(0x080488e7)、claripy.BVS('v',0x40*8)、angr.storage.SimFile(name,content=v,size=0x40)、state.fs.insert 与原文脚本一致；程序先 scanf+ignore_me+memset 再读文件，真正参与校验的是文件内容，卡片描述属实。图04 输出仅前 8 字节有效（AZOMMMZM），其余为未约束字节，原文未说明，PoC 照录原文。未本地复现。
---

## 一句话结论

当目标程序从固定文件名（如 OJKSQYDP.txt）读取 0x40 字节作为校验输入时，可创建 `angr.storage.SimFile`，把 0x40*8 位的 claripy 符号向量作为文件内容，并用 `state.fs.insert(filename, simfile)` 挂到初始状态的文件系统；符号执行时程序 `fopen/fread` 读到的就是符号数据，explore 命中 "Good Job" 后 eval 出文件内容即为答案。

## 原理

- angr 的 state 带有模拟文件系统（SimMount/SimFile）。程序 `fopen` 打开文件时从 state.fs 解析；插入同名 SimFile 后，`fread` 会将文件内容作为符号数据读入程序缓冲区。
- `angr.storage.SimFile(name=filename, content=v, size=0x40)` 用 `claripy.BVS('v', 0x40*8)` 作为内容，长度与读取长度一致；文件内容全部是符号位，约束求解器可在成功路径上求出满足校验的具体字节。
- 从读取文件之后的指令地址 blank_state 起步，跳过前面的交互输入，只让文件数据成为符号输入。
- 注意示例中程序先 `scanf` 再 `memset` 覆盖栈缓冲、再读文件，所以真正参与校验的是文件内容；文件名、大小必须与二进制一致，否则 fopen 失败走不到校验。

## 触发条件

- 程序读取固定名称文件作为输入，且文件大小/读取长度已知；
- 无 PIE、可从文件读取后的固定地址 blank_state；
- 校验逻辑可符号执行，成功/失败输出可区分。

## 利用步骤

1. IDA 确认 fopen 文件名、fread 长度（0x40）、读取后起始地址（0x080488e7）。
2. `blank_state(addr=start_addr)`；`v = claripy.BVS('v', 0x40*8)`。
3. `simfile = angr.storage.SimFile(name='OJKSQYDP.txt', content=v, size=0x40)`；`init_state.fs.insert(filename, simfile)`。
4. `simgr.explore(find=is_good, avoid=is_bad)`。
5. `solver.eval(v, cast_to=bytes)` 得到文件内容。

## PoC

```python
import angr, claripy
p = angr.Project('07_angr_symbolic_file')
init_state = p.factory.blank_state(addr=0x080488e7)
v = claripy.BVS('v', 0x40*8)
filename = 'OJKSQYDP.txt'
simfile = angr.storage.SimFile(name=filename, content=v, size=0x40)
init_state.fs.insert(filename, simfile)
simgr = p.factory.simgr(init_state)
simgr.explore(find=lambda s: b"Good Job" in s.posix.dumps(1),
               avoid=lambda s: b"Try again" in s.posix.dumps(1))
if simgr.found:
    print(simgr.found[0].solver.eval(v, cast_to=bytes))
```

## 变体与关联

- 输入同时在栈上出现时，用符号内存（伪指针）方案。
- 文件内容参与逐字符比较导致路径爆炸时，explore 到比较函数前再 add_constraints。
- 也可用 `state.posix.files` 或 SimFile 的 `size` 参数控制截断行为。

## 检测与防御

CTF 场景无防御；实际程序可校验文件大小/魔数/校验和并做反调试，增加符号化成本。
