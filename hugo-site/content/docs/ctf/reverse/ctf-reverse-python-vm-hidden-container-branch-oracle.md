---
id: ctf-reverse-python-vm-hidden-container-branch-oracle
title: Python 3.13 自定义 VM 逆向：隐藏容器解密 + 逐字节分支 oracle 求解
type: scenario
domain: ctf
path: ctf/reverse
technique: python-vm-hidden-container-branch-oracle
tags:
- ctf
- reverse
- python
- vm
- pyc
- hidden-container
- branch-oracle
- bytecode
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:52+08:00'
  notes: 已对照原文Salome段核对：M13P容器格式与解密公式、MirageVM 16条指令、逐字节PUSH_INPUT/CMP_EQ/JZ分支oracle、stage1 fake flag与stage2解均与原文一致。未验证点：PoC未本机复跑；原文“第二段返回Trace deeper.”与stage2得到flag body存在表述差异，卡片按VM比较逻辑描述；frontmatter无sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-python-vm-hidden-container-branch-oracle/
draft: false
kb_aliases:
- Salome
- MirageVM
- Python VM 逆向
- M13P 容器
- winsound.pyd 隐藏字节码
- 分支 oracle 逐字节
- pyc 反编译
---

## 一句话结论

`main.pyc` 先执行 `opcode.bin` 的第一段 VM（返回 fake flag，外层丢弃），再把伪装成 `winsound.pyd` 的 `M13P` 容器解密成第二段 1600 字节字节码；第二段 `MirageVM` 对输入逐字节 `CMP_EQ` 后 `JZ` 到失败出口，可以在每次 `PUSH_INPUT` 处快照 VM、枚举 256 个候选、保留“分支不跳转”的候选，逐字节恢复真实输入。

## 原理

- 外层 `CustomVM.run()`：先跑 `opcode.bin`，丢弃结果；再读取 `_resource_dir()/winsound.pyd`，用 `unpack_hidden_payload` 解密后跑第二段，只有第二段返回 `"Trace deeper."` 才打印 `Accepted.`。
- `M13P` 容器格式：`magic(4) + key(1) + seed(1) + length(2, LE) + checksum(1) + body`；`plain[i] = body[i] ^ ((key + seed + i*11) & 0xff) ^ b"curtain"[i % 7]`，`checksum = sum(plain) & 0xff`。
- `MirageVM` 指令集：`PUSH_IMM(0x01)`、`PUSH_INPUT(0x02)`、`XOR_IMM(0x03)`、`ADD_IMM(0x04)`、`ROL_IMM(0x05)`、`STORE(0x06)`、`LOAD(0x07)`、`XOR_SLOT(0x08)`、`ADD_SLOT(0x09)`、`CMP_EQ(0x0a)`、`JZ(0x0b)`、`JMP(0x0c)`、`PRINT_MSG(0x0d)`、`HALT(0x0e)`、`DUP(0x0f)`、`POP(0x10)`；槽位 16 个，值 8 位。
- 第二段程序对每个输入下标 `idx`：`PUSH_INPUT idx`，用多个状态槽做 `XOR/ADD/ROL`，得到 8 位结果，`CMP_EQ expected`，再 `JZ fail`；只有该字节正确才会继续。
- 逐字节求解：在 VM 执行到 `PUSH_INPUT idx` 时复制 VM 状态；对候选 0..255 分别运行到下一个分支，若 `branch_not_taken` 则保留；选第一个候选（或结合后续约束筛选），更新 VM 继续。
- 第一段 `opcode.bin` 同样结构，但返回 fake flag `flag{Y0uWe1eTr1ckEdbaby}`；真实 flag 由第二段给出。

## 触发条件

- 目标是 Python 打包的 exe/pyc（案例 Python 3.13），主逻辑加载自定义字节码/VM。
- 存在隐藏容器/伪装文件（如 `winsound.pyd`）承载第二段字节码。
- VM 指令可逐条解释，比较为“生成 1 字节 → CMP_EQ → JZ”的线性结构，无复杂数据相关分支。
- 能反编译/反汇编 pyc（高版本可用 pychaos/pylingual），并复现 VM 指令。

## 利用步骤

1. 解包/反编译 `main.pyc`，定位 `CustomVM.run` 与 `hidden_container.unpack_hidden_payload`。
2. 解析 `winsound.pyd` 的 `M13P` 头，按 `key/seed/length/checksum` 解密出第二段字节码。
3. 反编译 `vm_runtime.pyc` 或根据指令表实现 VM 解释器（栈、16 个槽、PC、消息）。
4. 实现 `step()` 与 `run_until_branch()`，在 `PUSH_INPUT` 处快照状态。
5. 对每个未解出的输入下标，枚举 0..255，运行到下一个分支；保留 `branch_not_taken` 的候选，更新 VM。
6. 解完后拼接输入，运行原程序验证 `Accepted.`；若有多候选，结合 flag 格式/后续分支筛选。

## PoC

```python
def step(vm, bytecode, read_input):
    op = bytecode[vm.pc]; vm.pc += 1
    if op == 0x01: vm.push(bytecode[vm.pc]); vm.pc += 1
    elif op == 0x02:
        idx = bytecode[vm.pc]; vm.pc += 1; vm.push(read_input(idx))
    elif op == 0x03:
        imm = bytecode[vm.pc]; vm.pc += 1; vm.push(vm.pop() ^ imm)
    elif op == 0x04:
        imm = bytecode[vm.pc]; vm.pc += 1; vm.push((vm.pop() + imm) & 0xFF)
    elif op == 0x05:
        n = bytecode[vm.pc]; vm.pc += 1; vm.push(rol8(vm.pop(), n))
    elif op == 0x06:
        slot = bytecode[vm.pc] & 0x0F; vm.pc += 1; vm.slots[slot] = vm.pop()
    elif op == 0x07:
        slot = bytecode[vm.pc] & 0x0F; vm.pc += 1; vm.push(vm.slots[slot])
    elif op == 0x08:
        slot = bytecode[vm.pc] & 0x0F; vm.pc += 1; vm.push(vm.pop() ^ vm.slots[slot])
    elif op == 0x09:
        slot = bytecode[vm.pc] & 0x0F; vm.pc += 1; vm.push((vm.pop() + vm.slots[slot]) & 0xFF)
    elif op == 0x0A:
        imm = bytecode[vm.pc]; vm.pc += 1; vm.push(1 if vm.pop() == imm else 0)
    elif op == 0x0B:
        rel = s16(int.from_bytes(bytecode[vm.pc:vm.pc+2], "little")); vm.pc += 2
        if vm.pop() == 0: vm.pc += rel; return "branch_taken"
        return "branch_not_taken"
    elif op == 0x0C:
        rel = s16(int.from_bytes(bytecode[vm.pc:vm.pc+2], "little")); vm.pc += 2; vm.pc += rel
    elif op == 0x0E: return "halt"
    elif op == 0x0F: vm.push(vm.stack[-1] if vm.stack else 0)
    elif op == 0x10: vm.pop()
    return "ok"

def solve_stage(bytecode):
    solved, vm = {}, VM.fresh()
    while vm.pc < len(bytecode):
        if bytecode[vm.pc] != 0x02:
            if step(vm, bytecode, lambda i: solved.get(i, 0)) == "halt": break
            continue
        idx = bytecode[vm.pc + 1]
        if idx in solved:
            if run_until_branch(vm, bytecode, lambda i: solved.get(i, 0)) == "branch_taken":
                raise RuntimeError("solved byte no longer satisfies path")
            continue
        snap = vm.copy(); hits = []
        for cand in range(256):
            probe = snap.copy()
            ev = run_until_branch(probe, bytecode, lambda i, c=cand: c if i == idx else solved.get(i, 0))
            if ev == "branch_not_taken":
                hits.append((cand, probe))
        solved[idx] = hits[0][0]; vm = hits[0][1]
    return bytes(solved[i] for i in range(max(solved) + 1))
```

案例：stage1 得到 fake flag `flag{Y0uWe1eTr1ckEdbaby}`，stage2 得到 `Y0uC@ncatcht1_1erealf1@9`，拼成最终 flag。

## 变体与关联

- 变体：VM 指令可能有 16/32 位立即数、跳转表、函数调用；按实际 opcode 表扩展解释器。
- 变体：隐藏容器可能用多层 XOR/RC4/AES；先恢复明文头（magic/长度/校验）再解 body。
- 变体：比较不是逐字节而是哈希/多字节时，可用符号执行/约束求解（z3）替代分支 oracle。
- 关联：[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（可逆 VM 反向执行）、[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller/pyc 解包）、[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（VM 求逆）。

## 检测与防御

- 防御：不要用“隐藏字节码 + 逐字节比较”作为保护；关键校验使用密码学哈希/签名，并做代码完整性校验。
- 防御：Python 打包不要只依赖 pyc 混淆；高版本 pyc 仍可反编译，VM 字节码也可被解释器复现。
- 检测：程序加载伪装 `.pyd`/`.bin` 并解释执行；VM 中出现大量 `PUSH_INPUT/CMP_EQ/JZ` 模式；pyc 与源码/行为不一致。
- 响应：提取隐藏容器与 VM 字节码，离线复现解释器；评估是否有反调试/反虚拟机与后续载荷。
