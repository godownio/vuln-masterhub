---
id: ctf-reverse-cpp-vtable-modified-tea-mask-xor
title: C++ 虚表构造函数混淆：魔改 TEA 生成状态掩码再异或还原输入
type: scenario
domain: ctf
path: ctf/reverse
technique: cpp-vtable-modified-tea-mask-xor
aliases:
- 虚表函数调用混淆
- key_create 虚表
- 魔改 TEA mask XOR
- C++ 构造函数逆向
- TLS 回调障眼法
tags:
- ctf
- reverse
- cpp
- vtable
- tea
- xor
- obfuscation
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:48:41+08:00'
  notes: 已对照原文与images 03-12核对：TLS callback无校验、key_create虚表sub_402A18/sub_402AFC、32轮魔改TEA（反编译v3-=0x21524111等价于每轮+0xDEADBEEF）、state小端8字节、mask+0x1B、40字节异或、PoC常量均与原文/反编译一致。未验证点：未复跑脚本，flag未在本会话核验。
---

## 一句话结论

样本用 C++ 对象构造函数把两个函数指针写入虚表，主流程通过 `call [vtable+0]` / `call [vtable+4]` 间接调用：第一个是魔改 TEA（每轮 `s += 0xDEADBEEF`），用 32 轮后的状态生成 8 字节掩码；第二个把掩码与 40 字节密文逐字节异或。逆向时先正向跑 TEA 得到掩码，再与密文异或即可还原明文。

## 原理

- **静态障眼法**：程序存在 TLS callback，但回调里没有真正的校验逻辑；主逻辑在 `main → input()` 中完成，容易让分析者误判为 TLS/SMC 保护。
- **虚表构造**：`key_create` 在栈/堆对象上写入两个函数指针，`[vtable+0] = sub_402A18`、`[vtable+4] = sub_402AFC`；随后 `input()` 读入数据并执行 `call rdx`、`call edx`，分别调用这两个槽位。直接交叉引用看不到对加密函数的 `call`，需要跟踪对象指针与虚表偏移。
- **第一个函数（魔改 TEA）**：输入 8 字节状态 `(v0,v1)` 与 4 个 32 位 key，循环 32 轮：
  ```c
  v0 += ((v1 + s) ^ ((v1 << 4) + k0) ^ ((v1 >> 5) + k1));
  s  += 0xDEADBEEF;                 // 原文是每轮加，不是标准 TEA 的减
  v1 -= ((v0 + s) ^ ((v0 << 4) + k2) ^ ((v0 >> 5) + k3));
  ```
  循环结束把 `(v0,v1)` 作为 state。
- **第二个函数（掩码异或）**：对 40 字节数据逐字节执行 `data[i] ^= state[i % 8] + 0x1B`（字节加法取低 8 位）。加密方向是“先 TEA 出 state，再异或输入”；解密方向因异或自反，直接重算 state 后与密文异或。
- **逆向关键**：确认 TEA 的 delta 与状态更新顺序（`s` 的符号、加减方向），并把 state 的字节序按小端 `struct.pack('<II', v0, v1)` 还原，掩码偏移 `+0x1B` 要按 8 位取模。
- 之所以成立：虚表只是间接调用，不改变算法本身；TEA 每轮可正向复算（解密不需要逆 TEA，因为掩码只用于异或），因此 state 可直接由相同初值/key 重算。

## 触发条件

- 目标为 C++ 编译的 Windows/Linux 程序，存在对象 + 虚表/函数指针表，加密调用通过 `call [reg+offset]` 完成。
- 加密算法为 TEA 变体（delta/加减方向/轮数可能改动）且状态只用于生成掩码，而非直接输出密文。
- 反向分析者可定位 `key_create`/构造函数对虚表的初始化，以及 `input()` 中的间接调用点。

## 利用步骤

1. 打开 TLS callback 与 `main`，确认回调无实际校验，主逻辑在 `main → input()`。
2. 跟进 `key_create`，记录写入虚表的两个函数地址及对象布局；在 `input()` 的 `call rdx`/`call edx` 处下断，确认槽位对应关系。
3. 反编译 `sub_402A18`：识别 TEA 结构，记录 32 轮、delta `0xDEADBEEF`、4 个 key、`v0 +=` / `v1 -=` 的更新方向。
4. 反编译 `sub_402AFC`：确认掩码生成方式 `state[i] + 0x1B` 与 40 字节异或范围。
5. 用相同初值与 key 正向跑 TEA 得到 state，按小端拼 8 字节掩码。
6. 将掩码与密文逐字节异或，得到明文/flag。

## PoC

```python
import struct

vals = [32003635, -1545304977, 646869827, -1577193378, 545813781,
        -1515805688, 596145429, -251989923, 1977512257, -386293495]
target = b''.join(struct.pack('<I', x & 0xffffffff) for x in vals)[:40]

v0, v1 = 0x18274A3A, 0x24F8D42F
k0, k1, k2, k3 = 0x9C8793BF, 0xBB5C1044, 0x2FEA4F74, 0xA142ED8B
s = 0
for _ in range(32):
    v0 = (v0 + (((v1 + s) ^ ((v1 << 4) + k0) ^ ((v1 >> 5) + k1)))) & 0xffffffff
    s = (s + 0xDEADBEEF) & 0xffffffff
    v1 = (v1 - (((v0 + s) ^ ((v0 << 4) + k2) ^ ((v0 >> 5) + k3)))) & 0xffffffff

state = struct.pack('<II', v0, v1)
mask = bytes(((b + 0x1B) & 0xff) for b in state)
plain = bytes(target[i] ^ mask[i % 8] for i in range(40))
print(plain)
```

## 变体与关联

- 变体：虚表槽位顺序/数量变化，或用 `std::function`/函数指针数组替代虚表；同样只需跟踪初始化与间接调用。
- 变体：TEA 的 delta 改为其他常数、轮数变化、`s` 递增/递减不同；按反编译结果调整。
- 变体：掩码不是 `+0x1B`，而是 `-k`、Rotate、查表或由 key 直接派生；核心仍是“状态生成掩码 + 异或”。
- 关联：TLS callback 反调试/混淆识别、SMC 自修改代码、C++ 虚表 hook 与 RTTI 分析。

## 检测与防御

- 逆向侧：遇到 TLS callback 先确认是否真正参与校验；对 `call [reg+offset]`、构造函数写函数指针的模式建立 xref 图；优先动态跟踪虚表槽位。
- 逆向侧：TEA 变体要核对 delta、轮数、加减方向与字节序，避免套用标准 TEA 解密脚本失败。
- 开发/保护侧：不要仅依赖虚表间接调用来隐藏校验逻辑；若需保护，可结合控制流平坦化、字符串加密与完整性校验，但需接受可逆性。
- 检测：对程序中异常 TLS callback、运行时写入函数指针表的行为可结合 EDR/沙箱监控；对分析者而言这是识别混淆的线索。
