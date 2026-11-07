---
id: ctf-reverse-pe-driver-4byte-xor-repair-chained-xor-z3
title: 损坏驱动 PE 修复与两轮链式异或逆向：每 4 字节 XOR 0x44 + z3 多解约束
type: scenario
domain: ctf
path: ctf/reverse
technique: pe-driver-4byte-xor-repair-chained-xor-z3
aliases:
- drive
- Driver.sys 修复
- 每 4 字节 XOR 0x44
- 链式异或还原
- z3 多解 flag 格式约束
tags:
- reverse
- pe
- driver
- windows
- xor
- chained-xor
- z3
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:44:28+08:00'
  notes: 已对照原文 drive 题核对：MZ 4D→09(^0x44)、每4字节首字节XOR 0x44修复循环、sub_140001000两轮链式异或化简 out[0]=in[0]^0x34^in[31]、out[1]=in[1]^0x34、out[i]=in[i]^in[i-2]、模18预处理与z3多解/flag约束均与原文一致；原文给出flag，未本机复跑。
---

## 一句话结论

题目给了一个被破坏的 Windows 驱动 `Driver.sys`：PE 头 `4D 5A` 被改成 `09 5A`，且从某偏移起每 4 字节的第一个字节都被异或了 `0x44`；按 `for i in range(0,len,4): data[i] ^= 0x44` 修复后得到正常驱动，再逆向其输入校验——两轮链式异或加一次模 18 预处理——可化简为 `out[i] = in[i] ^ in[i-2]` 的线性关系，用 z3 求解并结合 `flag{` 格式约束在多解中挑出正确明文。

## 原理

- **PE 破坏模式**：`Driver.sys` 本质是 PE，正常应以 `4D 5A`（MZ）开头，本题变成 `09 5A`；修复 MZ 后字符串出现 `J...D......L.!Th-s p6ogr%m c%nno0 bedrundin .OS`，其中 `Th-s` 应为 `This`，说明每 4 字节的第 1 个字节被异或了 `0x44`（`54 68 69 73` → `54 68 2D 73`）。
- **批量修复**：`for i in range(0, len(data), 4): data[i] ^= 0x44`；修复后 PE 正常，字符串暴露 `\??\DeviceDrive`、`\Device\MYDEVICE`、`flag is you input`、`wrong`，并确认缺失符号 `Drive` 的 MD5。
- **输入预处理**：驱动把 `Format` 复制到 `buf` 后，对 `n32=1..31` 执行 `buf[n32-1] ^= (buf[n32-1] % 0x12 + buf[n32] + 5) ^ 0x34`，即用自己的模 18 值、下一个字节和常量 0x34 做异或后再异或自身。
- **两轮链式异或**：`sub_140001000` 第一轮 `tmp[i] = in[i] ^ in[i-1]`（`in[-1]=0x34`）；第二轮 `out[i] = tmp[i] ^ tmp[i-1]`（`tmp[-1]=in[31]`）。两轮相消后：
  - `out[0] = in[0] ^ 0x34 ^ in[31]`
  - `out[1] = in[1] ^ 0x34`
  - `out[i] = in[i] ^ in[i-2]`（i ≥ 2）
- **多解与约束**：仅凭输出方程组，`in[0]` 与 `in[31]` 等存在自由度，z3 会给出多组解；加入 `in[0] == ord('f')`（flag 前缀）后收敛到正确明文。
- **为什么需要 z3**：预处理含 `in[i-1] % 18` 的非线性项，手工逆推要先猜取模分支；z3 可直接把 32 个 8 位 BitVec 与方程交给求解器，并支持追加“多解检测”约束。

## 触发条件

- 拿到损坏的 PE/驱动文件，头部或固定步长字节被异或/替换。
- 驱动校验逻辑由线性/半线性变换（链式异或、加减、取模）组成，输出目标常量已知。
- 输入长度固定（本题 32 字节），且明文有格式约束（`flag{`、长度、字符集）可用于消歧。
- 可用 z3 或等价约束求解器。

## 利用步骤

1. 检查 PE 头：`MZ` 是否被改；若被改先恢复 `4D 5A`。
2. 观察修复后字符串的异常模式（如 `Th-s`），推断固定步长的单字节异或；尝试 `0x44` 等常见值，直到 PE 结构/字符串正常。
3. 批量修复：`data[i] ^= 0x44`（i 从 0 开始、步长 4），保存为正常 PE。
4. 在 IDA/Ghidra 中定位校验函数：找 `flag is you input` 引用、`sub_140001000`、输出常量 `byte_140003000`。
5. 把两轮链式异或化简为 `out[0]=in[0]^0x34^in[31]`、`out[1]=in[1]^0x34`、`out[i]=in[i]^in[i-2]`。
6. 用 z3 建 32 个 8 位变量，加入预处理方程与化简后的输出方程；先求一组解。
7. 追加“存在不同解”的约束判断是否多解；若多解，加入 `in[0]=='f'`、`in[4]=='{'` 等格式约束，直到唯一。
8. 输出 32 字节明文，验证以 `flag{` 开头。

## PoC

```python
from z3 import *

out = [0x66,0xA,0x9,0xE0,0xE2,0xE3,0xCB,0x9,0x14,0x15,0xC,0x38,
       0x1,0x1F,0x5,0x42,0x71,0x6E,0x56,0x7A,0x0,0x20,0xE4,0xBF,
       0xE6,0xCD,0x28,0x30,0x2C,0x75,0xA0,0x3A]

# 两轮链式异或化简
s = Solver()
inn = [BitVec(f'x_{i}', 8) for i in range(32)]
s.add(out[0] == inn[0] ^ 0x34 ^ inn[31])
s.add(out[1] == inn[1] ^ 0x34)
for i in range(2, 32):
    s.add(out[i] == inn[i] ^ inn[i-2])
assert s.check() == sat
m = s.model()
mid = [m.eval(inn[i]).as_long() for i in range(32)]

# 预处理逆推：buf_new[n-1] == (buf_old[n-1]%18 + buf_old[n] + 5) ^ 0x34 ^ buf_old[n-1]
s2 = Solver()
old = [BitVec(f'y_{i}', 8) for i in range(32)]
for n in range(1, 32):
    s2.add(mid[n-1] == (old[n-1] % 18 + old[n] + 5) ^ 0x34 ^ old[n-1])
s2.add(old[0] == ord('f'))      # flag 格式约束消歧
assert s2.check() == sat
m2 = s2.model()
print(bytes(m2.eval(old[i]).as_long() for i in range(32)))
```

PE 修复：

```python
with open('Driver.sys', 'rb') as f:
    raw = bytearray(f.read())
for i in range(0, len(raw), 4):
    raw[i] ^= 0x44
open('Driver_repaired.sys', 'wb').write(raw)
```

原文得到 `flag{wnNCZJbBOqL3QA1C1cypiKYII4}`；未在本机复跑。

## 变体与关联

- **破坏模式变体**：固定步长 XOR、按块交换、头部/节表字段篡改、字符串混淆；先恢复 PE 结构再分析逻辑。
- **校验模式变体**：链式异或、滚动 XOR、加减/取模、RC4/自定义流；可逆部分手工化简，非线性部分交给 z3。
- **多解处理**：用 `flag{` 前缀、长度、字符集、可打印性、CRC/哈希约束消歧；注意 z3 默认只给一组解，需主动加 `Or` 约束检测多解。
- **关联**：[[ctf-reverse-z3-constraint-equation-solve]]（z3 解约束方程）、[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（可逆变换求逆）；本卡强调“PE 修复 + 链式异或化简 + 多解约束”。

## 检测与防御

- 驱动/PE 完整性校验应使用签名而非简单字节混淆；发现头部/固定步长异常时先做结构校验。
- 输入校验不要依赖可被约束求解的可逆变换；使用加密哈希/HMAC 并加盐。
- 检测：PE `MZ` 被改、固定步长字节分布异常、驱动中出现 `flag is you input` 等明文字符串、校验函数含链式 XOR + 取模。
