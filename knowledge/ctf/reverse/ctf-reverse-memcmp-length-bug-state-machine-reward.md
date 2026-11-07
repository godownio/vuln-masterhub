---
id: ctf-reverse-memcmp-length-bug-state-machine-reward
title: memcmp 长度写错只比 2 个 int：菜单状态机逆向 + reward 变换还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: memcmp-length-bug-state-machine-reward
aliases:
- Broken Quest
- brokenquest
- memcmp(state,target,8)
- 8x8 矩阵
- reward 变换
- 菜单状态机
tags:
- reverse
- memcmp
- state-machine
- matrix
- xor
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:52+08:00'
  notes: 已对照原文核对：菜单 0~8 操作、目标 [2,6,-4,6,0,4,-3,1]、memcmp(state,target,8) 只比前 2 个 int、4→2→3→3→7→0 序列、handle_flag 8x8 矩阵/异或与 intended 状态输出均一致。未验证点：原文 reward 明文本身含损坏字符，flag 按语义修复属原文不确定性；无二进制附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

`brokenquest` 用 8 个 int 维护菜单状态，`turn_in()` 本应比较 32 字节却写成 `memcmp(state, target, 8)`，只比前两个 int；用 `4→2→3→3→7→0` 把状态做成 `[2,6,0,...]` 即可交任务，但 `handle_flag(state)` 会用完整状态做 8×8 重排和异或，只有 intended 状态 `[2,6,-4,6,0,4,-3,1]` 才产出接近真 flag 的明文。

## 原理

- **状态机**：`int state[8]` 初始全 0；菜单 0~8 分别对应 turn in、reset、rotate pillars（右旋 1）、increase heat（`a0+=1,a4+=1`）、move gold（`a0+=3,a3-=2`）、swing sword（`a0/=5,a6%=5`）、swap gems（`a0↔a5`）、shift sand（`a1<<=1,a7>>=1` 算术右移）、reverse polarity（`a0=-a0,a2=-a2`）。
- **长度 bug**：`turn_in()` 目标 `[2,6,-4,6,0,4,-3,1]`，但 `memcmp(state, target, 8)` 的第三个参数是字节数；`int` 4 字节，所以只比较 `state[0]` 和 `state[1]`。只要前两个 int 是 `2,6`，后面 6 个任意即可通过。
- **漏洞流**：`4`（a0=3,a3=-2）→`2`（右旋）→`3`×2（a0=2,a4=1→0）→`7`（a1=6）→`0`，状态 `[2,6,0,0,0,0,0,0]`，turn in 成功。
- **为什么 reward 是乱码**：`handle_flag(state)` 不是简单打印；它用 8×8 常量矩阵对 state 做重排，按行调用 `transform()`/`calc_val()`，最后与 `.rodata` 密文异或。不同的 state 产生不同明文；漏洞状态只满足前两个 int，后 6 个为 0，所以解出乱码。
- **intended 状态**：用主函数里初始化的 `[2,6,-4,6,0,4,-3,1]` 跑 `handle_flag()`，得到几乎可读的 `xexsawg1x_ju5t_wor...5_m0r3_l...k3_%t_d@e5nt_w0rk}`；结合 `texsaw{...}` 格式和 leetspeak 句意恢复为 `texsaw{1t_ju5t_work5_m0r3_l1k3_!t_d0e5nt_w0rk}`。
- **两个“坏掉”的点**：`memcmp` 长度错（可绕过），`handle_flag` 本身也有字符损坏（reward 不完美）。

## 触发条件

- 二进制有菜单/状态数组和 `turn_in`/`check` 函数。
- `memcmp`/`strncmp` 的长度参数单位写错（字节 vs 元素），或只比较部分状态。
- 奖励/flag 生成依赖完整状态，存在矩阵/置换/异或等可复现变换。
- 能反编译菜单操作和目标状态常量。

## 利用步骤

1. 反编译 `main`，列出菜单操作及每个操作对 `state[8]` 的影响。
2. 定位 `turn_in()`：读目标数组与 `memcmp` 长度，确认只比较了哪些字节/元素。
3. 构造短操作序列让被比较的前缀等于目标；用本地程序验证 turn in 成功。
4. 观察 reward：若乱码，说明 `handle_flag(state)` 依赖完整状态；转去逆向该函数。
5. 复现 `handle_flag()`：8×8 矩阵重排、`transform`/`calc_val`、密文异或；喂 intended 状态得到接近明文的输出。
6. 用 flag 格式/语义修复损坏字符，或用程序校验/重加密确认。

## PoC

漏洞流（状态模拟）：

```python
state = [0] * 8

def op4(): state[0] += 3; state[3] -= 2
def op2(): state[:] = [state[-1]] + state[:-1]
def op3(): state[0] += 1; state[4] += 1
def op7(): state[1] <<= 1; state[7] >>= 1

op4(); op2(); op3(); op3(); op7()
print(state)  # [2, 6, 0, 0, 0, 0, 0, 0]
# memcmp(state, [2,6,-4,6,0,4,-3,1], 8) 只比前 2 个 int -> 通过
```

`handle_flag` 复现骨架（按原文脚本）：

```python
def handle_flag_like(state):
    perm = [[state[mat[r][c]] for c in range(8)] for r in range(8)]
    out = [0] * 46
    for row_idx, base, off, cnt in segments:
        oprow, valrow = mat[row_idx], perm[row_idx]
        for i in range(cnt):
            idx = oprow[i & 7]
            out[off + i] = calc_val(oprow, valrow, idx) ^ enc[base + i]
    return bytes(out)

print(handle_flag_like((2, 6, -4, 6, 0, 4, -3, 1)).decode("latin1"))
# xexsawg1x_ju5t_wor... -> texsaw{1t_ju5t_work5_m0r3_l1k3_!t_d0e5nt_w0rk}
```

## 变体与关联

- **长度 bug 变体**：`memcmp(a,b,sizeof(pointer))`、`memcmp(a,b,n*sizeof(char))` 当元素数、`strncmp` 少比、只比较前 N 字节。
- **状态机变体**：菜单操作、旋转/加减/移位/取模/交换；用 BFS/线性代数找目标状态。
- **reward 变体**：矩阵置换、分段变换、异或密文；先复现再喂 intended 状态。
- **关联卡片**：[[ctf-reverse-fjm-rv32-state-machine]]（状态机逆向）、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（可逆变换）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（同类 CTF 二进制）。
- **边界**：若 `memcmp` 比较的是完整 32 字节，漏洞流不成立；若 reward 变换不可复现，只能从 intended 状态/语义猜 flag。

## 检测与防御

- **代码修复**：`memcmp(state, target, sizeof(target))` 或 `8 * sizeof(int)`；用元素数时乘以 `sizeof`；测试边界状态。
- **设计**：不要把 flag 生成依赖客户端状态；服务端校验完整状态/签名。
- **检测信号**：`memcmp` 长度是 8 而数组是 8 个 int；状态数组部分比较；reward 函数有矩阵/异或。
- **CTF 技巧**：先找比较长度 bug 快速通关，再逆 reward 变换拿真 flag；两者可能不一致。
