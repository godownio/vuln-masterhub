---
id: ctf-reverse-fjm-rv32-state-machine
title: FJM 高地址 RV32 状态机：逆向输入格式与 16-bit 状态约束恢复 flag body
type: scenario
domain: ctf
path: ctf/reverse
technique: fjm-rv32-state-machine-inversion
aliases:
- ColorfulArray
- FJM 文件
- RV32 小端程序
- 16-bit 状态机
- 跳步掩码
- DFS 恢复 flag
tags:
- ctf
- reverse
- fjm
- rv32
- state-machine
- dfs
- firmware
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:25+08:00'
  notes: 已对照原文 §2 ColorfulArray 核对：FJM 高地址 RV32 小端程序、NepCTF{} 格式、targets/skip_mask 0x210042/body_order/idx_order/base_state/used_from_raw/DFS 与已知 Real 均一致；原文有实测 flag，未本机复跑。注：卡片称 FJM 为 Flash/嵌入式资源容器系推测，原文未说明 FJM 格式，属次要表述。
---

## 一句话结论

附件歌词文本不是重点；真正的校验逻辑藏在 `colorful.fjm` 高地址数据区的一段 RV32 小端程序里。反汇编后确认输入需要满足 `NepCTF{...}` 格式，并还原一个 16-bit 状态机：25 个目标 u16、跳步掩码、按特定 body/index 顺序的转移。用 DFS 枚举可打印字符，按 `base_state` 与 `used` 关系匹配目标，即可恢复唯一的 25 字节 flag body。

## 原理

- **FJM 与 RV32**：FJM 是 Flash/嵌入式资源容器；高地址数据区嵌入一段 RV32 小端程序。先用 RV32 反汇编器定位入口、输入读取和比较循环。
- **输入格式**：程序检查 `NepCTF{` 前缀和 `}` 后缀，body 长度 25；body 字符限制在可打印 ASCII（32..126）。
- **状态机**：当前 16-bit 状态 `state` 先经过 `base_state(state) = (((state >> 13) ^ 2) | ((state << 3) ^ 0x75A8)) & 0xFFFF`；对每个位置按 `body_order`/`idx_order` 处理：
  - 若 `skip_mask` 对应位为 0（checked），目标 `nxt = targets[idx]`，要求 `(nxt - base) & 0xFFFF <= 0xFF`；`used = (nxt - base) & 0xFFFF`；原始字符 `raw = used ^ pos`（pos<10）或 `used`；`raw` 必须在可打印范围。
  - 若 unchecked，则枚举可打印字符 `raw`，下一状态 `(base + used_from_raw(pos, raw)) & 0xFFFF`。
- **DFS**：按固定顺序递归，已知位置（如 body 10..13 = `Real`）作为剪枝；每一步候选唯一或很少，最终得到唯一 25 字节 body，加上 `NepCTF{}` 即 flag。
- **为什么可解**：状态转移是确定性的且每步约束强（目标值 + 可打印范围 + 已知明文片段），搜索空间被大幅剪枝。

## 触发条件

- 附件包含自定义容器/固件，内嵌非主流架构（RV32）校验程序。
- 输入格式和字符集可从反汇编恢复。
- 状态机每步有目标值/掩码约束，且字符集有限。
- 存在已知明文片段或可打印性约束用于剪枝。

## 利用步骤

1. 解包 `colorful.fjm`，定位高地址 RV32 程序；用 RV32 反汇编确认入口与比较逻辑。
2. 提取 25 个目标 u16、`skip_mask`、`body_order`、`idx_order`、`base_state`、`used_from_raw`。
3. 确认输入格式 `NepCTF{...}` 与 body 长度；记录已知字符（如 `Real`）。
4. 按顺序 DFS：checked 位置反推 `used`/`raw` 并校验范围；unchecked 位置枚举可打印字符并更新状态。
5. 得到唯一 body，拼接 `NepCTF{body}`。

## PoC

```python
targets = [int.from_bytes(target_bytes[i*2:i*2+2], "little") for i in range(25)]
skip_mask = 0x210042

body_order = [0,5,10,15,20, 1,6,11,16,21, 2,7,12,17,22, 3,8,13,18,23, 4,9,14,19,24]
idx_order  = [0,13,1,14,2, 15,3,16,4,17, 5,18,6,19,7, 20,8,21,9,22, 10,23,11,24,12]
known = {10: ord("R"), 11: ord("e"), 12: ord("a"), 13: ord("l")}
allowed = list(range(32, 127))
solutions = []

def base_state(state):
    return (((state >> 13) ^ 2) | ((state << 3) ^ 0x75A8)) & 0xFFFF

def used_from_raw(pos, ch):
    return ch ^ pos if pos < 10 else ch

def raw_from_used(pos, ch):
    return ch ^ pos if pos < 10 else ch

def dfs(step, state, body):
    if step == 25:
        solutions.append(bytes(body)); return
    pos, idx = body_order[step], idx_order[step]
    checked = ((skip_mask >> idx) & 1) == 0
    base = base_state(state)
    if checked:
        nxt = targets[idx]
        used = (nxt - base) & 0xFFFF
        if used > 0xFF:
            return
        raw = raw_from_used(pos, used)
        if raw not in allowed or (pos in known and raw != known[pos]):
            return
        old = body[pos]
        if old is not None and old != raw:
            return
        body[pos] = raw
        dfs(step + 1, nxt, body)
        body[pos] = old
        return
    candidates = [known[pos]] if pos in known else allowed
    for raw in candidates:
        old = body[pos]
        if old is not None and old != raw:
            continue
        body[pos] = raw
        dfs(step + 1, (base + used_from_raw(pos, raw)) & 0xFFFF, body)
        body[pos] = old

body = [None] * 25
for pos, ch in known.items():
    body[pos] = ch
dfs(0, 0, body)
print(solutions[0].decode())
print("NepCTF{%s}" % solutions[0].decode())
```

## 变体与关联

- 其他嵌入式 VM/状态机：8051、MSP430、Xtensa、自定义字节码；先识别架构再反汇编。
- 若状态转移不可逆/候选多，可用 SMT（Z3）或 meet-in-the-middle 代替 DFS。
- 若字符集更大，可先用已知明文/长度/校验和剪枝。
- 关联：RV32 固件逆向、状态机约束求解、可打印字符 DFS 卡。

## 检测与防御

- 这是 CTF 谜题；防御意义在于：不要把 flag 校验完全放在客户端固件中，关键逻辑放服务端或做白盒/混淆。
- 检测：FJM/固件中出现 RV32 代码、状态机比较表；输入处理函数对大字符集做逐字节约束。
