---
id: ctf-reverse-bitmask-target-table-position-recovery
title: 5×26 位图目标表逐位置反解：130 项 bitmask 相等校验直接还原 5 行输入
type: scenario
domain: ctf
path: ctf/reverse
technique: bitmask-target-table-position-recovery
aliases:
- Wizard Time
- 位图目标表
- magic string 复原
- 130 分满分校验
tags:
- ctf
- reverse
- bitmask
- ida
- constraint-recovery
- input-reconstruction
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:47:05+08:00'
  notes: 已对照原文 Wizard Time 及图18/20/22/23/25 核对：5 行输入、read_token 最大 64、score==130=5*26、I1iiIi 130 个 qword 目标表、按 pos 唯一映射 a-z 的反解脚本与原文一致。未验证点：未在 IDA 中实跑脚本。
---

## 一句话结论

校验函数把每行输入编码成“某字母在该行的哪些位置出现”的 26 个 64-bit 位图，再与硬编码目标表逐项比较，满分 130 项全等才通过。由于正常字符串每个位置只对应一个字母，目标表对每个位置只会有一个字母的位被置 1，因此遍历 26 个位图就能唯一还原该位置字符，直接读出全部 5 行输入，完全不需要爆破。

## 原理

- **编码方式**：对第 `line` 行（0..4）、字母下标 `idx`（0..25），维护 `mask[line][idx]`；若该行第 `pos` 个字符等于 `'a'+idx`，则置 `mask[line][idx]` 的第 `pos` 位为 1。
- **打分方式**：对 `line=0..4`、`idx=0..25`，若 `mask[line][idx] == target[line][idx]` 则 `score++`；最大值为 `5*26=130`，满分即逐项完全相等。
- **可逆性**：合法输入只含 `a..z`，同一行的同一位置只能是一个字母，所以对固定 `pos`，130 个目标位图中恰好有一个 `(line,idx)` 的 bit `pos` 为 1。把该 bit 映射回 `chr('a'+idx)` 即可得到该行该位置的字符。
- **长度恢复**：每个字母位图的最高置位位置决定该行最大下标，`max_pos+1` 就是该行长度；若目标表在某高位没有置位，则该行更短。
- **输入读取细节**：读取函数跳过前导空白，然后读非空白 token，最多 64 字符 + NUL；校验只接受 `a..z`，因此等价于“每行一个 token”，输入中不会出现空格。
- **为什么这是“信息泄露型”校验**：按位置是否相等打分而不是整体哈希，目标表本身保存了每一位的答案；比较粒度越细，泄露越多。

## 触发条件

- 程序要求输入多行字符串，且对每行字符做按位置编码/比较。
- 代码中存在 `50/130`、`5*26` 这类维度的位图数组或 qword 目标表。
- 计分/比较循环对每个 `(line, letter)` 做相等判断，而不是一次性哈希比较。
- 读取逻辑限制字符集（如只允许小写字母），使每个位置只有一个字母候选。

## 利用步骤

1. 从提示或字符串定位校验函数，确认行数（示例 5）与每行最大长度（示例 64）。
2. 找到目标表全局符号（示例 `I1iiIi`，130 个 qword，逻辑上 `5×26`）。
3. 在 IDA 中用脚本 dump 全部 qword；按 `line*26+idx` 取第 `line` 行第 `idx` 个字母的位图。
4. 对每行扫描 26 个位图的所有置位，记录 `pos -> chr('a'+idx)`，遇到多个字母命中同一 `pos` 说明目标表不是合法字符串或行维度判断有误。
5. 按 `0..max_pos` 拼接得到该行字符串，5 行依次输入即可拿满分。
6. 若满分后还有二次编码（示例中程序再打印由输入导出的星图/十六进制串），继续按输出提示解码即可得到最终 flag。

## PoC

```python
import idc, ida_bytes, struct

base = idc.get_name_ea_simple("I1iiIi")   # 130 个 qword 目标表
vals = [struct.unpack("<Q", ida_bytes.get_bytes(base + i * 8, 8))[0]
        for i in range(130)]

for line in range(5):
    pos_to_char = {}
    for idx in range(26):
        m = vals[line * 26 + idx]
        pos = 0
        while m:
            if m & 1:
                pos_to_char[pos] = chr(ord('a') + idx)
            m >>= 1
            pos += 1
    max_pos = max(pos_to_char)
    print("".join(pos_to_char[p] for p in range(max_pos + 1)))
```

若目标表在文件/内存中的字节序与 IDA 显示不同，先确认 qword 是小端读取；若行数或字母表不同，把 `5`/`26`/`'a'` 替换为反编译得到的实际维度即可。

## 变体与关联

- 同一思路适用于“每列/每位独立比较”的其他编码：字符集合位图、逐位布尔表、按位置的目标字符数组；只要比较是逐位置的，就能直接读出。
- 若目标表不是明文位图而是加密/压缩后的表，先解密或解压；若只给出哈希，则不可逆，需要回到爆破/约束求解。
- 若程序用相似方式对输入做置换/打分但存在多解，需要结合其他约束（如长度、额外校验）消歧。
- 与本库“位图/像素编码迷宫”类卡片的区别：这里的目标是直接恢复校验输入，而不是从图像/状态中解码路径。

## 检测与防御

- 识别特征：`score` 上限等于 `行数 × 字母表大小`；目标表为 `行数 × 字母表大小` 个整数；比较循环按 `(line, idx, pos)` 三层展开。
- 防御（真实系统）：不要用逐位置相等或可分桶的编码做秘密校验，应使用带盐的密码学哈希/HMAC，并对比较结果做恒定时间处理；不要把目标位图以明文形式放在二进制中。
- CTF 中若遇到更高维度的位图表，先确认每个位置的候选集合是否唯一，唯一则可直接反解，否则转约束求解。
