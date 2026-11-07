---
id: ctf-misc-maze-horizontal-move-bitstream
title: 迷宫 BFS 路径的左右移动编码成 bit 流还原 flag
type: scenario
domain: ctf
path: ctf/misc
technique: maze-path-horizontal-bit-encoding
aliases:
- PROCEDURAL LABYRINTH
- 迷宫路径编码
- 左右移动 bit 流
- BFS 迷宫还原
tags:
- ctf
- misc
- maze
- bfs
- bit-encoding
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:31:36+08:00'
  notes: '已对照原文核对：迷宫仅含 # . > <、701 行×51 列、BFS 从 > 到 <、路径 1089 点、右=0/左=1、跳过入口第一个水平 bit、每 8 位转 ASCII、flag VishwaCTF{p4th_1s_th3_m3ss4g3_00_57d006d5} 均一致。未验证点：无迷宫附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。'
---

## 一句话结论

给一个由 `#`（墙）、`.`（路）、`>`（入口）、`<`（出口）组成的迷宫时，用 BFS 求出唯一路径，把路径中的水平移动按“右=0、左=1”编码成 bit 流，跳过入口的前导水平位，再每 8 位转 ASCII，即可读出 flag。

## 原理

- 迷宫的可走点构成图，BFS 从 `>` 到 `<` 得到最短路径，`prev` 数组回溯出完整坐标序列。
- 出题人把 flag 编码在“左右移动序列”里：向右记 0、向左记 1，上下移动不参与编码。
- 入口处通常有一个进入迷宫的前导水平移动，它不是正文，需要跳过第一位。
- 剩余 bit 流按 8 位一组转字节，即可得到可打印的 flag 字符串。
- 之所以成立：迷宫路径是确定的，且水平移动序列与 bit 流一一对应；只要路径唯一，编码就无歧义。

## 触发条件

- 迷宫为字符矩阵，含明确的入口/出口标记，路径唯一。
- 编码约定为水平移动（右=0/左=1）或可从上下文推断。
- bit 流长度是 8 的倍数（可能有 1 位前导需要跳过）。

## 利用步骤

1. 从文本中提取只含 `# . > <` 且行长一致的迷宫区域。
2. 定位 `>` 与 `<`，以 `. > <` 为可走点做 BFS，记录 `prev`。
3. 回溯路径，遍历相邻坐标：`dc=+1` 记 0，`dc=-1` 记 1，`dr=±1` 忽略。
4. 去掉第一个水平 bit（入口前导），每 8 位转一个 ASCII 字符。
5. 读取 flag。

## PoC

```python
from collections import deque

def bfs_path(grid, start, end):
    R, C = len(grid), len(grid[0])
    q = deque([start]); prev = {start: None}
    while q:
        r, c = q.popleft()
        if (r, c) == end: break
        for dr, dc in [(1,0),(-1,0),(0,1),(0,-1)]:
            nr, nc = r+dr, c+dc
            if 0 <= nr < R and 0 <= nc < C and grid[nr][nc] in ".><" and (nr,nc) not in prev:
                prev[(nr,nc)] = (r,c); q.append((nr,nc))
    path, cur = [], end
    while cur is not None:
        path.append(cur); cur = prev[cur]
    return path[::-1]

bits = []
for (r1,c1),(r2,c2) in zip(path, path[1:]):
    if c2-c1 == 1: bits.append("0")
    elif c2-c1 == -1: bits.append("1")
s = "".join(bits)[1:]           # skip entry move
print("".join(chr(int(s[i:i+8], 2)) for i in range(0, len(s)-7, 8)))
```

## 变体与关联

- 上下移动编码、左=0/右=1、每 7 位 ASCII 等变体。
- 路径不唯一时需按编码结果可打印性筛选。
- 关联：[[ctf-misc-punctuation-2bit-encoding]]（字符级 bit 编码）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（迷宫类 stego）。

## 检测与防御

- 这是 CTF misc 题型；防御上可打乱路径唯一性、加入噪声分支或使用非线性编码。
- 检测：文本中出现大尺寸 `# . > <` 矩阵与入口/出口标记。
