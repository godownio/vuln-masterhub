---
id: ctf-reverse-fixed-grid-wasd-maze-bfs-path-md5
title: CTF 迷宫逆向：10×10 硬编码地图 WASD 移动校验，BFS 求最短路径后 MD5 得 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: fixed-grid-wasd-maze-bfs-path-md5
tags:
- ctf
- reverse
- maze
- bfs
- md5
- path
- wasd
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/ctf/reverse/ctf-reverse-fixed-grid-wasd-maze-bfs-path-md5/
draft: false
kb_aliases:
- 迷宫逆向
- WASD 迷宫
- BFS 求迷宫路径
- 路径 MD5 flag
- 迷宫题通用解法
---

## 一句话结论

迷宫题把 10×10 地图硬编码为二维数组（1 墙 / 0 通路），程序按 `w/a/s/d` 移动并在到达终点后对完整方向串做 MD5；逆向时提取地图数组、按同样的越界与撞墙规则建图，BFS 求出从起点到终点的最短方向串，其 MD5（或按题目格式包一层）就是 flag。

## 原理

- 程序逻辑是“输入方向序列 → 逐步模拟移动 → 到达终点 → 对路径做哈希/编码”。地图、起点、终点与移动规则都在二进制/源码中，不依赖隐藏状态，属于纯可逆的约束题。
- 地图通常以二维 int/byte 数组存放（本例 10×10，`1` 为墙、`0` 为通路），终点固定为 `(WIDTH-2, HEIGHT-2)` 一类的右下角坐标；移动函数只做边界检查与墙壁检查，非法移动被忽略或直接失败。
- 路径的含义由程序定义：每成功移动一步就把方向字符追加到字符串，最后对整串做 MD5 得到 flag 内容（本例 `polis{md5(path)}`）。因此不能只证明“存在一条到终点的路”，必须得到与程序哈希一致的路径串。
- BFS 在无权网格上第一次到达终点即为最短路径；若程序只校验路径能否到终点（不限定最短），多条路径都可能通过，但常见实现哈希的是具体输入串，需以程序校验逻辑为准，必要时枚举所有解或利用题目给出的唯一性。

## 触发条件

- 程序接受单字符方向输入（`w/a/s/d` 或 `E/N/S/W` 等），并有明确的终点判定。
- 数据区/反编译结果中可见二维地图数组、起终点常量或坐标比较。
- 最终校验是路径字符串哈希（MD5/SHA）或直接拼接 flag 格式。

## 利用步骤

1. 定位地图数组、起点与终点：在 IDA/Ghidra 中找校验函数里的二维数组初始化（连续 `1/0` 常量）与坐标立即数（如 `8,8` 或 `WIDTH-2`）。
2. 确认移动映射与判定：`w` 对应 `y-1`、`s` 对应 `y+1`、`a` 对应 `x-1`、`d` 对应 `x+1`；越界与 `maze[ny][nx] != 0` 的移动被拒绝。
3. 提取地图：可直接把反编译出的数组抄成脚本，或从二进制 `.data` 段 dump 出来；注意行列顺序（本例 `maze[y][x]`）。
4. 按程序相同规则建图并 BFS：从起点出发，按 `w/a/s/d` 顺序扩展并记录 visited，第一次到终点即最短路径（多解时按程序哈希的实际输入或额外校验确认）。
5. 对方向串做程序使用的哈希/格式化（本例 `md5(path).hexdigest()` 填入 `polis{...}`）。
6. 用原程序跑一遍该路径验证输出一致；若不一致，检查方向映射、起点终点、地图行列是否转置。

## PoC

```python
from collections import deque
import hashlib

maze = [
    [1,1,1,1,1,1,1,1,1,1],
    [1,0,1,1,0,0,0,0,0,1],
    [1,0,0,1,0,1,1,1,0,1],
    [1,0,1,1,1,1,0,1,0,1],
    [1,0,0,0,0,1,0,1,0,1],
    [1,1,1,1,0,1,0,1,0,1],
    [1,0,0,0,0,1,0,0,0,1],
    [1,0,1,1,1,1,1,1,0,1],
    [1,0,0,0,0,0,0,0,0,1],
    [1,1,1,1,1,1,1,1,1,1],
]
start, end = (1, 1), (8, 8)
moves = [('w', 0, -1), ('a', -1, 0), ('s', 0, 1), ('d', 1, 0)]

q = deque([(start, "")])
seen = {start}
while q:
    (x, y), path = q.popleft()
    if (x, y) == end:
        print(path)                      # sssdddssaaassddddddd
        print(hashlib.md5(path.encode()).hexdigest())
        # 538cc457b229b25d6bdbf7bae9ef357b
        break
    for ch, dx, dy in moves:
        nx, ny = x + dx, y + dy
        if 0 <= nx < 10 and 0 <= ny < 10 and maze[ny][nx] == 0 and (nx, ny) not in seen:
            seen.add((nx, ny))
            q.append(((nx, ny), path + ch))
```

本例 BFS 输出与程序一致：路径 `sssdddssaaassddddddd`（20 步），MD5 为 `538cc457b229b25d6bdbf7bae9ef357b`，最终 flag 为 `polis{538cc457b229b25d6bdbf7bae9ef357b}`。

## 变体与关联

- 方向字符可由 `w/a/s/d` 换成 `E/N/S/W`、数字键或宏块序列；地图可能来自像素/位图而非 int 数组（见 `ctf-reverse-pixel-low-nibble-direction-maze-bfs`）。
- 多解/最短路径约束：若程序只判可达，任意合法路径均可；若哈希固定路径，则需按程序实际接受的输入确定唯一解，必要时枚举全部路径或对哈希做约束求解。
- 地图可能被异或/加密后才比较，或分多段存放；先还原地图再 BFS。
- 与三维/状态机迷宫（`ctf-reverse-multi-stage-cube-fnv1a-linear-system-dynamic-maze`）、工业组态迷宫（`ctf-reverse-autothink-plc-project-maze-counter-tamper`）的区别是状态空间与移动规则更复杂，但“提取地图 → 建图 → BFS/DFS”方法相同。

## 检测与防御

- 这是 CTF/逆向题技巧，不是真实漏洞；防御方（出题方）可通过加壳、地图加密、路径哈希加盐、多解绑定具体路径等方式提高逆向成本。
- 实际软件若用“路径/序列”做授权，不应只依赖客户端校验或可预测的 MD5；关键判定应在服务端完成。
