---
id: ctf-reverse-pixel-low-nibble-direction-maze-bfs
title: 像素低 4 位方向编码的 10x10 迷宫逆向：XOR 0x7f 解密 + BFS 求路径
type: scenario
domain: ctf
path: ctf/reverse
technique: pixel-low-nibble-direction-maze-bfs
aliases:
- 像素迷宫
- decryptPixel
- isValidMove
- 低 4 位方向
tags:
- ctf
- reverse
- pixel
- maze
- bfs
- bitmask
- xor
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:27:02+08:00'
  notes: 已对照原文核对：extractPath 的 ISCC{}/E,N,S,W 限制、decryptPixel ^0x7f、isValidMove 低 4 位 E=bit0/W=bit1/S=bit2/N=bit3、10×10 起点 (0,0) 终点 (9,9)、三段像素与 qword 高低 32 位拆分、BFS 路径与 flag ISCC{SSENEEESENNEESWSESSSWNNWWWNWSSSWWSSEENESEENEESWSEEES} 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

像素不是黑白二值，而是低 4 位方向位图：bit0=E、bit1=W、bit2=S、bit3=N；像素值先 `^ 0x7f` 解密，再从 (0,0) 对 10×10 网格 BFS 到 (9,9)，路径字符就是 flag 内容。

## 原理

- **像素解密**：`decryptPixel(p) = p ^ 0x7f`；程序中保存的是加密像素，取真实值只需异或固定常量。
- **方向位编码**：`isValidMove(x,y,dir)` 判断 `E: pixel & 1`、`W: (pixel>>1)&1`、`S: (pixel>>2)&1`、`N: (pixel>>3)&1`。也就是说低 4 位分别表示四个方向是否可走；像素的高位可能是干扰/其他信息，不能只按 0/1 二值图处理。
- **迷宫结构**：10×10 网格，起点 (0,0)，终点 (9,9)；每个格子的低 4 位给出可走方向。因为边是单向的（某格可走 E 不代表邻格可走 W），应按有向图 BFS。
- **数据分散**：加密像素分布在三段：两个字节数组 + 一组 qword；每个 qword 的高 32 位和低 32 位各存一个“扩展为 32 位的像素值”，需要 `q & 0xffffffff` 与 `q >> 32` 拆开，再按行优先拼成 100 个像素。
- **BFS 求路径**：从 (0,0) 开始，按当前格允许的方向扩展，记录 visited 防止环；第一次到 (9,9) 的路径即 flag 中间串。

## 触发条件

- 程序检查 `ISCC{...}`，且花括号内只允许 E/N/S/W 四个字符。
- 反编译中存在 `decryptPixel`、`isValidMove`、`validatePath`、`extractPath` 等函数名或等价逻辑。
- 数据区有 10×10 像素数组，像素值不是 0/1，而是按位编码方向。

## 利用步骤

1. 从 `extractPath` 确认格式：`flag.substr(0,5)=="ISCC{"`、末位 `}`，中间只允许 E/N/S/W。
2. 从 `decryptPixel` 取异或常量（本例 `0x7f`）。
3. 提取三段加密像素；qword 段按低 32/高 32 拆成两个像素值，按行优先拼成 100 项。
4. 对每项异或常量，得到 10×10 网格。
5. 按方向位映射建图，BFS 从 (0,0) 到 (9,9)；输出路径并包成 `ISCC{...}`。
6. 用原程序验证；若有多条路径，按题目通常的唯一解或校验函数确认。

## PoC

```python
from collections import deque

# 三段加密像素：前两段为字节数组，第三段为 qword（高低 32 位各一个像素）
part1 = [...]   # 30 字节
part2 = [...]   # 40 字节
qwords = [...]  # 15 个 qword
part3 = []
for q in qwords:
    part3.append(q & 0xffffffff)
    part3.append((q >> 32) & 0xffffffff)

enc = part1 + part2 + part3
assert len(enc) == 100
grid = [[(enc[r * 10 + c] ^ 0x7f) & 0xff for c in range(10)] for r in range(10)]

moves = {"E": (0, 1, 1), "W": (0, -1, 2), "S": (1, 0, 4), "N": (-1, 0, 8)}
q = deque([(0, 0, "")]); vis = {(0, 0)}
while q:
    x, y, path = q.popleft()
    if (x, y) == (9, 9):
        print("ISCC{" + path + "}")
        break
    pixel = grid[x][y]
    for d, (dx, dy, bit) in moves.items():
        nx, ny = x + dx, y + dy
        if 0 <= nx < 10 and 0 <= ny < 10 and (pixel & bit) and (nx, ny) not in vis:
            vis.add((nx, ny)); q.append((nx, ny, path + d))
```

## 变体与关联

- **位分配变体**：E/W/S/N 的 bit 顺序可能不同；以 `isValidMove` 的实际移位为准，不要照搬。
- **网格变体**：尺寸、起点/终点、是否允许八方向、边是否双向；先确认 `MAZE_WIDTH/HEIGHT` 与边界检查。
- **像素编码变体**：异或常量可能是多字节、按坐标变化，或像素值需要先解密再取低 nibble；先找 `decryptPixel`。
- **数据布局变体**：数组可能被拆成多段、用 qword/dword 扩展存储、或按列优先；拼错顺序会导致 BFS 无解。
- **关联卡片**：[[ctf-reverse-quadratic-swap-image-encryption-rounds]]（图像像素级变换）、[[ctf-reverse-zhie-map-vm-search]]（地图状态机 + 搜索）、[[ctf-reverse-fjm-rv32-state-machine]]（状态机路径约束）。

## 检测与防御

- **检测特征**：输入只允许方向字符、10×10 像素数组、`^ 0x7f`、`pixel & 1/2/4/8`、BFS/DFS 可达性判断。
- **分析建议**：先把像素值打印成 10×10 十六进制表，人工观察低 4 位模式；再写 BFS，比逐格手推可靠。
- **防御视角**：用位图编码方向只是增加观察成本；把数据拆成多段/qword 也不构成保护，脚本可批量还原。
