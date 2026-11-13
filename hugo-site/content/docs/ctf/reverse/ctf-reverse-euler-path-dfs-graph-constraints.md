---
id: ctf-reverse-euler-path-dfs-graph-constraints
title: 逆向题转图论：9 结点无向图欧拉路径 DFS 搜索 + 路径位置约束过滤还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: reverse-graph-euler-path-dfs-constraint-filter
tags:
- ctf
- reverse
- graph
- euler-path
- dfs
- constraints
- flag-recovery
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:49+08:00'
  notes: 已对照原文核对并复跑卡片 PoC：邻接矩阵、9 结点 17 边、奇度点 0/4、约束串完全一致，DFS 得唯一解 085134620568327814 可拼 aliyunctf{...}；原文脚本 v 未初始化/vis 随机全 0 的坑已在卡中标注
url: /docs/ctf/reverse/ctf-reverse-euler-path-dfs-graph-constraints/
draft: false
kb_aliases:
- 欧拉路径逆向
- 欧拉路 DFS
- 邻接表转图论
- 路径约束过滤
- AliyunCTF 欧拉
---

## 一句话结论

逆向出程序用 9×9 邻接表校验输入序列后，可把问题转成无向图的欧拉路径：图中有且仅有两个奇数度结点（0 与 4），输入首尾被约束为 0 和 4，因此从 0 出发 DFS 枚举所有欧拉路径，再用程序里的位置关系约束过滤，唯一满足的路径序列就是 flag 内容。

## 原理

- **校验逻辑图论化**：程序把输入当作结点序列，要求相邻两项在邻接表中相连且每条边恰好走一次——这正是欧拉路径的定义；邻接矩阵可由静态分析直接提取。
- **端点判定**：无向图存在欧拉路径的充要条件是奇数度结点数为 0（欧拉回路）或 2（欧拉路径，端点为这两个结点）。本题邻接表只有结点 0 和 4 的度为奇数，故路径必须从 0 开始、到 4 结束。
- **已知端点**：题目约束最后一个输入为 4，进一步确认 4 是终点、0 是起点，搜索时可固定起点降低复杂度。
- **约束过滤**：程序还对路径序列的特定位置做大小/相等比较（如 record[1] > record[2]、record[0] == record[8]、record[14] == 7、record[17] == 4），这些约束对应 flag 字符的格式/内容，DFS 到完整路径后逐条检查即可筛出唯一解。
- **复杂度**：9 个结点、边数有限，回溯 DFS 枚举欧拉路径的规模很小，无需启发式。

## 触发条件

- 已从二进制/脚本中恢复邻接矩阵与输入校验约束。
- 图为小规模无向图，奇数度结点为 0 或 2 个。
- 输入序列长度与边数匹配（欧拉路径经过每条边一次）。

## 利用步骤

1. 静态分析或动态跟踪，提取 9×9 邻接矩阵与逐位比较条件。
2. 计算各结点度数，确认奇数度结点为 0 和 4，确定起点 0、终点 4。
3. 用 `vis[i][j]` 标记边是否走过，从起点 DFS，每步选择未访问的邻边并记录结点。
4. 当路径长度等于边数+1 时，按程序约束逐条过滤；命中即输出 `aliyunctf{序列}`。
5. 若存在多解，补充更多约束或回到程序确认比较顺序/下标。

## PoC

```python
graph = [
 [0,0,1,0,0,1,0,0,1],
 [0,0,0,1,1,1,0,0,1],
 [1,0,0,1,0,0,1,1,0],
 [0,1,1,0,1,0,0,0,1],
 [0,1,0,1,0,0,1,0,0],
 [1,1,0,0,0,0,1,0,1],
 [0,0,1,0,1,1,0,0,1],
 [0,0,1,0,0,0,0,0,1],
 [1,1,0,1,0,1,1,1,0]]

def dfs(cur, path, vis):
    if len(path) == 18:  # 边数+1
        r = path
        if (r[1] > r[2] and r[3] < r[4] and r[0] == r[8] and
            r[11] == r[15] and r[10] > r[5] and r[3] < r[13] and
            r[7] < r[4] and r[14] == 7 and r[17] == 4):
            print("aliyunctf{" + "".join(map(str, r)) + "}")
        return
    for nxt in range(9):
        if graph[cur][nxt] and not vis[cur][nxt]:
            vis[cur][nxt] = vis[nxt][cur] = 1
            dfs(nxt, path + [nxt], vis)
            vis[cur][nxt] = vis[nxt][cur] = 0

dfs(0, [0], [[0]*9 for _ in range(9)])
```

## 变体与关联

- 变体：若图是欧拉回路（全偶度），起点可任选，需遍历所有起点或利用输入约束确定。
- 变体：约束可能是哈希/加密后的路径，需要先逆向出变换再过滤。
- 关联：同类“路径/迷宫校验”逆向见 [[ctf-reverse-fixed-grid-wasd-maze-bfs-path-md5]]；图论/状态机约束题可参考 [[ctf-reverse-fjm-rv32-state-machine]]。
- 边界：原文脚本中 `v` 未初始化、`vis` 用随机函数生成（实际全 0），复现时需按边数自行计算并显式清零。

## 检测与防御

- 本题为 CTF 逆向题，防御侧无直接对应；出题侧可增加图规模/多解/约束加密提高难度。
- 若作为软件校验逻辑，应避免仅靠客户端路径约束，关键判定放到服务端并加入随机性。
