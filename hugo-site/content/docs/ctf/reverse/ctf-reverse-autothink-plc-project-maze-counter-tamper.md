---
id: ctf-reverse-autothink-plc-project-maze-counter-tamper
title: Autothink 组态工程逻辑逆向：FBD 迷宫位图还原与上升沿计数篡改
type: scenario
domain: ctf
path: ctf/reverse
technique: autothink-plc-project-maze-counter-tamper
tags:
- ctf
- reverse
- ics
- plc
- autothink
- fbd
- maze
- state-machine
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/ctf/reverse/ctf-reverse-autothink-plc-project-maze-counter-tamper/
draft: false
kb_aliases:
- Autothink 组态
- PLC 工程逆向
- FBD 逻辑
- 迷宫位图
- R_TRIG 上升沿
- 工控 CTF
---

## 一句话结论

工业组态软件（如 Autothink）的工程文件通常是一个 ZIP 容器，里面是可读的 FBD/梯形图逻辑。CTF 中常见两类题：一是把迷宫地图按“每行一个 8 位二进制数”存进 `Maze_Map0..7`，需要还原位图并模拟移动/终点条件；二是用 `R_TRIG` 检测按键上升沿并把 `count` 累加到 2999，直接改 `count=2999` 或删除/绕过上升沿检测块即可让一次触发即满足条件。核心是读逻辑、还原状态变量、改状态而不是硬跑次数。

## 原理

- **工程文件是自描述容器**：`.pcz` 等后缀常为 ZIP（`PK\x03\x04`），解压后是 XML/二进制工程；Autothink 打开后能看到变量表、FBD 逻辑块和注释。
- **位图编码**：每个 `Maze_MapN` 是 8 位整数，第 7 位到第 0 位对应一行 8 个格子的墙/通道；例如 `63=00111111`、`129=10000001`、`253=11111101`、`252=11111100`。逐行按位展开即可得到 8×8 迷宫。
- **位置/终点状态机**：`Current_Pos` 从起点开始，方向标志 `Dir_Up/Right/Down/Left` 触发移动；逻辑块判断 `Current_Pos == 63` 时置 `Maze_End=TRUE` 并计算 `Flag_Status`（示例 `1179402567 = 0x464C4147 = "FLAG"`）。程序移动看的是标志位的**上升沿**（0→1），所以每次移动前要把对应标志置 0。
- **R_TRIG 计数**：`R_TRIG` 在输入从 FALSE 变 TRUE 时输出一个扫描周期脉冲；`try_it` 每按一次产生一个上升沿，逻辑在 `count != 2999` 时把 `try_it` 置位并 `count+1`，末尾再把 `try_it` 复位。由于上升沿检测，单纯把 `try_it` 一直置 TRUE 只会计一次。
- **绕过思路**：删除/短路 `R_TRIG` 块，使每次置位都计数；或直接把 `count` 改为 2999、把 `result` 改为目标值；或用脚本连续产生 2999 次 0→1 的边沿（慢但可行）。
- **为什么成立**：组态工程是解释执行的逻辑/变量模型，运行时状态可被强制/修改；CTF 题目通常只校验最终变量值，不校验过程。

## 触发条件

- 拿到 Autothink/类似组态软件的工程文件（`.pcz`、工程目录或导出文件）。
- 能安装/运行组态软件并打开工程，或能解析其 XML/逻辑块。
- 题目逻辑依赖地图/计数器等状态变量，最终输出为变量值或 flag。
- 允许修改工程/强制变量/离线仿真。

## 利用步骤

1. 识别工程容器：`file`/`xxd` 看是否 `PK\x03\x04`；是则解压，找工程 XML、变量表、逻辑块。
2. 用 Autothink 打开工程，浏览变量表与 FBD 逻辑；搜索注释中的 `Flag`、`Maze`、`count`、`try_it` 等关键字。
3. 迷宫题：提取 `Maze_Map0..7` 的初值，按位展开成 8×8 网格；确认 `Current_Pos` 起点、方向标志与终点值（如 63）。
4. 写脚本模拟移动：维护位置，按方向标志更新坐标；遇到墙/越界则停在原地；到达终点读取 `Flag_Status`/输出值。
5. 计数题：定位 `R_TRIG` 与 `count` 逻辑；把 `count` 强制为 2999，或删除 `R_TRIG` 块并让 `try_it` 置位一次，或直接用脚本产生 2999 个上升沿。
6. 运行/离线仿真，读取 `result`/flag；记录修改点（逻辑块、变量强制）以便复现。

## PoC

迷宫位图展开与简单移动模拟（结构示意）：

```python
maze = [63, 129, 253, 253, 253, 253, 129, 252]

def print_maze(rows):
    for row in rows:
        print("".join("*" if row & (1 << (7 - i)) else " " for i in range(8)))

print_maze(maze)

# 方向与位置更新需按题目逻辑实现；到 Current_Pos == 63 时读取 Flag_Status
```

计数绕过（逻辑修改，不是代码）：

```text
原逻辑: try_it --[R_TRIG]--> count != 2999 ? (try_it:=TRUE, count:=count+1) : ...
绕过:   删除 R_TRIG，直接 try_it -> count+1
或:     count := 2999; result := 目标值
```

说明：工程文件格式因版本而异，以上为思路；实际修改需在 Autothink 中完成并重新仿真。

## 变体与关联

- 变体：迷宫按行/列位图、十六进制或 ASCII 存储；终点不是 63 而是坐标/变量组合。
- 变体：计数用 `CTU`/`CTD` 计数器、边沿检测指令（`R_TRIG`/`F_TRIG`）或扫描周期计数。
- 变体：工程文件加密/压缩，需要先脱壳或找密码；也可直接 patch 运行时变量。
- 关联：[[ctf-reverse-pixel-low-nibble-direction-maze-bfs]]（像素低位方向编码迷宫）；[[ctf-misc-maze-horizontal-move-bitstream]]（迷宫路径位流还原）；[[iot-industrial-s7comm-elevator-multi-db-state-forgery]]（工控状态伪造）。

## 检测与防御

- 检测：组态工程文件的哈希/签名变化；运行期变量被强制、逻辑块被删除/短路；离线仿真与现场逻辑不一致。
- 检测：按键计数、生产计数等关键变量异常跳变；`R_TRIG`/计数器逻辑被修改。
- 防御：对 PLC/组态工程做变更管理与完整性校验；关键逻辑块加保护/密码；运行时监控变量强制与在线修改。
- 防御：CTF/仿真环境与生产隔离；不要把工程文件的可写权限开放给非运维人员。
