---
id: ctf-reverse-zhie-map-vm-search
title: 文件驱动地图 VM 逆向：状态机复刻 + A* 搜索生成通关行动文件
type: scenario
domain: ctf
path: ctf/reverse
technique: zhie-map-vm-state-search
tags:
- ctf
- reverse
- vm
- map
- state-machine
- search
- astar
- emulator
- puzzle
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:27+08:00'
  notes: 已对照原文 §29 ZhiE 核对：27*11*11 地图、字节=行动(高4位x/低4位y)、0xC1..0xC7 商店/传送+0xFF、退出码判定、bd70->bd74/21层0x3B/23层0xCA/25层0xCB/22层0x18 隐藏链、优先队列搜索+资源支配剪枝、原 ELF ret:0 复核均一致；原文 final (1).bin 1552B 已验证，未本机复跑。
url: /docs/ctf/reverse/ctf-reverse-zhie-map-vm-search/
draft: false
kb_aliases:
- ZhiE
- REverse2
- 魔塔式地图 VM
- 行动文件
- 状态机复刻
- A* 搜索
- 隐藏事件链
---

## 一句话结论

`ZhiE` 是文件驱动的地图 VM/魔塔式资源规划逆向题，不是字符串校验：程序读取输入文件，把每个字节解释成一次行动（普通模式高 4 位 x、低 4 位 y；`0xC1..0xC7` 进入商店/传送状态机，`0xFF` 退出），目标是让原 ELF 走到胜利分支并 `exit(0)`。静态提取 `27*11*11` 地图与 switch/jump table，复刻楼层、坐标、血攻防、金币、经验、三色钥匙、商店状态、隐藏 flag 和动态地图改写，再用 A*/优先队列搜索一条通关行动序列，最后用原 ELF 复核退出码为 0。

## 原理

- **输入即行动**：每个字节是一位行动编码；普通移动用高 4 位 `x`、低 4 位 `y`，商店/传送用 `0xC1..0xC7` 进入对应 mode，`0xFF` 退出 mode。程序不打印 flag，只以退出码表示胜负，因此最终提交物是二进制行动文件。
- **地图与事件**：`.data` 中有 `27*11*11` 地图（27 层、11×11）；switch/jump table 决定每个 tile 的行为：空地、黄/蓝/红门、钥匙、血瓶、宝石、楼梯、商店、怪物、传送、隐藏事件等。
- **状态机**：需要复刻楼层、坐标、HP/ATK/DEF、金币、经验、三色钥匙、商店 mode、`max_floor`、隐藏 flags（`bd6c/bd70/bd74/...`）以及动态地图改写（击杀特定怪、特定事件后改 tile）。
- **隐藏事件链**：`bd70 -> bd74`、21 层击杀 `0x3B` 改图、23 层 `0xCA`/25 层 `0xCB` 置位，之后 22 层 `0x18` 打开 26 层终局怪；忽略这些会导致搜索走进死路。
- **搜索**：用优先队列/A* 按“到达楼层/获得 shop4/击败终局怪”的启发式扩展；状态签名包含地图哈希、楼层/坐标、钥匙、mode、flags，资源（HP/ATK/DEF/金币/经验）做支配剪枝；找到胜利路径后写出行动文件，用原 ELF 跑 `ret:0` 验证。

## 触发条件

- 目标是读取文件、按字节解释行动的地图/VM 程序，胜负由退出码表示。
- 地图、switch/jump table、怪物/商店/事件参数可静态提取。
- 状态可复刻，且搜索空间可通过资源支配/楼层目标剪枝。
- 有原 ELF 可做最终 `exit(0)` 验证。

## 利用步骤

1. 静态提取 `.data` 的 `27*11*11` 地图与 switch/jump table，标注每个 tile 的行为。
2. 复刻解释器：普通移动、门/钥匙、血瓶/宝石、怪物战斗、商店 1..7、传送、隐藏 flags、动态地图改写。
3. 识别隐藏事件链与终局条件（21 层 0x3B、23/25 层 0xCA/0xCB、22 层 0x18、26 层终局怪）。
4. 用优先队列/A* 搜索：状态签名 + 资源支配剪枝，候选动作来自可达 tile 与商店命令。
5. 找到胜利路径后写 `pass.bin`/`final.bin`，用原 ELF 运行并检查退出码为 0；失败则调整启发式/补充状态。

## PoC

```python
def state_sig(s):
    return (hash(bytes(s.m)), s.floor, s.x, s.y, s.ky, s.kb, s.kr,
            s.mode, s.max_floor, tuple(sorted(s.flags.items())))

def is_dominated(old, vals):
    hp, atk, df, gold, exp = vals
    return any(ohp >= hp and oatk >= atk and odf >= df and ogold >= gold and oexp >= exp
               for ohp, oatk, odf, ogold, oexp in old)

def priority(s, n):
    return (0 if s.flags.get("shop4") else 1,
            abs(s.floor - 14),
            -(s.max_floor * 300 + s.flags.get("bd7c", 0) * 200 + s.flags.get("bd74", 0) * 100),
            -(s.hp + s.atk * 2000 + s.df * 1500 + s.gold * 80 + s.exp * 100),
            n, -s.hp, -s.atk)

# 从 START 状态出发，按 candidate_bytes(s) 扩展，直到 s.won 或 shop4
```

## 变体与关联

- 其他地图/资源规划题：魔塔、RPG 关卡、网格路径搜索；核心是“精确复刻状态机 + 启发式搜索”。
- 若状态空间过大，可用分层目标（先拿 key/商店，再打 boss）、宏动作、强化学习/蒙特卡洛。
- 若原程序有反调试/校验，可先 patch 或直接在模拟器中验证后再用原 ELF 复核。
- 关联：文件驱动 VM、魔塔/地图状态机、A* 搜索卡。

## 检测与防御

- 这是 CTF 谜题；防御意义在于：不要把胜负逻辑完全放在客户端，关键判定放服务端；对输入文件做结构/长度/状态校验。
- 检测：程序读取大文件并按字节解释为坐标/命令；高频状态机分支；大量 tile 比较表。
