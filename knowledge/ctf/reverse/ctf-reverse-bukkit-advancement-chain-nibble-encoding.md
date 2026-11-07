---
id: ctf-reverse-bukkit-advancement-chain-nibble-encoding
title: Bukkit 插件用成就依赖链编码 flag 半字节：jadx 逆向与路径还原
type: scenario
domain: ctf
path: ctf/reverse
technique: bukkit-advancement-chain-nibble-encoding
aliases:
- Fubukkit
- Minecraft 成就链
- advancement 编码
- 4-bit flag
- chal:goal
tags:
- ctf
- reverse
- java
- bukkit
- minecraft
- advancement
- nibble
- jadx
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:05:31+08:00'
  notes: 已对照原文与图片核对：split半字节、成就依赖链路径与flag一致；已修正44字节为split后半字节数组长度44即flag不超过22字节；未本机执行。
---

## 一句话结论

Bukkit 插件把 flag 的每个字节拆成高/低两个 4-bit，映射成 `chal:<index>_<value>` 成就名，并用“必须先获得父成就”的依赖链强制顺序；从插件源码还原 `root → goal` 的依赖路径，读取每一步的列值并按高/低半字节拼回字节，即可得到 flag。

## 原理

- **半字节拆分**：`split(byte[] bytes)` 对每个输入字节 `b` 生成两个字节：`(b & 0xF0) >> 4`（高 4 位）和 `b & 0x0F`（低 4 位）。因此一个 22 字节的 flag 会产生 44 个 0–15 的值。
- **成就命名**：`generateAdvancements()` 创建 `v0_0` 到 `v43_15` 的成就矩阵，名称模式为 `chal:<index>_<value>`，即“第几个半字节 + 该半字节的值”。每个成就的 `parent` 指向上一列中的某个特定行，例如 `v1_*` 依赖 `v0_7`、`v2_*` 依赖 `v1_3`。
- **依赖链即校验**：`tryGrant(player, key)` 先取成就的父成就，若父成就未授予则直接返回 false；只有按正确顺序依次获得成就，才能到达 `chal:goal`。因此合法路径本身就是题目要求的半字节序列。
- **为什么能逆推**：矩阵是 44 列 × 16 行，但每列只有一个“正确行”被作为下一列的父节点；从 `goal` 的父节点反向走回 `root`，或从 `root` 沿每列被指向的子节点走到 `goal`，路径唯一。把路径上每个成就名的第二个数字按顺序收集，得到 44 个 4-bit 值；每两个值按 `(high << 4) | low` 组合成一个字节，即 flag。
- **插件侧行为**：`test(player, flag)` 先检查是否有本插件调度任务（防止自动检查），再调用 `split(flag.getBytes())`；若 split 后的半字节数组长度不超过 44（即 flag 不超过 22 字节）则逐个授予对应成就，全部成功后触发 `chal:goal`。这解释了为什么玩家必须“按顺序获得成就，否则失败”。

## 触发条件

- 附件是 Minecraft Bukkit/Spigot 插件 jar，`plugin.yml` 声明了成就/进度相关逻辑。
- 用 jadx 打开后能看到 `split(byte[])`、`generateAdvancements()`、`tryGrant(Player, String)`、`test(Player, String)` 等方法。
- 成就标签页或代码中出现大量 `chal:<index>_<value>` 形式的名称，且父依赖构成链式结构。
- flag 长度被限制（原文限制 split 后的半字节数组为 44，即 flag 不超过 22 字节），每个字节对应两个半字节。

## 利用步骤

1. 用 `jadx-gui` 打开 jar，定位主类；搜索 `split`、`generateAdvancements`、`tryGrant`、`advancement`、`chal:` 等关键字。
2. 从 `generateAdvancements()` 提取每个成就的 `key` 与 `parent`，建立 `name -> parent` 映射；或从 `test()` 的 `split` 逻辑确认字节到半字节的映射顺序。
3. 从 `chal:goal` 的父节点开始反向回溯到 `root`，记录路径；也可从 `root` 开始，按“哪个成就以当前成就为 parent”向下走。
4. 按路径顺序取每个成就名 `chal:<index>_<value>` 的 `<value>`，得到半字节序列。
5. 每两个半字节组合：`byte_val = (values[i] << 4) | values[i+1]`，再 `bytes(...).decode()` 得到 flag。
6. 若路径出现分支，优先选择能走通到 `goal` 的分支；若名称中的 index 与路径顺序不一致，以 parent 链为准。

## PoC

原文还原出的 44 个半字节值（从 `root` 到 `goal`）：

```text
7, 3, 6, 11, 6, 14, 6, 2, 7, 11, 6, 2, 7, 5, 6, 11, 6, 11, 6, 9,
7, 4, 5, 15, 7, 7, 6, 15, 5, 15, 6, 2, 6, 1, 6, 11, 6, 11, 6, 9,
7, 4, 7, 13
```

组合脚本（未在本机对插件执行）：

```python
values = [
    7, 3, 6, 11, 6, 14, 6, 2, 7, 11, 6, 2, 7, 5, 6, 11, 6, 11, 6, 9,
    7, 4, 5, 15, 7, 7, 6, 15, 5, 15, 6, 2, 6, 1, 6, 11, 6, 11, 6, 9,
    7, 4, 7, 13,
]
data = bytes((values[i] << 4) | values[i + 1] for i in range(0, len(values), 2))
print(data.decode())
```

结果形如 `sknb{...}`（原文为 `sknb{bukkit_wo_bakkit}`）。若组合后不可打印，先检查半字节顺序是否应为 `low<<4 | high`。

## 变体与关联

- **半字节顺序变体**：先低 4 位后高 4 位；组合时交换 `values[i]` 与 `values[i+1]`。
- **命名变体**：`chal_<index>_<value>`、`<index>-<value>`、十六进制字符；从 `split` 与 `String.format` 确认格式。
- **图结构变体**：依赖链可能分叉、成环或用多个根；用图遍历（BFS/DFS）找唯一到达 `goal` 的路径。
- **关联**：[[ctf-reverse-memcmp-length-bug-state-machine-reward]]（状态机/奖励路径）、[[ctf-reverse-python-str-eq-monkey-patch-comparison-log]]（校验逻辑逆向）、[[ctf-reverse-pixel-low-nibble-direction-maze-bfs]]（低半字节编码 + BFS）。
- **边界**：若插件使用服务端数据包/资源包混淆成就名，需先解包资源；若 `test()` 有防自动化检查（如调度任务），静态分析不受影响。

## 检测与防御

- **CTF 识别**：Bukkit 插件 + 大量 `chal:` 成就 + `split` 半字节拆分，是“成就链编码 flag”的典型组合；优先看 `generateAdvancements` 的 parent 参数。
- **逆向技巧**：jadx 导出全部源码后，用正则提取 `CustomAdvancement("x_y", ...)` 与 `parent`，再用脚本建图；比手动追踪 44 列快得多。
- **防御（真实系统）**：这属于 CTF 校验逻辑，不是真实漏洞；若要把敏感数据编码进游戏成就，注意客户端可读取成就名称，不能当作保密手段。
- **出题思路**：用“依赖链唯一路径 + 半字节拆分 + 防自动化”提高静态/动态分析成本，但路径与命名最终都会泄露在插件字节码中。
