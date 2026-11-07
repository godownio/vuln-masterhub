---
id: ctf-misc-prism-shadow-oracle-permutation-search
title: 黑盒交互状态机 + shadow 哈希 oracle：还原随机 wiring 并用 MITM/beam 搜索打开七层 seal
type: scenario
domain: ctf
path: ctf/misc
technique: prism-shadow-oracle-permutation-search
tags:
- ctf
- misc
- interactive
- state-machine
- hash-oracle
- permutation
- mitm
- beam-search
- blake2s
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:47:53+08:00'
  notes: 已对照原文核对：mirror token 反转、look/scan/oracle/shadow/turn/verify 命令、blake2s digest_size=12 person=PRISMv2、9 个基础物理转动建 150 位置换库、5 次 shadow 探测、goal_type 与 cycle left_to_right 生成、MITM/beam 评分函数、15 秒 scan ids keepalive、七层 seal 输出均一致。未验证点：PoC 未在本机复跑，C++ 辅助程序未提供完整源码；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-prism-shadow-oracle-permutation-search/
draft: false
kb_aliases:
- PRISM's end BLACKBOX
- 七层 seal
- sticker 状态机
- shadow hash oracle
- wiring 还原
- 置换搜索 MITM
- beam search
---

## 一句话结论

TLS 交互服务有七层 seal，每层给出 24 个 sticker 的扫描面、转动次数、shadow 次数与目标规则；`shadow` 命令不改变真实状态但返回转动后完整状态的 `blake2s-12` 哈希，`turn` 才真正转动。每轮命令到物理轴的 wiring 会随机改线，先用同一初始状态的 9 个基础物理转动建立 150 位置换库，再用 5 次 `shadow` 探测反推出轴/层/符号映射；把 oracle 转换为“若干 sticker 从当前位置移动到目标位置”的置换搜索问题，浅层用双向 meet-in-the-middle、深层用 beam search，连续验证七层后得到 flag。

## 原理

- **服务协议**：连接后 banner 给出 `mirror token: <token>`，反转 token 发送即可进入命令行；主要命令 `look ids <front|back|left|right|top|bottom>`、`scan ids`、`oracle`、`shadow <axis> <layer> <sign>`、`turn <axis> <layer> <sign>`、`verify`。
- **状态模型**：`look ids` 可读六个面共 150 个 sticker 的完整状态；`scan ids` 给出当前 opening 需要匹配的 24 个扫描槽位；`oracle` 给出目标与规则；`shadow` 返回某个转动后的状态哈希但不改变真实状态；`turn` 执行真实转动；`verify` 提交当前 opening。
- **shadow 哈希**：服务端对完整状态计算 `blake2s(bytes(state), digest_size=12, person=b"PRISMv2").hexdigest()`；同一状态哈希稳定，可用于比对本地物理转动库。
- **wiring 随机化**：每个 opening 都会随机改线，`turn roll low +` 并不对应固定物理动作。先在同一初始状态下依次执行 9 个基础物理转动，记录每次 `look ids` 的完整状态；对相邻状态比较得到每个基础动作的 150 位 permutation，反向动作取逆置换。
- **wiring 还原**：每个 opening 用 5 次 shadow 探测（`roll low +`、`pitch low +`、`yaw low +`、`roll mid +`、`pitch mid +`），把返回 trace 与本地物理转动库逐一比对，确定输入轴到物理轴的置换、输入层到物理层的置换、每个轴的正负号；`low`、`mid` 两层观测到后，缺失的输入层/物理层由三层集合差补出。
- **目标类型**：`selected_slots`、`locked_match` 是精确位置匹配；`required_ids` 只要求指定 id 出现在 24 个扫描位置；`cycle_program`/`local_delta` 给出若干 cycle，`cycle_order=left_to_right` 表示 `(a b c)` 中 a 的 id 移到 b、b 移到 c、c 移到 a，据此生成目标扫描数组；最后一层 `full_scan_match` 等价于 24 个槽位全部精确匹配 target_ids。
- **搜索**：先把目标 id 映射成当前完整状态中的位置，再把扫描槽位映射成完整状态中的目标位置；浅层用双向 MITM（12 步以内精确），深层（17-22 步）用 beam search；beam 评分只依赖当前匹配数量和每个 sticker 到目标位置的单点最短距离：`fixed*10000 - total*30 - worst*200 - depth`。
- **连接保持**：外部 C++ 求解可能运行几十秒，期间空闲会被服务端断开；每 15 秒发送只读 `scan ids` 作为 keepalive，不改变状态也不消耗 turn budget。

## 触发条件

- 交互式服务提供完整状态读取、目标 oracle、无副作用的哈希探测与真实转动命令。
- 命令到物理动作的映射每轮随机化，但可通过探测还原。
- 状态是有限置换（sticker 位置），目标可转化为置换/路径搜索。
- 转动次数预算足够 MITM/beam 搜索；服务端允许 keepalive。

## 利用步骤

1. 连接服务，反转 mirror token 登录；用 `look ids` 拉取六个面完整状态。
2. 在同一初始状态下依次执行 9 个基础物理转动，记录每次完整状态，构建 150 位 permutation 库与逆置换。
3. 每个 opening 发送 5 个 `shadow` 探测，比较 trace 与库，恢复 axis/layer/sign 映射；缺失层用集合差补出。
4. 解析 `oracle` 的 goal_type 与目标；按类型生成目标扫描数组（cycle 按 left_to_right 方向）。
5. 把目标映射为位置序列，按预算选择 MITM（<=12 步）或 beam（17-22 步）搜索，把命令序列转换为本轮真实 turn 命令。
6. 执行 `turn`，`verify` 提交；等待 C++ 求解时每 15 秒发 `scan ids` keepalive。
7. 连续打开七层 seal，读取最终 `d3ctf{...}`。

## PoC

状态哈希与 wiring 探测：

```python
import hashlib

def trace_state(state):
    return hashlib.blake2s(bytes(state), digest_size=12, person=b"PRISMv2").hexdigest()

probes = ["roll low +", "pitch low +", "yaw low +", "roll mid +", "pitch mid +"]
for cmd in probes:
    trace = client.cmd(f"shadow {cmd}")
    match = library.lookup(trace)      # 与本地物理转动库比对
    print(cmd, trace, match)
```

cycle 目标生成：

```python
target_scan = meta["base_ids"][:]
constrained = set(meta["fixed_slots"] or meta["anchors"])
for cycle in meta["cycles"]:
    old = target_scan[:]
    constrained.update(cycle)
    for i, slot in enumerate(cycle):
        target_scan[cycle[(i + 1) % len(cycle)]] = old[slot]
slots = sorted(constrained)
targets = [target_scan[s] for s in slots]
```

beam 评分：

```python
def score(positions, depth):
    fixed = sum(1 for p, g in zip(positions, goal) if p == g)
    total = sum(dist[p] for dist, p in zip(dist_tables, positions))
    worst = max(dist[p] for dist, p in zip(dist_tables, positions))
    return fixed * 10000 - total * 30 - worst * 200 - depth
```

## 变体与关联

- 无副作用哈希探测可换成时间侧信道、错误码、响应长度；核心是“用 oracle 还原随机映射”。
- 置换搜索可换成 A*、IDA*、SAT/CP-SAT、遗传算法；状态空间大时用分层/子目标分解。
- wiring 可换成每轮随机密钥/坐标变换；先校准再探测的思路通用。
- 关联：黑盒状态机、哈希 oracle、置换群搜索、MITM/beam search 卡。

## 检测与防御

- 服务端不要提供无副作用的完整状态哈希 oracle，或对探测做速率/次数限制；wiring 随机化不能只靠隐藏映射。
- 校验应在服务端一次性完成，避免客户端有足够 turn 预算做搜索；对异常高频 shadow/scan 请求告警。
- 对交互式挑战/游戏，限制 keepalive 与空闲连接，记录探测序列；核心状态不要完整暴露给客户端。
