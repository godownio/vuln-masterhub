---
id: iot-protocol-can-log-signal-mining
title: CAN 日志信号挖掘：按 ID 估周期、定位变化字节/位并区分计数器与校验
type: scenario
domain: iot
path: iot/protocol
technique: can-log-signal-mining
tags:
- iot
- automotive
- can-bus
- can-utils
- python-can
- recon
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:51:05+08:00'
  notes: 已对照原文与11张图片核对：candump -tz/-L 日志解析、按 ID 估 fps/周期中位数、变化字节/位定位、熵/变化率/counter_score 分类、id_summary.csv/signal_table.csv 输出与原文代码2/3一致；日志差分 19B 与 cansend 19B#00000E000000 的步骤与原文一致。原文为 vcan0/ICSim 仿真，未在真实车辆验证；未执行脚本。
url: /docs/iot/protocol/iot-protocol-can-log-signal-mining/
draft: false
kb_aliases:
- can_signal_miner
- candump 日志分析
- CAN 信号定位
- 变化字节
- rolling counter 识别
- 日志差分定位功能帧
---

## 一句话结论

把 candump 日志按 CAN ID 分组后，用帧间隔中位数估计周期、用相邻帧差异定位变化字节/位、用熵/变化率/自增得分区分 rolling counter、checksum、开关量和模拟量，可在不接触 ECU 的情况下把原始 CAN 流量变成可操作的信号表，为后续重放/伪造/诊断提供入口。

## 原理

- CAN 是广播式多主总线，ID 表示消息语义与优先级而非源/目的地址；同一 ID 的周期报文通常以 10/20/100ms 固定间隔发送，因此对时间戳序列取相邻差的中位数（比均值抗抖动）即可估计周期。
- 数据区 0–8 字节按信号编码：开关量（单 bit）、计数器（每帧 +1 mod 256）、物理量（连续变化）、校验（高熵、无规律）、认证（随 payload 变化）。对同一 ID 的字节序列计算变化率、Shannon 熵、`(prev+1)&0xFF==cur` 的自增比例和逐 bit 翻转率，可把字段粗分类。
- 周期报文描述“当前状态”，事件报文只在事件发生时发送；前者适合做周期/信号统计，后者（门锁、按键）适合做日志差分：分别记录基线日志和触发功能后的日志，按 ID 集合求差集，即可定位只在某功能发生时出现的帧。
- 变化字节/位的意义：操作某个功能（加速、转向、门锁）时，对应 ID 的某些 byte/bit 会变化；把 counter/checksum 剥离后，剩余字段才是可复现的功能载荷。CAN 无认证/加密，这一步是后续重放和伪造的前提。

## 触发条件

- 有 candump 日志（推荐 `candump -tz -L <if> > candump.log`）或可实时监听 SocketCAN 接口。
- Python 3 + python-can（实时模式）；离线分析只需标准库。
- 目标总线为明文 Classic CAN（未部署 SecOC/加密）；能触发目标功能以建立“操作→帧变化”对应关系。

## 利用步骤

1. 抓包：`candump -tz -L vcan0 > candump.log`（带时间戳、log 格式）；或用 `candump -l` 落盘。
2. 解析：正则匹配 `(ts) iface ID#DATA` 或 `ID [DLC] DATA` 两种格式，按 ID 分组并按时间排序。
3. 汇总：统计每 ID 帧数、fps、相邻时间差中位数（周期）、DLC 众数；按帧数排序取 Top N。
4. 字段分析：对 Top ID 的每个字节计算变化率、熵、counter 得分、bit 翻转率，按阈值分类为 `rolling_counter?`、`checksum_or_auth?`、`switch_or_flags?`、`analog_or_state?`、`static_or_constant?`。
5. 聚类：把时间轴切成 N 个窗口，记录每个字节在各窗口是否变化，按变化模式聚类，识别同组信号。
6. 输出 `id_summary.csv` 与 `signal_table.csv`，按 change_rate/label 排序人工复核。
7. 实时验证：运行实时 diff 脚本，操作 ICSim/控制面板，观察哪个 ID 的哪个 byte/bit 变化，建立功能映射。
8. 日志差分：记录正常日志与触发门锁/转向后的日志，`awk` 提取 ID 集合并 `diff`；例如 19B 仅在门未解锁时出现，`cansend vcan0 19B#00000E000000` 可复现解锁。

## PoC

```python
import re, math
from collections import defaultdict, Counter
from statistics import median

PAT = re.compile(r"\((?P<ts>[\d.]+)\)\s+\S+\s+(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)")

def parse(path):
    out = []
    for line in open(path, encoding="utf-8", errors="ignore"):
        m = PAT.search(line)
        if m:
            out.append((float(m["ts"]), int(m["id"], 16), bytes.fromhex(m["data"])))
    return out

def period_ms(ts):
    d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    return median(d) * 1000 if len(d) >= 4 else None

def counter_score(vals):
    return sum(1 for a, b in zip(vals, vals[1:]) if (a + 1) & 0xFF == b) / max(1, len(vals) - 1)

def change_rate(vals):
    return sum(1 for a, b in zip(vals, vals[1:]) if a != b) / max(1, len(vals) - 1)

def entropy(vals):
    c = Counter(vals); n = len(vals)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

frames = parse("candump.log")
by_id = defaultdict(list)
for ts, cid, data in frames:
    by_id[cid].append((ts, data))
for cid, items in sorted(by_id.items(), key=lambda x: -len(x[1]))[:10]:
    ts = [t for t, _ in items]
    n = max(len(d) for _, d in items)
    cols = [[d.ljust(n, b"\x00")[i] for _, d in items] for i in range(n)]
    print(f"0x{cid:X} frames={len(items)} period={period_ms(ts)}ms",
          [(i, round(change_rate(c), 2), round(entropy(c), 2), round(counter_score(c), 2))
           for i, c in enumerate(cols) if change_rate(c) > 0])
```

```bash
# 日志差分定位功能帧
candump vcan0 -f normal_log
candump vcan0 -f door_unlock_log
cat normal_log | awk '{print $3}' | cut -d'#' -f1 | sort | uniq > normal_ids.txt
cat door_unlock_log | awk '{print $3}' | cut -d'#' -f1 | sort | uniq > unlock_ids.txt
diff normal_ids.txt unlock_ids.txt      # 19B 只在解锁日志出现
grep '19B#' door_unlock_log | uniq       # 19B#00000E000000
cansend vcan0 19B#00000E000000          # 定点复现
```

## 变体与关联

- 变体：CAN FD（DLC>8）、29 位扩展 ID；解析正则需适配。
- 变体：加密/SecOC 总线，载荷高熵且无 counter 规律，信号挖掘只能得到统计特征，无法直接伪造。
- 变体：实时在线分析（python-can 订阅 + 滑动窗口）替代离线日志。
- 关联：[[iot-protocol-can-arbitration-id-discovery-spoofing]]（ICSim/cansniffer 交互式定位 + 注入）、[[iot-protocol-can-replay-candump-canplayer]]（记录回放）、[[iot-protocol-uds-routinecontrol-can-injection-takeover]]（诊断停发后注入）。

## 检测与防御

- 检测：被动嗅探本身难以发现；可在总线/网关侧监控异常抓包设备、诊断口接入；IDS 以基线周期/信号范围检测后续伪造。
- 防御：CAN 网关白名单/过滤、SecOC 消息认证与新鲜度、物理接口保护（OBD 锁）、对诊断与关键控制帧限速。
- 分析侧：把 counter/checksum 与功能载荷分离后再做重放/伪造，避免误判。
