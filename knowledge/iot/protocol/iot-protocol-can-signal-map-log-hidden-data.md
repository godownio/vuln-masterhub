---
id: iot-protocol-can-signal-map-log-hidden-data
title: CAN 日志 + 信号映射表隐藏数据提取：按 sig_N 末值拼出 ASCII 字符串
type: scenario
domain: iot
path: iot/protocol
technique: can-signal-map-log-hidden-data
aliases:
- CAN 信号映射表
- signal_map.csv
- canlog 解析
- CAN 隐写提取
- sig_1..sig_N
tags:
- iot
- automotive
- can-bus
- signal-map
- canlog
- data-extraction
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:39:03+08:00'
  notes: 已对照原文 Misc 部分与 CAN 截图核对：signal_map.csv 字段 signal/can_id/byte/len/type、can0 ID#data 日志格式、sig_N 取末值转 ASCII 按数字序号拼接、去重/众数思路均与原文一致；原文最终 flag 为 flag{V3h1cle_N3tw0rk1ng_53cu71ty}，PoC 逻辑可复现，未在本机用原始日志执行。
---

## 一句话结论

当拿到 `signal_map.csv`（信号名→CAN ID/字节偏移/长度/类型）和 `canlog.txt`（`(时间戳) can0 ID#数据`）时，按映射表把每个 `sig_N` 的取值抽出来，取每个信号的最后一个值（或该通道出现最多的值）转成 ASCII，再按 `sig_N` 的数字顺序拼接，就能还原藏在 CAN 信号末字节里的 flag/字符串。

## 原理

- CAN 是广播总线，同一信号会被 ECU 周期性重复发送；日志里同一 `sig_N` 会出现很多帧，但隐藏数据只关心“最终状态”或“稳定值”，所以取最后一个值/众数即可去噪。
- `signal_map.csv` 给出每个信号的语义：`signal,can_id,byte,len,type`。`can_id` 是十六进制，`byte` 是该信号在 8 字节数据中的起始偏移，`len` 是字节数，`type` 决定解析方式（`uint8` 直接取一个字节，`uint16` 按小端组合两个字节）。
- 本题的 `sig_1`–`sig_72` 都是 `uint8`，每个信号对应一个 CAN ID 和一个字节位置，相当于把一条 ASCII 字符串拆成 72 个单字符通道，每个通道的最后一个值就是该字符的编码。
- 为什么能还原：映射表与日志是同一套信号定义；只要按 ID/偏移正确取值，字符顺序由 `sig_N` 的数字序号决定，拼接后即可读。
- 若日志中同一信号有多个不同值，优先取最后值；仍不稳定时取该通道出现次数最多的值，或按时间窗口过滤。

## 触发条件

- 有信号映射表（CSV/JSON/DBC 等）和对应时间段的 CAN 日志。
- 日志格式可解析出 CAN ID 与数据字节（如 `candump` 的 `can0 113#cf6d...`）。
- 隐藏数据按信号通道拆分，单通道值在可打印 ASCII 范围内。
- 能确定信号顺序（`sig_N` 的数字后缀或映射表行序）。

## 利用步骤

1. 解析 `signal_map.csv`，建立 `signal -> {can_id, byte, len, type}` 映射；注意 `can_id` 按十六进制解析。
2. 逐行解析 CAN 日志，正则提取时间戳、CAN ID、数据字节；忽略无法匹配的行。
3. 对每一帧、每个信号，若 CAN ID 匹配且数据长度足够，按 `byte`/`len` 取出值；`uint8` 取单字节，`uint16` 按约定端序组合。
4. 对每个信号保留最后一个值（或统计众数）；把值转成字符，过滤不可打印项。
5. 按 `sig_N` 的数字序号排序（不要按字符串排序，否则 `sig_10` 会排在 `sig_2` 前），拼接字符。
6. 用 `flag{...}` 等格式正则定位结果；若出现乱码，检查字节偏移、端序、是否取错帧。

## PoC

```python
import re, csv
from collections import defaultdict, Counter

CAN_RE = re.compile(r'\(([\d.]+)\)\s+can0\s+([0-9a-fA-F]+)#([0-9a-fA-F]+)')

signals = {}
with open('signal_map.csv', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        signals[row['signal']] = {
            'can_id': int(row['can_id'], 16),
            'byte': int(row['byte']),
            'len': int(row['len']),
        }

values = defaultdict(list)
with open('canlog.txt', encoding='utf-8') as f:
    for line in f:
        m = CAN_RE.match(line.strip())
        if not m:
            continue
        cid = int(m.group(2), 16)
        data = bytes.fromhex(m.group(3))
        for name, info in signals.items():
            if cid == info['can_id'] and len(data) > info['byte']:
                b, n = info['byte'], info['len']
                v = data[b] if n == 1 else int.from_bytes(data[b:b+n], 'little')
                values[name].append(v)

def order(name):
    return int(name.split('_')[1]) if name.startswith('sig_') else 0

chars = []
for name in sorted(values, key=order):
    if not name.startswith('sig_'):
        continue
    # 末值；若不稳定可改成 Counter(values[name]).most_common(1)[0][0]
    v = values[name][-1]
    chars.append(chr(v) if 32 <= v <= 126 else '?')
print(''.join(chars))
```

## 变体与关联

- 变体：同一信号有噪声时取众数/中位数，或只保留时间窗口内稳定不变的通道。
- 变体：`uint16`/`int16`/大端信号需要按映射表的类型和端序解析；多字节信号可能跨字节边界。
- 变体：日志格式换成 `candump -l`、BLF、ASC、MDF4 时，先用对应解析库转成 ID+数据再套同一逻辑。
- 变体：隐藏数据不一定在末值，也可能在每次变化的差值、信号名本身或通道间的组合关系里；先做可打印性筛选。
- 关联：[[iot-protocol-can-replay-candump-canplayer]]（CAN 日志记录与回放）、[[iot-protocol-can-arbitration-id-discovery-spoofing]]（CAN ID 与信号定位）、[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（本题信号映射表所在压缩包的伪加密修复）。

## 检测与防御

- 检测（CTF/取证）：对 CAN 日志做按 ID/字节位置的取值分布统计，寻找只取可打印 ASCII 且按序号排列的通道；检查信号映射表中异常的 `sig_*` 批量信号。
- 检测（车联网）：CAN 日志与 DBC/信号映射表属于敏感资产，泄露后可还原车辆行为与隐藏数据；限制诊断口/日志导出权限。
- 防御：不要用 CAN 信号通道传输敏感数据；对日志导出做脱敏与访问控制；信号映射表按最小权限分发。
- 边界：该方法依赖映射表准确；映射错误、端序错误或信号被网关重写时会得到乱码，需要用已知信号（车速、转速）校验解析。
