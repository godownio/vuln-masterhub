---
id: ctf-forensics-can-uds-wdbi-request-response-pair-extract
title: candump 日志里成对提取 UDS 0x2E（WriteDataByIdentifier）请求与 0x6E 正响应，把请求帧第 4 字节起的负载按 UTF-8 解码即还原被写入的数据
type: scenario
domain: ctf
path: ctf/forensics
technique: can-uds-wdbi-frame-pair-payload-decode
tags:
- ctf
- forensics
- can
- uds
- candump
- automotive
- hex-decode
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:51:58+08:00'
  notes: 已对照原文核对：line.split('#')[1] 取数据段、frame[2:4]=='2E' 与紧随帧 '6E' 配对、bytes.fromhex(frame[8:]) 解码，PoC 与原文脚本一致；原文为单帧 CAN 经典帧，PCI/SID/DID 偏移推导成立。本次核对未读取图片，仅依据正文；未验证点：多帧 ISO-TP 重组为卡内推广说明，原文未给出实例，未复跑脚本。
url: /docs/ctf/forensics/ctf-forensics-can-uds-wdbi-request-response-pair-extract/
draft: false
kb_aliases:
- candump.txt 提 UDS WDBI
- 0x2E WriteDataByIdentifier
- 0x6E 正响应配对
- CAN 帧负载 hex 解码
- candump 分列解析
---

## 一句话结论

汽车类 CTF 给的 `candump` 文本里，真正带信息的往往只有 UDS 诊断请求：用 `line.split("#")[1]` 取出数据段，筛选 `frame[2:4] == "2E"`（0x2E = WriteDataByIdentifier，写数据）的帧，再看**紧随其后**的一帧是否为 `6E` 开头的正响应，两者配对成立就把请求帧第 4 个数据字节起的内容按 hex 解成字符串 —— 逐条拼接即得被写入的明文。

## 原理

- `candump` 每行格式为 `(时间戳) 接口 ID#DATA`，`#` 之后是 8 字节（CAN 经典帧）十六进制数据；**数据段前两个字节是 UDS 服务标识 + 长度/子功能**，`2E` 就是 `WriteDataByIdentifier`。
- UDS 正响应规则：服务 ID 加 `0x40`。`0x2E + 0x40 = 0x6E`，所以下一帧以 `6E` 开头即表示这次写入被 ECU 接受，可确认为"真实发生过的一次写操作"。
- 偏移为什么是第 4 个字节（`frame[8:]`）：`frame` 字符串里前 2 字节是 PCI（单帧则为 `0x0x` 长度）、接着 2 字节服务 ID、再 2 字节 DID（数据标识符），其后才是 `dataRecord`。
- 多帧传输（ISO-TP）时首个数据帧是 `10 LL`，续帧 `2x`，此时需先重组再按 `2E` 判断；本题为单帧，直接按偏移取即可。
- 之所以要"配对"，是为了过滤掉写了但被 ECU 拒绝（负响应 `7F 2E xx`）的噪声帧，避免把失败写入当数据解出来。

## 触发条件

- 拿到的是 `candump`/`candump -l` 文本或 `candump` 转换后的日志，且其中包含 UDS 诊断流量。
- 目标数据（密码、序列号、配置串）是经 `WriteDataByIdentifier` 写入的，且长度小于单帧可承载的 7 字节，或可多帧重组。

## 利用步骤

1. 逐行 `split("#")[1]` 取出数据段，去掉空白。
2. 筛 `[2:4] == "2E"` 的请求帧；检查 `i+1` 帧是否 `[2:4] == "6E"`。
3. 取请求帧 `[8:]` 的十六进制内容 → `bytes.fromhex(...).decode("utf-8")`。
4. 按时间顺序拼接；若出现 `10`/`21`/`22` 等多帧 PCI，先按 ISO-TP 重组（首帧 `10 LL` 给出总长，续帧序号递增）。

## PoC

```python
frames = []
with open("candump.txt") as f:
    for line in f:
        frames.append(line.split("#")[1].strip())   # 去掉时间戳/接口/ID

out = ""
for i in range(len(frames) - 1):
    if frames[i][2:4] == "2E":                       # WriteDataByIdentifier 请求
        if frames[i + 1][2:4] == "6E":               # 紧跟的正响应
            out += bytes.fromhex(frames[i][8:]).decode("utf-8", "ignore")
print(out)
```

## 变体与关联

- 服务 ID 推广：`0x22` ReadDataByIdentifier（正响应 `0x62`）、`0x2E` 写、`0x27` SecurityAccess（`0x67`）、`0x31` RoutineControl（`0x71`）。
- 多帧重组：`10 xx` 首帧 + `2x` 续帧按序号拼接后再按服务 ID 解析。
- 若日志是 `.blf`/`.asc`/pcap（带 CAN 驱动），先转 candump 或直接按 `can.id == 0x7xx` 抓诊断 ID 再套同样逻辑。
- 与"CAN 信号挖掘（按 ID 估周期、找变化字节）"互补：信号挖掘用于找周期广播帧，本卡用于抓一次性诊断写入。

## 检测与防御

- 检测：车辆/网关侧对 `0x2E` 写入做完整性校验与审计日志；诊断 ID 上的异常写入序列（连续写、非法 DID）应告警。
- 防御：诊断服务需 SecurityAccess 解锁后再允许写；生产环境关闭非必要写服务；对 CAN 日志做留存以便事后还原写入内容。
