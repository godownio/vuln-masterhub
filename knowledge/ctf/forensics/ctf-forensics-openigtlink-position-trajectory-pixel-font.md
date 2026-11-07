---
id: ctf-forensics-openigtlink-position-trajectory-pixel-font
title: OpenIGTLink POSITION 轨迹还原：剔除失真点后按 z 分层栅格化成 5×7 像素字体
type: scenario
domain: ctf
path: ctf/forensics
technique: openigtlink-position-trajectory-pixel-font
aliases:
- 手术室的空中笔迹
- OpenIGTLink 轨迹隐写
- NAV_TRACKER 坐标
- 5x7 像素字体
- HD44780 glcdfont
- 512Hz 采样
- 三维轨迹还原文本
tags:
- ctf
- forensics
- openigtlink
- medical-protocol
- pcap
- trajectory
- rasterization
- pixel-font
- hd44780
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:33+08:00'
  notes: 对照 Misc241：602 条 86B POSITION、z 三层、83×7 栅格、5×7 字库 42 字符一致
---

## 一句话结论

从 TCP 会话中按 `\x00\x01POSITION` 切出 602 条 OpenIGTLink POSITION 消息，剔除坐标失真的离群点后，按 z 值分成三层，把每层 x/y 映射到 83×7 栅格并用 5×7 像素字体逐字形匹配，三行各 14 字符拼出 42 字符 flag。

## 原理

- OpenIGTLink 是手术导航常用协议。POSITION 消息每条 86 字节：58 字节头（版本、类型 `POSITION`、设备名 `NAV_TRACKER`、时间戳、`body_size=28`、CRC64）+ 28 字节体（3 个 float 坐标 + 单位四元数）。
- 时间戳以 1/256 秒递增，即 512Hz 采样；602 个点构成一条连续轨迹。按 `\x00\x01POSITION` 魔数切分 TCP 重组流即可定位每条消息。
- 602 个点中 z 只有 310/314/318 三个整数值（共 573 点），其余 29 个点坐标全是非整数且 z 高达 700~1290、y 到 -1694，是明显的失真/干扰点。CRC64 字段与常见变体（XZ、ECMA-182 等）都对不上，不能靠校验识别，只能用坐标合法性/分布剔除。
- 剔除后 x∈[1250,1332]（83 列）、y∈[-730,-724]（7 行），正好是 83×7 的栅格；按 z 分三层，每层是一行 5×7 字符点阵（HD44780/glcdfont 经典像素字体），每行 14 个字符，三层共 42 字符。
- 把每层按 x 分块、y 映射到 7 行，与 5×7 字库逐格匹配（先精确匹配，失败取汉明距离最近的候选）；18 个不同字形与 18 个不同字符一一对应且无冲突，说明拼读无歧义。三层按 z 升序拼接，开头即 `flag{`。

## 触发条件

- 抓到包含 OpenIGTLink POSITION 消息的 TCP 流量，消息结构可解析。
- 轨迹点数量与目标文本长度匹配（每字符 5×7 点阵、按 z 分层）；坐标范围可映射到离散栅格。
- 存在离群/失真点，需要按坐标合法性或统计分布剔除。
- 有 5×7 像素字体字库可用于模板匹配。

## 利用步骤

1. 重组 TCP 流，按 `\x00\x01POSITION` 切分消息；解析头部的版本、类型、设备名、时间戳、body_size 与 CRC64。
2. 解析 28 字节体中的 3 个 float 坐标与四元数；按时间戳排序。
3. 统计 x/y/z 分布，识别离群点（非整数、超出主流范围）并剔除；用主流 z 值分层。
4. 把每层 x 归一化到 83 列、y 归一化到 7 行，栅格化为二值图像；按 5 列宽切分字符。
5. 与 5×7 字库做精确匹配，失败时用汉明距离最近邻；按 z 升序拼接各层结果。
6. 用 `flag{` 前缀/`}` 后缀和字符唯一性校验解码正确性。

## PoC

```python
import struct, re

raw = reassemble_tcp(pcap)                      # TCP 重组后的字节流
msgs = raw.split(b"\x00\x01POSITION")[1:]
points = []
for m in msgs:
    # 头部 58B：版本(2) 类型(12) 设备名(20) 时间戳(8) body_size(8) CRC64(8)
    body = m[58:58 + 28]
    x, y, z = struct.unpack(">fff", body[:12])
    points.append((x, y, z))

# 剔除离群点：z 只保留主流三个整数值
z_vals = sorted({round(p[2]) for p in points})
main_z = [z for z in z_vals if sum(round(p[2]) == z for p in points) > 100]
pts = [p for p in points if round(p[2]) in main_z]

# 按 z 分层，x/y 栅格化到 83x7，再与 5x7 字库匹配
for z in sorted(main_z):
    layer = [(x, y) for x, y, zz in pts if round(zz) == z]
    grid = rasterize(layer, width=83, height=7)  # x -> 列, y -> 行
    text = match_5x7_font(grid)                   # 精确匹配 + 汉明距离最近邻
    print(z, text)
```

## 变体与关联

- 变体：坐标可编码为 8×8、6×8 或其他点阵字体；分层维度可换成时间、颜色、四元数分量；离群点可用 RANSAC/聚类剔除。
- 变体：若 CRC64 是自定义变体，可先逆向校验多项式，或像本题一样完全依赖坐标合法性。
- 关联：[[ctf-forensics-fhir-observation-base4-affine-stego]]（结构化字段隐写）、[[ctf-forensics-midi-shared-tick-register-stego]]（时间网格隐写）。
- 边界：需要正确的 TCP 重组与消息切分；坐标缩放/平移未知时需先估计范围；字体不标准时模板匹配可能歧义。

## 检测与防御

- 检测：医疗设备流量中出现异常坐标范围、离群点、固定采样率下的规则轨迹；设备名/类型与业务不符；轨迹可栅格化为文本。
- 防御/取证：保留原始 pcap 与时间戳；对 OpenIGTLink 消息做完整性校验与来源认证；监控坐标分布异常；对导出轨迹做精度/噪声处理。
- 加固（若用于隐蔽通信）：不要用固定点阵/固定字体编码；加入随机抖动与认证；限制轨迹数据导出精度。
