---
id: ctf-misc-gpx-track-outlier-nearby-coordinate-time
title: GPX 轨迹异常点定位：按相邻 trkpt 距离找离群点，读取其 time 作为 flag
type: scenario
domain: ctf
path: ctf/misc
technique: gpx-track-outlier-time-recovery
tags:
- ctf
- misc
- gpx
- gps
- xml
- track
- outlier
- timestamp
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:39:00+08:00'
  notes: 已对照原文核对：GPX 轨迹异常点可视化、XML 中定位相近坐标的 trkpt、time=2025-07-25T01:05:07Z 与 flag 一致；卡中 haversine 离群检测为通用化补充；未拿到原 GPX 文件实跑。
url: /docs/ctf/misc/ctf-misc-gpx-track-outlier-nearby-coordinate-time/
draft: false
kb_aliases:
- GPS
- GPX 轨迹异常
- trkpt 离群点
- 轨迹点时间戳
- GPX 坐标查找
---

## 一句话结论

拿到 GPX 轨迹文件时，把 `<trkpt>` 按时间排序并计算相邻点的距离/速度，正常轨迹应连续平滑；某个点若突然跳到路线之外（地图上表现为一条穿过街区/建筑的虚线），它就是异常点，读取该点的 `<time>` 即可得到 flag（本题为 `flag{2025-07-25T01:05:07Z}`）。

## 原理

- **GPX 结构**：GPX 是 GPS Exchange Format 的 XML，轨迹点形如 `<trkpt lat="36.68370482037203" lon="117.13241461277197"><ele>45.9</ele><time>2025-07-25T01:05:07Z</time></trkpt>`；`lat`/`lon` 是 WGS84 坐标，`time` 是 UTC 时间，`ele` 是海拔。
- **轨迹连续性**：正常轨迹的相邻点在时间和空间上都应连续；若某点与前后点的球面距离远大于相邻点间距（或速度远超步行/车辆合理范围），它很可能是被插入/篡改的异常点。
- **视觉与文件互相印证**：用 GPX 查看器（地图软件、在线 GPX 编辑器）叠加轨迹，异常点会表现为离开道路的折线/穿越建筑；在原始 XML 中搜索该坐标附近的 `<trkpt>`，即可定位到具体点及其 `<time>`。
- **为什么 flag 是时间**：题目把答案藏在异常点的 `time` 字段中；异常点的坐标/海拔可能是干扰，真正需要的是该点的时间戳。
- **实现要点**：解析 XML 时注意命名空间（`http://www.topografix.com/GPX/1/1`）；按文件顺序或 `time` 排序；距离可用 haversine；异常检测可用“相邻距离的最大值/中位数比”或“速度阈值”，也可直接按地图上圈出的坐标搜索。
- **成立条件**：GPX 文件可解析；异常点是坐标/时间明显离群的点；flag 格式与 `time` 字段一致（如 ISO 8601）。

## 触发条件

- 题目给一个 `.gpx` 轨迹文件，提示“轨迹/坐标/地图”或要求找某个点。
- 轨迹中存在一个或多个异常点（坐标跳变、时间跳变、海拔异常）。
- 能解析 XML 或使用 GPX 查看器；有地图底图可辅助判断。

## 利用步骤

1. 用 GPX 查看器/地图工具打开文件，观察轨迹是否连续；异常点通常表现为离开道路的直线段或穿越建筑的折线。
2. 在 XML 中搜索地图上异常位置的 `lat`/`lon` 附近值，找到对应的 `<trkpt>` 节点。
3. 读取该节点的 `<time>` 字段；若 flag 格式为时间戳，直接作为答案（如 `flag{2025-07-25T01:05:07Z}`）。
4. 如果视觉不明显，用脚本计算相邻点 haversine 距离与速度，找最大离群值；或按 `time` 排序检查时间跳变。
5. 检查异常点前后若干点的坐标/时间，确认它确实是插入点而非正常转弯/停留。
6. 如 flag 不是时间，继续检查异常点的 `ele`、`name`、`cmt`、`desc` 或附近节点。

## PoC

```python
import math
import xml.etree.ElementTree as ET

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*R*math.asin(math.sqrt(a))

ns = {'g': 'http://www.topografix.com/GPX/1/1'}
root = ET.parse('track.gpx').getroot()
pts = []
for trkpt in root.iter('{http://www.topografix.com/GPX/1/1}trkpt'):
    lat = float(trkpt.get('lat')); lon = float(trkpt.get('lon'))
    t = trkpt.findtext('g:time', default='', namespaces=ns)
    pts.append((lat, lon, t))

# 找出与前一点距离最大的 trkpt
best = None
for i in range(1, len(pts)):
    d = haversine(*pts[i-1][:2], *pts[i][:2])
    if best is None or d > best[0]:
        best = (d, i, pts[i])
print(best)  # 离群点及其实 time
# 本题异常点 time: 2025-07-25T01:05:07Z -> flag{2025-07-25T01:05:07Z}
```

说明：实际 GPX 可能没有命名空间或使用不同版本，按文件调整 `iter` 的标签；若轨迹有停留/绕路，单纯最大距离可能有误，可结合速度与地图人工确认。

## 变体与关联

- **异常点变体**：坐标跳变、时间跳变、海拔异常、重复点、逆行点；分别用距离/速度、时间差、海拔差、重复坐标、方向角检测。
- **编码变体**：坐标本身可能编码信息（小数位、经纬度顺序、坐标转像素），时间可能是 Unix 时间戳/本地时区；按 flag 格式尝试转换。
- **工具变体**：GPXSee/QGIS/Google Earth/在线 GPX 编辑器可直接可视化；也可用 `gpxpy` 库解析。
- 关联：[[ctf-forensics-openigtlink-position-trajectory-pixel-font]]（轨迹点还原像素字体）、[[iot-vehicle-gps-l1-spoofing-gps-sdr-sim-hackrf]]（GPS 欺骗背景）。
- **边界**：若轨迹本身噪声很大或异常点与正常点差异不明显，纯算法可能误判；需结合地图与题目提示。

## 检测与防御

- **分析侧**：先可视化再写脚本；用多指标（距离、速度、时间差、海拔）交叉确认异常点，避免只取最大距离。
- **题目设计侧**：若想隐藏答案，可把异常点做得更隐蔽或使用编码；但 GPX 是明文 XML，任何字段都可能被直接读取。
- **取证侧**：GPX 的 `time`、`ele`、`name`、`desc` 都可能携带信息；保留原始文件并记录解析/排序方式，避免破坏证据。
