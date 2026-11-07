---
id: web-generic-client-timestamp-replay-typing-speed-bypass
title: 打字测速服务只校验内容与 seed、信任客户端时间戳：抓取合法提交压缩时间间隔伪造 650 WPM
type: scenario
domain: web
path: web/generic
technique: client-timestamp-replay-performance-bypass
tags:
- web
- business-logic
- client-side-trust
- timestamp
- replay
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:06:41+08:00'
  notes: 已对照原文与图01–02核对：前端/doneTest提交{startPoint,typed,seed}，后端校验typed与seed但按客户端time计算WPM；保留typed/seed、线性压缩time后重放，原文返回watctf{this_works_in_more_places_than_you_think}（截图532.86 WPM，>500阈值）与卡一致。未验证点：未在本机复跑脚本；frontmatter无sources/source_url；无版本。
url: /docs/web/generic/web-generic-client-timestamp-replay-typing-speed-bypass/
draft: false
kb_aliases:
- 打字速度篡改
- typed 时间戳重放
- WPM 伪造
- 客户端时间戳信任
- doneTest 绕过
- 测速业务逻辑绕过
---

## 一句话结论

打字测速服务把每次按键的 `{key,time}` 数组和 `seed` 交给后端 `/doneTest`，后端只校验打字内容与 seed 是否匹配，却直接信任客户端时间戳计算 WPM；攻击者先正常完成一次拿到合法 `typed`/`seed`，再把各条 `time` 线性压缩到目标总时长（如 650 WPM），重放即可让后端算出超过 500 WPM 的成绩并返回 flag。

## 原理

- **前端采集、后端判定**：页面记录每个按键的 key 与时间戳 `time`，随机 `seed` 决定要打的目标文本；完成后 `fetch("/doneTest", {startPoint, typed, seed})`。
- **后端做了一部分校验**：服务端会检查 `typed` 的字符序列是否与 seed 对应的文本一致（所以不能随便提交任意内容），并根据首尾时间戳/字符数计算 WPM；超过 500 即发放奖励。
- **时间戳仍由客户端提供**：服务端没有自己的开始/结束计时，也没有把提交与一次性 nonce/会话绑定；`typed[i].time` 完全可改。
- **攻击**：抓取一次合法完成的请求，保留 `typed` 的 key 序列与 `seed`（内容校验仍通过），只把每个 `time` 重写为 `start_time + i * interval`，使总时长对应目标 WPM（原文 650）。重放后服务端按伪造时间戳计算出高 WPM，返回 `watctf{this_works_in_more_places_than_you_think}`。
- **根因**：服务端把客户端上报的“性能度量/时间元数据”当作权威事实，只校验内容一致性，缺少服务端计时、提交签名与防重放。

## 触发条件

- 测速/反应时间/游戏回放类业务，成绩由客户端采集的时间戳或事件序列计算。
- 服务端校验内容/seed 等业务数据，但信任客户端时间字段，且没有服务端计时或一次性 nonce。
- 攻击者能抓取一次合法提交并在有效期内重放（会话/seed 未一次性失效）。
- 成绩阈值直接对应奖励/flag/排名。

## 利用步骤

1. 正常完成一次打字测试，抓包保存 `/doneTest` 请求的 JSON（含 `startPoint`、`typed`、`seed`）。
2. 计算目标总时长：`target_minutes = (总字符数 / 5) / target_wpm`，`target_ms = target_minutes * 60 * 1000`。
3. 保持 `typed` 的 key 顺序与 `seed` 不变，把首条时间设为原 `start_time`，末条设为 `start_time + target_ms`，中间按等间隔重写 `time`。
4. 重放修改后的请求到 `/doneTest`；服务端内容校验通过，按伪造时间戳计算 WPM。
5. 若阈值更高，继续压缩间隔；若服务端校验时间单调性，保持递增即可。
6. 读取响应中的奖励/flag。

## PoC

```python
import json

with open('typed_raw.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

typed = data['typed']
total_chars = len(typed)
target_wpm = 650

target_minutes = (total_chars / 5) / target_wpm
target_ms = target_minutes * 60 * 1000

start_time = typed[0]['time']
end_time = start_time + target_ms
interval = (end_time - start_time) / (total_chars - 1)

new_typed = []
for i, entry in enumerate(typed):
    e = entry.copy()
    e['time'] = int(start_time + i * interval)
    new_typed.append(e)

data['typed'] = new_typed
with open('typed_fast.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
```

把 `typed_fast.json` 作为 `/doneTest` 的请求体重放；原文返回 `watctf{this_works_in_more_places_than_you_think}`。

## 变体与关联

- 度量变体：打字 WPM、反应时间、点击速度、游戏回放时长、视频观看进度、运动轨迹耗时。
- 数据变体：时间戳数组、开始/结束时间、帧间隔、事件序列；保留业务内容，只改时间字段。
- 重放变体：同一 seed 重复提交、跨会话复用、并发提交取最优。
- 关联卡片：[[web-generic-client-side-score-trust]]（客户端上报分数/时间戳的通用信任问题）、[[web-generic-client-side-race-distance-tamper]]、[[web-generic-payment-amount-tamper-no-order-binding]]。
- 边界：服务端若自己记录开始/结束时间、使用一次性 nonce/签名、或校验时间戳与服务器时钟/事件速率，本手法失效。

## 检测与防御

- **服务端权威计时**：开始时间由服务端在发起测试时记录并绑定会话/nonce，结束时间以服务端收到提交为准；不接受客户端时间戳作为成绩依据。
- **防重放**：每次测试使用一次性 seed/nonce，提交后立即失效；对同一会话/seed 的重复提交拒绝。
- **一致性校验**：校验时间戳单调递增、间隔合理、与字符数/事件数匹配；异常压缩的间隔触发风控。
- **成绩签名**：客户端事件流由服务端签名或使用不可篡改的计时服务；奖励发放前做二次校验。
- **监控**：对超高速完成、重复提交、时间间隔过于均匀的请求告警。
