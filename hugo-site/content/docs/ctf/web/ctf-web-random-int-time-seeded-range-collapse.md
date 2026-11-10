---
id: ctf-web-random-int-time-seeded-range-collapse
title: 随机数上下界同时依赖 date('s')：秒数归零时取值区间退化为单值，卡整点秒提交即命中
type: scenario
domain: ctf
path: ctf/web
technique: time-seeded-random-range-collapse-guess
tags:
- php
- random-int
- time-based
- ctf
- side-channel
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:36+08:00'
  notes: 已对照原文核对；本次核对未读取图片；random_int(114,114+date('s')*100000) 与 intval 全等比较、以及 s=0 时区间塌缩为 114 均与原文 TimeCage 第一步源码一致，PoC 为按该源码整理的卡点脚本、未对真实目标执行；属 CTF 时序取巧，原文无受影响版本
url: /docs/ctf/web/ctf-web-random-int-time-seeded-range-collapse/
draft: false
kb_aliases:
- random_int 时间种子退化
- date('s') 作为随机数上界
- 整点秒猜数字
- 时间侧信道猜随机数
---

## 一句话结论

当校验用 `random_int(114, 114 + date('s') * 100000)` 这类“下界固定、上界随时间秒数线性增长”的方式生成目标值，并与用户输入做 `intval` 全等比较时，攻击者不需要暴力猜：在秒数为 0 的那一秒内提交下界值（本题 `114`），区间 `[114, 114]` 退化为单点，必中；若秒数窗口抓不稳，也可以在秒数较小时枚举少量候选。

## 原理

- **上界由时间决定**：`date('s')` 返回 0–59。当 `s = 0` 时上界 = 下界 = 114，`random_int(114, 114)` 只能返回 114，随机性完全消失。
- **窗口是周期性的**：秒数每分钟回到 0，因此“等整分”是可控的；网络时延需小于 1 秒，或者提前发多个请求覆盖 59→0 的边界（或读到服务端 Date 头对齐时钟）。
- **比较是 `intval` 全等**：`intval($guess) === intval($target)`，所以传 `114`、`114abc`、`0114` 都等价于 114，不需要精确的字符串。
- **这类缺陷的共性**：随机数的**范围**而不是种子来自外部可控/可观测的量（时间、会话 ID、计数器），使得取值范围在某些时刻塌缩；一旦范围退化，攻击成本从“猜 32 位”变为“猜一次”。

## 触发条件

- 目标值由 `random_int`/`rand`/`mt_rand` 生成，且至少一个边界来自时间（`date('s')`、`time()`、`microtime()`）或其它可观测值。
- 校验逻辑对用户输入做弱比较（`intval`、`==`、`strcmp` 前截断）。
- 攻击者能对目标时钟做估计（响应头 `Date`、`Server-Timing`、先发一次请求测偏移），或能高频请求覆盖窗口。

## 利用步骤

1. 读源码，确认随机数边界表达式（本题 `114 + date('s') * 100000`）。
2. 找出使区间退化的时刻：这里 `s=0` → 唯一值 114。
3. 用响应头 `Date` 或本地时钟估算服务端秒数，在秒数接近 59 时连续发送若干请求（覆盖跨秒），或在整分瞬间发送。
4. 用 `intval` 等价的写法提交（`114`、`114.9`、`114abc`），避免因类型判断失败。
5. 命中后服务端回显下一关入口（本题为 `Trapping2147483647.php`），继续后续阶段。

## PoC

```python
import time, requests

URL = "http://target/?input=114"

# 等到本地时间接近整分（服务端 s≈0），连续打几发覆盖跨秒
while True:
    if time.localtime().tm_sec >= 58:
        break
    time.sleep(0.2)

for _ in range(6):
    r = requests.get(URL, timeout=3)
    print(r.status_code, r.text[:120])
    if "next challenge" in r.text.lower() or ".php" in r.text:
        break
```

```php
// 等价的服务端判定（说明为什么秒数为 0 时必中）
$target = random_int(114, 114 + date('s') * 100000); // date('s')==0 => random_int(114,114) => 114
var_dump(intval("114abc") === intval($target));      // true
```

说明：PoC 按原文题目脚本整理，未对真实目标执行；实际需按网络 RTT 调整连发次数与提前量。

## 变体与关联

- **边界变体**：`mt_rand(0, date('s'))`、`rand(1, intval(date('i')))`、`random_int(0, time() % 100)`——只要边界在某个时刻为 0 或与下界相等，区间就塌缩。
- **种子变体**：`mt_srand(time())` 后取随机数，可用同一秒内的 `mt_rand` 预测（PHP 的 Mersenne Twister 状态可由少量输出反推），属于“种子可预测”而非“区间退化”。
- **弱比较变体**：`==` 下 `0 == "abc"`（PHP 7）、`intval` 截断、`strcmp` 数组绕过，可与本卡叠加使用。
- **关联**：`web-generic-auth-per-char-sleep-timing-password-oracle`（同为 CTF 里的时间侧信道，但那是逐字符 sleep 时序）、`crypto-prng-mt19937-state-recovery`（种子可预测的随机数预测）。
- **边界**：若随机数边界不依赖可观测值、或比较使用严格字符串全等且要求定长，则上述退化不成立；高精度 `microtime` 边界使窗口小于 RTT 时也难以卡点。

## 检测与防御

- **代码层**：不要用时间/计数器参与随机数**范围**；需要一次性挑战值时使用 `random_bytes()` 生成足够熵的 token 并服务端保存（session/redis），而不是“可推导范围 + 用户输入比较”。
- **比较层**：使用 `hash_equals()` 比较定长随机串，避免 `intval`/`==` 的类型弱化。
- **检测**：短时间内在整分秒附近出现多次同接口请求；请求参数为极小整数（如下界值）且反复出现；同一 IP 的请求间隔呈现“等整分”规律（可据此识别卡点脚本）。
