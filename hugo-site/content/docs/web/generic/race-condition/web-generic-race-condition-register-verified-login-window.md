---
id: web-generic-race-condition-register-verified-login-window
title: 注册先写入宽松状态再异步收紧的竞态窗口：窗口内并发登录绕过 verified 校验
type: scenario
domain: web
path: web/generic/race-condition
technique: register-verify-async-window-login-race
tags:
- race-condition
- toctou
- registration
- verified
- concurrency
- nodejs
- auth-bypass
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:27:30+08:00'
  notes: 已对照原文 index.js/db.js 与图 05 核对：users.verified 建表 DEFAULT true；register 先 INSERT→await sendEmailToAdministrator(sleep 1000)→UPDATE verified=false；login 查当前 verified 后签发 token 并返回 LOGIN_WELCOME_MESSAGE；图 05 显示 register 后紧接 login 返回 success 且 welcome_msg 含 flag，窗口打通。注：严格说这是约 1 秒 TOCTOU 窗口，串行抢登也可，不一定需要并发，标题『并发登录』措辞偏强但机制无误。
url: /docs/web/generic/race-condition/web-generic-race-condition-register-verified-login-window/
draft: false
kb_aliases:
- 注册审批竞态
- verified 先 true 后 false
- TOCTOU 登录窗口
- 异步通知 sleep 竞态
---

## 一句话结论

注册接口先 `INSERT` 用户（建表默认 `verified=true`），再 `await` 一个耗时的异步通知（内部 `sleep(1000)`），最后才 `UPDATE users SET verified=false`；在这个「已插入、尚未降级」的约 1 秒窗口内并发发起登录，就能以 `verified=true` 通过校验，拿到只有已验证用户可见的会话/响应数据。

## 原理

- 状态转换非原子：INSERT 与 UPDATE 是两条独立语句，中间夹着 `await sendEmailToAdministrator()`（函数体 `await sleep(1000)`），形成一个可观测的竞态窗口。
- 默认值陷阱：建表 `verified BOOLEAN DEFAULT true`，INSERT 未显式给 `verified`，于是新用户初始为 true；「先允许、后撤销」的顺序把宽松状态暴露在窗口里。
- 登录只看当前值：`SELECT id, username, verified FROM users WHERE username=? AND password=?` 取出的是查询时刻的 `verified`；窗口内读到 true 就签发 token。
- Node 单线程不构成防护：`await` 让出事件循环，其它请求（login）能在 sleep 期间被处理，因此同一进程内并发即可，不需要多机时钟对齐。
- 完整危害：窗口内登录成功，响应体里 `welcome_msg` 取自环境变量（本例含目标数据），即拿到未登录用户看不到的内容。

## 触发条件

- 注册/审批类流程「先写入宽松状态、异步或延迟后再收紧」；
- 数据库默认值宽松（如 `verified DEFAULT true`），或插入时未显式设为最小权限；
- 登录/鉴权接口在窗口期内可并发访问；
- 受保护数据出现在登录成功响应或登录后接口。

## 利用步骤

1. 读源码，定位 `INSERT → await(耗时) → UPDATE(收紧)` 的顺序与宽松默认值。
2. 用两个并发请求：一个 `POST /api/register`，紧接着在 sleep 窗口内用同账号口令反复 `POST /api/login`。
3. 调整并发时序/重放，直到 login 返回 `success` 而非 `not approved`。
4. 读取登录响应（`welcome_msg` 等环境变量内容）或带 token 访问受保护接口。

## PoC

```python
import concurrent.futures, requests
BASE = "http://<target>"
U, P = "raceuser", "pw"

def reg():
    return requests.post(f"{BASE}/api/register",
                         json={"username": U, "password": P, "email": "x@x"})

def login():
    for _ in range(50):                       # 在 register 的 1s sleep 窗口内抢登
        r = requests.post(f"{BASE}/api/login", json={"username": U, "password": P})
        if r.json().get("success"):
            return r.json()
    return None

with concurrent.futures.ThreadPoolExecutor() as ex:
    ex.submit(reg)
    print(ex.submit(login).result())
```

## 变体与关联

- 变体：限次/配额 TOCTOU 绕过、重复提现/双花、先发邮件后人工审批、验证码/一次性令牌校验窗口、验证码校验与业务操作分离；把耗时操作移到状态定稿之前都会造窗口。
- 关联：条件竞争类限次绕过、数据库默认值最小权限原则；本例前置入口是 nginx alias 任意文件读到的源码与凭据。

## 检测与防御

- 防御：把「插入」与「定稿」放进同一事务，或 INSERT 时显式写 `verified=false`（默认最小权限）；耗时操作（发邮件）放到状态定稿之后或交给消息队列异步，不要卡在事务/状态切换中间；登录查最终状态而非中间态。
- 检测：同一账号 register 后极短时间内出现成功 login；DB 审计里 `verified` 从 true→false 的短暂翻转；注册/登录并发突增。
- 加固：对特权状态用状态机（pending→active）并由服务端单线程/锁串行化，避免「先给后收」。
