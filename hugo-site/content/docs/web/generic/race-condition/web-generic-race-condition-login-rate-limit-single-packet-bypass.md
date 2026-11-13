---
id: web-generic-race-condition-login-rate-limit-single-packet-bypass
title: 登录失败次数限制并发绕过：单包攻击同时提交多个不同口令，每用户 3 次限制被突破并命中口令
type: scenario
domain: web
path: web/generic/race-condition
technique: login-attempt-limit-single-packet-race-bypass
tags:
- web
- race-condition
- rate-limit-bypass
- brute-force
- login
- single-packet-attack
- burp-turbo-intruder
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:06:57+08:00'
  notes: 已对照原文与图16-19：POST /login 用户名+密码送Turbo Intruder，clipboard逐口令gate脚本；结果表第27行302/40字节命中，与卡判据一致，失败行为200。dedup top候选为验证码单包复用、cookie/xff绕过、短信爆破等，本卡无验证码、绕的是失败计数非原子，非同链，new判断成立。原文无组件版本。未验证点：未复跑PoC；作者自述成功率低需重试。
url: /docs/web/generic/race-condition/web-generic-race-condition-login-rate-limit-single-packet-bypass/
draft: false
kb_aliases:
- 登录次数限制条件竞争
- 并发绕过爆破频率限制
- rate limit race condition
- 单包攻击多口令
- Turbo Intruder 不同 password
- PortSwigger bypassing rate limits
---

## 一句话结论

登录接口按"每用户 3 次失败"限制爆破，但失败计数是"先查计数再自增"的非原子操作：用 HTTP/2 单包攻击在同一时刻提交一整批各不相同的口令，所有请求都读到"尝试次数 < 3"的旧值，于是远超 3 次的口令校验被放行；批量响应中只要有一条 302 且响应体明显不同（登录成功），即完成对该账号的口令爆破。

## 原理

- **计数器的先查后写**：典型实现是 `if attempts >= 3: lock; else: attempts += 1; verify(password)`。串行时第 4 次请求会看到 attempts=3 被锁定；并发时 N 个请求在同一窗口内都读到 attempts 的旧值，随后各自自增/校验，限制被放大成"每批 N 次"。
- **单包攻击保证同时性**：Turbo Intruder 的 `Engine.BURP2` + `concurrentConnections=1` + gate 把每个请求的最后一帧保留到 `openGate()`，在同一个 TCP 包内发出，使所有请求几乎同时到达服务端，最大化落在竞争窗口内的概率。与验证码复用卡的区别：本卡每个请求的 `password` 不同（用 `engine.queue(target.req, password, gate='1')` 逐个替换），目标不是复用同一个校验值，而是让计数检查同时通过。
- **响应判别**：失败通常返回 200 + "Invalid username or password"；成功返回 302 跳转，响应体/长度明显不同（本例成功响应 302、body 40 字节）。并发结果表按状态码/长度过滤即可定位命中口令。
- **成功率与限制**：并发窗口极短，批次中能通过计数检查的请求数不确定；本例作者实测成功率较低，需要多次尝试/增大批次。目标若把计数放在数据库事务、Redis 原子 INCR 或网关层，竞态窗口会缩小甚至消失。
- **与"验证码一码多用"的区别**：`[[web-generic-race-condition-captcha-one-time-multi-use-login-bruteforce]]` 复用同一个验证码并发试多个口令；本卡场景没有验证码，绕过的是失败次数/频率计数。

## 触发条件

- 登录接口按账号、IP 或会话来限制失败尝试次数（如 3 次/周期），并存在锁定/封禁逻辑。
- 计数检查与自增不是原子操作（先 SELECT 再 UPDATE、内存变量无锁、多实例共享不一致等）。
- 服务端并发处理请求，目标支持 HTTP/2 或可用多连接并发；能接受较高请求量。
- 口令字典覆盖目标口令；有可区分的成功响应（302、Set-Cookie、响应长度变化）。

## 利用步骤

1. 登录自己的测试账号，连续输错 3 次确认限制行为与失败响应（状态码、文案、长度）。
2. 抓取一次登录请求（含 `username/password/csrf`），把 `password` 值作为 Turbo Intruder 的替换点。
3. 把口令字典（每行一个）复制到剪贴板。
4. 在 Turbo Intruder 使用 gate 脚本：`engine = RequestEngine(..., concurrentConnections=1, engine=Engine.BURP2)`，对每个 password `engine.queue(target.req, password, gate='1')`，最后 `openGate('1')`。
5. Attack 后按状态码（302）与响应体/长度差异筛选命中；若全为 200 失败，重试下一批或调整并发/时序。
6. 命中后登录验证权限，评估影响并停止。注意控制请求量，避免对业务造成压力。

## PoC

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    passwords = wordlists.clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

请求模板：

```http
POST /login HTTP/2
Host: target
Cookie: session=<自己的会话>
Content-Type: application/x-www-form-urlencoded

csrf=<token>&username=<目标账号>&password=%s
```

判据：并发批次中出现 `302 Found`（本例成功响应 body 40 字节），其余为 200 失败；用命中口令登录验证。

## 变体与关联

- **计数维度**：按账号、按 IP、按会话、按设备指纹；换维度/组合并发可测试限制落在哪一层。多实例部署时计数不同步会天然放大窗口。
- **工具变体**：Repeater 并行组（每个 tab 用不同口令）、多线程 requests、Turbo Intruder 分批 gate；HTTP/1.1 可用 last-byte sync。
- **关联**：验证码并发复用 `[[web-generic-race-condition-captcha-one-time-multi-use-login-bruteforce]]`；短信发送频控并发绕过 `[[web-generic-race-condition-sms-rate-limit-concurrency-bypass]]`。
- **边界**：原子计数、账号锁定、验证码/二次认证、设备指纹风控、网关级限速都会使本手法失效；成功与否受网络时序影响，需多次尝试。

## 检测与防御

- **原子计数**：用 Redis `INCR`（先自增并判断结果）或数据库 `UPDATE ... SET attempts=attempts+1 WHERE user=? AND attempts<3` 检查受影响行数；计数与校验在同一事务内完成。
- **锁定与退避**：达到阈值后锁定账号/来源一段时间，采用指数退避；不要只返回"还剩 N 次"提示。
- **并发防护**：同一账号的登录请求串行化或加分布式锁；对单连接突发多请求、相同 session 的批量登录做限速。
- **检测信号**：同一账号/会话在毫秒级出现大量登录请求；失败率突增但无锁定记录；单 TCP 连接上多个 HTTP/2 流同时到达且 body 高度相似；响应中 302 与 200 混合出现。
