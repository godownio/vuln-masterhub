---
id: web-generic-race-condition-captcha-one-time-multi-use-login-bruteforce
title: 登录图形验证码并发复用（一码多用）：HTTP/2 单包攻击让多个口令请求同时通过验证码校验实现口令爆破
type: scenario
domain: web
path: web/generic/race-condition
technique: captcha-one-time-multi-use-single-packet-bruteforce
aliases:
- 验证码一码多用
- 单包攻击绕过验证码
- single-packet attack 爆破
- Turbo Intruder gate 并发登录
- 验证码竞态复用
- 一码多登
tags:
- race-condition
- captcha
- single-packet-attack
- http2
- brute-force
- login
- burp-turbo-intruder
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V598
  verified_at: '2026-11-12T17:07:07+08:00'
  notes: 已对照原文与19张截图核对：img01 登录页含图形验证码、img02 请求体 ssid/username/password/captcha 与卡内 PoC 字段一致（HTTP/2）、img03 Turbo Intruder 脚本与原文 gate 脚本一致、img04 多条 200 响应中出现 {"token":"qbb_jh0fo6ssk40976u6u7ghaa5","result_code":2000}，验证“不再出现验证码错误、需按响应体筛选成功”的判据。卡内对“校验→失效非原子、单包攻击压到微秒级”的原理为对原文行为的合理归纳。dedup：与 login-rate-limit-single-packet-bypass（同类单包攻击但绕过对象是失败计数而非验证码消费）、captcha-client-refresh-session-reuse（失败不轮换可串行重放）、OCR 识别、2FA 参数篡改等均为 related，非同链；dup-scan 无 pair。原文未标组件版本，无 affected_versions。未实测复现。
---

## 一句话结论

登录接口要求图形验证码且设计为"校验通过后立即失效"，但校验与失效不是原子操作：用 HTTP/2 单包攻击（single-packet attack）把整份口令字典的登录请求在同一时刻发出，多个请求会在任何一个请求把验证码标记为已用之前同时读到"验证码正确且未使用"的状态，从而一个验证码通过多个口令的校验——图形验证码形同虚设，可继续做口令爆破。

## 原理

- **验证码的"一码一用"靠什么实现**：服务端把验证码存在会话里，登录时先比对提交值与会话值，再（无论对错）刷新或删除该值。请求串行到达时，第二个请求读到的已经是失效状态，所以正常爆破每试一个口令都要重新识别一次验证码。
- **校验与消费的窗口**：比对和删除是两次独立操作，中间存在极短窗口。若服务端用多线程/协程并发处理登录请求，多个请求可以同时完成比对、随后各自删改会话值——每个请求都认为"我用掉了一次有效的验证码"。
- **为什么要单包攻击**：普通多线程并发受网络抖动影响，请求到达服务端的间隔可达毫秒级，窗口往往已被第一个请求关掉。HTTP/2 单包攻击把多个请求的 HEADERS/DATA 帧预先排好，在 `openGate()` 时写到同一条 TCP 连接上，使多个请求几乎在同一个 TCP 包里到达，把到达间隔压到微秒级，从而稳定命中窗口。`concurrentConnections=1` + `Engine.BURP2` 正是 Turbo Intruder 对单连接 HTTP/2 单包攻击的配置。
- **为什么能爆破**：验证码本应是"每次尝试口令的人机成本"，一旦同一个验证码可被 N 个并发请求共用，攻击者只需人工/OCR 识别一次验证码，就能在同一批次里试 N 个口令；循环"取一个码 → 并发一批口令"即可完成字典爆破。
- **登录成功的判据**：本例登录响应为 JSON，失败与成功的 `result_code` 不同，成功时返回 `token` 字段；HTTP 状态码可能同为 200，需按响应体字段/长度筛选。

## 触发条件

- 登录接口带图形验证码，服务端按会话保存并在登录时校验。
- 验证码的"校验 → 失效"不是原子操作（无 `GETDEL`、无 `UPDATE ... WHERE used=0` 影响行数判断、无分布式锁）。
- 服务端并发处理登录请求（线程池/异步框架），且目标支持 HTTP/2（单包攻击的前提）；仅 HTTP/1.1 时可退化为末字节同步（last-byte sync）尝试。
- 存在可用的弱口令字典；登录接口无账号/IP 维度的失败锁定或频控兜底。

## 利用步骤

1. 正常注册/登录一次，抓到登录请求，确认字段结构（如 `ssid/username/password/captcha`，`ssid` 即会话标识，验证码值随请求提交）。
2. 保持会话，取一个当前有效的图形验证码并填入请求，把 `password` 的值替换为爆破占位符（如 `%s`）。
3. 把请求发送到 Burp Turbo Intruder，将字典（每行一个口令）复制到剪贴板。
4. 用 gate 脚本把所有口令请求排队，`openGate('1')` 时一次性发出；引擎选 `Engine.BURP2`、`concurrentConnections=1` 以启用单包攻击。
5. 观察结果：若不再出现"验证码错误"类响应，而是每条请求都进入口令校验分支（返回体为口令错误/成功两种），说明验证码已被并发复用。
6. 按响应中的成功标识（如 `result_code` 成功值、出现 `token`、Cookie 变化）筛选命中的口令；命中后登录验证并停止测试。
7. 若单批失败，检查目标是否 HTTP/2、是否关闭连接复用；可减小每批口令数、重取验证码重试，或改用多连接并发多批次。

## PoC

Turbo Intruder 脚本（`password` 参数处用 `%s`，字典走剪贴板）：

```python
def queueRequests(target, wordlists):
    # 目标支持 HTTP/2 时用单包攻击：单连接 + BURP2 引擎
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    passwords = wordlists.clipboard
    # 所有请求挂在同一个 gate 上，openGate 时同包发出
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

请求形态示意（字段名以实际为准）：

```http
POST /login HTTP/2
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=<自己的会话>

ssid=<会话标识>&username=<账号>&password=%s&captcha=<人工识别一次的验证码>
```

判据：并发批次内多条响应均进入口令校验（无"验证码错误"），且成功响应返回会话/`token` 等登录凭证。

## 变体与关联

- **验证码消费点变体**：有的站点在"获取验证码"接口生成、登录时只比对不删除（天然一码多用）；有的在登录成功后删除，失败不删除。测试时先串行重放两次同一验证码，确认其真实生命周期，再决定是否需要并发。
- **协议变体**：HTTP/1.1 且服务器串行处理时单包攻击无效，可尝试 last-byte sync（把每个请求的最后一个字节留到同一时刻发送）；HTTP/2 服务端若把同一连接上的流串行化，也会降低成功率，可换多连接批次。
- **同型并发复用**：短信/邮箱验证码的发送频控同样存在"先查后写"窗口，见 `[[web-generic-race-condition-sms-rate-limit-concurrency-bypass]]`；注册后状态窗口滥用见 `[[web-generic-race-condition-register-verified-login-window]]`。
- **非竞态路线的验证码爆破**：客户端生成验证码、前端加密口令、OCR 识别等绕过方式属于认证域的其他卡，与本卡的"服务端一次性验证码被并发复用"不同。

## 检测与防御

- **原子消费验证码**：用 `GETDEL`/`DEL` 返回值判断、或数据库 `UPDATE captcha SET used=1 WHERE id=? AND used=0` 检查受影响行数，保证"比对 + 消费"只成功一次；失败也应在同一原子操作里作废。
- **串行化与锁**：同一会话的登录请求按会话加互斥锁或单飞（single-flight），使同一验证码只能被一个请求消费。
- **风控兜底**：按账号、IP、设备指纹做失败计数、锁定、速率限制；验证码本身绑定会话与短 TTL，不因"验证码正确但口令错误"而长期有效。
- **检测信号**：同一会话/同一验证码在极短时间（毫秒级）内出现多条登录请求；单条 TCP 连接上一批 HTTP/2 流同时到达且请求体高度相似；同一账号在短时间内大量失败登录；响应体中验证码校验失败占比异常低。
- **测试边界**：仅对授权目标验证，命中即停，不扩大口令尝试规模。
