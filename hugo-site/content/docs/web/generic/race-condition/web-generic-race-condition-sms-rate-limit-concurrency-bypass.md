---
id: web-generic-race-condition-sms-rate-limit-concurrency-bypass
title: 短信发送接口并发绕过频控：同号多请求与多号同发同时通过验证与计数检查，造成纵向与横向短信轰炸
type: scenario
domain: web
path: web/generic/race-condition
technique: sms-rate-limit-concurrency-bypass
tags:
- race-condition
- sms
- rate-limit-bypass
- captcha
- business-logic
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V598
  verified_at: '2026-11-12T17:07:09+08:00'
  notes: 已对照原文与截图核对：img05 注册页含手机号/图形验证码/手机验证码、img06 Turbo Intruder 选 race-single-packet-attack.py、img07 纵向单号 15:13 仅收到 3 条（原文称 4 条，卡内已写明仅 3–4 条、下游按号码限流未被绕过）、img08/09 Repeater Send group(parallel) 请求 mobile=...&imgcaptcha=...（其中一条响应 result_code=4014 图形验证码错误，属组内单个响应）、img10-13 四个不同号码均在 15:35 各收到一条验证码（074540/404559/545019/415658），横向并发成功与卡内描述一致。卡内对“应用层先查后写被绕过、下游仍有硬限制”的边界如实注明。dedup：与 sms-bombing-rate-limit-bypass（参数解析差异）、验证码一码多用、空验证码注册、OTP 终端检测等均为 related，非同链；dup-scan 无 pair。无 affected_versions。未实测发送。
url: /docs/web/generic/race-condition/web-generic-race-condition-sms-rate-limit-concurrency-bypass/
draft: false
kb_aliases:
- 短信轰炸 条件竞争
- 并发绕过短信频率限制
- 横向短信轰炸
- 纵向短信轰炸
- 发送验证码并发
- 短信接口竞态
---

## 一句话结论

发送短信验证码的接口在"校验图形验证码/检查发送间隔 → 记录计数或标记验证码已用 → 调用短信通道"之间存在先查后写的竞态：把同一份发码请求并发化（同一号码多份为纵向、多个号码各一份为横向），多个请求会在任何一个请求写入计数之前同时通过检查，从而在应用层绕过"同一号码/同一会话只能发一条"的限制，让多个号码在同一时刻各收到一条短信。

## 原理

- **频控的典型实现**：收到发码请求后，服务端依次做：图形验证码比对、按手机号/会话/IP 查上次发送时间或当日次数、更新计数、标记图形验证码已用、调用短信网关。若这些步骤不是原子操作、也没有互斥锁，读和写之间就存在窗口。
- **并发为什么能过**：N 个请求在同一时刻到达，各自读到"尚未发送/计数未超限/验证码未使用"的旧状态，随后各自写入"已发送"，结果 N 条短信都被下发。串行时第二个请求会读到已更新的状态而被拒。
- **纵向与横向**：纵向轰炸是同一手机号并发多请求，目标是让单号连续收到大量短信；横向轰炸是攻击者同时用多个手机号各发一份，目标是同一时刻骚扰多个号码（本例为 4 个号码同时收到）。两者用的是同一个竞态，只是批量维度的选择不同。
- **实测的边界**：本例纵向并发时服务端接受了数十个请求，但目标手机实际只收到 3–4 条短信，说明除应用层频控外还有下游/运营商按号码的硬性限制，单靠应用层竞态无法突破；横向 4 个号码在同一分钟各自收到，说明应用层检查确实被并发绕过。因此该场景的实际危害取决于下游短信通道是否还有按号码/按通道的二次限制。
- **为什么仍值得记录**：短信轰炸的计费与骚扰成本由站点和用户承担，属于典型的业务逻辑滥用；且"并发绕过限次"的检查位置与短信内容无关，同样的手法可平移到邮件、站内信、语音验证码等发送接口。

## 触发条件

- 发码接口带图形验证码或发送间隔限制，但校验、计数、下发不是原子操作（无锁、无原子自增、无幂等键）。
- 服务端并发处理请求；同一会话/同一号码的多份请求可同时到达（HTTP/2 单连接并发或 Burp 并行分组即可）。
- 图形验证码可被同一批次请求共用（与 `[[web-generic-race-condition-captcha-one-time-multi-use-login-bruteforce]]` 同源：验证码未原子消费）。
- 短信网关没有严格的按号码/按模板/按通道的二次限流，或限流阈值高于应用层。

## 利用步骤

1. 在自己的账号上正常走一遍注册/登录发码流程，确认发码请求的字段（手机号、图形验证码、会话参数）与响应结构。
2. 人工识别一次图形验证码，填入发码请求，确认单发成功。
3. 纵向验证：把同一请求复制多份（同手机号），在 Burp Repeater 里合成 group，选择 `Send group (parallel)` 并行发送；或用 Turbo Intruder 把号码列表全部挂到同一个 gate 后 `openGate()`。
4. 对比响应：并发请求是否都返回成功（对照正常单发成功响应），而不是"操作频繁/验证码错误"。
5. 横向验证：复制多份请求，每份替换为不同手机号（自己可控的号码），并行发送，记录各号码收到短信的时间戳是否一致。
6. 检查目标手机实际收到的条数，判断应用层限制与下游限制各在哪一层；不要对非授权号码发送，测试完成后停止。

## PoC

Turbo Intruder 并发发送（手机号列表走剪贴板或文件，`mobile=%s`）：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    numbers = wordlists.clipboard   # 每行一个手机号；纵向场景则重复同一号码
    for number in numbers:
        engine.queue(target.req, number, gate='1')
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

Burp 替代做法：Repeater 中复制 N 份请求 → 全选加入同一 group → `Send group (parallel)`。

请求形态示意：

```http
POST /api/sendSmsCode HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=<同一会话>

mobile=<手机号>&imgcaptcha=<人工识别一次的验证码>
```

判据：同一批次多个请求均返回发送成功（而非"发送过于频繁"），且多个号码在几乎同一时刻各收到验证码短信。

## 变体与关联

- **验证码复用是前置条件**：若验证码一码一用且原子消费，则同一批次里只有第一个请求能过验证码校验；本卡通常与验证码并发复用一起使用，或目标只按号码限频而不校验验证码。
- **限次维度**：有的接口只限会话不限号码（换号即可）、只限号码不限会话、或按 IP 限频；分别构造并发测试可判断限制落在哪一层。
- **同型发送接口**：邮件验证码、站内信、语音验证码、邀请/分享短信等发送接口同样适用"先查后写"竞态；OWASP 归类为业务逻辑层限流绕过。
- **关联**：注册后状态窗口竞态见 `[[web-generic-race-condition-register-verified-login-window]]`；登录验证码并发复用见 `[[web-generic-race-condition-captcha-one-time-multi-use-login-bruteforce]]`。

## 检测与防御

- **原子限流**：用 Redis `INCR` + TTL、或数据库 `UPDATE ... SET cnt=cnt+1 WHERE phone=? AND cnt<N`（检查受影响行数）实现计数，保证同一号码/会话单位时间内只有一个请求能通过。
- **幂等与锁**：发码请求带幂等键（会话 + 号码 + 时间窗）并加互斥锁；同一验证码在一次成功后原子作废。
- **下游兜底**：短信网关按号码、按模板、按通道设置硬性限流与费用告警；对同一号码短时间内的重复发送在网关侧拦截。
- **风控与检测**：按号码/IP/设备/账号多维限频；监控"同一 IP/会话在一秒内触发多条发码"、并发请求体高度相似、多号码同一时刻发码等模式；对异常批次暂停发码并要求人机验证升级。
- **合规**：短信轰炸会造成真实资费损失与骚扰，测试只用自有号码、最小化发送量并在报告中说明。
