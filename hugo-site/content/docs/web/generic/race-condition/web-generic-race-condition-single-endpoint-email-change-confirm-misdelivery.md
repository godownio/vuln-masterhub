---
id: web-generic-race-condition-single-endpoint-email-change-confirm-misdelivery
title: 单端点条件竞争：并发改邮箱令管理员确认邮件改投攻击者，绑定内部域名邮箱提权
type: scenario
domain: web
path: web/generic/race-condition
technique: single-endpoint-race-email-change-confirmation-misdelivery
tags:
- race-condition
- concurrency
- email-change
- account-takeover
- auth
- privilege-escalation
- burp-group
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V596
  verified_at: '2026-11-12T16:57:58+08:00'
  notes: 已对照原文与图01-12核对：change-email 同一会话两个请求（email=攻击者地址 / carlos@ginandjuice.shop）放入同一 group 并行（图03-06）；攻击者邮箱收到正文为 confirm change to carlos@ginandjuice.shop 的确认邮件（图07），点击后账户邮箱变为 carlos@ginandjuice.shop（图08-10），获得管理面板删除 carlos（图11-12），与卡片的收件人错配竞态一致。dedup：与 web-generic-auth-email-change-no-verification-password-reset-takeover 非同链（后者改绑无确认）判定成立；dup-scan 无本卡 pair。未验证点：PortSwigger 靶场未复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/race-condition/web-generic-race-condition-single-endpoint-email-change-confirm-misdelivery/
draft: false
kb_aliases:
- 单端点条件竞争
- single-endpoint race condition
- 改邮箱并发
- 确认邮件改投
- 管理员确认邮件发到攻击者邮箱
- change-email race
---

## 一句话结论

改邮箱接口先在共享会话/账户状态里写入“待确认邮箱”，随后再从该状态读取收件地址和确认令牌发信；把“改成自己的邮箱”和“改成管理员邮箱”两个请求放在同一组内并发发送，服务端会把本应发给管理员的、目标为管理员地址的确认邮件投递到攻击者邮箱，攻击者点自己收到的链接即可把管理员邮箱绑定到自己账户，借内部域名特权接管高权限。

## 原理

- 改邮箱流程不是单一原子操作，而是一串：写待确认邮箱 → 生成确认令牌 → 读取收件地址 → 发送确认邮件。若这些步骤读取的是同一份可变状态（session 里的 pending email 或数据库字段），并发请求之间就会发生状态串扰。
- 两个请求同时进入：请求 A 把待确认邮箱设为攻击者地址，请求 B 设为管理员地址（如 carlos@ginandjuice.shop）。由于服务端并发处理、步骤间没有锁，B 生成的确认令牌（绑定到攻击者当前会话/账户）在发信时读到的收件人却是 A 写入的攻击者地址，反过来也一样；最终攻击者邮箱里出现“收件人是自己、正文要求确认改为管理员地址”的邮件。
- 关键在于确认令牌仍然有效且绑定发起请求的账户：攻击者点击自己收到的该链接，服务端按令牌把**攻击者账户**的邮箱确认为管理员地址，而不是先验证该地址归属。
- 危害放大条件：应用信任特定邮箱域名（如员工/内部域名）并据此授予管理员权限。于是“把管理员地址绑到我的账户”等价于提权：可见管理面板并删除其他用户。
- 该场景属于“同一端点、单请求即可完成、靠并发产生状态串扰”的一类竞态，不需要两个不同接口配合。

## 触发条件

- 改邮箱/改绑流程存在“先写状态、后读状态发信”的多个非原子步骤，且待确认邮箱只有一个存储槽位；
- 服务端对同一会话的并发请求并行处理（多线程/多进程/FPM 多 worker），步骤之间无锁或事务隔离；
- 确认令牌在一次并发中保持与账户绑定且可被复用（同一 CSRF/令牌可用于多个并发请求）；
- 应用对特定域名邮箱授予高权限，使邮箱绑定成为提权路径。

## 利用步骤

1. 登录普通账户，抓 `POST /my-account/change-email` 请求，确认参数为 `email=...&csrf=...`，服务器接受 302 重定向。
2. 复制该请求，构造两个版本：一个 `email` 为攻击者可控邮箱（如 exploit-server 地址，URL 编码 `@`），另一个 `email` 为管理员/内部地址（如 `carlos@ginandjuice.shop`）。
3. 将两个请求放入同一个 Burp group，使用 “Send group (parallel)” 并发发送（或脚本多线程同时发出）。
4. 打开自己的收件箱：应收到一封收件人为攻击者邮箱、正文却要求确认改为管理员地址的邮件。对比并发前后的正常邮件即可识别串扰。
5. 访问该邮件中的确认链接，使攻击者账户的邮箱变为管理员地址；刷新账户页面确认绑定成功。
6. 以内部域名邮箱身份获得管理员能力（如管理面板），执行删除目标用户等操作。

## PoC

```http
POST /my-account/change-email HTTP/1.1
Host: <target>
Cookie: session=<session>
Content-Type: application/x-www-form-urlencoded

email=attacker%40exploit-server.net&csrf=<csrf>
```

```http
POST /my-account/change-email HTTP/1.1
Host: <target>
Cookie: session=<session>
Content-Type: application/x-www-form-urlencoded

email=carlos%40ginandjuice.shop&csrf=<csrf>
```

将两个请求置于同一 group 并行发送（Burp: Send group in parallel；脚本：两个线程同时 requests.post）。随后在攻击者邮箱查找 “To confirm your email change to carlos@ginandjuice.shop” 的邮件，访问其中链接完成绑定。

```python
import threading, requests
BASE = "http://<target>"
COOKIE = {"session": "<session>"}
CSRF = "<csrf>"

def change(email):
    requests.post(f"{BASE}/my-account/change-email",
                  data={"email": email, "csrf": CSRF}, cookies=COOKIE,
                  allow_redirects=False, timeout=5)

t1 = threading.Thread(target=change, args=("attacker@exploit-server.net",))
t2 = threading.Thread(target=change, args=("carlos@ginandjuice.shop",))
t1.start(); t2.start(); t1.join(); t2.join()
```

## 变体与关联

- 变体：改密码/改手机号/绑定第三方登录等“先写后发信”的确认流程同样可能出现收件人与内容错配；多步骤注册、邀请、审批流程中任意共享可变状态都可能被并发串扰。
- 关联：与[[web-generic-race-condition-register-verified-login-window]]同属“状态非原子切换”类竞态；与[[web-generic-auth-email-change-no-verification-password-reset-takeover]]的区别是后者根本不需要确认、本卡是确认邮件被错误投递；利用结果都指向账号恢复渠道劫持。
- 该手法依赖服务器并发与发信时序，单次不一定稳定，实战中需多次尝试并调整并发数与请求间隔。

## 检测与防御

- 防御：把“写待确认邮箱 + 生成令牌 + 发信”放入同一事务并串行化（按账户/会话加锁）；确认邮件发信前重新读取并校验待确认邮箱归属；确认令牌一次性使用并绑定“账户 + 目标邮箱 + 会话”三元组；并发请求下拒绝第二个未完成的改绑请求（先到先得）。
- 防御：不要以邮箱域名直接授予高权限；管理员身份应有独立、不可自助绑定的凭证。
- 检测：同一账户在极短时间内对改邮箱端点出现多个不同目标地址的并发请求；确认邮件收件人与待确认地址不一致；单账户短时间多次改绑尝试。
