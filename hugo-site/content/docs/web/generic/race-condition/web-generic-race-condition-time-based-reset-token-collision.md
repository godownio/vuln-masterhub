---
id: web-generic-race-condition-time-based-reset-token-collision
title: 时间戳派生重置 token 的并发碰撞：同一时刻请求得到相同 token 重置任意用户密码
type: scenario
domain: web
path: web/generic/race-condition
technique: timestamp-token-collision-password-reset
tags:
- race-condition
- concurrency
- password-reset
- token
- timestamp
- auth
- php
- account-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V596
  verified_at: '2026-11-12T16:58:13+08:00'
  notes: 已对照原文与图13-20核对：多封重置邮件 token 长度固定且每次不同（图13）；同一会话并发因 PHP session 锁被顺序执行失败；按原文改为不带 Cookie GET /forgot-password 取新 session 与 csrf（图14-15），两组 POST 并行后两组响应时间一致、两封邮件 token 完全相同 f266f196c2a70f1f8359f7bfaced945f8aba6ea8（图16-17），再将 username 改为 carlos 发请求（图18-19）；图20 的 Invalid CSRF token 印证 csrf 一次性。卡片的新会话+各取新鲜 csrf+同组并发 PoC 与原文一致。dedup：与 username-tampering（客户端篡改 username、token 存在即可）、token=md5(unix时间戳) 暴力枚举、Host 头注入等候选机制不同，非同链判定成立；dup-scan 无本卡 pair。未验证点：原文未给出 token 具体派生算法（仅由长度/变化推断为时间派生），靶场未复跑；无版本。
url: /docs/web/generic/race-condition/web-generic-race-condition-time-based-reset-token-collision/
draft: false
kb_aliases:
- 时间敏感 token 碰撞
- time-sensitive vulnerabilities
- 重置密码 token 相同
- 时间戳令牌并发
- forgot-password race
- token 未绑定用户
---

## 一句话结论

密码重置令牌由时间戳（及服务器密钥）派生、长度固定且不包含用户名时，同时发起的两个重置请求会落在同一时间单位内而得到完全相同的 token；攻击者用自己的账户拿到该 token 后，把重置链接里的 user 参数换成任意受害者即可设置其新密码并登录。

## 原理

- 令牌生成缺陷：token 是 `hash(时间戳 [+ 密钥])` 一类的时间派生值，每次请求都变化但长度固定，且没有把 user 参与哈希。同一秒内的两个请求天然算出同一个 token。
- 校验缺陷：服务端校验令牌时只验证 token 本身有效（或只按 token 查记录），不校验 token 与链接中 `user` 参数/收件人是否绑定；因此攻击者知道自己的 token 就等于知道了同一时刻受害者的 token。
- 并发前提（PHP 场景）：默认文件型 session 对同一 session id 加锁，会把同一会话的请求串行化，并发也变成顺序执行、时间戳不同。解决办法是让两个请求使用**不同的新会话**——不带 Cookie 请求 `GET /forgot-password`，服务端各自新建 session 并返回各自的 CSRF token。
- CSRF 单次使用：同一 CSRF token 只能用一次，所以每个并发请求都必须先从自己的新会话里取一个新鲜 CSRF，再在 POST 时替换 Cookie 与 csrf 字段，两个请求才能在各自会话中真正并行。
- 命中的判据：两组响应时间戳相同，且两个邮箱收到的 token 完全一致；此后用任一 token 拼出 `?user=<victim>&token=<同一 token>` 完成受害者密码重置。
- 本质是“时间敏感 + 令牌未绑定用户”的加密/逻辑缺陷，并发只是让两个请求对齐同一时间单位；原文也指出该场景并非传统资源竞争。

## 触发条件

- 重置令牌由时间戳等可预测/可对齐的状态派生，且未把用户身份纳入哈希；
- 令牌校验不绑定 user 参数或收件邮箱，仅校验 token 存在/有效；
- 服务端能并行处理不同会话的请求（多 worker 的 PHP-FPM/Apache 等）；
- 攻击者能观测自己收到的重置邮件中的 token，并能反复发起重置请求。

## 利用步骤

1. 正常走一次忘记密码流程，收集多封重置邮件，确认 token 长度固定、每封不同，判断其为时间/状态派生。
2. 准备两个并发请求：先不带 Cookie `GET /forgot-password` 两次，分别拿到两套新 session Cookie 和各自的 CSRF token。
3. 构造两个 `POST /forgot-password`：分别使用两套 Cookie 与 CSRF，username 一个填自己、一个填受害者（或先都填自己以验证 token 是否相同），放入同一 group 并行发送。
4. 对比两封邮件：若 token 相同且两响应时间一致，碰撞成立。
5. 用邮件中的 token 拼出 `GET /forgot-password?user=<victim>&token=<token>`，提交新密码；用新密码登录受害者账户。
6. 该利用依赖同秒命中，需反复尝试；并发数不宜过大以免请求跨秒。

## PoC

```python
import requests, threading

BASE = "http://<target>"

def fresh_session():
    s = requests.Session()
    r = s.get(f"{BASE}/forgot-password")            # 不带旧 Cookie，服务端新建 session
    csrf = r.text.split('name="csrf" value="')[1].split('"')[0]
    return s, csrf

def request_reset(s, csrf, username, out):
    r = s.post(f"{BASE}/forgot-password",
               data={"csrf": csrf, "username": username})
    out[username] = r.status_code

s1, c1 = fresh_session()
s2, c2 = fresh_session()
out = {}
t1 = threading.Thread(target=request_reset, args=(s1, c1, "wiener", out))
t2 = threading.Thread(target=request_reset, args=(s2, c2, "carlos", out))
t1.start(); t2.start(); t1.join(); t2.join()

# 从两个收件箱取邮件中的 token；相同则用
# GET /forgot-password?user=carlos&token=<token> 提交新密码
```

## 变体与关联

- 变体：验证码/OTP 由时间戳派生且不绑定手机号或用户；邀请 token、API 签名 nonce 只取秒级时间；令牌哈希不含 user 导致横向可比。
- 关联：与[[web-generic-auth-reset-token-setcookie-leak-user-token-param]]（token 泄露/参数可控）不同，本卡是 token 生成与绑定缺陷；与[[web-generic-race-condition-register-verified-login-window]]同属并发对齐状态窗口，但目标是令牌碰撞而非资源竞争。
- 实战中若服务端将 token 与 user 绑定，此手法失效；可转而尝试 token 可预测性（时间爆破）或响应时间侧信道。

## 检测与防御

- 防御：使用密码学随机数生成重置令牌（如 32 字节 random），绝不使用时间戳作熵源；令牌必须与用户 ID、用途、过期时间一起存储并绑定校验，链接中的 user 参数不得单独决定重置对象；令牌一次性使用并在重置后立即失效。
- 防御：同一账户/来源的重置请求做速率限制，降低并发对齐机会。
- 检测：极短时间内出现多个不同用户、不同会话的重置请求且时间戳聚集；同一 token 被用于不同 user；重置邮件 token 与请求用户不匹配的访问日志。
