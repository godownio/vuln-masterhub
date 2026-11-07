---
id: web-generic-auth-username-enumeration-timing-lockout
title: 用户名枚举侧信道：响应时间差异与账号锁定 oracle
type: scenario
domain: web
path: web/generic/auth
technique: username-enumeration-timing-lockout
tags:
- auth
- enumeration
- timing-attack
- lockout
- side-channel
- web
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:29+08:00'
  notes: 已对照 Level 16 响应时间差异与 Level 18 锁定 oracle 截图核对；未验证点：时间差为靶场单次观察，卡片已注明需多次采样
url: /docs/web/generic/auth/web-generic-auth-username-enumeration-timing-lockout/
draft: false
kb_aliases:
- 用户名枚举
- 响应时间侧信道
- 账号锁定 oracle
- timing username enumeration
- 登录时间差
---

## 一句话结论

当登录或找回密码接口对“存在的用户名”和“不存在的用户名”处理路径不同，会出现响应时间差异或锁定行为差异；攻击者可以先用固定错误密码批量探测候选用户名，按响应时间中位数或“连续错误后是否锁定”筛出有效用户名，再对有效账号集中爆破密码。

## 原理

- 存在性检查通常先查数据库/缓存；不存在时可能提前返回，存在时还会执行密码哈希（bcrypt/Argon2 较慢）或额外的风控/日志逻辑，导致响应时间不同。
- 账号锁定策略往往只对真实账号生效：连续 N 次错误密码后锁定。对不存在的用户名，服务端可能始终返回“用户名或密码错误”而不锁定。于是“是否触发锁定”成为存在性 oracle。
- 响应长度/错误文案也可能不同（“用户不存在” vs “密码错误”），但很多应用已统一文案；时间和锁定行为更难被统一处理，因此常被忽略。
- 时间差异通常只有几十到几百毫秒，需要多次采样取中位数/分位数，并控制网络抖动、并发和缓存影响；单次请求不可靠。

## 触发条件

- 登录/找回密码/注册接口对存在与不存在的用户名走不同代码路径。
- 攻击者能发送足够多的探测请求，且未被限速/封禁（或可绕过）。
- 存在账号锁定策略，且锁定行为对真实账号与不存在账号不同。
- 响应时间可测量，或锁定状态可从响应文案/状态码区分。

## 利用步骤

1. 准备候选用户名列表（常见管理员名、员工名、邮箱前缀、从其它接口泄露的账号）。
2. 对每个候选用户名用同一个错误密码发送多次请求（例如 5–10 次），记录响应时间；取中位数/去掉首包（TCP/TLS 建连）后的值。
3. 先测一批已知不存在/已知存在的用户名作为基线，确定时间差阈值。
4. 若时间差不明显，改用锁定 oracle：对每个候选用户名连续发送 N 次错误密码，观察第 N+1 次是否出现“账号已锁定”或锁定提示；出现者为有效账号。
5. 筛出有效用户名后，再对这些账号做密码爆破；注意锁定策略，控制失败次数。
6. 用不同来源/会话复测，排除缓存、CDN、WAF 干扰。

## PoC

时间差探测（Python 伪代码，仅示意，需在授权环境使用）：

```python
import statistics, time, requests

def sample(user, n=7):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        requests.post("https://target/login", data={"username": user, "password": "wrong-pass"}, timeout=10)
        times.append(time.perf_counter() - t0)
    return statistics.median(times[1:])  # 去掉首个建连样本

for u in candidates:
    print(u, sample(u))
```

锁定 oracle：

```text
for i in 1..5: POST /login username=<candidate>&password=wrong
POST /login username=<candidate>&password=wrong
# 若返回“账号已锁定/请稍后再试”，candidate 很可能是有效用户名
```

## 变体与关联

- 变体：通过找回密码/注册接口的“该邮箱已注册/验证码已发送”差异枚举。
- 变体：通过响应长度、HTTP 状态码、错误码、跳转差异枚举。
- 变体：利用大小写/空格/Unicode 归一化差异判断账号存在。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（枚举后爆破）。
- 关联：[[web-generic-auth-login-rate-limit-bypass-cookie-xff]]（枚举/爆破时绕过限速）。
- 注意：时间差异受网络和负载影响大，必须多次采样并做统计；不要把单次慢响应当作有效账号。

## 检测与防御

- 防御：对不存在用户执行 dummy 哈希/固定延迟，使存在与不存在的处理时间接近；统一错误文案、状态码和响应长度。
- 防御：锁定策略对所有用户名一致（或对不存在用户名也做等价计数），避免锁定行为成为 oracle；锁定后同样返回通用提示。
- 防御：对枚举行为限速、加验证码、按 IP/账号风控；监控同一来源对大量不同用户名的探测。
- 检测：同一 IP/会话在短时间内用大量不同用户名尝试登录；响应时间分布呈双峰；大量请求触发锁定或 429；失败响应长度/状态码异常集中。
