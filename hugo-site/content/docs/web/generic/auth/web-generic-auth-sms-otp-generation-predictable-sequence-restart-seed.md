---
id: web-generic-auth-sms-otp-generation-predictable-sequence-restart-seed
title: 短信验证码生成阶段可预测：连续递增、重启复用与种子取手机号
type: scenario
domain: web
path: web/generic/auth
technique: sms-otp-generation-predictable-sequence-restart-seed
tags:
- web
- auth
- sms
- otp
- verification-code
- prng
- predictable
- logic-flaw
- brute-force
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:11+08:00'
  notes: 已对照 content.md 与 50 张图核对：案例78/79/80 的递增码（截图为 723455、723458→723459，预测 723460）、重启后 234765 复用、seed=88888888 生成 50 码并爆破，均与卡一致；原稿“步长4”已按截图修正。未验证点：未在好靶场复跑；frontmatter 无 sources/source_url；原文无产品版本。
url: /docs/web/generic/auth/web-generic-auth-sms-otp-generation-predictable-sequence-restart-seed/
draft: false
kb_aliases:
- 验证码生成可预测
- 短信验证码连续递增
- 重启后验证码复用
- 验证码种子取手机号
- OTP 生成阶段逻辑漏洞
---

## 一句话结论

如果短信验证码在生成阶段使用自增计数器、重启后复用同一初始状态，或以手机号等用户已知值作为 PRNG 种子，攻击者无需接收短信就能预测验证码；再叠加验证接口无尝试次数限制，即可用自己的号码观察规律、为受害者号码生成候选码并爆破登录，形成任意账号接管。

## 原理

- **验证码不是普通随机数**：安全的 OTP 必须由 CSPRNG 生成、与手机号/会话绑定、一次性使用并在短时间后失效。生成阶段一旦引入确定性，后续所有校验都失去意义。
- **连续递增**：服务端用全局计数器或“上一次验证码 + 固定步长”生成新码。攻击者多次向自己的号码请求验证码，观察响应/SMS 中的码值差值（原文实测连续两次请求为 `723458` → `723459`，更早一次为 `723455`），即可推算出为受害者号码生成的下一个码（如 `723460`）。
- **重启后复用**：部分实现把首个验证码写在全局变量/固定种子中，服务重启后状态被重置，第一个验证码与上次启动时相同。攻击者先记录一个码，重启服务后再为另一个号码请求验证码，直接用旧码通过校验（本例 `234765`）。
- **种子取手机号**：服务端用 `random.seed(phone)` 或类似方式初始化 PRNG，再生成 6 位验证码。由于手机号是攻击者已知/可控的，攻击者可在本地用相同算法和种子生成整个序列（本例 `seed=88888888`，前 50 个码中包含目标 `805431`/`640723`），把候选码作为字典对登录接口爆破。
- **为什么能接管账号**：验证码是登录/注册/找回密码的唯一凭据；可预测后，攻击者无需控制受害者手机，即可用自己的会话提交受害者的手机号和预测码，服务端只比较码值，不校验“这个码是否发给这个手机号/这个会话”，登录成功。
- **放大条件**：验证接口没有次数限制、没有图形验证码/滑块、验证码有效期长、验证码不因失败次数作废；这些使字典爆破可行。

## 触发条件

- 验证码生成使用自增/时间/固定步长、固定初始状态，或 PRNG 种子来自手机号、时间、PID 等可预测值。
- 攻击者能触发验证码发送并观察自己号码收到的码（或响应包/虚拟短信平台），从而发现规律。
- 验证接口无频率限制/尝试次数限制，或限制可被绕过；验证码未与手机号/会话强绑定。
- 目标账号使用手机号登录/找回密码，且没有额外 MFA。
- 服务可被重启（重启复用场景）或攻击者能观察到重启后的第一个码。

## 利用步骤

1. 用测试手机号多次请求验证码，抓取发送响应与收到的短信码；记录每次请求的码值、时间、请求序号。
2. 计算差值：若码值按固定步长递增/递减，预测下一次为受害者手机号生成的码；直接用自己的会话来提交受害者手机号 + 预测码。
3. 若怀疑重启复用：记录当前首个验证码；重启目标/等待服务重置后，为另一个手机号请求验证码，提交旧码验证。
4. 若怀疑种子取手机号：根据提示/源码确认 PRNG 算法与种子；用 Python `random.seed(phone)` 等本地生成 50–100 个候选 6 位码；用 Burp Intruder/requests 对登录接口爆破，观察 `success`/会话。
5. 成功后检查是否需要验证码与手机号绑定；若绑定，改用受害者手机号请求验证码后立即爆破，或利用未绑定缺陷。
6. 记录步长、种子、候选码与成功响应，便于复现和报告。

## PoC

```python
import random

def gen_codes(seed, count=50, digits=6):
    random.seed(seed)
    return [''.join(str(random.randint(0, 9)) for _ in range(digits)) for _ in range(count)]

# 案例：种子取手机号 88888888，目标码出现在前 50 个中
codes = gen_codes(88888888, 50)
print(codes)
```

```http
# 连续递增案例：先向自己的号码请求两次，观察码值步长
GET /getSend?phone=18888888888 HTTP/1.1
# 响应: {"code":"723455","phone":"18888888888","success":true}
GET /getSend?phone=18888888888 HTTP/1.1
# 响应: {"code":"723459","phone":"18888888888","success":true}
# 推算为受害者号码生成的码（+4）并用受害者手机号提交
POST /check HTTP/1.1
Content-Type: application/json

{"phone":"15123456789","code":"723460"}
```

```text
# 重启复用案例
1) 记录当前号码收到的验证码：234765
2) 重启服务/重置状态
3) 为另一手机号 15123456789 请求验证码
4) 提交 234765，验证通过（码未绑定手机号/会话）
```

说明：原文在“好靶场”环境用上述三种方式分别拿到 flag；PoC 未在本机复跑，实际种子/步长/字段名需按目标调整。

## 变体与关联

- 变体：种子取时间戳（秒/毫秒）、PID、自增 ID、用户名/邮箱哈希；用 `crypto/prng` 中的小种子爆破、时间种子复现、MT19937 状态恢复等方法预测。
- 变体：验证码只在客户端生成/校验，服务端仅比对客户端提交的“正确性”字段；可直接改响应或跳过生成。
- 关联：[[web-generic-auth-sms-code-echo-response-arbitrary-login]]（验证码回显，直接读响应）、[[web-generic-auth-password-reset-response-tampering-sms-bypass]]（篡改响应 success 绕过）、[[mobile-android-sms-login-code-bruteforce-replay]]（无次数限制爆破与重放）、[[web-generic-auth-sms-code-multi-number-shared-arbitrary-login]]（多号码同码/未绑定）。
- 关联：[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子 2FA）、[[crypto-prng-glibc-rand-small-seed-bruteforce]]（小种子爆破）、[[crypto-prng-hardcoded-seed-custom-lcg-admin-password-predict]]（硬编码种子 LCG）。
- 边界：使用 `secrets`/`random.SystemRandom`/硬件随机、种子不可观测、验证码与手机号/会话强绑定、一次性失效、严格频率限制与图形验证码时，本手法不成立。

## 检测与防御

- 生成：使用 CSPRNG（Python `secrets`、`random.SystemRandom`、Java `SecureRandom`），禁止自增计数器/固定种子/手机号种子；不要把验证码写入日志或响应。
- 绑定与生命周期：验证码与手机号+会话强绑定，一次性使用，短 TTL（如 5 分钟），失败多次作废；发送/验证接口做手机号、IP、会话多维限流与图形验证码。
- 监控：同一手机号/同一 IP 的发送频率、验证失败率、连续码值规律；响应包中出现 `code`/验证码字段；账号在异常 IP 登录。
- 检测：验证码请求响应体中出现 4–8 位数字字段；短时间内同一接口大量 200 且 `success` 变化；注册/登录日志中手机号与验证码请求来源不一致。
