---
id: web-generic-auth-password-reset-token-unix-timestamp-md5-bruteforce
title: 密码重置链接的 token 是「Unix 时间戳的 MD5」：发信后按秒级时间窗枚举 token，即可为任意账号构造出可用的重置链接
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-token-unix-timestamp-md5-bruteforce
aliases:
- 邮箱弱 token
- 重置链接 token 可预测
- md5(unix 时间戳) 重置令牌
- 服务器时间作随机 token
- 重置令牌时间窗枚举
- token 差 1-2 推断服务器时间
tags:
- web
- auth
- password-reset
- predictable-token
- md5
- timestamp
- account-takeover
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:10+08:00'
  notes: 已对照原文核对；正文「邮箱弱 token」案例的三条依据——链接里的 md5 串解出形如 1491293277 的 10 位 Unix 时间戳、重置链接以用户名区分、两账号同时点找回后 token 只差 1-2 从而可推断服务器时间——与卡片的识别判据（10 位十进制 / 32 位十六进制 / 时间窗线性递增）与利用步骤一一对应；本次核对未读取图片，16 张图（含 img/13 邮件链接截图）未读图核对；原文未给出具体 md5 拼接串与接口，卡片把「md5(用户名+时间戳)」等列为待反推的常见变体而非确定结论，属未验证点，保留 confidence=medium；卡片 PoC 仅为形态示例，未对其中的 target 发起任何请求，未执行文中任何命令
---

## 一句话结论

当找回密码邮件里的重置链接携带的 token 不是随机串，而是「Unix 时间戳（秒）的 MD5」或「服务器时间参与的直接拼接」时，token 的取值空间就只有发信前后那几十秒：用自己的账号发一封重置邮件、从链接里解出时间戳 `t`，再对目标账号发一封重置邮件，在 `t ± 若干秒` 的窗口内逐秒计算 `md5(str(t+i))`（或按题目给的拼接规则计算）并请求重置接口，命中即可把任意账号的密码改成自己指定的值。

## 原理

- **token 熵不足**：MD5 输出看起来是 32 位十六进制，但如果输入只有「秒级时间戳」这一个变量，则同一秒内的所有用户共享同一个 token，实际熵就是「窗口秒数」——几十比特变几十种可能。
- **识别方法**：把 token 当十六进制/十进制看，若恰好是 10 位十进制（如 `1491293277`）或能解成 10 位十进制，就是 Unix 时间戳；把它与当前时间对比，差值在几分钟内即可确认；再对自己的另一个账号发一次，比较两个 token 的时间戳差 1–2 秒，说明它随发信时刻线性递增。
- **为什么服务端不校验绑定也不救场**：很多实现把 token 当「查表键」——`reset_token` 表按 token 找用户。若 token 由时间派生，攻击者算出的 token 一定对应「那一秒内发起重置的那个用户」；只要在目标账号发信后立刻枚举，命中的 token 就属于目标账号，攻击者无需知道对方邮箱密码。
- **两种典型实现**：
  - 链接里直接放时间戳：`?token=1491293277`，服务端把它当校验值比对当前时间窗口。
  - 链接里放 `md5(时间戳)` 或 `md5(用户名+时间戳)`：需要知道拼接规则（可从自己账号的 token 反推：已知自己的用户名与时间戳，试几种常见拼接即可确定）。
- **窗口为什么必须小**：服务端通常允许 token 在 5–30 分钟内有效，但攻击者只能对自己「刚发出的那封」做精确时间对齐；`t` 已知后，枚举范围实际是「目标发信时刻 − 自己发信时刻」的偏差（几秒到几十秒），远小于有效期。
- **与「弱随机」的区别**：不是 PRNG 可预测（如 `srand(time)`），而是根本没有随机数——token 是时间的纯函数，因此不需要恢复任何状态。

## 触发条件

- 找回密码邮件中的重置链接带 token，且 token 可被识别为时间戳或时间戳的哈希。
- 服务端以该 token 为键查询待重置用户，且不额外校验 token 与请求来源/会话的绑定。
- 攻击者能触发「给目标账号发送重置邮件」（知道目标邮箱或用户名即可），并能观察到 token 与时间的对应关系。
- 重置接口没有验证码/速率限制，或限制不足以阻断几十次枚举。

## 利用步骤

1. 用自己账号走一遍找回密码，收取邮件，取出重置链接里的 token。
2. 判定结构：token 为 10 位十进制 → 直接当时间戳；为 32 位十六进制 → 取 `md5(str(t))`、`md5(str(t) + username)`、`md5(username + str(t))` 等常见拼接逐个比对（用自己账号已知的 `t` 与 username 反推规则）。
3. 再对自己的另一个账号或同一账号连发两次，记录两次 token 对应的时间戳差值，确认「随发信秒数线性变化」（常见差 1–2 秒）。
4. 对目标账号触发一次重置邮件，记下发起时刻 `t0`；在 `t0 - 5` 到 `t0 + 60` 的窗口内逐秒计算候选 token。
5. 用候选 token 请求「校验 token / 设置新密码」接口，按响应差异（成功跳转、返回新密码页、错误提示不同）判定命中；命中后立刻提交新密码。
6. 用新密码登录目标账号验证接管，记录证据后停止；不要继续改动目标账号的其他数据。

## PoC

判定与枚举（token = md5(unix 秒) 形态）：

```python
import hashlib, time, requests

def md5(s): return hashlib.md5(s.encode()).hexdigest()

# 步骤 1：用自己的账号确认规则
my_token = "<自己邮件里的 token>"
my_ts_guess = int(time.time())
assert md5(str(my_ts_guess)) == my_token or md5(str(my_ts_guess - 1)) == my_token

# 步骤 4-5：目标发信后，在窗口内枚举
base = int(time.time())          # 目标发信时刻（误差 ±5s 即可）
for i in range(-5, 61):
    tok = md5(str(base + i))
    r = requests.post("https://target/reset/verify",
                      data={"token": tok, "newpass": "P@ssw0rd!"}, timeout=10)
    if "success" in r.text or r.status_code == 302:
        print("hit", base + i, tok); break
```

若 token 直接是明文时间戳，则省去哈希：`for t in range(base-5, base+61): requests.get(f"https://target/reset?token={t}&user=<目标>")`。

## 变体与关联

- 拼接变体：`md5(username + timestamp)`、`md5(timestamp + email)`、`timestamp` 与随机盐拼接后再 md5（需先反推盐）；也可用 `sha1`/`crc32` 代替 md5，识别思路相同（把已知时间戳代入试）。
- 「服务器时间」变体：两个账号同时点找回，token 只差 1–2 且都不等于本地时间，说明用的是服务器时钟——此时先用响应头 `Date` 或页面时间校准偏移，再枚举。
- 「用户名直通」变体：链接直接以用户名区分（`?user=victim`），完全不需要枚举，见 [[web-generic-auth-password-reset-username-tampering]]。
- 关联：[[web-generic-auth-password-reset-hash-low12-bruteforce]]（另一种「token 空间只有几千种」的暴力面）、[[web-generic-auth-otp-derived-from-current-minute-deterministic-reset]]（时间派生的验证码）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（PRNG 时间种子路线）。

## 检测与防御

- **服务端**：重置 token 必须用 CSPRNG 生成足够长度（≥128 bit）并与用户 + 会话绑定、一次性、短时效（如 15 分钟）；不要用时间戳或时间戳哈希作为 token。
- **绑定与校验**：重置页要求携带 token 与邮箱/用户名的组合校验，token 使用后立即失效；同账号短时间内多次申请只保留最后一个 token（或全部作废）。
- **风控**：对「校验 token」接口做失败次数限制与速率限制，同一 IP/账号超出阈值即拒绝；对短时间内大量 `token` 校验失败告警。
- **检测信号**：重置链接 token 为 10 位数字或长度固定且与发信时间强相关；同一 token 前缀在多个账号的邮件中出现；校验接口在数秒内收到数十个连续候选值（时间窗扫描特征）。
