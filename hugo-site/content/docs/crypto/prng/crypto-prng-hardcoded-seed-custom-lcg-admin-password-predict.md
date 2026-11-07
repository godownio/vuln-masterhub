---
id: crypto-prng-hardcoded-seed-custom-lcg-admin-password-predict
title: 硬编码 PRNG 种子 + 自定义 LCG：按调用顺序预测 session secret 与管理员密码
type: scenario
domain: crypto
path: crypto/prng
technique: hardcoded-seed-custom-lcg-password-prediction
tags:
- prng
- lcg
- hardcoded-seed
- predictable-password
- nodejs
- session-secret
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:53+08:00'
  notes: 已对照原文核对；LCG 输出已本地复算一致（JbjULcgJmg6EyKcQ / XrfGpmeEFZmz8NDZ）；未在目标复跑。
url: /docs/crypto/prng/crypto-prng-hardcoded-seed-custom-lcg-admin-password-predict/
draft: false
kb_aliases:
- 硬编码随机种子
- 114514
- 自定义 LCG
- 48271 mod 998244353
- 预测管理员密码
- session secret 预测
- 小W和小K的故事
---

## 一句话结论

Node.js 应用用 `new random(114514)` 这类硬编码种子初始化自定义线性同余发生器（LCG），并用它依次生成 session secret 与管理员密码时，攻击者只要拿到 `random.js` 的算法与调用顺序，就能在本地复现同一序列，算出管理员密码 `XrfGpmeEFZmz8NDZ`，直接登录后台；session secret 也可预测，可用于伪造会话。

## 原理

- **LCG 是确定性的**：本例的 `Random` 类为 `seed = seed % 998244353`，每次 `next()` 执行 `seed = (seed * 48271) % 998244353` 并返回；`getRandomInt(min,max)` 返回 `min + (next() % (max-min))`；`getRandomString(length)` 从固定字符集 `A-Za-z0-9` 按 `getRandomInt(0,62)` 取字符。整个过程没有系统随机源，同一初始种子必然产生同一序列。
- **种子硬编码**：`app.js` 中 `const rng = new random(114514);` 把种子写死在源码里；攻击者通过源码泄露/备份/前端 bundle 拿到 `random.js` 和 `app.js` 即可复现。
- **调用顺序决定输出**：应用先用同一个 `rng` 生成 session secret（第一次 `getRandomString(16)`），再生成 admin 密码（第二次 `getRandomString(16)`）。由于 LCG 状态在两次调用之间连续推进，不能只重放第一次；必须按真实调用顺序先消耗 session secret 的 16 次 `next()`，再生成密码。
- **为什么能登录**：管理员密码不是随机不可预测的，而是由公开算法 + 固定种子 + 固定顺序决定；攻击者本地跑同样代码即可得到 `XrfGpmeEFZmz8NDZ`，无需爆破。
- **影响扩大**：如果 session secret 也由同一 PRNG 生成，攻击者可预测/伪造签名 cookie（如 express-session 的签名），绕过认证或伪造其他用户；即使只泄露 admin 密码，也足以接管后台。
- **边界**：若种子来自 `crypto.randomBytes`/`Date.now()` 且不可观测、算法/调用顺序未知、或每次启动重新随机化，则不能直接预测；若只泄露 session secret 而密码用 CSPRNG，则影响有限。

## 触发条件

- 应用使用自定义 PRNG/LCG，种子硬编码或可预测（时间、PID、固定常量），且算法公开/可泄露。
- 攻击者能获得算法源码（前端 bundle、备份、Git 泄露、npm 包）与调用顺序（生成 session secret、密码、token 等）。
- 目标密码/session 密钥直接由该 PRNG 输出生成，没有额外的 CSPRNG/盐/哈希。
- 管理员账号名已知（如 `admin`），登录接口无锁定/验证码/多因素。
- 需要能访问登录接口并提交预测的密码。

## 利用步骤

1. 获取 `random.js`/`app.js`（源码泄露、前端 bundle、Git 历史、备份文件），确认 LCG 参数（模数 998244353、乘数 48271）、种子 `114514` 与字符集。
2. 确认调用顺序：先 `getRandomString(16)` 生成 session secret，再 `getRandomString(16)` 生成 admin 密码；注意是否有其它中间调用（日志、其他用户初始化）会推进状态。
3. 在本地用 Python/Node 复现同一类与调用顺序；输出 session secret 与 admin 密码。
4. 用 `admin` + 预测密码登录；若失败，检查是否有额外调用/不同字符集/密码哈希前的处理，调整调用次数。
5. 若 session secret 可预测，进一步伪造签名 cookie/会话，测试越权；登录后台后寻找 flag/敏感功能。
6. 若目标重启后种子/序列变化，确认种子是否仍硬编码；若种子是时间/PID，枚举候选并批量尝试。

## PoC

Python 复现（与原文 `random.js` 等价）：

```python
class Random:
    def __init__(self, seed):
        self.seed = seed % 998244353

    def next(self):
        self.seed = (self.seed * 48271) % 998244353
        return self.seed

    def getRandomInt(self, min_val, max_val):
        return min_val + (self.next() % (max_val - min_val))

    def getRandomString(self, length):
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(charset[self.getRandomInt(0, len(charset))] for _ in range(length))

rng = Random(114514)
session_secret = rng.getRandomString(16)   # 第一次调用
admin_password = rng.getRandomString(16)   # 第二次调用
print("Session Secret:", session_secret)   # JbjULcgJmg6EyKcQ
print("Admin Password:", admin_password)   # XrfGpmeEFZmz8NDZ
```

登录：

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=XrfGpmeEFZmz8NDZ
```

## 变体与关联

- 变体：LCG 参数/模数/字符集不同；用 `z3`/线性代数从少量输出反推参数与状态（见关联卡）。
- 变体：种子来自 `Date.now()`、`process.pid`、容器启动时间等可观测值；可枚举候选种子。
- 变体：PRNG 用于生成 2FA 码、重置 token、邀请码、API key；同一预测思路适用。
- 关联：[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（LCG 参数恢复）、[[crypto-prng-lcg-known-modulus-xor-keystream]]（已知模数 LCG）、[[crypto-prng-observable-pid-uptime-derived-admin-secret-token-forgery]]（可观测 pid/uptime 派生密钥）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子 2FA 预测）。
- 边界：种子不可预测/每次随机、算法未泄露、调用顺序有未知中间步骤、密码额外加盐哈希且盐随机时，该链不成立。

## 检测与防御

- **修复**：使用 CSPRNG（Node `crypto.randomBytes`/`crypto.randomUUID`、Python `secrets`）生成密码、session secret、token；不要用自定义 LCG/`Math.random` 做安全用途。
- **代码审计**：禁止硬编码种子；检查 `new Random(...)`、`Math.random()` 是否用于认证/密钥；密码应使用强哈希（bcrypt/argon2）加随机盐存储。
- **运维**：源码/备份/前端 bundle 不暴露服务端随机算法与种子；限制 Git/备份访问；管理员账号启用 MFA、登录限速。
- **检测**：监控同一 IP 对 admin 的少量精确登录尝试（非爆破）、异常 session 签名；代码扫描硬编码种子/LCG 参数；对 session secret 定期轮换。
- **响应**：泄露后立即更换 admin 密码与 session secret，使所有会话失效；审计登录日志与后台操作。
