---
id: web-generic-jwt-password-as-hmac-key-bruteforce
title: JWT 以用户密码作 HS256 密钥：枚举 userId 后离线/在线爆破口令接管教师账号
type: scenario
domain: web
path: web/generic/jwt
technique: password-derived-jwt-key-bruteforce
tags:
- jwt
- hs256
- weak-key
- password
- brute-force
- shiro
- account-takeover
- userid-enumeration
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:02:28+08:00'
  notes: 已对照原文与34张图核对：sign 使用 Algorithm.HMAC256(password)、载荷仅 userId、教师详情页 teacherInfo?id= 泄露 userId、Shiro filterMap 将 /common/** 等放行其余走 jwt，均与卡片一致。未验证点：截图显示 jwtTokenRefresh 校验的是 Redis 缓存 token 而非请求 token（卡片关联段已注明），故“以业务响应为 oracle 爆破密码”的在线链路原文未打通、未给成功截图，confidence=medium 合理；原文本机未复现。
url: /docs/web/generic/jwt/web-generic-jwt-password-as-hmac-key-bruteforce/
draft: false
kb_aliases:
- JWT 密码当密钥
- 教师账号爆破
- userId 枚举
- HMAC256 password
- 无感 JWT 爆破
---

## 一句话结论

当应用用 `Algorithm.HMAC256(<用户密码>)` 签发 JWT、令牌载荷只含可枚举的 `userId` 时，攻击者可以先从教师列表/个人主页拿到 `userId`，再用候选口令逐个生成 HS256 令牌去访问任意受保护接口，以业务响应而不是登录框来判断口令是否正确，从而静默爆破教师账号并接管其权限。

## 原理

- JWT 的 HS256 签名密钥是共享 secret；若代码把“用户密码”直接作为 `HMAC256(password)` 的 key，则每个 userId 对应一个可离线计算的密钥空间。
- 令牌载荷只有 `userId`（`JWT.create().withClaim("userId", userId)`），没有角色/过期等复杂声明；服务端 `JwtUtil.getUserId(token)` 解析出 userId 后，用数据库中该用户的密码作为 key 验证签名。
- 签名的验证本质上是一次 HMAC 计算：攻击者对候选口令 `pw` 计算 `HMAC-SHA256(header.payload, pw)`，与/或直接生成完整 token 发给受保护接口。成功则得到该用户的有效令牌，失败则收到鉴权错误；整个爆破不经过 `/login`，不会触发登录失败计数/告警。
- `userId` 不是秘密：教师列表页、教师详情页 URL（如 `/teacherInfo?id=...`）会直接暴露每个教师的 userId；结合弱口令/常见口令字典即可逐个尝试。
- 服务端校验还依赖 Redis 中的缓存 token（`jwtTokenRefresh` 读取 `PREFIX_USER_TOKEN + userId`）；目标用户需有已登录/未过期的缓存 token，否则会返回失败。这解释了为什么该攻击更适合针对活跃教师账号。
- 结果是攻击者获得教师（甚至管理员，若 userId 可枚举到）身份，可访问课程管理、审批、用户数据等接口。

## 触发条件

- 应用使用 Shiro + JWT，签名 key 直接取自用户密码/手机号等用户可控或可猜测字段。
- JWT 载荷包含可枚举的 `userId`，且服务端仅以该 id 查用户并用其密码验签。
- 目标用户已在 Redis 中有有效缓存 token（通常意味着近期登录过）。
- 口令策略较弱或用户使用常见口令；攻击者可访问任意受保护接口作为爆破 oracle。
- 教师列表/详情页等公开接口泄露 userId。

## 利用步骤

1. 浏览教师列表，进入教师详情页，从 URL 或接口响应提取 `userId`。
2. 准备候选口令字典（常见弱口令、姓名/学校/手机号变体）。
3. 对每个候选口令生成 HS256 JWT：payload 为 `{"userId": "<id>"}`，key 为候选口令。
4. 用生成的 token 请求一个需要登录的轻量接口（如 `/user/getUserInfo`、`/task/...`），根据返回码/业务响应判断口令是否正确。
5. 命中后保存该用户 token，访问教师/管理接口验证权限；仅做只读或授权范围内的操作。
6. 若接口有频控，降低速率并分散到多个 userId/时间窗口，避免触发告警。

## PoC

概念性脚本（不执行真实爆破）：

```python
import jwt, requests

uid = "<teacher-user-id>"
url = "http://target/api/user/getUserInfo"
for pw in ["123456", "admin123", "password", "<姓名拼音>", "<手机号后六位>"]:
    token = jwt.encode({"userId": uid}, pw, algorithm="HS256")
    r = requests.get(url, headers={"x_access_token": token}, timeout=5)
    if r.status_code == 200 and '"code":1000' in r.text:
        print("hit:", pw, token)
        break
```

原文未给出爆破成功后的 token/后台截图，PoC 为按代码逻辑构造；实际测试需使用授权账号与无害接口。

## 变体与关联

- 密钥来源变体：密码、手机号、邮箱、用户名等用户可控字段作为 HMAC key；也可先离线验证已知 token（若拿到任意合法 token）。
- userId 枚举变体：教师列表、个人主页、评论/订单等公开对象；连续数字/雪花 ID 可在页面 URL 中直接获取。
- 判定变体：受保护页面的 200/302、业务 JSON 的 code 字段、响应长度差异；避免使用会锁定账号的登录接口。
- 关联卡片：[[web-generic-jwt-weak-hmac-key-bruteforce]]（HS256 弱密钥字典爆破）、[[web-generic-jwt-unverified-signature-payload-tamper]]（签名校验缺失）、[[web-generic-auth-missing-function-level-role-check]]（拿到教师身份后的越权面）。
- 关联：代码中 `jwtTokenRefresh` 校验的是 Redis 缓存 token 而非请求 token，若 `getUserId` 不验签，可能存在更直接的伪造路径；原文未验证，未单独建卡。

## 检测与防御

- 检测：大量携带不同 `x_access_token` 的请求命中同一受保护接口，token 的 `userId` 相同但签名不同；同一 IP 对多个 userId 轮询；401/1006 错误比例异常升高。
- 检测：JWT 签名密钥与用户密码/手机号相关（代码审计）；教师详情页批量枚举 userId。
- 防御：JWT 使用服务端随机生成的高熵密钥（环境变量/密钥管理），绝不用用户密码或可猜测字段；定期轮换。
- 防御：令牌加入 `exp`、`jti`、签发时间并在服务端维护撤销列表；校验时同时验证请求 token 的签名，而不是只验证缓存 token。
- 加固：强口令策略、登录与接口频控、异常 token 告警；教师/用户列表不返回不必要的 userId；对敏感接口做角色与对象级校验。
- 响应：命中后立即吊销该用户 token、重置口令、审计其访问记录与敏感操作。
