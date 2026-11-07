---
id: web-generic-auth-login-header-userid-token-binding-takeover
title: 移动端登录接口复用令牌续期：任意 Userid + 任意 Token 绑定接管账户
type: scenario
domain: web
path: web/generic/auth
technique: login-header-userid-token-binding-takeover
aliases:
- 移动端任意用户接管
- Userid Token 请求头绑定
- 登录接口令牌续期缺陷
- tempToken 绑定任意用户
- 自增 Userid 枚举
- token 验证接口复用
tags:
- auth
- mobile
- api
- token
- idor
- account-takeover
- enumeration
- web
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:39:54+08:00'
  notes: '已对照原文与4张图核对：登录接口带 Userid 头返回“用户不存在!”，枚举到有效 ID 后返回 tempToken（图04 显示 Token: a 被原样绑定回 tempToken）与用户信息；类型为整型。原文为 SRC 案例，未披露厂商/版本，响应示例中部分字段为示意。PoC 未在本机执行；frontmatter 无 sources/source_url。'
---

## 一句话结论

移动端登录接口本应只校验手机号/验证码，却同时接受 `Userid` 与 `Token` 两个请求头并复用了“令牌续期/验证”逻辑：当传入有效 `Userid` 时，服务端返回该用户信息和 `tempToken`，并把攻击者随意提供的 `Token` 值绑定到该用户 ID；由于 Userid 是自增整数，攻击者可枚举 ID、无需验证码即可接管任意账户。

## 原理

- 登录接口职责混淆：同一个接口既处理“手机号+验证码登录”，又在检测到 `Userid`/`Token` 头时走“根据 Userid 查用户、签发/刷新 token”的分支。两条路径共享了“根据 Userid 查用户 + 返回 tempToken”的代码。
- 权限校验缺失：服务端只校验 `Userid` 是否存在，没有校验调用者是否拥有该 ID，也没有校验请求中的 `Token` 是否原本属于该用户；它直接把客户端提供的 `Token` 作为该用户的临时令牌返回/绑定。
- 结果是“任意 Token 值 + 任意有效 Userid”组成一对可用凭证：攻击者不需要知道目标密码、验证码或原 Token，只要枚举出一个有效 Userid，就能获得该用户的 tempToken 并访问其接口。
- Userid 为整型自增，遍历成本低；早期 ID 往往是管理员/测试账号，权限更高。响应中的 `type`/`role` 字段可用于筛选高权限用户。
- 该漏洞与“IDOR 读取他人资料”不同：它不仅读，还把攻击者的 token 绑定到目标账户，形成会话接管。

## 触发条件

- 移动 App/小程序 API 使用 `Userid` + `Token` 请求头做认证，登录接口也接受这两个头。
- 登录接口在带 `Userid` 时走“按 ID 查用户/刷新 token”分支，且不验证调用者身份或 token 归属。
- Userid 为可枚举的整数（自增/短 ID），响应可区分“用户不存在”和成功。
- 攻击者能抓包/改包（Burp、mitmproxy、Frida 等），并能访问登录接口。
- 目标未对登录接口做严格频率限制/验证码绑定。

## 利用步骤

1. 抓取正常登录请求，确认请求体只含手机号/验证码；观察正常登录失败/成功响应。
2. 在请求中加入 `Userid: 1`、`Token: <任意字符串>` 两个头，观察响应是否从“验证码错误”变为“用户不存在/成功”——出现“用户不存在”说明接口在用 Userid 查用户。
3. 用边界值（`-1`、`0`、超大整数、字符串）判断 Userid 类型与错误处理；确认是整型后开始枚举。
4. 从 0/1 开始按数量级/随机采样枚举有效 Userid；有效 ID 的响应会返回用户信息与 `tempToken`。
5. 记录 `tempToken`（通常就是请求头里的 Token 值），用它 + 对应 Userid 访问业务接口，验证是否为目标用户。
6. 优先枚举较小的 ID（管理员/测试账号），查看响应中的 `type`/`role`/权限字段；成功后停止并保存证据。
7. 若接口返回敏感信息（手机号、身份证、地址），记录泄露范围；避免批量导出。

## PoC

带 Userid/Token 的登录请求：

```http
POST /api/login HTTP/1.1
Host: target
Content-Type: application/json
Userid: 1
Token: attacker-chosen-token

{"phone":"13333333333","code":"123456"}
```

若 Userid 有效，响应可能为：

```json
{"code":0,"message":"请求成功","data":{"userId":1,"tempToken":"attacker-chosen-token","type":"admin","tel":"138****0000"}}
```

随后用同一对头访问业务接口：

```http
GET /api/user/profile HTTP/1.1
Host: target
Userid: 1
Token: attacker-chosen-token
```

Userid 边界测试：

```text
Userid: -1      -> 异常/不存在
Userid: 0       -> 异常/不存在
Userid: 999999999999999999999 -> 整数溢出/未知错误
Userid: abc     -> 类型错误
```

枚举脚本（伪代码，需授权）：

```python
import requests
for uid in range(1, 10000):
    r = requests.post(url, headers={"Userid": str(uid), "Token": "x"},
                      json={"phone": "13333333333", "code": "000000"})
    if "tempToken" in r.text or "请求成功" in r.text:
        print(uid, r.text[:200])
```

## 变体与关联

- 变体：`Userid` 可能叫 `UserId`、`user-id`、`uid`、`X-User-Id`；逐一尝试大小写/连字符。
- 变体：Token 头可能叫 `Token`、`Authorization`、`X-Token`；登录接口可能只认其中一个。
- 变体：接口不返回 `tempToken`，但会把传入 Token 写入会话/缓存，后续请求直接用该 Token 即可。
- 变体：Userid 为 UUID/长 ID 时枚举成本高，但仍可通过响应差异/泄露的 ID 做定向接管；优先找整数自增场景。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（同类“客户端可控用户标识”缺陷）。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（认证后越权到他人账户）。
- 注意：枚举会产生大量请求，必须在授权范围内并控制速率；不要批量读取/导出真实用户敏感数据。

## 检测与防御

- 修复：登录接口只处理手机号/验证码，忽略或拒绝 `Userid`/`Token` 请求头；令牌刷新/验证使用独立接口。
- 修复：任何按 Userid 查询/操作都必须以服务端会话中的用户为准，禁止客户端指定目标用户；校验 Token 与 Userid 的绑定关系，拒绝“任意 Token + 任意 Userid”。
- 加固：使用标准 JWT/不透明 session，包含过期时间、签名与用户 ID；登录成功后签发，刷新时验证原 token 有效性。
- 加固：Userid 使用不可枚举的随机 ID/UUID；对登录和资料接口做速率限制、验证码绑定、异常枚举告警；敏感字段脱敏。
- 检测：登录请求中出现 `Userid`/`Token` 头且请求体验证码无效；同一来源枚举连续/大量 Userid；响应中大量“用户不存在”；同一 Token 值出现在多个 Userid 请求中；登录接口异常返回用户信息/tempToken。
