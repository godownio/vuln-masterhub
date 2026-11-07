---
id: web-generic-auth-api-param-fuzz-idcard-pii-enumeration
title: 移动端接口参数枚举 + 身份证 PII 越权查询：从参数缺失报错到手机号遍历
type: scenario
domain: web
path: web/generic/auth
technique: api-param-fuzz-idcard-pii-enumeration
tags:
- web
- api
- idor
- pii
- enumeration
- parameter-fuzzing
- mobile
- auth
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:09:04+08:00'
  notes: 已对照原文与截图核对：按“参数X不能为空”补参、mobile_code=111111 任意值通过、响应返回 identity_category/idtype/addr/staff_name/branch_name/position 等身份证PII、手机号遍历1300+请求均一致。未验证点：未复跑接口，部分字段名与域名在截图中打码。
url: /docs/web/generic/auth/web-generic-auth-api-param-fuzz-idcard-pii-enumeration/
draft: false
kb_aliases:
- 参数缺失报错枚举
- 接口参数增删改查
- 身份证信息泄露
- 手机号遍历
- PII 越权查询
- 移动端 API 越权
---

## 一句话结论

移动端接口在缺少参数时返回“参数 X 不能为空”，攻击者据此逐个增删改参数、枚举出完整请求字段；构造 `mobile_no + mobile_code` 等参数后，接口未校验手机号归属/验证码，直接返回该手机号对应的身份证号、姓名、地址、工号等 PII，遍历手机号即可批量泄露。

## 原理

- 很多后端框架在参数校验失败时返回具体字段名（如 `参数[mobileNo]不能为空`），这等于把接口的必填参数表泄露给攻击者；逐个补参即可还原完整请求。
- 该接口看起来是“查询某手机号信息”，但服务端只校验参数是否存在/格式，不校验当前用户是否有权查询该手机号，也不要求验证码真实有效（示例 `mobile_code=111111` 即可）。
- 响应包含身份证相关字段（`identity_category`、`idtype`、`addr`、`id`、`idenddate`、`staff_name`、`branch_name`、`position`、`credit_record` 等），属于高敏感 PII。
- 手机号是连续/可枚举的，攻击者可批量替换 `mobile_no`，按响应长度/字段差异筛选有效记录，形成大规模数据泄露。
- 根因是“错误信息过于详细 + 对象级授权缺失 + 验证码未校验 + 无速率限制”的组合；即使接口需要登录，普通账号也能越权查询他人信息。

## 触发条件

- 移动端 API 对缺失参数返回具体字段名/校验错误。
- 接口按手机号/用户 ID 查询敏感信息，但不校验归属/权限。
- 验证码参数可填任意值，或验证码未与手机号/会话绑定。
- 无速率限制/批量审计，手机号可枚举。

## 利用步骤

1. 抓取一个疑似查询接口的请求，记录 URL、方法、已有参数与响应。
2. 逐个删除/修改参数，观察错误信息；按“参数 X 不能为空”补齐字段，直到请求成功。
3. 对成功响应分析字段，确认是否包含身份证号、姓名、地址、工号等 PII。
4. 将 `mobile_no`/`phone`/`userId` 等标识参数作为爆破点，用 Burp Intruder/Yakit 遍历手机号或 ID。
5. 按响应长度、状态码、关键字段筛选有效记录，导出证据；控制频率，避免大规模骚扰。
6. 评估是否需要登录态/验证码；尝试无 token、低权限账号、任意 `mobile_code` 等变体。

## PoC

```python
import requests

BASE = "https://target"
URL = f"{BASE}/api/xxx/query.json"

# 1) 参数枚举：从空请求开始，按错误信息补参
params = {}
for _ in range(10):
    r = requests.post(URL, data=params, timeout=10)
    print(r.status_code, r.text[:200])
    # 若响应提示 "参数[xxx]不能为空"，把 xxx 加入 params 后重试
    break

# 2) 构造完整请求（示例字段名，按实际接口调整）
params = {
    "mobile_no": "18888888888",
    "mobile_code": "111111",   # 未校验/可任意
    "op_source": "0",
    "flow_type": "twvideo",
}
r = requests.post(URL, data=params, timeout=10)
print(r.text)  # 可能包含身份证号、姓名、地址等

# 3) 遍历手机号（授权范围内，控制频率）
for phone in ["18888888888", "18888888889"]:
    params["mobile_no"] = phone
    resp = requests.post(URL, data=params, timeout=10)
    print(phone, len(resp.text), resp.text[:120])
```

## 变体与关联

- 变体：参数名可能是驼峰/下划线/缩写；错误信息可能是英文/中文/JSON 字段。
- 变体：接口用 GET/POST JSON、GraphQL、RPC；参数枚举思路相同。
- 变体：需要登录态时，用普通账号/低权限账号测试水平越权；验证码可回显/可爆破时结合短信漏洞。
- 关联：[[web-generic-auth-mobile-person-permission-userid-idor-pii]]（userId 越权遍历 PII）、[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（验证码/参数篡改）、[[mobile-android-sms-login-code-bruteforce-replay]]（短信验证码登录接管）。

## 检测与防御

- 防御：参数校验错误返回统一文案，不泄露字段名；对敏感查询做对象级授权（当前用户只能查自己/授权范围）。
- 防御：验证码必须与手机号/会话绑定且一次性；对手机号/ID 查询做速率限制、审计与异常告警。
- 检测：同一账号/ IP 高频查询不同手机号、响应包含大量 PII、参数缺失错误被反复触发。
- 响应：确认泄露后下线接口/加授权，通知受影响用户，按法规评估数据泄露影响并轮换相关凭据。
