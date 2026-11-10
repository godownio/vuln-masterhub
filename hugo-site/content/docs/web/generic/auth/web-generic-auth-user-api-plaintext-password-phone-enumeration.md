---
id: web-generic-auth-user-api-plaintext-password-phone-enumeration
title: 用户信息接口既无鉴权又回明文口令：遍历 id/拼接用户即可批量拉取全站账号、密码与手机号
type: scenario
domain: web
path: web/generic/auth
technique: user-api-plaintext-password-phone-bulk-enumeration
tags:
- web
- auth
- information-disclosure
- pii
- idor
- enumeration
- plaintext-password
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:12:40+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文只有'敏感接口泄露用户信息（含密码/手机号）'与'接口遍历拼接可发现用户密码手机号'两句概述，未给出接口路径、请求与响应字段，卡内 PoC 的 /api/user/detail 与返回体为通用示例而非原文实证；场景本身（未鉴权用户接口回明文口令+手机号可遍历）与正文一致，confidence low 恰当。
url: /docs/web/generic/auth/web-generic-auth-user-api-plaintext-password-phone-enumeration/
draft: false
kb_aliases:
- 接口遍历拿密码手机号
- 敏感接口泄露用户信息
- 用户列表回明文密码
- 拼接口枚举账号
---

## 一句话结论

业务系统里存在返回用户对象的接口，既没有做角色/归属校验（登录后的普通账号甚至未登录都能调），又把 `password` 以明文（或可逆形式）和 `phone` 一起返回；攻击者按自增 id 或把用户名拼进接口路径遍历一遍，就能一次性拿到全站账号口令与手机号，等于拿到大批可直接登录的凭据。

## 原理

- **越权 + 敏感字段回显的叠加**：单看「越权读用户列表」只是 PII 泄露，单看「密码字段返回」也只是实现缺陷；两者叠加时，攻击者拿到的是**可直接使用的登录凭据**，危害从「信息泄露」升级为「批量账号接管」。
- **为什么接口会被遍历**：后端把用户查询写成 `/api/user/{id}`、`/api/user/detail?username=xxx` 这类以客户端参数为唯一条件的查询，没有校验「当前会话是否等于目标用户/是否有管理角色」，属于 IDOR（不安全的直接对象引用）+ 缺失功能级鉴权。
- **为什么密码会出现明文**：注册/登录未用哈希（或用了可逆加密仍原样返回 DTO），实体类直接序列化给前端；前端只需展示「重置密码」等场景，结果把整个对象吐了出来。
- **为什么遍历成本极低**：自增主键 + 无频率限制，几百次请求即可覆盖全表；配合手机号字段还能用于撞库、社工与短信轰炸。
- **与前端隐藏的关系**：这类接口常常只在前端管理菜单里被引用，普通用户看不到入口，但请求本身不做校验，直接构造 URL 即可调用。

## 触发条件

- 存在以用户标识（id、username、email）为参数的用户查询接口。
- 服务端不校验请求者身份/角色/归属，或仅校验「已登录」。
- 响应体包含 `password`（明文或可逆）、`phone`、`idcard` 等敏感字段。
- 标识可枚举（自增 id、可猜用户名）。

## 利用步骤

1. 注册或获取一个最低权限账号，进入个人中心，抓取「我的资料/用户详情」请求。
2. 把请求中的用户标识改成其它值（`id+1`、他人用户名），观察是否返回他人数据。
3. 确认响应里是否带口令与手机号等字段；若字段被裁剪，尝试换接口版本、加 `?fields=all`、或调用「编辑前回显」类接口。
4. 用小范围脚本遍历 id 区间，落库保存 `username/password/phone`，控制请求速率避免触发封禁。
5. 用拿到的账号口令撞同一系统的更高权限入口（管理后台）、SSH/VPN 或其它复用口令的系统。

## PoC

```http
GET /api/user/detail?id=1001 HTTP/1.1
Host: target
Cookie: <低权限账号会话>

HTTP/1.1 200 OK
Content-Type: application/json

{"id":1001,"username":"zhangsan","password":"Abc12345","phone":"138****0000","role":"admin"}
```

遍历（伪代码，勿对未授权目标执行）：

```python
for uid in range(1000, 1200):
    r = sess.get(f"{base}/api/user/detail", params={"id": uid})
    if r.ok and "password" in r.text:
        save(r.json())
```

## 变体与关联

- **只泄露哈希**：需要离线爆破，见 [[web-generic-auth-proxy-history-unauth-user-all-leak]]（同类未鉴权的 `user/all`）。
- **接口粒度不一致导致的批量拉取**：把 `queryById` 换成 `list` 绕过鉴权，见 [[web-generic-auth-endpoint-granularity-unauth-list-bulk-pii]]。
- **按业务 ID 遍历 PII**：[[web-generic-auth-imid-userinfo-mobile-pii-enumeration]]、[[web-generic-auth-api-param-fuzz-idcard-pii-enumeration]]。
- **弱口令入口**：本例登录框用 `test/123456` 一类常见组合即可进入，本身也是既有弱口令手法的实例。

## 检测与防御

- **检测**：单账号短时间内以递增 id 访问用户详情接口的高频模式；响应体出现 `password` 字段（可在网关侧做响应脱敏规则与告警）；异常 UA/无 Referer 的批量请求。
- **防御**：用户对象序列化白名单，永不返回口令（连哈希也不行）；接口按「当前会话 = 目标用户」或明确的管理角色校验；分页与频率限制；口令使用强哈希（bcrypt/argon2）并禁止任何形式的回显。
