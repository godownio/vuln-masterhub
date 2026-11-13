---
id: web-generic-auth-yii-oa-withub-hardcoded-md5-token-arbitrary-login
title: Yii OA AuthController::actionWithub 硬编码密钥 + md5(username+key) token：伪造 token 未授权登录任意已存在用户
type: scenario
domain: web
path: web/generic/auth
technique: yii-oa-withub-hardcoded-md5-token-login
aliases:
- actionWithub
- /oa/auth/withub
- 硬编码密钥登录
- md5(username+key) token
- base64(user) token 登录
- Yii OA 任意用户登录
tags:
- php
- yii
- oa
- auth-bypass
- hardcoded-secret
- token-forgery
- md5
- base64
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V522
  verified_at: '2026-11-11T13:21:59+08:00'
  notes: 已通读原文并逐张核对33张截图：图24-25 AuthController 源码显示 $disableCsrfAction=['withub']、$ignoreList=['oa/auth/withub']、actionWithub 中 $user=base64_decode(request->get('user'))、$str=$user.$key、$result=strtolower(md5($str))、与 $token 相等且 UserIdentity::findByUsername(strtolower($user)) 存在则 login 并 redirect(main/index)，key 被厚码；图25 另有 actionTest 回显 base64_encode(name) 与 strtolower(md5(name.key))；图26 注释说明 user base64、token=md5(用户名+密钥) 32位小写（密钥行厚码）；图27 GET /oa/auth/withub?user=emhhbmdzYW4=&token=b336aa3ea64e703583bb7cbe6d924269 返回302并 Set-Cookie，登录成功；卡片未写入原文厚码的 key/token，PoC 用占位符，符合要求。dedup 推荐 new：JWT/3DES skey 候选签名方案不同；web-generic-auth-cookie-php-serialized-signature-forge 虽同为 md5(username+硬编码key) 原语，但载体是 base64(serialize) Cookie、sink 为受限页面而非 withub 登录 action，按库内'不同 sink/载荷不重复'先例非同链；dup-scan.json 无涉及 pair。未实机复现。
---

## 一句话结论

某 Yii OA 的免鉴权接口 `/oa/auth/withub` 用 `user`（用户名 base64）与 `token` 做登录校验：`token == strtolower(md5(base64_decode(user) . $key))`，其中 `$key` 是硬编码在 `AuthController` 里的约定密钥；拿到源码/密钥后即可为任意已存在用户（如 `zhangsan`）计算 token，未授权登录其账号。

## 原理

- **接口在 ignoreList 中**：`AuthController` 设置 `$disableCsrfAction = ['withub']`、`$ignoreList = ['oa/auth/withub']`，`actionWithub()` 不经过登录态校验，任何人都能访问。
- **token 生成方式不安全**：`$user = base64_decode($_GET['user'])`；`$str = $user . $key`；`$result = strtolower(md5($str))`；若 `$result == $_GET['token']` 且 `UserIdentity::findByUsername(strtolower($user))` 存在，就 `Yii::$app->user->login($user)` 并跳转主页。这里不是 HMAC，也没有时间戳/nonce/过期，`key` 直接硬编码在代码里，等于“公开的签名密钥”。
- **为什么能拿到 key**：源码审计/备份泄露/测试 action 都可能暴露——`actionTest($name)` 直接 `echo` 出 `base64_encode($name)` 与 `md5($name.$key)`，把密钥变成了可离线验证的签名 oracle（若可访问）；原文即在源码中看到硬编码 key 与注释说明。
- **用户名可枚举**：`user` 是 base64 明文，常见账号名（admin/zhangsan/lisi 等）可猜；接口只检查用户是否存在，不校验来源/密码，命中即可登录。
- **影响**：任意已存在用户的账号接管（含管理员），后续可访问 OA 全部业务数据；若该 OA 与域/SSO 打通，还可能横向。

## 触发条件

- 目标为使用该 `withub` 登录接口的 Yii OA 系统（原文未公开产品名）。
- 攻击者能获得硬编码 `$key`（源码审计、源码泄露、备份、测试 action 回显等）。
- 目标存在已知/可猜测的用户名。
- `/oa/auth/withub` 可从攻击网络访问，且前置网关未拦截。

## 利用步骤

1. 审计/获取源码：在 `AuthController::actionWithub` 找到硬编码 `$key`；若 `actionTest` 可访问，直接请求 `?name=zhangsan` 获得 `user=base64(zhangsan)` 与对应 `token`（等同拿到签名能力）。
2. 选择目标用户名（如 `zhangsan`），计算 `user = base64(username)`、`token = strtolower(md5(username . key))`。
3. 发送 `GET /oa/auth/withub?user=<base64>&token=<md5>`；服务端比较通过且用户存在时返回 302 并 `Set-Cookie` 登录态。
4. 携带返回的 Cookie 访问 `/oa/main/index` 等后台页面，确认已登录目标用户。

## PoC

```text
# 已知 key（源码审计获得）时：
user  = base64("zhangsan")            # emhhbmdzYW4=
token = lowercase(md5("zhangsan" + key))
```

```http
GET /oa/auth/withub?user=emhhbmdzYW4=&token=<lowercase_md5_of_username_plus_key> HTTP/1.1
Host: target
```

## 变体与关联

- 变体：`actionTest` 若可访问会直接回显 `user` 和 `token`，无需自行计算；也可用其验证 key 是否正确。
- 变体：密钥泄漏途径包括源码仓库、`.git`/备份文件、错误页、前端 JS/配置导出；同类设计还有 `md5(user+固定salt)`、`md5(uid+secret)` 等，均可伪造。
- 关联：[[web-generic-auth-hardcoded-token-handlebase-admin-bypass]]（硬编码 token 直接放行的另一种实现）、[[web-python-framework-astrbot-cve-2025-55449-hardcoded-jwt-plugin-upload-rce]]（硬编码 JWT 密钥伪造 token 的跨语言同类问题）、[[pentest-recon-js-hardcoded-secret-entropy-vocabulary-scan]]（找硬编码密钥的侦察方法）。
- 边界：若 key 已轮换且无法获取、接口加了 IP 白名单/时间戳/签名算法升级（HMAC+nonce），伪造失败；用户不存在时也会跳回登录页。

## 检测与防御

- 检测：`/oa/auth/withub` 出现 base64 形式的 user 参数与 32 位十六进制 token；同一 IP 对多个 username 尝试；非正常登录时间/来源的成功登录日志；源码中出现 `md5($user . $key)` 与硬编码常量。
- 防御：删除/下线该 `withub` 接口或改为标准登录（密码/OAuth）；如必须保留，使用 HMAC-SHA256 + 每用户独立密钥 + 时间戳/nonce + 过期时间，密钥放配置/密钥管理而非源码；移除 `actionTest` 等调试接口；对 username 做来源与频率限制。
- 加固：全量审计 `ignoreList`/`disableCsrfAction` 中的免鉴权接口；对登录类接口做签名校验与重放防护；定期轮换密钥并监控异常登录。
