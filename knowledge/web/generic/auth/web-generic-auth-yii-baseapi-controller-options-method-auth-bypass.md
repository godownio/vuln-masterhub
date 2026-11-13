---
id: web-generic-auth-yii-baseapi-controller-options-method-auth-bypass
title: Yii API BaseApiController::behaviors 把 OPTIONS 与免鉴权 action 并列：OPTIONS 请求绕过 authenticator 直接执行受保护 action 返回数据
type: scenario
domain: web
path: web/generic/auth
technique: yii-baseapi-options-method-auth-bypass
aliases:
- Yii OPTIONS 鉴权绕过
- BaseApiController behaviors 绕过
- OPTIONS 预检跳过认证
- notAuthAction 下划线连字符
- oa-api.php get-info
tags:
- php
- yii
- api
- auth-bypass
- options
- cors
- notAuthAction
- behaviors
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V522
  verified_at: '2026-11-11T13:21:57+08:00'
  notes: '已通读原文并逐张核对33张截图：图29 UserController 实际 $notAuthAction=[''auth'',''verify-url'']，注释写''用下划线形式，如get_info''但数组用连字符，原卡误称 notAuthAction 含 get_info，已修正为：getinfo→404、get-info→401、OPTIONS→200；图32 BaseApiController::behaviors 实际条件为 getMethod()==''OPTIONS'' || (hasProperty(''notAuthAction'') && (in_array(''*'',...) || in_array(action->id,...)))，已在卡中按截图改正；图31 GET /oa-api.php/v1/user/get-info?id=1 返回401（WWW-Authenticate: Bearer realm=\"api\"）；图33 OPTIONS 同一接口?id=2 返回200并回显 username/realname/gender/email/group=研发部/position=技术岗，与卡 PoC 一致；图28/30 确认 api/modules/v1/controllers 与 oa-api.php 入口。dedup 推荐 new，候选 web-generic-cors-options-preflight-authz-oracle 是 CORS 中间件 OPTIONS 预检造成的枚举 oracle，非 Yii behaviors 鉴权基类把 OPTIONS 当免鉴权执行 action，非同链；dup-scan.json 无涉及 pair。未实机复现。'
---

## 一句话结论

某 Yii OA 的 API 基类 `BaseApiController::behaviors()` 用 `if (Yii::$app->request->getMethod() == 'OPTIONS' || ($this->hasProperty('notAuthAction') && (in_array('*', $this->notAuthAction) || in_array($this->action->id, $this->notAuthAction))))` 决定是否跳过 `HttpBearerAuth` 认证；由于 Yii 对 OPTIONS 请求仍会正常路由并执行 action，未登录攻击者只要把受保护接口改成 `OPTIONS` 方法（如 `OPTIONS /oa-api.php/v1/user/get-info?id=2`），就能绕过 Bearer 认证拿到用户信息（同一路径 GET 返回 401）。

## 原理

- **behaviors 先于 action**：Yii 控制器在进入 action 前先执行 `behaviors()` 注册过滤器；该基类在 `parent::behaviors()` 基础上加了 CORS 过滤器，并用一个 `if` 判断：请求方法是 `OPTIONS`，或 action id 在 `notAuthAction` 里，就不注册 `authenticator`（`HttpBearerAuth`），否则注册。
- **OPTIONS 的条件写错**：`OPTIONS` 本应只是 CORS 预检，不应等同于“免鉴权”；但代码把它和 `notAuthAction` 放在同一个 `||` 条件里，导致任何 action 在 OPTIONS 方法下都不装认证过滤器。
- **Yii 不限制 action 的 HTTP 方法**：控制器没有 `verbs()` 限制时，Yii 对任意方法都会路由到同一个 `actionGetInfo()`；因此 `OPTIONS` 不是“只返回 Allow 头”的预检，而是真实执行了业务逻辑（读取 `id` 参数并返回用户数据）。
- **命名与路由的易混点**：代码注释宣称“不需要认证的方法，用下划线形式，如 `get_info`”，但实际 `$notAuthAction = ['auth','verify-url']` 用的是连字符；作者先试 `/v1/user/getinfo?id=1` 返回 404（路由不存在），再试 `/v1/user/get-info?id=1` 返回 401（路由存在但需要 Bearer 认证），最后把方法改为 OPTIONS 得到 200。OPTIONS 分支不依赖 `notAuthAction` 匹配，所以直接生效。
- **影响**：任意“需要 Bearer 认证”的 GET/查询类 action 都可能被 OPTIONS 调用读取数据，形成未授权访问/信息泄露；若 action 有副作用（修改、删除），还可能造成越权操作。

## 触发条件

- Yii（2.x）应用存在类似 `BaseApiController`，`behaviors()` 把 `OPTIONS` 与免鉴权 action 并列跳过认证。
- 目标 action 没有 `verbs()` 限制或允许 OPTIONS，且不自行校验用户身份。
- API 入口可访问（如 `/oa-api.php/v1/...`），路由能命中受保护 action。
- 前置 CORS/网关允许 OPTIONS 请求透传到应用。

## 利用步骤

1. 从入口文件确认 API 路由（如 `/web/oa-api.php`、模块 `v1`），并列出 controllers（`UserController`、`PropertyController` 等）与 action。
2. 先用正常方法请求受保护接口（如 `GET /oa-api.php/v1/user/get-info?id=1`；原文先试 `getinfo` 得到 404），确认返回 401 与 `WWW-Authenticate: Bearer realm="api"`。
3. 把方法改为 `OPTIONS` 重放同一 URL（`OPTIONS /oa-api.php/v1/user/get-info?id=2`）；若 behaviors 的 OPTIONS 分支生效，响应 200 并返回用户 JSON（username/realname/email/group 等）。
4. 对其它 action 重复（尤其是带 id/查询参数的读取接口）；必要时尝试 `POST`/`PUT` 是否有同样副作用，但注意只在授权范围验证。

## PoC

```http
OPTIONS /oa-api.php/v1/user/get-info?id=2 HTTP/1.1
Host: target
```

```text
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF-8
...
{"code":0,"message":"success","data":{"username":"...","realname":"...","email":"...","group":"研发部","position":"技术岗"}}
```

## 变体与关联

- 变体：若 `notAuthAction` 与 action id 命名不一致（注释说下划线、实际数组用连字符），普通请求会 404/401，但 OPTIONS 分支仍可绕过；审计时不要只盯 `notAuthAction` 拼写，先确认路由 action id 的实际形式。
- 变体：部分 Yii 应用支持 `X-HTTP-Method-Override`/`_method`，若网关允许，可把真实方法藏在请求头/参数里，进一步绕过“只允许 OPTIONS 之外的方法”的限制。
- 关联：[[web-generic-cors-options-preflight-authz-oracle]]（OPTIONS 预检导致鉴权缺失的枚举面）、[[web-generic-auth-hardcoded-token-handlebase-admin-bypass]]（另一类认证绕过）、[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]（同 Yii 生态的其他框架级问题）。
- 边界：应用在 action 内部再次校验用户/权限，或 `verbs()` 显式限制 GET/POST 时，OPTIONS 可能返回 405/不执行；前置 WAF 拦截 OPTIONS 时同样失效。

## 检测与防御

- 检测：访问日志中大量 `OPTIONS` 请求命中业务 action（而非 CORS 预检路径）、返回体包含业务数据；同一路径 GET 401/OPTIONS 200 的方法差异；`BaseApiController` 源码中出现 `getMethod() == 'OPTIONS'` 与鉴权条件混写。
- 防御：不要把 `OPTIONS` 视为免鉴权；CORS 预检由专门的 CORS 过滤器处理并只返回协议头，不执行 action；对每个 action 用 `verbs()` 限制允许的方法；在 `beforeAction`/action 内做二次权限校验。
- 加固：统一认证基类实现，OPTIONS 分支只允许返回 Allow/CORS 头；对 API 网关做方法白名单与异常方法审计。
