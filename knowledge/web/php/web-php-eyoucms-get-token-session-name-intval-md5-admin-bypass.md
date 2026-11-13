---
id: web-php-eyoucms-get-token-session-name-intval-md5-admin-bypass
title: eyoucms 任意用户登录：get_token 可控 session 键名 + intval(md5) 弱类型绕过后台鉴权，改模板 getshell
type: scenario
domain: web
path: web/php
technique: eyoucms-get-token-session-key-injection-intval-md5-bypass
aliases:
- eyoucms 任意用户登录
- eyoucms get_token
- Session::set 键名可控
- intval(md5) 绕过
- admin_login_expire
- admin_info.role_id
- 后台模板写 shell
- eyoucms 后台登录绕过
tags:
- php
- eyoucms
- thinkphp
- session
- session-injection
- type-juggling
- auth-bypass
- template
- getshell
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V666
  verified_at: '2026-11-13T08:48:47+08:00'
  notes: 已对照原文52图核对并经复核修正：intval 超管分支仅在 role_id 为字母开头 md5（intval=0）时成立，数字开头会落入权限检查；待验证点补充目标仪表盘当前版本 v1.5.1（环境版本，未设 affected_versions）与案例 /eyoucms/ 部署路径。核心两段代码（Base.php 登录过期判断、check_priv 0>=intval(role_id)）与截图逐字一致；exp 输出 admin_id/PHPSESSID/Max-Age=3600 与模板管理、蚁剑连 WWW 均有截图。待验证：完整 exp 源码与 get_token 具体路由/参数绑定需按目标版本复核。
---

# 一句话结论

eyoucms 的 `/api/Ajax/get_token` 把请求参数 `name` 原样当作 session 键名，值为 `md5($_SERVER['REQUEST_TIME_FLOAT'])` 并回显；攻击者可借此任意写入 `admin_id`、`admin_login_expire`、`admin_info.role_id` 等后台鉴权所用 session 键，并利用 `intval(md5(...))` 的弱类型结果（字母开头为 0、数字开头可得到超大数）同时绕过“登录过期”与“role_id<=0 即超管”两个判断，无需口令进入后台；再通过后台模板管理编辑首页模板写入 PHP 代码，访问后获得 webshell（案例蚁剑连接、列出 WWW 目录）。

# 原理

- **入口：get_token 把用户输入当 session 键**。`application/api/controller/Ajax.php` 的 `get_token($name='__token__')` 在 AJAX 请求下直接 `echo $this->request->token($name)`；ThinkPHP `Request::token($name,$type='md5')` 生成 `$token = md5($_SERVER['REQUEST_TIME_FLOAT'])`，执行 `Session::set($name, $token)` 并返回/回显 token。攻击者控制 `name`（session 键）且从响应中得知写入值——于是能向当前会话写入任意键值对。
- **后台鉴权读取这些 session 键**。`application/admin/controller/Base.php` 的登录判断为：`if (session('admin_id') && getTime() - intval(session('admin_login_expire')) < $_web_login_expiretime) { session('admin_login_expire', getTime()); $this->check_priv(); }`——只要 `admin_id` 为真、且当前时间减去 `intval(admin_login_expire)` 小于过期时长（案例 3600 秒）就进入权限检测。`intval(md5字符串)` 的 PHP 弱类型结果：md5 以字母开头时为 0（差值为当前时间戳，条件不满足）；以数字开头时取前导数字，可能大于 `getTime()`（差值为负，条件满足）。攻击者反复调用 get_token 换不同时间戳的 md5，直到拿到满足条件的值（文章改版 get_token 直接回显 `getTime() - intval($token)` 便于筛选）。
- **超管判断同样被 intval 绕过**。`check_priv()` 开头 `if (0 >= intval(session('admin_info.role_id'))) { return true; }`——role_id 存的是字母开头的 md5 字符串时 `intval` 为 0，`0 >= 0` 成立，直接按超级管理员放行，不再检查具体权限；若 md5 以数字开头则 `intval > 0`，会落入后续权限检查分支，故需挑选字母开头的 md5。
- **完整链**：同一 PHPSESSID 下依次写入 `admin_id`（任意 md5）、`admin_login_expire`（满足过期差值的 md5）、`admin_info.role_id`（字母开头的 md5 → intval 0），随后带该会话访问 `/login.php?s=/Admin/...` 即已登录后台（文章 exp 的 `setCookie/setExpire/setRoleID/CheckLogin` 即这几步，输出中可见 `admin_id[+]`、`PHPSESSID`、`expires ... Max-Age=3600`）。
- **后台模板 getshell**：后台“模板管理”可直接编辑站点模板文件（案例模板目录下 footer.htm/header.htm/index.htm 等），在首页模板中写入 PHP 代码；ThinkPHP 模板编译后访问首页即执行，案例用蚁剑连接成功列出 `C:\phpstudy_pro\WWW` 目录。

# 触发条件

- 目标为 eyoucms（存在 `api/Ajax/get_token` 暴露 `name` 参数的版本），未登录可访问该接口；`IS_AJAX` 校验可用 `X-Requested-With: XMLHttpRequest` 满足。
- 会话由 cookie（PHPSESSID）标识且 get_token 与后台共用同一 session 存储；攻击者能在多次请求间保持同一会话。
- 后台登录判断与超管判断使用 `intval(session(...))` 弱类型比较（案例代码），且 `admin_id` 只判断真值。
- 后台模板管理可编辑模板文件，模板引擎允许模板内 PHP 执行（默认 ThinkPHP 模板编译）。
- 攻击者能访问后台路由（案例 `/login.php?s=/Admin/login`）。

# 利用步骤

1. 目录扫描识别 eyoucms 与后台入口（案例 `/admin`、`/login.php?s=/Admin/login`）。
2. 固定一个 PHPSESSID（或从首次响应获取），带 `X-Requested-With: XMLHttpRequest` 请求 `?s=/api/Ajax/get_token&name=admin_id`，把返回的 md5 写入 session。
3. 反复请求 `?s=/api/Ajax/get_token&name=admin_login_expire`，用返回的 md5 计算 `getTime()-intval(md5)`（或按改版接口直接返回差值），直到差值 < 3600 秒，使过期判断通过。
4. 请求 `?s=/api/Ajax/get_token&name=admin_info.role_id`，取字母开头（intval=0）的 md5，使 role_id 判断落入 `<=0` 超管分支。
5. 带同一 PHPSESSID 访问后台首页（案例 `/login.php?s=/Admin/Index/index`），确认已登录（案例仪表盘、服务器信息页）。
6. 进入模板管理，编辑首页模板写入 PHP 一句话/蚁剑马并保存；访问站点首页触发模板编译执行，用蚁剑连接 webshell（案例成功浏览 `C:\phpstudy_pro\WWW`）。

# PoC

```http
# 1) 写入 admin_id（全程保持同一 PHPSESSID）
GET /index.php?s=/api/Ajax/get_token&name=admin_id HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<固定会话>

# 2) 写入超管 role_id（取 intval=0 的 md5）
GET /index.php?s=/api/Ajax/get_token&name=admin_info.role_id HTTP/1.1
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<固定会话>

# 3) 多次请求 admin_login_expire，直到 getTime()-intval(md5) < 3600
GET /index.php?s=/api/Ajax/get_token&name=admin_login_expire HTTP/1.1
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<固定会话>

# 4) 访问后台（已登录）
GET /login.php?s=/Admin/Index/index HTTP/1.1
Cookie: PHPSESSID=<固定会话>
```

# 变体与关联

- 与库内 `web-php-rce-joomla-admin-template-editor-webshell`、DedeCMS 模板/文件管理类卡的关系：那些是“已取得后台后模板写 shell”；本卡的入口是 eyoucms **session 键名可控 + intval 弱类型**，可无口令直接进后台。
- 与 `web/generic/auth` 下“服务端按客户端可控字段签发会话”类卡（如登录重定向按 username 签发 session）同属身份信任缺陷；本卡新增两个要素：session 键名本身可控、鉴权值用 intval 弱类型比较。
- 变体：`get_token` 可写任意 session 键（案例还观察到 `home_lang`、`admin_lang` 等），可影响依赖 session 的其它逻辑；后台模板写入也可替换为上传插件、改配置等其它后台能力。
- 若目标对 `name` 做白名单、改用严格类型比较（===/强转校验）或模板禁 PHP，则该链失效。

# 检测与防御

- 修复 `get_token`：`name` 只允许固定键（如 `__token__`），禁止用用户输入作为 `Session::set` 的键；token 不作为鉴权凭据、不应回显给前端。
- 后台鉴权使用服务端可信数据（数据库中的管理员记录/签名会话），不要用 `intval(session(...))` 弱类型比较 role_id/过期时间；`admin_id` 需与真实账号绑定。
- 模板管理限制可编辑文件类型与目录，禁止模板内 PHP 执行，模板目录不可写；后台路径加认证网关。
- 检测：`/api/Ajax/get_token` 被高频请求且 `name` 含 `admin_`/`role`/`expire`；同一 PHPSESSID 无登录记录直接访问后台；模板文件被修改并出现 `<?php` 代码；后台仪表盘出现异常登录（无对应认证日志）。

# 待验证点

- 文章未给出完整 exp 源码与受影响版本区间；后台仪表盘截图显示目标“当前版本 v1.5.1”（仅为目标环境版本，不作为 affected_versions）。接口路由 `?s=/api/Ajax/get_token`、参数传递方式与 `intval(md5)` 筛选细节按文章代码片段与 exp 输出（admin_id/PHPSESSID/expires）归纳，且案例站点部署在 `/eyoucms/` 子目录，需按目标实际版本与部署路径复核。后台模板写 shell 的落地路径与蚁剑连接在文章中已展示成功。
