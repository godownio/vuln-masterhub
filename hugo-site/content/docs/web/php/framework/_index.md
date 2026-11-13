---
title: PHP 框架
weight: 1
---

# PHP 框架

## 这层是什么

ThinkPHP、Laravel、Yii 等框架漏洞。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CMS Made Simple 链式利用：CVE-2019-9053 SQL 注入取回 pwreset token 重置管理员口令，再由设计师权限用 Smarty {function name=} 注入 RCE](web-php-framework-cmsms-sqli-pwreset-token-smarty-function-rce/) | verified | medium | 2026-11-08 |
| [Discuz! X3.5 utility/convert 配置导入把可控数组键写回 PHP 配置文件导致代码执行](web-php-discuz-utility-convert-saveconfig-key-injection-webshell/) | draft | low | 2026-11-09 |
| [DolphinPHP 后台行为管理日志规则注入：call_user_func 回调任意函数 RCE（v1.5.0；v1.5.1 黑名单可绕过）](web-php-framework-dolphinphp-action-log-rule-call-user-func-rce/) | verified | high | 2026-11-08 |
| [FrankenPHP splitPos 大小写折叠长度差：KK.txt.php 被解析为执行 KK.txt 的 PHP 脚本](web-php-frankenphp-splitpos-unicode-casefold-path-differential/) | verified | high | 2026-11-06 |
| [Joomla 3.7 com_fields 未授权 SQL 注入：list[fullordering] 直接拼进 ORDER BY，用 extractvalue/updatexml 报错注入取 users 表哈希再爆破进后台](web-php-framework-joomla-com-fields-fullordering-unauth-sqli/) | verified | high | 2026-11-08 |
| [Laravel Ignition debug 模式 RCE：日志写入 PHAR + php://filter 解码（CVE-2021-3129）](web-php-framework-laravel-ignition-debug-log-phar-rce/) | verified | high | 2026-11-05 |
| [Laravel Livewire CVE-2025-54068：快照校验缺陷导致未授权 PHP 对象注入 RCE](web-php-framework-livewire-cve-2025-54068-snapshot-hydration-rce/) | verified | high | 2026-11-05 |
| [ThinkPHP 3.2.x assign 数组变量覆盖 _filename：ParseTemplateBehavior → File::load 的 extract(EXTR_OVERWRITE) 把模板 include 改成任意文件，配 runtime 日志投毒/上传 getshell](web-php-framework-thinkphp32-assign-filename-extract-overwrite-include/) | verified | high | 2026-11-13 |
| [ThinkPHP 3.2.x cache 选项覆盖模板缓存 RCE：cid[cache][key]/[temp] 让 S() 写入 ParseTemplateBehavior 待 include 的 md5 缓存文件](web-php-framework-thinkphp32-cache-option-template-cache-include-rce/) | verified | medium | 2026-11-09 |
| [ThinkPHP 5.0.15 invokefunction 写 WebShell：call_user_func_array 调 file_put_contents + 三次 URL 解码蚁剑编码器](web-php-framework-thinkphp-invokefunction-file-put-contents-webshell/) | verified | high | 2026-11-07 |
| [ThinkPHP 5.x RCE：invokefunction 任意函数调用与 captcha _method=__construct 过滤器注入](web-php-framework-thinkphp-5x-invokefunction-captcha-rce/) | verified | medium | 2026-11-06 |
| [ThinkPHP app_debug 开启且 runtime/log 可直读：按日期遍历日志泄露 SQL、请求参数与数据库连接信息](web-php-framework-thinkphp-runtime-log-web-exposure-app-debug/) | verified | high | 2026-11-13 |
| [ThinkPHP fetchSql(true) 生成的未参数化 SQL 被 UNION 拼接：where 数组条件演变为 SQL 注入](web-php-framework-thinkphp-fetchsql-union-where-sqli/) | verified | high | 2026-11-11 |
| [ThinkPHP View::display 模板源拼接注入：{$Request.get.f|$Request.get.c} 绕过黑名单执行 system](web-php-framework-thinkphp-view-display-template-source-injection/) | verified | high | 2026-11-06 |
| [ThinkPHP 调试页 + 单引号 SQL 报错：Whoops 环境变量泄露数据库账号口令与绝对路径](web-php-framework-thinkphp-debug-sql-error-env-credential-leak/) | verified | medium | 2026-11-07 |
| [Yii OA SaveUpload::saveFile 扩展名白名单被整段注释 + 依赖忽略路由未授权：/salary/record/upload 等接口任意 PHP 上传 getshell](web-php-framework-yii-oa-saveupload-commented-extension-unauth-upload/) | verified | high | 2026-11-11 |
| [Yii2 UploadedFile::saveAs 不做校验：客户端文件名直入保存路径导致任意脚本上传](web-php-framework-yii2-uploadedfile-saveas-unfiltered/) | verified | high | 2026-11-05 |
| [主机上有可执行的 drush 时直接重置 Drupal 管理员口令进后台；Drupal 8 已移除 PHP filter，需先从官方源装 php 模块再在内容里写一句话](web-php-framework-drupal-drush-reset-password-php-filter-module-webshell/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
