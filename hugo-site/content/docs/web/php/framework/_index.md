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
| [FrankenPHP splitPos 大小写折叠长度差：KK.txt.php 被解析为执行 KK.txt 的 PHP 脚本](web-php-frankenphp-splitpos-unicode-casefold-path-differential/) | verified | high | 2026-11-06 |
| [Laravel Ignition debug 模式 RCE：日志写入 PHAR + php://filter 解码（CVE-2021-3129）](web-php-framework-laravel-ignition-debug-log-phar-rce/) | verified | high | 2026-11-05 |
| [Laravel Livewire CVE-2025-54068：快照校验缺陷导致未授权 PHP 对象注入 RCE](web-php-framework-livewire-cve-2025-54068-snapshot-hydration-rce/) | verified | high | 2026-11-05 |
| [ThinkPHP 5.x RCE：invokefunction 任意函数调用与 captcha _method=__construct 过滤器注入](web-php-framework-thinkphp-5x-invokefunction-captcha-rce/) | verified | medium | 2026-11-06 |
| [ThinkPHP View::display 模板源拼接注入：{$Request.get.f|$Request.get.c} 绕过黑名单执行 system](web-php-framework-thinkphp-view-display-template-source-injection/) | verified | high | 2026-11-06 |
| [Yii2 UploadedFile::saveAs 不做校验：客户端文件名直入保存路径导致任意脚本上传](web-php-framework-yii2-uploadedfile-saveas-unfiltered/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
