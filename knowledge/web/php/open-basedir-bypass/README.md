# PHP open_basedir 绕过

## 这层是什么

open_basedir 限制绕过、伪协议、symlink、报错 oracle 与竞态。

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
| [Apache 2.4.13+ ErrorDocument 表达式 %{file:} 读取任意文件（无视 PHP open_basedir）](web-php-open-basedir-bypass-apache-errordocument-file-read.md) | verified | high | 2026-11-05 |
| [Caddy Admin API 127.0.0.1:2019 未授权配置改写：新增 file_server route 读任意文件绕过 PHP open_basedir](web-php-open-basedir-bypass-caddy-admin-api-file-server-read.md) | verified | high | 2026-11-06 |
| [PHP 8.3 curl 扩展 open_basedir 绕过：CURLOPT_PROTOCOLS_STR 设为 all 读取任意文件](web-php-open-basedir-bypass-curl-protocols-all.md) | verified | high | 2026-11-05 |
| [PHP getcwd() 失败竞态绕过 open_basedir（MAXPATHLEN 溢出 + 目录重命名）](web-php-open-basedir-bypass-getcwd-race.md) | verified | high | 2026-11-05 |
| [PHP open_basedir 经典绕过：命令函数、glob://、symlink、ini_set 与报错 oracle](web-php-open-basedir-bypass-classic-methods.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
