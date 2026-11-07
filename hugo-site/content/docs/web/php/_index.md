---
title: PHP Web
weight: 1
---

# PHP Web

## 这层是什么

PHP 反序列化、文件包含、RCE 与框架漏洞。

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

- [PHP 反序列化](deserialization/) —— POP 链、魔术方法、Phar 反序列化。
- [PHP 代码执行](rce/) —— 命令执行、代码执行、回调与绕过。
- [PHP 文件包含](file-inclusion/) —— LFI/RFI、伪协议、日志包含与临时文件。
- [PHP open_basedir 绕过](open-basedir-bypass/) —— open_basedir 限制绕过、伪协议、symlink、报错 oracle 与竞态。
- [PHP 框架](framework/) —— ThinkPHP、Laravel、Yii 等框架漏洞。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [.htaccess 关闭 PHP engine 导致目录内 PHP 源码被明文返回](web-php-htaccess-engine-off-source-disclosure/) | verified | high | 2026-11-05 |
| [Joomla 4 /api/index.php/v1/config/application?public=true 未授权泄露数据库账号口令（CVE-2023-23752）](web-php-joomla-api-config-application-public-db-credential-leak/) | verified | high | 2026-11-05 |
| [PHP Warning 提前输出导致 CSP 响应头失效](web-php-warning-header-already-sent-csp-bypass/) | verified | medium | 2026-11-05 |
| [PHP 数值前缀/宽松比较绕过：score=300abc 通过 >=300 校验](web-php-loose-numeric-prefix-score-bypass/) | verified | high | 2026-11-06 |
| [WordPress 配置与旧数据库备份泄露：phpass 破解历史账户并复用至宿主机 SSH](web-php-wordpress-backup-sql-phpass-credential/) | verified | high | 2026-11-05 |
| [源码隐藏参数：Unicode Bidi 控制符构造不可见 GET 参数名](web-php-unicode-bidi-hidden-get-parameter/) | verified | high | 2026-11-06 |
| [独角数卡 dujiaoka 管理员口令哈希复现：固定盐 + bcrypt 替换登录](web-php-dujiaoka-admin-password-hash-reproduce/) | draft | medium | 2026-11-06 |
| [禅道后台 backup/editor 控制器路径穿越与任意路径删除](web-php-zentao-backup-editor-arbitrary-file-delete/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
