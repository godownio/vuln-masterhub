# CRLF 注入

## 这层是什么

响应头注入、日志注入与缓存组合。

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
| [CFITSIO EFS URL Path 换行注入 HTTP 请求头](web-generic-crlf-cfitsio-efs-http-request-header-injection.md) | verified | high | 2026-11-05 |
| [Nginx error_page 302 Location 拼接 $uri 未过滤：CRLF 注入 Set-Cookie 覆盖会话](web-generic-crlf-nginx-uri-location-set-cookie.md) | verified | high | 2026-11-05 |
| [php-memcached <2.2.0 键名 CRLF 注入：用户可控 key 拼进 Memcached 文本协议，NUL 截断 + 换行注入 set 篡改缓存](web-generic-crlf-php-memcached-key-injection.md) | verified | high | 2026-11-11 |
| [反馈接口邮件 Subject 头 CRLF 注入伪造 From: admin，配合发件人过滤与域名白名单 SSRF、SQLi 回显 SSTI 打通 RCE](web-generic-crlf-smtp-header-injection-forged-from.md) | draft | high | 2026-11-08 |
| [应用把用户输入拼进 RESP 命令写 Redis，WAF 变长替换（admin→hacker）打乱 $len 长度字段：CRLF 注入整条 SET 改写 role 为 admin](web-generic-crlf-redis-resp-length-shift-waf-bypass-role-escalation.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
