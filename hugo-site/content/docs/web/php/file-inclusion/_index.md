---
title: PHP 文件包含
weight: 1
---

# PHP 文件包含

## 这层是什么

LFI/RFI、伪协议、日志包含与临时文件。

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
| [.htaccess auto_append_file 自包含执行注释内 PHP 并容忍尾随脏字符](web-php-file-inclusion-htaccess-self-include-dirty-bypass/) | verified | high | 2026-11-05 |
| [.htaccess auto_prepend_file + php://filter base64-decode：把 base64 图片当 PHP 预包含执行](web-php-file-inclusion-htaccess-auto-prepend-base64-filter/) | verified | high | 2026-11-06 |
| [.htaccess If 表达式盲读：ErrorDocument 404 作为 file('/flag') 前缀匹配 oracle 逐字符爆破](web-php-file-inclusion-htaccess-if-errordocument-blind-read/) | verified | high | 2026-11-06 |
| [.user.ini auto_prepend_file 包含上传文件实现 PHP-FPM RCE](web-php-file-inclusion-user-ini-auto-prepend-rce/) | verified | high | 2026-11-05 |
| [.user.ini 改写 session.save_path 把可控 Session 文件写入 Web 目录](web-php-file-inclusion-user-ini-session-save-path-webshell/) | verified | medium | 2026-11-05 |
| [.user.ini 时区配置报错写 shell：date.timezone 注入 error_log](web-php-file-inclusion-user-ini-timezone-error-log-webshell/) | verified | high | 2026-11-06 |
| [Fastadmin lang 参数路径穿越读 database 配置：连库查 fa_admin_log 找后台入口并替换管理员密文登录](web-php-file-inclusion-fastadmin-lang-traversal-database-admin-takeover/) | verified | high | 2026-11-07 |
| [iconv UTF-7//IGNORE 脏字节夹在关键词中绕过 WAF 后读取任意文件](web-php-file-inclusion-iconv-ignore-dirty-byte-waf-bypass/) | verified | high | 2026-11-05 |
| [ISO-2022-CN-EXT 状态机吞字节绕过路径黑名单：iconv //IGNORE 归一化还原 ../ 路径](web-php-file-inclusion-iso2022cn-ext-state-machine-blacklist-bypass/) | verified | medium | 2026-11-06 |
| [JSON 预览服务两阶段文件读取：前缀校验路径穿越读源码 + .tmp 内容二次解析 php://filter 绕过 scheme 黑名单](web-php-file-inclusion-json-preview-tmp-uri-php-filter-scheme-bypass/) | verified | high | 2026-11-06 |
| [LFI 包含 pearcmd.php：register_argc_argv 查询串注入 config-create 写 Webshell](web-php-file-inclusion-pearcmd-argv-config-create-webshell/) | verified | high | 2026-11-05 |
| [LFI 包含 Web 访问日志 getshell：把 PHP 代码写进 User-Agent 或请求行](web-php-file-inclusion-access-log-poisoning-webshell/) | verified | high | 2026-11-05 |
| [MaxSite CMS require-maxsite 路由：Base64 路径包含泄露更新密钥与源码](web-php-maxsite-require-route-base64-include-key-leak/) | verified | medium | 2026-11-06 |
| [PHP data:// 伪协议包含 + 短标签：allow_url_include 开启时 LFI 直接执行内联 PHP](web-php-file-inclusion-data-wrapper-short-tag-rce/) | verified | medium | 2026-11-06 |
| [PHP filter chain + CP037 编码绕过：convert.iconv.ASCII.CP037 隐藏 base64/flag 关键字，双重 URL 编码过黑名单](web-php-file-inclusion-filter-chain-cp037-double-urlencode/) | verified | high | 2026-11-06 |
| [PHP Filter Chain 从空流生成任意字节实现无文件包含 RCE](web-php-file-inclusion-filter-chain-fileless-rce/) | verified | high | 2026-11-05 |
| [PHP include 白名单校验与执行变量不一致：FileGuard 只校验](web-php-file-inclusion-fileguard-check-use-mismatch-hash-truncation/) | verified | medium | 2026-11-06 |
| [PHP LFI 读取 /dev/fd 已打开文件描述符绕过路径长度限制](web-php-file-inclusion-proc-self-fd-open-handle-read/) | verified | high | 2026-11-06 |
| [PHP Session 文件包含：应用把 POST 参数写入 $_SESSION 后 LFI 包含 sess_<PHPSESSID> 执行代码](web-php-file-inclusion-session-poisoning-sess-file/) | draft | medium | 2026-11-07 |
| [PHP 错误日志投毒将恶意代码写入 Web 目录实现 RCE](web-php-file-inclusion-php-error-log-poisoning-webshell/) | verified | high | 2026-11-05 |
| [php://filter chain 写文件：file_put_contents(file_get_contents) 把生成内容落到 eval.php](web-php-file-inclusion-filter-chain-file-write-webshell/) | verified | high | 2026-11-06 |
| [php://filter 只校验 resource 值不校验完整 wrapper：resource=index.php 通过检查后包含整个 filter URL 读源码](web-php-file-inclusion-php-filter-resource-check-bypass/) | verified | high | 2026-11-07 |
| [php://filter 在 filter 与 resource 之间插入编码过滤器，绕过 ter/res 关键字黑名单读源码](web-php-file-inclusion-php-filter-insert-bypass/) | verified | high | 2026-11-05 |
| [RewriteRule 前缀绕过 + 插件标记行：恢复被禁用的上传并包含 PHP](web-php-file-inclusion-addon-manager-rewrite-marker-bypass/) | verified | high | 2026-11-05 |
| [ThinkPHP 5.0.x view() 模板路径可控导致文件包含 RCE](web-php-file-inclusion-thinkphp-view-template/) | verified | high | 2026-11-04 |
| [WordPress get_page_template 页面模板路径遍历未授权 LFI（CVE-2026-87902）](web-php-file-inclusion-wordpress-page-template-path-traversal/) | verified | high | 2026-11-05 |
| [WordPress LatePoint <5.1.94 layout 参数本地文件包含（CVE-2025-6715）：set_layout 无条件信任请求参数，render 拼接 include](web-php-file-inclusion-latepoint-layout-cve-2025-6715/) | verified | high | 2026-11-07 |
| [主题包预览 include preview.tpl 导致 PHP RCE；再利用 ctf 组可写的 root 维护脚本提权读 flag](web-php-file-inclusion-theme-preview-tpl-rce-root-cron/) | verified | high | 2026-11-06 |
| [强制拼接 .php 后缀的 include 绕过：zip:// 包内条目吸收后缀执行压缩包木马](web-php-file-inclusion-zip-wrapper-forced-suffix/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
