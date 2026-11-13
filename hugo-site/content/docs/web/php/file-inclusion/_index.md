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
| [Apache mod_log_rotate 轮转日志文件名预测 + LFI 日志包含：access.log.<当日08:00时间戳> 请求行投毒 getshell](web-php-file-inclusion-apache-mod-log-rotate-timestamp-log-poisoning/) | verified | high | 2026-11-08 |
| [Fastadmin lang 参数路径穿越读 database 配置：连库查 fa_admin_log 找后台入口并替换管理员密文登录](web-php-file-inclusion-fastadmin-lang-traversal-database-admin-takeover/) | verified | high | 2026-11-07 |
| [H3C 网管系统 .mds 路由 sys_corefile_sysinfo_download：file_name 直拼 /mnt/ 前缀、../ 穿越 file_get_contents 任意文件读取](web-php-file-inclusion-h3c-mds-syscorefile-filename-traversal-read/) | verified | high | 2026-11-11 |
| [iconv UTF-7//IGNORE 脏字节夹在关键词中绕过 WAF 后读取任意文件](web-php-file-inclusion-iconv-ignore-dirty-byte-waf-bypass/) | verified | high | 2026-11-05 |
| [include($path) 黑名单漏掉 php://filter：用 filter chain 在包含点执行 echo base64|base64 -d > shell.php 落 webshell](web-php-file-inclusion-filter-chain-exec-write-webshell/) | verified | medium | 2026-11-09 |
| [ISO-2022-CN-EXT 状态机吞字节绕过路径黑名单：iconv //IGNORE 归一化还原 ../ 路径](web-php-file-inclusion-iso2022cn-ext-state-machine-blacklist-bypass/) | verified | medium | 2026-11-06 |
| [JSON 预览服务两阶段文件读取：前缀校验路径穿越读源码 + .tmp 内容二次解析 php://filter 绕过 scheme 黑名单](web-php-file-inclusion-json-preview-tmp-uri-php-filter-scheme-bypass/) | verified | high | 2026-11-06 |
| [LFI 包含 pearcmd.php：register_argc_argv 查询串注入 config-create 写 Webshell](web-php-file-inclusion-pearcmd-argv-config-create-webshell/) | verified | high | 2026-11-05 |
| [LFI 包含 Web 访问日志 getshell：把 PHP 代码写进 User-Agent 或请求行](web-php-file-inclusion-access-log-poisoning-webshell/) | verified | high | 2026-11-05 |
| [LFI 黑名单扫原始串、`php://filter` 包含时再解码一次：只把关键字里一个字符写成 `%25XX` 即可穿过长篇黑名单](web-php-file-inclusion-filter-name-partial-urlencode-bypass/) | verified | medium | 2026-11-09 |
| [MaxSite CMS require-maxsite 路由：Base64 路径包含泄露更新密钥与源码](web-php-maxsite-require-route-base64-include-key-leak/) | verified | medium | 2026-11-06 |
| [PHP data:// 伪协议包含 + 短标签：allow_url_include 开启时 LFI 直接执行内联 PHP](web-php-file-inclusion-data-wrapper-short-tag-rce/) | verified | medium | 2026-11-06 |
| [PHP filter chain + CP037 编码绕过：convert.iconv.ASCII.CP037 隐藏 base64/flag 关键字，双重 URL 编码过黑名单](web-php-file-inclusion-filter-chain-cp037-double-urlencode/) | verified | high | 2026-11-06 |
| [PHP Filter Chain 从空流生成任意字节实现无文件包含 RCE](web-php-file-inclusion-filter-chain-fileless-rce/) | verified | high | 2026-11-05 |
| [PHP include 白名单校验与执行变量不一致：FileGuard 只校验](web-php-file-inclusion-fileguard-check-use-mismatch-hash-truncation/) | verified | medium | 2026-11-06 |
| [PHP LFI 读取 /dev/fd 已打开文件描述符绕过路径长度限制](web-php-file-inclusion-proc-self-fd-open-handle-read/) | verified | high | 2026-11-06 |
| [PHP Session 文件包含：应用把 POST 参数写入 $_SESSION 后 LFI 包含 sess_<PHPSESSID> 执行代码](web-php-file-inclusion-session-poisoning-sess-file/) | verified | medium | 2026-11-07 |
| [PHP 文件包含 `../` 被单次替换 → `....//` 双写绕过读源码，再逐层把 eval 改 echo 脱混淆取一句话木马密码拿 RCE](web-php-file-inclusion-doublewrite-lfi-eval-chain-webshell/) | verified | medium | 2026-11-08 |
| [PHP 编辑器 file_get_contents("uploads/$file")：../ 穿越读取任意文件](web-php-file-inclusion-editor-file-get-contents-uploads-prefix-traversal/) | verified | high | 2026-11-08 |
| [PHP 错误日志投毒将恶意代码写入 Web 目录实现 RCE](web-php-file-inclusion-php-error-log-poisoning-webshell/) | verified | high | 2026-11-05 |
| [php://filter chain 写文件：file_put_contents(file_get_contents) 把生成内容落到 eval.php](web-php-file-inclusion-filter-chain-file-write-webshell/) | verified | high | 2026-11-06 |
| [php://filter 只校验 resource 值不校验完整 wrapper：resource=index.php 通过检查后包含整个 filter URL 读源码](web-php-file-inclusion-php-filter-resource-check-bypass/) | verified | high | 2026-11-07 |
| [php://filter 在 filter 与 resource 之间插入编码过滤器，绕过 ter/res 关键字黑名单读源码](web-php-file-inclusion-php-filter-insert-bypass/) | verified | high | 2026-11-05 |
| [php://filter 桶队尺寸控制：zlib.inflate 生成多桶 + dechunk 每桶前置尺寸与零填充，使 0x100 等指定大小的 bucket 按需出现](web-php-file-inclusion-php-filter-bucket-brigade-dechunk-sizing/) | verified | medium | 2026-11-09 |
| [PHP_SESSION_UPLOAD_PROGRESS + LFI 条件竞争：把 payload 写进 session 文件并包含 getshell](web-php-file-inclusion-session-upload-progress-lfi-shell/) | verified | high | 2026-11-08 |
| [RewriteRule 前缀绕过 + 插件标记行：恢复被禁用的上传并包含 PHP](web-php-file-inclusion-addon-manager-rewrite-marker-bypass/) | verified | high | 2026-11-05 |
| [robots.txt 绝对路径 + img.php LFI 读后台凭据，页面注释泄露 cmd 参数 RCE](web-php-file-inclusion-robots-absolute-path-credentials-comment-rce/) | verified | high | 2026-11-08 |
| [ShirneCMS UEditor action=proxy source 伪协议任意文件读取（CVE-2022-37299）→ config/database.php 凭据 → phpMyAdmin/后台 → 模板写入与包含 getshell](web-php-file-inclusion-shirnecms-cve-2022-37299-ueditor-file-read-to-admin-shell/) | verified | medium | 2026-11-13 |
| [ThinkPHP 5.0.x view() 模板路径可控导致文件包含 RCE](web-php-file-inclusion-thinkphp-view-template/) | verified | high | 2026-11-04 |
| [ThinkPHP ≤6.0.13 开启多语言后 LoadLangPack 用 get/header/cookie 的 lang 参数拼路径并 include：目录穿越包含任意文件，配 pearcmd 达成 RCE（CVE-2022-47945）](web-php-file-inclusion-thinkphp6-loadlangpack-detect-var-traversal-include/) | verified | high | 2026-11-08 |
| [URL 域名安全校验对本地路径失效：url=D:/1.txt 直入 file_get_contents 任意文件读取](web-php-file-inclusion-url-domain-check-local-path-bypass/) | verified | high | 2026-11-08 |
| [WeiPHP 3.0 前台 RCE：UEditor scrawlUp 涂鸦上传图片马 + Forum 控制器 temp 模板包含](web-php-file-inclusion-weiphp3-ueditor-scrawlup-template-include/) | verified | medium | 2026-11-12 |
| [WeiPHP 5.0 前台 RCE：common_add/common_lists 的 templateFile 经 ThinkPHP 参数绑定自动注入 fetch，包含日志执行](web-php-file-inclusion-weiphp5-templatefile-param-binding-fetch-log/) | verified | medium | 2026-11-12 |
| [WordPress Advanced Video 1.0 插件 ave_publishPost 的 thumb 路径穿越：wp-config.php 被附件缩略图流程复制到 uploads 后公开下载](web-php-file-inclusion-wordpress-advanced-video-thumb-lfi-wpconfig/) | verified | high | 2026-11-13 |
| [WordPress Brandfolder 插件 <=3.0 callback.php 未认证 LFI/RFI：wp_abspath 参数直接拼接 require_once 实现任意文件包含](web-php-file-inclusion-wordpress-brandfolder-wp-abspath-unauth-rce/) | verified | high | 2026-11-12 |
| [WordPress get_page_template 页面模板路径遍历未授权 LFI（CVE-2026-87902）](web-php-file-inclusion-wordpress-page-template-path-traversal/) | verified | high | 2026-11-05 |
| [WordPress LatePoint <5.1.94 layout 参数本地文件包含（CVE-2025-6715）：set_layout 无条件信任请求参数，render 拼接 include](web-php-file-inclusion-latepoint-layout-cve-2025-6715/) | verified | high | 2026-11-07 |
| [WordPress mail-masta 1.0 的 count_of_send.php/csvexport.php pl 参数直接 include($_GET['pl'])：本地文件包含读配置与任意文件（CVE-2016-10956）](web-php-file-inclusion-mail-masta-cve-2016-10956-lfi/) | verified | high | 2026-11-08 |
| [WP Umbrella 插件 handleClonerRequest 未授权文件包含（CVE-2024-12209）：umbrella-backup 查询变量 + filename 参数拼进 include_once，读文件/包含图片马 getshell](web-php-file-inclusion-wp-umbrella-filename-unauth-rce/) | verified | medium | 2026-11-08 |
| [主题包预览 include preview.tpl 导致 PHP RCE；再利用 ctf 组可写的 root 维护脚本提权读 flag](web-php-file-inclusion-theme-preview-tpl-rce-root-cron/) | verified | high | 2026-11-06 |
| [后台头像上传 + admin.php?file= 包含：GIF89a 头 + <script language="PHP"> 绕内容检测，图片后缀经 LFI 解析执行](web-php-file-inclusion-upload-jpg-script-tag-lfi/) | verified | medium | 2026-11-08 |
| [强制拼接 .php 后缀的 include 绕过：zip:// 包内条目吸收后缀执行压缩包木马](web-php-file-inclusion-zip-wrapper-forced-suffix/) | verified | high | 2026-11-06 |
| [极致CMS（jizhicms）留言详情模板路径包含：@../../ 指向上传图片，模板编译后 include 执行](web-php-file-inclusion-jizhicms-message-template-upload-image-include-rce/) | verified | medium | 2026-11-09 |
| [登录后 manage.php "File does not exist"：wfuzz 爆破出 LFI 参数 file，用 ../ 目录穿越读任意系统文件](web-php-file-inclusion-manage-file-param-wfuzz-traversal/) | verified | high | 2026-11-08 |
| [禅道 api debug 接口 getMethod 文件包含：filePath 经 safe64 解码，../xxx.php/foo.txt 绕过 basename](web-php-file-inclusion-zentao-api-debug-getmethod-basename-bypass/) | verified | medium | 2026-11-13 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
