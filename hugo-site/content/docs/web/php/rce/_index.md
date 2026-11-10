---
title: PHP 代码执行
weight: 1
---

# PHP 代码执行

## 这层是什么

命令执行、代码执行、回调与绕过。

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
| [.htaccess AddHandler cgi-script 让上传脚本由 CGI 执行绕过 disable_functions](web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions/) | verified | high | 2026-11-05 |
| [.htaccess 将 pcre.backtrack_limit 置 0 使 preg_match 返回 false 绕过正则黑名单](web-php-rce-htaccess-pcre-backtrack-limit-bypass/) | verified | high | 2026-11-05 |
| [.htaccess 开启 SSI 后上传页面执行任意命令与读取文件](web-php-rce-htaccess-ssi-includes-exec/) | verified | high | 2026-11-05 |
| [0o0o 嵌套混淆生成器：随机双字母表 strtr 前置密钥 + urldecode 字母表拼装变量函数，双层 eval 隐藏 sink 名](web-php-rce-webshell-0o0o-nested-obfuscator-random-alphabet/) | verified | medium | 2026-11-08 |
| [Cacti ≤1.2.28 认证后命令注入：图形模板 RRDTool 参数未过滤写 PHP 文件 RCE（CVE-2025-24367）](web-php-rce-cacti-cve-2025-24367-rrdtool-parameter-injection/) | verified | medium | 2026-11-05 |
| [Chamilo LMS bigupload 未授权上传 PHP 文件致 RCE（CVE-2023-4220）：action=post-unsupported 直接落地 files/ 目录](web-php-rce-chamilo-bigupload-post-unsupported-php-upload-rce/) | verified | medium | 2026-11-07 |
| [CmsEasy 7.7 后台第三方代码 header/footer 写入 header-js.html 被模板包含导致 RCE（CNVD-2024-10069）](web-php-rce-cmseasy-thirdparty-header-footer-write-php/) | verified | high | 2026-11-09 |
| [CmsEasy 7.7.5 后台模板保存路径穿越写 WebShell（CVE-2021-42643）](web-php-rce-cmseasy-cve-2021-42643-template-save-file-write/) | verified | medium | 2026-11-06 |
| [CVE-2012-1823 PHP-CGI 参数注入 RCE：query string 被当作 php-cgi 选项，-d allow_url_include + auto_prepend_file=php://input 执行 POST 代码](web-php-rce-cve-2012-1823-php-cgi-querystring-argument-injection/) | verified | high | 2026-11-08 |
| [CVE-2024-4577 PHP-CGI Windows Best-Fit 参数注入 RCE：0xAD 还原为 -d，allow_url_include + auto_prepend_file=php://input 执行 POST 代码](web-php-rce-cve-2024-4577-php-cgi-bestfit-argument-injection/) | verified | high | 2026-11-08 |
| [DedeCMS ≤5.7.113 后台 makehtml_homepage.php：position 路径穿越 + 模板内容回写覆盖 tags.php getshell](web-php-rce-dedecms-makehtml-homepage-position-file-write/) | verified | high | 2026-11-08 |
| [DedeCMS ≤5.7.115 二阶任意文件覆盖：makehtml_homepage 写 homepageset 表 + task_do.php makeindex 触发 getshell](web-php-rce-dedecms-homepageset-task-do-stored-file-write/) | verified | high | 2026-11-08 |
| [DeDeCMS 会员模型字段名/字段串二阶标签注入：runphp=yes 触发模板引擎 eval（CNVD-2025-20330）](web-php-rce-dedecms-field-tag-runphp-stored-injection/) | verified | high | 2026-11-05 |
| [DedeCMS 超级管理员模板标签源码编辑 getshell：substr_replace 动态构造 system 绕过恶意代码检测](web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass/) | verified | medium | 2026-11-06 |
| [Drupal 8 CVE-2018-7600 表单渲染数组注入 RCE（Drupalgeddon2）](web-php-rce-drupal-cve-2018-7600-drupalgeddon2/) | verified | high | 2026-11-07 |
| [elFinder ≤2.1.47 PHP connector：上传文件夹带 shell 元字符，rotate 触发 imgRotate 里 $path 未加引号造成命令注入（CVE-2019-9194）](web-php-rce-elfinder-imgrotate-filename-command-injection/) | verified | high | 2026-11-09 |
| [escapeshellcmd 之下仍能执行：黑名单只封读文件命令（cat/tac/nl/head/tail/read）而漏掉 env，两段 md5（松散 0e/数组 + 严格数组）过关后直接读环境变量拿 flag](web-php-rce-escapeshellcmd-blacklist-env-flag-read/) | verified | high | 2026-11-08 |
| [eval 前的字符集排列校验被「少一个字母」绕过：用剩余标识符拼出变量函数调用执行 POST 参数](ctf-web-eval-char-permutation-post-param-rce/) | verified | medium | 2026-11-09 |
| [eval 正则函数调用检测：函数名加引号绕过 + ThinkPHP input() 两级取值构造 system(/readflag)](web-php-rce-eval-quoted-function-input-helper-waf-bypass/) | verified | medium | 2026-11-08 |
| [eval(var_dump($input)) 注入：用 $_GET[1]($_GET[2]) 变量函数绕过关键词过滤执行命令](web-php-rce-eval-var-dump-superglobal-variable-function/) | verified | medium | 2026-11-06 |
| [exec 无回显 RCE 用 curl --data "$(命令)" 外带执行结果](web-php-rce-exec-silent-curl-oob-exfil/) | verified | high | 2026-11-08 |
| [Fastadmin 后台权限规则条件代码注入：裸 PHP 函数 + 二级管理员登录触发 + 远程下载/Base64 分步写 WebShell](web-php-rce-fastadmin-auth-rule-condition-code-injection-webshell/) | verified | high | 2026-11-07 |
| [FoxCMS 模板标签 id 参数拼接进编译模板导致 PHP 代码执行](web-php-rce-foxcms-taglib-id-code-injection/) | verified | high | 2026-11-05 |
| [FrankenPHP php_ini 运行时注入：POST /config/apps/frankenphp/php_ini 清空 disable_functions/open_basedir](web-php-rce-frankenphp-php-ini-disable-functions-bypass/) | verified | high | 2026-11-06 |
| [FreePBX CVE-2025-57819：认证绕过 + SQL 注入写 Webshell 到 RCE](web-php-rce-freepbx-cve-2025-57819-auth-bypass-sqli-webshell/) | verified | high | 2026-11-05 |
| [GreenCMS elFinder fileconnect 命令滥用：upload/mkfile/put 写 WebShell（CVE-2025-9415）](web-php-rce-greencms-elfinder-fileconnect-upload-put-webshell/) | verified | medium | 2026-11-06 |
| [ICPAS php/ping.php 将 ip/times 拼入 exec 执行 ping：jsondata[ip] 分号/管道命令注入](web-php-rce-icpas-ping-ip-exec-command-injection/) | verified | medium | 2026-11-07 |
| [IP-guard WebServer flexpaper view.php 命令注入 RCE：doc/page 参数拼接进 tool_transform 的 exec，管道符执行 php.exe 写 webshell](web-php-rce-ipguard-flexpaper-view-php-command-injection/) | verified | high | 2026-11-09 |
| [Joomla 后台 com_templates 模板编辑新建 cmd.php 写 WebShell RCE](web-php-rce-joomla-admin-template-editor-webshell/) | verified | high | 2026-11-06 |
| [Pandora FMS netflow 视图 ip_src 命令注入：闭合引号后 curl 带外确认执行（CVE-2019-20224）](web-php-rce-pandorafms-netflow-ip-src-command-injection/) | verified | medium | 2026-11-08 |
| [PbootCMS pboot:if 表达式注入配合三元字符串拼接函数名绕过 WAF 与 RASP](web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass/) | verified | high | 2026-11-05 |
| [PbootCMS 前台 URL 反射进 Spider 脚本并写入 HTML 缓存，二次命中解释执行 PHP](web-php-rce-pbootcms-html-cache-poisoning-rce/) | verified | high | 2026-11-05 |
| [PbootCMS 后台站点信息插入 PHP + 动态缓存触发 copy() 落地 WebShell](web-php-rce-pbootcms-backend-siteinfo-copy-webshell/) | verified | high | 2026-11-05 |
| [Pdo\Sqlite::loadExtension 加载恶意扩展库实现 RCE（PHP 8.4+）](web-php-rce-pdo-sqlite-loadextension/) | verified | high | 2026-11-05 |
| [PHP 5.2 魔术引号环境写 WebShell：写入内容被自动转义时用 stripslashes($_POST[...]) 让蚁剑连通](web-php-rce-magic-quotes-stripslashes-webshell-write-bypass/) | verified | medium | 2026-11-07 |
| [PHP 7.0-7.4.3 debug_backtrace UAF 绕过 disable_functions（蚁剑插件）](web-php-rce-php7-backtrace-uaf-disable-functions-bypass/) | verified | medium | 2026-11-05 |
| [PHP 8 UAF 内存破坏解析 zif_system 绕过 disable_functions](web-php-rce-uaf-memory-corruption-disable-functions-bypass/) | verified | high | 2026-11-05 |
| [PHP create_function 回调点代码注入：} 闭合函数体并用八进制转义绕过黑名单](web-php-rce-create-function-callback-gadget/) | verified | high | 2026-11-05 |
| [PHP disable_functions 下用 LD_PRELOAD 劫持子进程执行命令](web-php-rce-disable-functions-ld-preload/) | verified | medium | 2026-11-05 |
| [PHP eval 校验副本不校验原串：getallheaders() 把请求头变成任意函数参数，system(implode(...)) 命令执行](web-php-rce-eval-getallheaders-no-param-function-call/) | verified | high | 2026-11-05 |
| [PHP exec 4 字符命令长度限制绕过：> 重定向拼文件 + sh 执行](web-php-rce-four-char-command-length-bypass/) | verified | high | 2026-11-06 |
| [PHP iconv 触发 glibc ISO-2022-CN-EXT 堆溢出（CVE-2024-2961）：php://filter 堆风水劫持 Zend MM free_slot 调用 system](web-php-rce-glibc-iconv-iso2022cn-ext-heap-overflow-cve-2024-2961/) | verified | medium | 2026-11-06 |
| [PHP OOM 清理路径堆破坏：恶意 multipart 请求触发未认证 RCE](web-php-rce-php2shell-oom-multipart/) | verified | medium | 2026-11-04 |
| [PHP ping 命令注入：只过滤斜杠时用分号注入并写入 WebShell](web-php-rce-ping-slash-filter-semicolon-webshell-write/) | verified | high | 2026-11-08 |
| [PHP putenv 注入 BASH_FUNC_ 导出函数执行命令](web-php-rce-putenv-bash-func-env-injection/) | verified | high | 2026-11-05 |
| [PHP ReflectionClass::newInstanceArgs 任意类实例化：SimpleXMLElement 读文件 + Imagick MSL gray: 写 webshell](web-php-reflectionclass-newinstanceargs-imagick-msl-webshell/) | verified | medium | 2026-11-06 |
| [PHP shell_exec 黑名单绕过：c''at 引号拼接 + /f* 通配符读取 flag](web-php-rce-shell-exec-quote-concat-glob-flag/) | verified | high | 2026-11-06 |
| [PHP WebShell RSA 加密流量编码器（蚁剑 myencoder）](web-php-rce-webshell-rsa-traffic-encoder/) | verified | high | 2026-11-05 |
| [PHP WebShell 业务数据载体分片重组：10 种数组/配置/流/迭代器隐写绕过 AI 检测](web-php-rce-webshell-business-data-carrier-obfuscation/) | verified | medium | 2026-11-06 |
| [PHP WebShell 免杀：字符串按位取反 + 可变变量 + array_map 动态调用](web-php-rce-webshell-string-not-dynamic-call-av-bypass/) | verified | high | 2026-11-05 |
| [PHP WebShell 多层免杀：函数名分片重建 + 冷门回调 sink + goto/自定义函数拆分控制流绕过静态正则](web-php-rce-webshell-name-rebuild-callback-goto-multilayer/) | verified | medium | 2026-11-08 |
| [PHP 一句话木马免杀：@eval(end($_GET)) 取最后一个 GET 参数执行](web-php-rce-webshell-end-get-last-param-eval/) | verified | medium | 2026-11-06 |
| [PHP 上传内容 WAF 绕过：chr() 拼接 system 与命令的 ASCII 马](web-php-rce-upload-chr-ascii-webshell-waf-bypass/) | verified | medium | 2026-11-06 |
| [PHP 任意 putenv + 固定文件名写文件：LD_PRELOAD 劫持 system(wget) 子进程 RCE 与 SUID nl 读取](web-php-rce-putenv-fixed-filename-write-ldpreload-wget/) | verified | high | 2026-11-07 |
| [PHP 免杀 WebShell：类封装 + array_map(assert, $_POST) 回调执行](web-php-rce-class-array-map-assert-webshell/) | verified | medium | 2026-11-08 |
| [PHP 全局变量覆盖 + if/elseif 缺 else：请求参数直达 popen 的命令执行审计技巧](web-php-rce-globals-overwrite-missing-else-popen/) | verified | medium | 2026-11-09 |
| [PHP 函数名前置反斜杠绕过 in_array 精确黑名单，call_user_func 任意命令执行](web-php-rce-call-user-func-leading-backslash-blacklist-bypass/) | verified | high | 2026-11-08 |
| [PHP 变量函数名异或编码：随机 key 逐字符 XOR 生成「$a.$b.$c」拼接式，静态无完整敏感词](web-php-rce-webshell-xor-encoded-function-name/) | verified | high | 2026-11-08 |
| [PHP 可变类与函数调用：echo new $v1($v2()) 模式执行任意函数](web-php-rce-variable-class-function-call-reflection/) | verified | medium | 2026-11-05 |
| [PHP 命令白名单 ^[./*t ]+$ 绕过：`. /t*/*` glob 展开执行 /tmp 上传临时文件并落地 webshell](web-php-rce-regex-whitelist-glob-tmp-upload-exec/) | verified | medium | 2026-11-07 |
| [PHP 文档预览 LibreOffice 转换接口命令注入：file 参数直拼 shell_exec 写 WebShell](web-php-rce-document-preview-libreoffice-shell-exec-injection/) | verified | high | 2026-11-07 |
| [PHP 无参 RCE：localeconv+scandir+next+chdir 逐级上跳并用 show_source 读文件](web-php-rce-no-param-localeconv-scandir-chdir/) | verified | high | 2026-11-05 |
| [PHP 无字母数字自增构造变量函数 RCE：黑名单下用 ++ 拼出函数名执行 cat /f*](web-php-rce-no-alnum-self-increment-variable-function/) | verified | medium | 2026-11-06 |
| [PHP 正则黑名单双重转义：在关键字中插入反斜杠（ca\t /fl\ag）绕过 cat/flag 过滤](web-php-rce-regex-backslash-escape-command-injection/) | verified | medium | 2026-11-07 |
| [PHP 直接调用 iconv() 触发 CVE-2024-2961：N+32 输出缓冲单请求堆塑形泄露 zend_string，篡改 $_SESSION 数组经 Roundcube preferences 反序列化 RCE](web-php-rce-glibc-iconv-direct-call-roundcube-session-overwrite-cve-2024-2961/) | verified | medium | 2026-11-08 |
| [PHP 计算器 eval 拼接表达式被右括号闭合导致任意代码执行](web-php-rce-eval-expression-closing-paren-injection/) | verified | high | 2026-11-05 |
| [PHP 请求头触发式隐蔽后门：base64 解码 header 名/值校验 + base64 命令头 + chr 拼接 system 交给 call_user_func](web-php-rce-header-gated-backdoor-call-user-func/) | verified | medium | 2026-11-06 |
| [PHP 迭代器 WebShell 免杀：拆分函数名与命令并在运行时重组](web-php-rce-iterator-webshell-split-reassemble/) | verified | high | 2026-11-05 |
| [PHP-FPM FastCGI 注入 PHP_ADMIN_VALUE extension：加载恶意 .so 构造函数绕过 disable_functions](web-php-rce-fastcgi-php-admin-value-extension-so/) | verified | high | 2026-11-05 |
| [PHPMailer 参数注入打 exim4 MTA：-be 批处理模式 + ${run}/${readsocket} 字符串扩展实现 RCE](web-php-rce-phpmailer-exim-be-expansion-command-exec/) | verified | high | 2026-11-08 |
| [phpStudy Windows 版 php_xmlrpc.dll 后门：Accept-Charset 传 Base64 PHP 代码即执行](web-php-rce-phpstudy-xmlrpc-accept-charset-backdoor/) | verified | high | 2026-11-09 |
| [ping 参数校验只锚定开头 + 12 字符长度上限：用换行符在 IP 后另起一条命令，5 个字符内完成注入](web-php-rce-ping-ip-regex-no-end-anchor-newline-short-command/) | verified | medium | 2026-11-08 |
| [PopojiCMS 2.0.1 后台 Meta Social 设置无过滤写入 meta_social.txt，主题 index.php include 固定文件导致 RCE](web-php-rce-popojicms-metasocial-txt-include/) | verified | high | 2026-11-09 |
| [preg_match 函数黑名单下用 chr() 拼接函数名经 PHP 变量函数调用 readfile 读文件](web-php-rce-chr-concat-variable-function-blacklist-bypass/) | verified | high | 2026-11-08 |
| [preg_replace /e 修饰符把替换串当 PHP 执行，配合不区分大小写的自过滤绕过](web-php-rce-preg-replace-e-modifier-case-insensitive-blacklist-bypass/) | draft | high | 2026-11-08 |
| [runkit_function_add 动态函数体注入：用户可控 rule 被编译为 PHP 函数体执行](web-php-rce-runkit-function-add-rule-body/) | verified | high | 2026-11-06 |
| [SeaCMS 12.9 后台 admin_ping.php 设置项未过滤拼接写入 data/admin/ping.php 导致代码执行](web-php-rce-seacms-admin-ping-post-write-php-code/) | verified | high | 2026-11-08 |
| [SQLite 数据库当函数名载体：先 file_put_contents 落地 .db，再用 PDO queryString 切片取出 system](web-php-rce-webshell-sqlite-query-string-function-name/) | verified | medium | 2026-11-08 |
| [watchbird 后台 change() 任意键值写入：config_path 经 $$key 覆盖后任意文件写入 Web 根 RCE](web-php-rce-watchbird-config-change-config-path-overwrite-webshell/) | verified | high | 2026-11-08 |
| [WBCE CMS 后台语言包安装把上传文件直接 require：file_get_contents 校验不严导致任意 PHP 解析执行（CVE-2022-25099）](web-php-rce-wbce-install-language-file-getcontents-rce/) | verified | high | 2026-11-08 |
| [WeGIA 备份恢复文件名未转义拼接 shell_exec 导致命令注入（CVE-2026-28409）](web-php-rce-wegia-backup-filename-command-injection/) | verified | medium | 2026-11-05 |
| [WonderCMS installModule 主题 zip 远程安装：登录页 XSS 借管理员会话拉取恶意主题落 WebShell](web-php-rce-wondercms-installmodule-theme-zip-csrf-xss/) | verified | high | 2026-11-08 |
| [WordPress GutenKit 插件 REST 安装端点缺 permission_callback：未授权 download_url 拉取远程 zip 解压到 wp-content/plugins 落地 WebShell（CVE-2024-9234）](web-php-rce-wordpress-gutenkit-cve-2024-9234-plugin-install-upload-rce/) | verified | high | 2026-11-08 |
| [WordPress 后台弱口令 + 主题文件编辑器写入 PHP：管理员会话直接改 comments.php getshell](web-php-wordpress-admin-weak-password-theme-editor-rce/) | verified | high | 2026-11-07 |
| [Yii 菜单 href 表达式求值 + disable_functions 绕过：分段写 PHP 入口并用 pcntl_exec 读 flag](web-php-rce-yii-menu-href-expression-eval-disable-functions-bypass/) | verified | high | 2026-11-06 |
| [Yxcms 演示公告泄露默认后台口令 admin/123456 + 前台模板文件管理新建 x.php：模板目录在 Web 根内直接解析 getshell](web-php-rce-yxcms-default-admin-template-file-webshell/) | verified | high | 2026-11-10 |
| [ZzzCMS 后台模板编辑写入 {if:assert()} 标签 getshell](web-php-rce-zzzcms-admin-template-assert-webshell/) | verified | medium | 2026-11-08 |
| [上传文件名注入 mv -S 选项，利用备份后缀把脚本文件改名为 .php](web-php-rce-mv-option-injection-suffix-webshell/) | verified | high | 2026-11-05 |
| [信呼 OA copymode 任意文件写入：name 拼接 PHP 代码并访问 Model.php 执行](web-php-rce-xinhu-oa-copymode-file-write/) | verified | high | 2026-11-05 |
| [信呼 OA copymode 写马被 AV 拦截后的免杀绕过：get_defined_vars 读 Cookie 参数并二次写入 WebShell](web-php-rce-xinhu-copymode-get-defined-vars-av-bypass/) | verified | high | 2026-11-07 |
| [信呼OA v2.6.3 flowAction::inputAction 用 flow_set 的 name/num 生成 mode_*Action.php：注释闭合注入 eval 直接 RCE](web-php-rce-xinhu-flowaction-inputaction-generated-mode-file-comment-breakout/) | verified | high | 2026-11-08 |
| [内网运维面板 log_file 参数拼进 shell 命令：先 `;id;#` 打通命令执行，再写 sudoers 换 root](web-php-rce-monitor-log-file-param-shell-write-sudoers-root/) | verified | high | 2026-11-08 |
| [写入点被前置「<?php exit();?>」封死时，用 php://filter/write=convert.base64-decode 剥离前缀并对齐填充，让后面的 base64 载荷照常落成 PHP 代码](web-php-rce-put-contents-exit-prefix-base64-decode-webshell/) | verified | low | 2026-11-09 |
| [冷门回调函数作 sink：array_uintersect_uassoc 的比较器参数直接执行 assert，文件里没有 eval/assert/array_map 关键字](web-php-rce-webshell-obscure-callback-uintersect/) | verified | medium | 2026-11-08 |
| [命令执行接口以 X-Forwarded-For 做 IP 白名单：伪造头绕过限制后用 `;` 拼接命令读取任意文件](web-php-rce-xff-spoof-ip-allowlist-command-injection/) | verified | medium | 2026-11-09 |
| [命令执行黑名单同时过滤函数名与空格：passthru 替代 + Tab/IFS + 通配符](web-php-rce-command-space-blacklist-tab-passthru/) | verified | high | 2026-11-05 |
| [命令执行黑名单过滤 `/` 与 `>` 时用 `|tee` 落盘写马、用相对路径取 flag](web-php-rce-blacklist-no-slash-no-redirect-tee-write-webshell/) | verified | medium | 2026-11-09 |
| [命令注入黑名单 + 字符集白名单绕过：base64 -d | tee 写 WebShell](web-php-rce-command-injection-blacklist-base64-tee-webshell/) | verified | high | 2026-11-05 |
| [命令长度<6 且禁用 nl：用 `od /*` 八进制转储根目录文件还原 flag](web-php-rce-short-command-od-wildcard-octal-root-read/) | verified | medium | 2026-11-08 |
| [哥斯拉 PHP payload 命令执行降级链：system→passthru→shell_exec→exec→popen→proc_open→COM→pcntl_exec→Shellshock](web-php-rce-godzilla-payload-command-exec-fallback-chain/) | verified | medium | 2026-11-09 |
| [哥斯拉 PHP 魔改 WebShell：一阶段 payload 入 session + AES-128-ECB Base64 + username/password 伪装](web-php-rce-godzilla-aes-session-webshell-disguise/) | verified | high | 2026-11-05 |
| [哥斯拉自定义 Cryption 栅栏加密混淆流量：Base64→3 栏栅栏→Base64 与配套 PHP 马](web-php-rce-godzilla-railfence-custom-cryption-traffic/) | verified | high | 2026-11-09 |
| [安装向导未转义数据库名写入 config.php 导致代码执行](web-php-rce-install-config-unescaped-dbname/) | verified | high | 2026-11-05 |
| [指令集随机化防护下通过源码泄露、短标签爆破或内建函数枚举恢复随机化函数名](web-php-rce-isr-randomized-function-name-recovery/) | verified | medium | 2026-11-05 |
| [无参数 RCE：正则只允许无参函数调用时用 get_defined_vars 取回外部参数](web-php-rce-no-param-get-defined-vars/) | verified | high | 2026-11-05 |
| [无回显命令执行：把目标文件 cp 覆盖到一个已存在的 .php 路径上，再直接访问把它当纯文本读出来](web-php-rce-blind-copy-target-over-existing-php-file/) | verified | high | 2026-11-09 |
| [无回显无写文件的命令执行：用「head -c n /flag | tail -c 1」+ 条件 sleep 做时间布尔盲注逐字符取 flag](web-php-blind-rce-time-oracle-ifs-base64-char-bruteforce/) | verified | high | 2026-11-09 |
| [日志过滤参数拼接进 shell 命令，用 ${IFS} 绕过空格黑名单执行命令](web-php-rce-ifs-space-bypass-command-injection/) | verified | high | 2026-11-08 |
| [极致CMS 后台插件更新任意下载+解压：download_url 拉取 zip 到 cache/update，解压后 A/exts/ 落地 PHP webshell](web-php-rce-jizhicms-plugin-update-download-unzip-webshell/) | verified | medium | 2026-11-07 |
| [栅栏加密藏函数名字母 + 辅助函数间接取 POST：绕过河马/安全狗/SHELLPUB 的 PHP 木马](web-php-rce-webshell-railfence-function-name-helper-post/) | verified | high | 2026-11-09 |
| [注释与 NUL 序列灌入 + 伪语法错误：用垃圾代码撑大文件让静态解析器与 AI 判读提前放弃](web-php-rce-webshell-junk-comment-nul-padding/) | verified | medium | 2026-11-08 |
| [海洋CMS search.php 模板代码执行与 WAF 函数黑名单绕过](web-php-rce-seacms-search-template-code-execution/) | verified | high | 2026-11-04 |
| [用 ReflectionClass::getDocComment 把危险代码藏在类注释里：substr 切片后交 eval 执行](web-php-rce-webshell-doccomment-string-carrier/) | verified | medium | 2026-11-08 |
| [禅道 12.4.2 CNVD-2020-121325：client/download 的 link 参数 base64 任意 URL 下载，写入 data/client/ 落地 PHP webshell](web-php-rce-zentao-cnvd-2020-121325-link-download-webshell/) | verified | high | 2026-11-07 |
| [禅道 misc/captcha 任意 session 键 + repo 创建/编辑：SCM=Subversion 时 client 参数进 exec，仅凭前台 zentaosid 即可命令执行](web-php-rce-zentao-captcha-session-repo-checkconnection-exec/) | verified | high | 2026-11-09 |
| [算法生成数组当字节载体：把函数名切成 ASCII 值塞进噪声数组，用状态机派生偏移量切片还原](web-php-rce-webshell-algorithmic-array-byte-carrier/) | verified | medium | 2026-11-08 |
| [自实现 escapeshellarg_jp 只补反斜杠不闭合引号：password 传 `';ls;#` 逃出单引号注释掉后续命令](web-php-rce-escapeshellarg-jp-custom-escape-quote-semicolon/) | verified | high | 2026-11-08 |
| [蚁剑 LD_PRELOAD 插件绕过 disable_functions：上传 .so 与 .antproxy.php，经本地 PHP 服务器代理执行 GET 命令](web-php-rce-disable-functions-ldpreload-antsword-proxy/) | verified | medium | 2026-11-08 |
| [解谜状态机门控 WebShell：RCE 藏在「方块全等」判定之后，静态与沙箱只看到游戏逻辑](web-php-rce-webshell-puzzle-state-gate-av-bypass/) | verified | medium | 2026-11-08 |
| [超长输入触发 PCRE 回溯上限：preg_match 返回 false 被当“未匹配”，绕过正则黑名单上传 WebShell](web-php-rce-pcre-backtrack-limit-false-filter-bypass/) | verified | high | 2026-11-09 |
| [过滤逻辑写在同目录可写的 PHP 文件里：先命令执行读出 no.php 确认它是 WAF，再 rm 掉它使限制失效，随后通配符 cat 根目录取 flag](web-php-rce-deletable-waf-prepend-file-bypass/) | verified | medium | 2026-11-09 |
| [防病毒管控台 PageController 无鉴权 cmd 参数 exec 直接命令执行并回显](web-php-rce-esm-console-page-controller-cmd-exec/) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
