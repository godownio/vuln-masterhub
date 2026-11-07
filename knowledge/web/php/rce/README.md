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
| [.htaccess AddHandler cgi-script 让上传脚本由 CGI 执行绕过 disable_functions](web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions.md) | verified | high | 2026-11-05 |
| [.htaccess 将 pcre.backtrack_limit 置 0 使 preg_match 返回 false 绕过正则黑名单](web-php-rce-htaccess-pcre-backtrack-limit-bypass.md) | verified | high | 2026-11-05 |
| [.htaccess 开启 SSI 后上传页面执行任意命令与读取文件](web-php-rce-htaccess-ssi-includes-exec.md) | verified | high | 2026-11-05 |
| [Cacti ≤1.2.28 认证后命令注入：图形模板 RRDTool 参数未过滤写 PHP 文件 RCE（CVE-2025-24367）](web-php-rce-cacti-cve-2025-24367-rrdtool-parameter-injection.md) | verified | medium | 2026-11-05 |
| [CmsEasy 7.7.5 后台模板保存路径穿越写 WebShell（CVE-2021-42643）](web-php-rce-cmseasy-cve-2021-42643-template-save-file-write.md) | verified | medium | 2026-11-06 |
| [DeDeCMS 会员模型字段名/字段串二阶标签注入：runphp=yes 触发模板引擎 eval（CNVD-2025-20330）](web-php-rce-dedecms-field-tag-runphp-stored-injection.md) | verified | high | 2026-11-05 |
| [DedeCMS 超级管理员模板标签源码编辑 getshell：substr_replace 动态构造 system 绕过恶意代码检测](web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass.md) | verified | medium | 2026-11-06 |
| [eval(var_dump($input)) 注入：用 $_GET[1]($_GET[2]) 变量函数绕过关键词过滤执行命令](web-php-rce-eval-var-dump-superglobal-variable-function.md) | verified | medium | 2026-11-06 |
| [Fastadmin 后台权限规则条件代码注入：裸 PHP 函数 + 二级管理员登录触发 + 远程下载/Base64 分步写 WebShell](web-php-rce-fastadmin-auth-rule-condition-code-injection-webshell.md) | draft | high | 2026-11-07 |
| [FoxCMS 模板标签 id 参数拼接进编译模板导致 PHP 代码执行](web-php-rce-foxcms-taglib-id-code-injection.md) | verified | high | 2026-11-05 |
| [FrankenPHP php_ini 运行时注入：POST /config/apps/frankenphp/php_ini 清空 disable_functions/open_basedir](web-php-rce-frankenphp-php-ini-disable-functions-bypass.md) | verified | high | 2026-11-06 |
| [FreePBX CVE-2025-57819：认证绕过 + SQL 注入写 Webshell 到 RCE](web-php-rce-freepbx-cve-2025-57819-auth-bypass-sqli-webshell.md) | verified | high | 2026-11-05 |
| [GreenCMS elFinder fileconnect 命令滥用：upload/mkfile/put 写 WebShell（CVE-2025-9415）](web-php-rce-greencms-elfinder-fileconnect-upload-put-webshell.md) | verified | medium | 2026-11-06 |
| [ICPAS php/ping.php 将 ip/times 拼入 exec 执行 ping：jsondata[ip] 分号/管道命令注入](web-php-rce-icpas-ping-ip-exec-command-injection.md) | verified | medium | 2026-11-07 |
| [Joomla 后台 com_templates 模板编辑新建 cmd.php 写 WebShell RCE](web-php-rce-joomla-admin-template-editor-webshell.md) | verified | high | 2026-11-06 |
| [PbootCMS pboot:if 表达式注入配合三元字符串拼接函数名绕过 WAF 与 RASP](web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass.md) | verified | high | 2026-11-05 |
| [PbootCMS 前台 URL 反射进 Spider 脚本并写入 HTML 缓存，二次命中解释执行 PHP](web-php-rce-pbootcms-html-cache-poisoning-rce.md) | verified | high | 2026-11-05 |
| [PbootCMS 后台站点信息插入 PHP + 动态缓存触发 copy() 落地 WebShell](web-php-rce-pbootcms-backend-siteinfo-copy-webshell.md) | verified | high | 2026-11-05 |
| [Pdo\Sqlite::loadExtension 加载恶意扩展库实现 RCE（PHP 8.4+）](web-php-rce-pdo-sqlite-loadextension.md) | verified | high | 2026-11-05 |
| [PHP 7.0-7.4.3 debug_backtrace UAF 绕过 disable_functions（蚁剑插件）](web-php-rce-php7-backtrace-uaf-disable-functions-bypass.md) | verified | medium | 2026-11-05 |
| [PHP 8 UAF 内存破坏解析 zif_system 绕过 disable_functions](web-php-rce-uaf-memory-corruption-disable-functions-bypass.md) | verified | high | 2026-11-05 |
| [PHP create_function 回调点代码注入：} 闭合函数体并用八进制转义绕过黑名单](web-php-rce-create-function-callback-gadget.md) | verified | high | 2026-11-05 |
| [PHP disable_functions 下用 LD_PRELOAD 劫持子进程执行命令](web-php-rce-disable-functions-ld-preload.md) | verified | medium | 2026-11-05 |
| [PHP eval 校验副本不校验原串：getallheaders() 把请求头变成任意函数参数，system(implode(...)) 命令执行](web-php-rce-eval-getallheaders-no-param-function-call.md) | verified | high | 2026-11-05 |
| [PHP exec 4 字符命令长度限制绕过：> 重定向拼文件 + sh 执行](web-php-rce-four-char-command-length-bypass.md) | verified | high | 2026-11-06 |
| [PHP iconv 触发 glibc ISO-2022-CN-EXT 堆溢出（CVE-2024-2961）：php://filter 堆风水劫持 Zend MM free_slot 调用 system](web-php-rce-glibc-iconv-iso2022cn-ext-heap-overflow-cve-2024-2961.md) | verified | medium | 2026-11-06 |
| [PHP OOM 清理路径堆破坏：恶意 multipart 请求触发未认证 RCE](web-php-rce-php2shell-oom-multipart.md) | verified | medium | 2026-11-04 |
| [PHP putenv 注入 BASH_FUNC_ 导出函数执行命令](web-php-rce-putenv-bash-func-env-injection.md) | verified | high | 2026-11-05 |
| [PHP ReflectionClass::newInstanceArgs 任意类实例化：SimpleXMLElement 读文件 + Imagick MSL gray: 写 webshell](web-php-reflectionclass-newinstanceargs-imagick-msl-webshell.md) | verified | medium | 2026-11-06 |
| [PHP shell_exec 黑名单绕过：c''at 引号拼接 + /f* 通配符读取 flag](web-php-rce-shell-exec-quote-concat-glob-flag.md) | verified | high | 2026-11-06 |
| [PHP WebShell RSA 加密流量编码器（蚁剑 myencoder）](web-php-rce-webshell-rsa-traffic-encoder.md) | verified | high | 2026-11-05 |
| [PHP WebShell 业务数据载体分片重组：10 种数组/配置/流/迭代器隐写绕过 AI 检测](web-php-rce-webshell-business-data-carrier-obfuscation.md) | verified | medium | 2026-11-06 |
| [PHP WebShell 免杀：字符串按位取反 + 可变变量 + array_map 动态调用](web-php-rce-webshell-string-not-dynamic-call-av-bypass.md) | verified | high | 2026-11-05 |
| [PHP 一句话木马免杀：@eval(end($_GET)) 取最后一个 GET 参数执行](web-php-rce-webshell-end-get-last-param-eval.md) | verified | medium | 2026-11-06 |
| [PHP 上传内容 WAF 绕过：chr() 拼接 system 与命令的 ASCII 马](web-php-rce-upload-chr-ascii-webshell-waf-bypass.md) | verified | medium | 2026-11-06 |
| [PHP 任意 putenv + 固定文件名写文件：LD_PRELOAD 劫持 system(wget) 子进程 RCE 与 SUID nl 读取](web-php-rce-putenv-fixed-filename-write-ldpreload-wget.md) | verified | high | 2026-11-07 |
| [PHP 可变类与函数调用：echo new $v1($v2()) 模式执行任意函数](web-php-rce-variable-class-function-call-reflection.md) | verified | medium | 2026-11-05 |
| [PHP 文档预览 LibreOffice 转换接口命令注入：file 参数直拼 shell_exec 写 WebShell](web-php-rce-document-preview-libreoffice-shell-exec-injection.md) | verified | high | 2026-11-07 |
| [PHP 无参 RCE：localeconv+scandir+next+chdir 逐级上跳并用 show_source 读文件](web-php-rce-no-param-localeconv-scandir-chdir.md) | verified | high | 2026-11-05 |
| [PHP 无字母数字自增构造变量函数 RCE：黑名单下用 ++ 拼出函数名执行 cat /f*](web-php-rce-no-alnum-self-increment-variable-function.md) | verified | medium | 2026-11-06 |
| [PHP 正则黑名单双重转义：在关键字中插入反斜杠（ca\t /fl\ag）绕过 cat/flag 过滤](web-php-rce-regex-backslash-escape-command-injection.md) | verified | medium | 2026-11-07 |
| [PHP 计算器 eval 拼接表达式被右括号闭合导致任意代码执行](web-php-rce-eval-expression-closing-paren-injection.md) | verified | high | 2026-11-05 |
| [PHP 请求头触发式隐蔽后门：base64 解码 header 名/值校验 + base64 命令头 + chr 拼接 system 交给 call_user_func](web-php-rce-header-gated-backdoor-call-user-func.md) | verified | medium | 2026-11-06 |
| [PHP 迭代器 WebShell 免杀：拆分函数名与命令并在运行时重组](web-php-rce-iterator-webshell-split-reassemble.md) | verified | high | 2026-11-05 |
| [PHP-FPM FastCGI 注入 PHP_ADMIN_VALUE extension：加载恶意 .so 构造函数绕过 disable_functions](web-php-rce-fastcgi-php-admin-value-extension-so.md) | verified | high | 2026-11-05 |
| [runkit_function_add 动态函数体注入：用户可控 rule 被编译为 PHP 函数体执行](web-php-rce-runkit-function-add-rule-body.md) | verified | high | 2026-11-06 |
| [WeGIA 备份恢复文件名未转义拼接 shell_exec 导致命令注入（CVE-2026-28409）](web-php-rce-wegia-backup-filename-command-injection.md) | verified | medium | 2026-11-05 |
| [WordPress 后台弱口令 + 主题文件编辑器写入 PHP：管理员会话直接改 comments.php getshell](web-php-wordpress-admin-weak-password-theme-editor-rce.md) | verified | high | 2026-11-07 |
| [Yii 菜单 href 表达式求值 + disable_functions 绕过：分段写 PHP 入口并用 pcntl_exec 读 flag](web-php-rce-yii-menu-href-expression-eval-disable-functions-bypass.md) | verified | high | 2026-11-06 |
| [上传文件名注入 mv -S 选项，利用备份后缀把脚本文件改名为 .php](web-php-rce-mv-option-injection-suffix-webshell.md) | verified | high | 2026-11-05 |
| [信呼 OA copymode 任意文件写入：name 拼接 PHP 代码并访问 Model.php 执行](web-php-rce-xinhu-oa-copymode-file-write.md) | verified | high | 2026-11-05 |
| [信呼 OA copymode 写马被 AV 拦截后的免杀绕过：get_defined_vars 读 Cookie 参数并二次写入 WebShell](web-php-rce-xinhu-copymode-get-defined-vars-av-bypass.md) | verified | high | 2026-11-07 |
| [命令执行黑名单同时过滤函数名与空格：passthru 替代 + Tab/IFS + 通配符](web-php-rce-command-space-blacklist-tab-passthru.md) | verified | high | 2026-11-05 |
| [命令注入黑名单 + 字符集白名单绕过：base64 -d | tee 写 WebShell](web-php-rce-command-injection-blacklist-base64-tee-webshell.md) | verified | high | 2026-11-05 |
| [哥斯拉 PHP 魔改 WebShell：一阶段 payload 入 session + AES-128-ECB Base64 + username/password 伪装](web-php-rce-godzilla-aes-session-webshell-disguise.md) | verified | high | 2026-11-05 |
| [安装向导未转义数据库名写入 config.php 导致代码执行](web-php-rce-install-config-unescaped-dbname.md) | verified | high | 2026-11-05 |
| [指令集随机化防护下通过源码泄露、短标签爆破或内建函数枚举恢复随机化函数名](web-php-rce-isr-randomized-function-name-recovery.md) | verified | medium | 2026-11-05 |
| [无参数 RCE：正则只允许无参函数调用时用 get_defined_vars 取回外部参数](web-php-rce-no-param-get-defined-vars.md) | verified | high | 2026-11-05 |
| [海洋CMS search.php 模板代码执行与 WAF 函数黑名单绕过](web-php-rce-seacms-search-template-code-execution.md) | verified | high | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
