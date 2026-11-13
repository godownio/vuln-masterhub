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

- [PHP 反序列化](deserialization/README.md) —— POP 链、魔术方法、Phar 反序列化。
- [PHP 代码执行](rce/README.md) —— 命令执行、代码执行、回调与绕过。
- [PHP 文件包含](file-inclusion/README.md) —— LFI/RFI、伪协议、日志包含与临时文件。
- [PHP open_basedir 绕过](open-basedir-bypass/README.md) —— open_basedir 限制绕过、伪协议、symlink、报错 oracle 与竞态。
- [PHP 框架](framework/README.md) —— ThinkPHP、Laravel、Yii 等框架漏洞。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [.htaccess 关闭 PHP engine 导致目录内 PHP 源码被明文返回](web-php-htaccess-engine-off-source-disclosure.md) | verified | high | 2026-11-05 |
| [CMS 安装目录残留 install/sql-config/sql.json：未授权读取数据库主机、库名、账号与明文口令](web-php-cms-install-sql-json-unauth-db-credential-disclosure.md) | verified | high | 2026-11-09 |
| [CmsEasy 后台 editcategorytemplate：POST module_name 按 {tag_...} 解析后拼接模板缓存路径，../ 穿越 unlink 删除任意文件](web-php-cmseasy-template-editcategorytemplate-module-name-unlink.md) | verified | high | 2026-11-09 |
| [CmsEasy 后台 image deleteimg：dir 参数未过滤的路径穿越 unlink 任意文件删除](web-php-cmseasy-image-deleteimg-dir-traversal-file-delete.md) | verified | high | 2026-11-09 |
| [eyoucms 任意用户登录：get_token 可控 session 键名 + intval(md5) 弱类型绕过后台鉴权，改模板 getshell](web-php-eyoucms-get-token-session-name-intval-md5-admin-bypass.md) | verified | medium | 2026-11-13 |
| [IBOS 后台数据库恢复 key[] 参数拼接备份目录 unlink：只滤正斜杠，Windows 反斜杠穿越任意文件删除](web-php-ibos-database-restore-key-unlink-traversal.md) | verified | medium | 2026-11-13 |
| [IP-guard WebServer mApplyList 权限绕过 + 任意文件读取（QVD-2024-14103）：getdatarecord 分支跳过登录跳转，tempFile 路径穿越读文件](web-php-ipguard-mapplylist-getdatarecord-auth-bypass-file-read.md) | verified | high | 2026-11-09 |
| [Joomla 4 /api/index.php/v1/config/application?public=true 未授权泄露数据库账号口令（CVE-2023-23752）](web-php-joomla-api-config-application-public-db-credential-leak.md) | verified | high | 2026-11-05 |
| [json_encode(INF) 失败导致内部请求变空包，json_decode(500 错误页) 返回 NULL 绕过 === FALSE 校验](web-php-json-encode-inf-false-jsondecode-null-strict-bypass.md) | verified | high | 2026-11-09 |
| [PHP QUERY_STRING 校验与 $_GET 拼接解析差异：timestamp[day]$ 注入 .php 后缀写 webshell](web-php-query-string-get-parser-differential-upload.md) | verified | medium | 2026-11-07 |
| [PHP Warning 提前输出导致 CSP 响应头失效](web-php-warning-header-already-sent-csp-bypass.md) | verified | medium | 2026-11-05 |
| [PHP 内置开发服务器（php -S）被畸形/流水线请求读出 .php 源码：先拿源码再打通后续反序列化链](web-php-builtin-server-malformed-request-php-source-disclosure.md) | verified | low | 2026-11-09 |
| [PHP 数值前缀/宽松比较绕过：score=300abc 通过 >=300 校验](web-php-loose-numeric-prefix-score-bypass.md) | verified | high | 2026-11-06 |
| [PHP 源码审计硬编码 SM4 默认密钥：StringUtil::encrypt 的 $key='xiaoyewl' 复用 decrypt() 还原后台口令](web-php-hardcoded-sm4-default-key-password-decrypt.md) | verified | medium | 2026-11-09 |
| [WordPress wp_authenticate 后门：修改 pluggable.php 把登录明文账号密码落盘或外带 C2](web-php-wordpress-wp-authenticate-plaintext-credential-backdoor.md) | verified | high | 2026-11-12 |
| [WordPress 配置与旧数据库备份泄露：phpass 破解历史账户并复用至宿主机 SSH](web-php-wordpress-backup-sql-phpass-credential.md) | verified | high | 2026-11-05 |
| [拿到 MySQL root 后直接 UPDATE Joomla 用户表覆盖管理员口令哈希进入后台](web-php-joomla-db-root-reset-admin-password-hash.md) | verified | high | 2026-11-08 |
| [拿到 WordPress 数据库凭据后直改 wp_users 密码哈希接管后台，再读取密码管理插件存储的 SSH 私钥](web-php-wordpress-db-hash-update-plugin-credential-harvest.md) | verified | medium | 2026-11-12 |
| [源码隐藏参数：Unicode Bidi 控制符构造不可见 GET 参数名](web-php-unicode-bidi-hidden-get-parameter.md) | verified | high | 2026-11-06 |
| [独角数卡 dujiaoka 管理员口令哈希复现：固定盐 + bcrypt 替换登录](web-php-dujiaoka-admin-password-hash-reproduce.md) | draft | medium | 2026-11-06 |
| [禅道后台 backup/editor 控制器路径穿越与任意路径删除](web-php-zentao-backup-editor-arbitrary-file-delete.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
