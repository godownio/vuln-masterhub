---
title: 文件上传
weight: 1
---

# 文件上传

## 这层是什么

上传绕过、解析漏洞、竞争与二次利用。

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
| [.htaccess auto_append_file + php://filter base64-decode：上传纯文本实现 PHP 代码执行](web-generic-file-upload-htaccess-auto-append-php-filter-base64/) | verified | high | 2026-11-06 |
| [.NET uploadPicture 无后缀校验覆盖上传：aspx webshell 直接 getshell](web-generic-file-upload-dotnet-uploadpicture-aspx-webshell/) | verified | high | 2026-11-05 |
| [7-Zip 解压符号链接任意文件写入（CVE-2025-55188）写 cron 提权](web-generic-file-upload-7zip-cve-2025-55188-symlink-cron-rce/) | verified | high | 2026-11-06 |
| [AdonisJS bodyparser 上传文件名路径穿越任意文件写](web-generic-file-upload-adonisjs-bodyparser-filename-traversal/) | verified | high | 2026-11-05 |
| [AI 内容检测只扫前 1KB + .htaccess AddType：2KB 填充后上传 PHP webshell](web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell/) | verified | high | 2026-11-06 |
| [Apache Ant 1.9.11 ZipSlip：startsWith('../') 用 './../../' 绕过 + 上传 filename 目录穿越覆盖 Enjoy 模板](web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass/) | verified | high | 2026-11-06 |
| [Apache 未禁用 .htaccess 时上传分布式配置，将图片后缀交给 PHP 解析](web-generic-file-upload-htaccess-handler-override/) | verified | high | 2026-11-05 |
| [ASP.NET 头像上传抓包改后缀：aspx 落地 Web 目录 GetShell（响应报路径错误仍可利用）](web-generic-file-upload-aspnet-avatar-extension-aspx-webshell/) | verified | high | 2026-11-05 |
| [Base64 data URI 上传按 MIME 生成后缀：data:image/jsp 落盘 JSP WebShell](web-generic-file-upload-base64-data-uri-extension-jsp/) | verified | high | 2026-11-05 |
| [CCFlow/CCBPM 未授权文件上传：文件名按最后 / 截断、反斜杠穿越并上传 web.config 开启 aspx 解析 RCE](web-generic-file-upload-ccflow-iis-webconfig-aspx/) | verified | high | 2026-11-05 |
| [Cookie 对象注入改 admin + .htaccess 解除 /tmp 403 + PNG 双文件竞态写持久 WebShell](web-generic-file-upload-cookie-admin-htaccess-png-race-webshell/) | verified | high | 2026-11-06 |
| [CRM sendfile.jsp 保留原始后缀上传 JSP（文件名尾空格）直接落地 WebShell](web-generic-file-upload-crm-sendfile-jsp-preserve-suffix/) | verified | high | 2026-11-05 |
| [DedeCMS 后台弱口令 + 模板管理上传改名 .php：WAF 拦截危险函数时用 scandir/array_rand 随机读根目录文件](web-generic-file-upload-dedecms-template-rename-php-waf-fileread/) | verified | medium | 2026-11-06 |
| [EIS 办公平台 bulkinsert_data.aspx 上传：取最后反斜杠后段、正斜杠绕过穿越写入 aspx getshell](web-generic-file-upload-eis-bulkinsert-aspx-filename-traversal/) | verified | high | 2026-11-05 |
| [EMLOG 后台模板 ZIP 上传只校验 header.php 存在，解压后 PHP 落 Web 目录执行](web-generic-file-upload-emlog-template-zip-header-php-rce/) | verified | high | 2026-11-05 |
| [FastCMS 0.1.5 后台模板上传：原始文件名未过滤导致路径穿越任意文件写入](web-generic-file-upload-fastcms-template-upload-filename-traversal/) | verified | medium | 2026-11-05 |
| [FeehiCMS 2.1.1 广告图片上传未校验扩展名：Yii2 saveAs 保留 php 后缀写入 Web 目录 RCE（CVE-2025-65657）](web-generic-file-upload-feehicms-ad-upload-saveas-rce/) | verified | high | 2026-11-05 |
| [FineCMS 会员头像 base64 上传改后缀为 php：注册普通账号即可写 PHP WebShell](web-generic-file-upload-finecms-avatar-base64-php-webshell/) | verified | high | 2026-11-05 |
| [FineVis 主题附件 metadata.name 路径穿越：三步链把上传内容写入 Web 根 getshell（FineVis 插件 2.7.1–2.9.0.2）](web-generic-file-upload-finevis-theme-attach-metadata-path-write/) | verified | high | 2026-11-05 |
| [Gogs ≤0.14.1 LFS 跨仓库 OID 覆盖：上传不校验 SHA-256 导致供应链投毒（CVE-2026-25921）](web-generic-file-upload-gogs-lfs-oid-content-hash-cross-repo-overwrite/) | verified | medium | 2026-11-05 |
| [ImageIO.read 图片校验可被图片马绕过：保留原后缀上传 HTML 形成同源存储型 XSS](web-generic-file-upload-imageio-polyglot-arbitrary-extension/) | verified | high | 2026-11-05 |
| [jeeWMS CgformTemplateController 用 templateCode 控制解压目标目录导致 Zip Slip 写 JSPX](web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode/) | verified | high | 2026-11-05 |
| [jeeWMS CgUploadController 任意扩展名上传配合三种路径回显写 JSPX WebShell](web-generic-file-upload-jeewms-cgupload-extension-upload/) | verified | high | 2026-11-05 |
| [jeeWMS TokenController saveImage 的 fileAddr 路径穿越导致 PUT 任意文件写与 JSPX RCE](web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal/) | verified | high | 2026-11-05 |
| [Keras get_file PATH_MAX 符号链接链绕过 filter_safe_paths：恶意 tar 解压写到缓存目录之外（CVE-2025-12638）](web-generic-file-upload-keras-pathmax-symlink-chain-traversal/) | verified | high | 2026-11-06 |
| [Keras get_file tar 解压 filter_safe_paths 检查顺序缺陷：符号链接条目绕过过滤逃逸解压目录](web-generic-file-upload-keras-tar-filter-symlink-check-order-bypass/) | verified | high | 2026-11-06 |
| [Langflow /api/v2/files 文件名路径穿越导致任意文件写入与 RCE（CVE-2026-5027）](web-generic-file-upload-langflow-v2-filename-traversal-arbitrary-write/) | verified | high | 2026-11-05 |
| [Laravel 未鉴权图片上传接口扩展名零校验：原始后缀落盘 public 目录写入 PHP WebShell](web-generic-file-upload-laravel-unauth-uploadphoto-extension-webshell/) | verified | high | 2026-11-05 |
| [MAKU 低代码平台 /sys/file/upload 无后缀校验任意文件上传导致 HTML 存储型 XSS](web-generic-file-upload-maku-lowcode-no-extension-html-xss/) | verified | high | 2026-11-05 |
| [MES 上传接口信任 uploadFileName：任意后缀 + 目录穿越写入 JSP（uploadImages/uploadFile）](web-generic-file-upload-mes-uploadfilename-arbitrary-jsp/) | verified | high | 2026-11-05 |
| [Monsta FTP 未授权 downloadFile 从攻击者 FTP 下载并写入任意 localPath 落地 webshell](web-generic-file-upload-monsta-ftp-unauth-download-write/) | verified | medium | 2026-11-05 |
| [move_uploaded_file 归一化尾部 /. 与 \\.，配合数组文件名绕过白名单](web-generic-file-upload-move-uploaded-file-trailing-dot/) | verified | high | 2026-11-05 |
| [multipart filename 路径穿越：PUT /file_upload 写任意路径并植入 SSH authorized_keys](web-generic-file-upload-multipart-filename-traversal-ssh-key/) | verified | high | 2026-11-05 |
| [NewBeeMall /;/admin/upload/file 未校验后缀上传 JSP：分号绕过后台鉴权后任意文件落 Web 根](web-generic-file-upload-newbeemall-admin-upload-jsp/) | verified | medium | 2026-11-05 |
| [NocoDB 附件上传不限 MIME + 三个下载路由零守卫：任意类型文件公开可读与跨用户 IDOR](web-generic-file-upload-nocodb-attachment-unauth-download-idor/) | verified | high | 2026-11-05 |
| [node-tar hardlink linkpath 未做边界校验：解压目录内文件名绑定外部 inode 导致任意文件读写（CVE-2026-24842）](web-generic-file-upload-node-tar-hardlink-linkpath-traversal/) | verified | high | 2026-11-05 |
| [OA JSF 上传：getFieldName 拼入保存名 + 原始文件名后缀可控，路径穿越写 JSP](web-generic-file-upload-oa-jsf-transferdata-attachfile-getfieldname-traversal/) | verified | high | 2026-11-05 |
| [OA 三处上传：原始文件名/后缀可控 + skey 伪造写入 JSP（filecase/netdisk/notice）](web-generic-file-upload-oa-skey-filecase-netdisk-notice/) | verified | high | 2026-11-05 |
| [PHP 空字节截断上传保存路径：GET 解码 %00 或 POST 注入原始 NUL](web-generic-file-upload-null-byte-path-truncation/) | verified | medium | 2026-11-05 |
| [pluck CMS 4.7.16 后台主题 ZIP 上传执行 info.php 写 Webshell（CVE-2022-26965）](web-generic-file-upload-pluck-cve-2022-26965-theme-zip-info-php-rce/) | verified | high | 2026-11-05 |
| [RootHub CommonController 上传：customPath 未校验导致任意目录写入且不限制文件后缀](web-generic-file-upload-roothub-custompath-traversal-no-extension/) | verified | medium | 2026-11-05 |
| [Spring MVC 上传接口 UUID 重命名但保留原始后缀：跳过扩展名校验的 JSP 任意文件上传](web-generic-file-upload-spring-uuid-preserve-original-extension/) | verified | medium | 2026-11-05 |
| [Spring 上传接口 tempPath + getOriginalFilename 直接拼接：../ 穿越写 JSP 到 Tomcat webapps getshell](web-generic-file-upload-spring-temppath-original-filename-traversal-jsp/) | verified | high | 2026-11-05 |
| [ThinkPHP5 后台未授权 ZIP 上传 + Update/unzip 任意解压：压缩包内 public/shell.php 落 Web 根 RCE](web-generic-file-upload-thinkphp-admin-upload-unzip-webshell/) | verified | high | 2026-11-05 |
| [UEditor filePathFormat 模板目录穿越导致任意路径文件写](web-generic-file-upload-ueditor-filepathformat-traversal/) | verified | high | 2026-11-05 |
| [UEditor 默认 fileAllowFiles 白名单包含 .xml，上传脚本文件导致同源存储型 XSS](web-generic-file-upload-ueditor-default-whitelist-xml-xss/) | verified | medium | 2026-11-05 |
| [uploadPicture_qt.jsp 未授权上传：RandomFileRenamePolicy 保留原始后缀写入 Web 目录](web-generic-file-upload-uploadpictureqt-rename-policy-jsp/) | verified | medium | 2026-11-05 |
| [WordPress WP-DownloadManager <=1.68.11 download-add.php 上传无后缀校验：管理员上传 PHP 直接执行（CVE-2025-10747）](web-generic-file-upload-wordpress-wp-downloadmanager-addfile-no-extension-check/) | verified | high | 2026-11-05 |
| [WordPress WPCargo 插件未授权文件上传写 WebShell（CVE-2021-25003）](web-generic-file-upload-wordpress-wpcargo-cve-2021-25003/) | verified | high | 2026-11-05 |
| [YiFangCMS ≤2.0.5 /api/file/webUploader 分片合并上传：uploadPath/md5value/name 可控写任意 PHP 文件 RCE（CVE-2025-9400）](web-generic-file-upload-yifangcms-webuploader-chunk-merge-rce/) | verified | high | 2026-11-05 |
| [Zip Slip 覆盖服务端模板泄露隐藏上下文变量：上传压缩包写 memo.html 后 {{flag}} 直接渲染](web-generic-file-upload-zipslip-template-overwrite-context-variable-leak/) | verified | high | 2026-11-06 |
| [ZIP 条目名 NUL 截断：白名单看到 .pdf，Windows 解压落盘为 evil.php](web-generic-file-upload-zip-entry-nul-windows-truncation/) | verified | high | 2026-11-05 |
| [Zip 解压目录穿越（Zip Slip）写入 Web 根目录实现 RCE](web-generic-file-upload-zip-slip-webshell-write/) | verified | high | 2026-11-05 |
| [上传 SVG 经服务端缩略图转换读取本地文件：ImageMagick text: 协议任意文件读取](web-generic-file-upload-svg-imagemagick-text-protocol-file-read/) | verified | high | 2026-11-06 |
| [上传仅按文件名后缀弱校验，改后缀即可落地任意类型文件](web-generic-file-upload-weak-suffix-bypass/) | verified | low | 2026-11-04 |
| [上传扩展名零校验导致 webshell 落盘](web-generic-file-upload-extension-zero-check/) | draft | high | 2026-11-04 |
| [上传接口不校验内容与类型且原始文件名含 ../：穿越写 JSP 到 Tomcat webapps](web-generic-file-upload-upload1-filename-traversal-jsp-webroot/) | verified | high | 2026-11-05 |
| [上传接口把 allow 参数当扩展名白名单：请求传 allow=php 直接上传 PHP WebShell](web-generic-file-upload-upload-allow-param-whitelist-bypass/) | verified | high | 2026-11-05 |
| [上传文件名目录穿越：单次 replace("../","") 用 ..././ 还原绕过](web-generic-file-upload-single-replace-dotdot-bypass/) | verified | high | 2026-11-05 |
| [上传点接受 PHP 但明文 WebShell 被查杀，改用加密 WebShell 落地](web-generic-file-upload-encrypted-webshell-av-bypass/) | verified | medium | 2026-11-04 |
| [上传白名单放行 ipa：IPA 自解压把包内 JSP 释放到 Web 目录 getshell](web-generic-file-upload-ipa-autounzip-jsp-webshell/) | verified | high | 2026-11-05 |
| [上传落地即删场景：分离密钥 XOR loader + 蚁剑自定义编码器落地 WebShell](web-generic-file-upload-xor-split-key-loader-antsword/) | verified | high | 2026-11-05 |
| [东胜物流两处任意文件上传：FileInputHandler/Upload 与 MsWl_HaierMain/File 均不做扩展名白名单](web-generic-file-upload-dongsheng-logistics-extension-no-check/) | verified | medium | 2026-11-06 |
| [九垠赢系统 Common.ashx uploadtemppicture 未授权上传 ASPX 并执行](web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx/) | draft | high | 2026-11-05 |
| [亿赛通 CDG uploadSoftWareFile 的 patch 参数未校验路径穿越写入 WebShell](web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell/) | verified | high | 2026-11-05 |
| [仅前端 JavaScript 校验上传后缀，禁用脚本、改包或断点修改白名单均可绕过](web-generic-file-upload-clientside-js-whitelist-bypass/) | verified | high | 2026-11-05 |
| [任意后缀上传 HTML 到 Web 静态目录形成同源存储型 XSS](web-generic-file-upload-html-static-stored-xss/) | verified | high | 2026-11-05 |
| [先落盘后校验的删除竞态：上传并抢访问生成持久 WebShell](web-generic-file-upload-save-then-validate-race/) | verified | medium | 2026-11-05 |
| [前端 RC4+MD5 上传签名伪造：从源码取密钥后上传 phtml webshell](web-generic-file-upload-frontend-rc4-md5-signature-forge/) | verified | medium | 2026-11-06 |
| [压缩包内软链接解压导致任意文件读取与写入](web-generic-file-upload-archive-symlink-extract-read-write/) | verified | high | 2026-11-05 |
| [后端仅信任 multipart 的 Content-Type 判断类型，改包即可上传脚本](web-generic-file-upload-content-type-trust-bypass/) | verified | high | 2026-11-05 |
| [图片二次渲染上传：把 PHP 载荷写进渲染后仍保留的像素/数据块](web-generic-file-upload-image-render-payload-survival/) | verified | medium | 2026-11-05 |
| [图片头 + ZIP 多语义上传：GIF89a 伪装压缩包，软链接解压读 /flag](web-generic-file-upload-image-zip-polyglot-symlink-read/) | verified | high | 2026-11-06 |
| [对象存储预签名 URL 覆盖 response-content-type 把上传文件当 HTML 渲染的存储型 XSS](web-generic-file-upload-presigned-url-response-content-type-xss/) | verified | medium | 2026-11-05 |
| [小智 ESP32 管理平台：/api/file/upload 仅取原始后缀且无类型校验，任意文件落 Web 可访问 uploads 目录](web-generic-file-upload-xiaozhi-upload-any-extension-webroot/) | verified | medium | 2026-11-05 |
| [帝国CMS 7.5 后台导入系统模型上传 .mod 执行 PHP 写 Webshell](web-generic-file-upload-empirecms-model-import-mod-php-rce/) | verified | high | 2026-11-05 |
| [文件头魔数只比对前 4 字节，GIF89a 前缀即可夹带 PHP 代码](web-generic-file-upload-magic-byte-gif-prefix-bypass/) | verified | high | 2026-11-05 |
| [未授权文件上传接口导致对象存储同名对象覆盖](web-generic-file-upload-unauth-object-storage-overwrite/) | verified | high | 2026-11-05 |
| [未授权文件管理接口：上传/读取/删除三权裸奔](web-generic-file-upload-unauth-file-management-upload-read-delete/) | verified | high | 2026-11-05 |
| [未鉴权文件上传叠加 ThinkPHP 调试异常页变量泄露落盘路径 getshell](web-generic-file-upload-thinkphp-debug-error-path-leak/) | verified | high | 2026-11-05 |
| [模板上传 relativePath 与原始文件名直拼路径：任意目录、任意后缀文件写入](web-generic-file-upload-template-relative-path-original-filename-arbitrary-write/) | verified | high | 2026-11-06 |
| [模板批量导入 batchImport Zip Slip：条目名 ../ 穿越写任意文件](web-generic-file-upload-template-batchimport-zipslip-arbitrary-write/) | verified | high | 2026-11-06 |
| [用户资料更新接口不校验上传类型，保留原名落盘 Web 目录写 WebShell](web-generic-file-upload-user-controlled-filename-webshell/) | verified | high | 2026-11-05 |
| [禅道 importMiniProgram 后台 zip 解压不校验文件名：并发绕过即时删除写入 PHP 并 RCE](web-generic-file-upload-zentao-importminiprogram-zip-extract-race/) | verified | high | 2026-11-05 |
| [黑名单关键字被替换为空时，双写 php 使过滤后恢复可解析后缀](web-generic-file-upload-blacklist-double-write-bypass/) | verified | high | 2026-11-05 |
| [黑名单漏掉 Apache 默认 PHP 解析后缀，phtml/pht/php3 可直接执行](web-generic-file-upload-apache-alternate-php-extension/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
