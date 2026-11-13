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
| [.NET ashx 处理器参数未知时的突破：从前端 JS 配置读出 method 分发值，未授权 DoWebUpload 直接落 aspx webshell](web-generic-file-upload-ashx-method-dispatch-frontend-js-unauth-aspx/) | verified | high | 2026-11-08 |
| [.NET MVC 上传黑名单只拦 .asp/.aspx：.ashx/.cshtml/.asmx 等 IIS 可解析扩展绕过](web-generic-file-upload-dotnet-blacklist-only-asp-aspx/) | verified | medium | 2026-11-07 |
| [.NET uploadPicture 无后缀校验覆盖上传：aspx webshell 直接 getshell](web-generic-file-upload-dotnet-uploadpicture-aspx-webshell/) | verified | high | 2026-11-05 |
| [.NET 分片上传 Chunked 接口 pathkey/filename 可控：无扩展名校验合并写入 aspx webshell](web-generic-file-upload-dotnet-chunked-pathkey-filename-aspx-webshell/) | verified | high | 2026-11-07 |
| [7-Zip 解压符号链接任意文件写入（CVE-2025-55188）写 cron 提权](web-generic-file-upload-7zip-cve-2025-55188-symlink-cron-rce/) | verified | high | 2026-11-06 |
| [AdonisJS bodyparser 上传文件名路径穿越任意文件写](web-generic-file-upload-adonisjs-bodyparser-filename-traversal/) | verified | high | 2026-11-05 |
| [AI 内容检测只扫前 1KB + .htaccess AddType：2KB 填充后上传 PHP webshell](web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell/) | verified | high | 2026-11-06 |
| [Apache Ant 1.9.11 ZipSlip：startsWith('../') 用 './../../' 绕过 + 上传 filename 目录穿越覆盖 Enjoy 模板](web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass/) | verified | high | 2026-11-06 |
| [Apache 未禁用 .htaccess 时上传分布式配置，将图片后缀交给 PHP 解析](web-generic-file-upload-htaccess-handler-override/) | verified | high | 2026-11-05 |
| [Artery ERP FormStudioUpdater#uploadStudioFile 任意文件写入：XML 的 filename/filepath 穿越写 jspx](web-generic-file-upload-artery-erp-formstudioupdater-uploadstudiofile/) | verified | medium | 2026-11-07 |
| [Artery ERP 两处未授权文件上传：DiskFileItemFactory 不校验后缀，jspx 落入 webapps/ROOT/attachments](web-generic-file-upload-artery-erp-servletupload-phoneupload/) | verified | high | 2026-11-07 |
| [ASP.NET 头像上传抓包改后缀：aspx 落地 Web 目录 GetShell（响应报路径错误仍可利用）](web-generic-file-upload-aspnet-avatar-extension-aspx-webshell/) | verified | high | 2026-11-05 |
| [Base64 data URI 上传按 MIME 生成后缀：data:image/jsp 落盘 JSP WebShell](web-generic-file-upload-base64-data-uri-extension-jsp/) | verified | high | 2026-11-05 |
| [BossCMS ueditor 附件上传白名单取自可配置 upload_extension：加入 .php 后经 code 分组校验落盘 getshell](web-generic-file-upload-bosscms-ueditor-upload-extension-code-php/) | verified | high | 2026-11-13 |
| [BuildAdmin 模块市场安装包 info.ini 的 uid 路径穿越：解压目录可控导致任意目录写 PHP getshell](web-generic-file-upload-buildadmin-module-ini-uid-traversal/) | verified | medium | 2026-11-11 |
| [CCFlow/CCBPM 未授权文件上传：文件名按最后 / 截断、反斜杠穿越并上传 web.config 开启 aspx 解析 RCE](web-generic-file-upload-ccflow-iis-webconfig-aspx/) | verified | high | 2026-11-05 |
| [CMS 后台 Templates/Modules ZIP 安装只校验包内 info.php 存在：改 info.php 元数据后整包解压落 WebShell](web-generic-file-upload-cms-addon-info-php-zip-installer-rce/) | verified | high | 2026-11-08 |
| [Cookie 对象注入改 admin + .htaccess 解除 /tmp 403 + PNG 双文件竞态写持久 WebShell](web-generic-file-upload-cookie-admin-htaccess-png-race-webshell/) | verified | high | 2026-11-06 |
| [CRM sendfile.jsp 保留原始后缀上传 JSP（文件名尾空格）直接落地 WebShell](web-generic-file-upload-crm-sendfile-jsp-preserve-suffix/) | verified | high | 2026-11-05 |
| [CXF WebService uploadFileByUrl 抓取任意 URL 内容并按自定义 suffix 落盘：远程拉取式上传 getshell](web-generic-file-upload-cxf-webservice-uploadfilebyurl-suffix-webshell/) | verified | high | 2026-11-08 |
| [DedeCMS 后台弱口令 + 模板管理上传改名 .php：WAF 拦截危险函数时用 scandir/array_rand 随机读根目录文件](web-generic-file-upload-dedecms-template-rename-php-waf-fileread/) | verified | medium | 2026-11-06 |
| [DedeCMS 文件管理器上传内容检测绕过：/*<?php ... ?>*/ 逃逸 preg_replace 注释过滤后仍执行 PHP](web-generic-file-upload-dedecms-content-check-comment-wrap-bypass/) | verified | high | 2026-11-12 |
| [DocSys uploadDoc.do 的 path/name 未校验：目录穿越把文件写到 webapps 落地 jsp，新建文件写入接口同样可越界](web-generic-file-upload-docsys-uploaddoc-path-name-traversal-jsp/) | verified | medium | 2026-11-08 |
| [EIS 办公平台 bulkinsert_data.aspx 上传：取最后反斜杠后段、正斜杠绕过穿越写入 aspx getshell](web-generic-file-upload-eis-bulkinsert-aspx-filename-traversal/) | verified | high | 2026-11-05 |
| [EMLOG 后台模板 ZIP 上传只校验 header.php 存在，解压后 PHP 落 Web 目录执行](web-generic-file-upload-emlog-template-zip-header-php-rce/) | verified | high | 2026-11-05 |
| [FastCMS 0.1.5 后台模板上传：原始文件名未过滤导致路径穿越任意文件写入](web-generic-file-upload-fastcms-template-upload-filename-traversal/) | verified | medium | 2026-11-05 |
| [FeehiCMS 2.1.1 广告图片上传未校验扩展名：Yii2 saveAs 保留 php 后缀写入 Web 目录 RCE（CVE-2025-65657）](web-generic-file-upload-feehicms-ad-upload-saveas-rce/) | verified | high | 2026-11-05 |
| [FineCMS 会员头像 base64 上传改后缀为 php：注册普通账号即可写 PHP WebShell](web-generic-file-upload-finecms-avatar-base64-php-webshell/) | verified | high | 2026-11-05 |
| [FineVis 主题附件 metadata.name 路径穿越：三步链把上传内容写入 Web 根 getshell（FineVis 插件 2.7.1–2.9.0.2）](web-generic-file-upload-finevis-theme-attach-metadata-path-write/) | verified | high | 2026-11-05 |
| [Gogs ≤0.14.1 LFS 跨仓库 OID 覆盖：上传不校验 SHA-256 导致供应链投毒（CVE-2026-25921）](web-generic-file-upload-gogs-lfs-oid-content-hash-cross-repo-overwrite/) | verified | medium | 2026-11-05 |
| [GraphQL uploadPaste 任意文件写入：filename 直接拼 WEB_UPLOADDIR，../../../tmp/pwn 写出上传目录](web-generic-file-upload-graphql-uploadpaste-filename-traversal-write/) | verified | high | 2026-11-08 |
| [Guns 后台 sysFileInfo/upload：fileBucket 目录穿越 + 原文件名后缀，把 .exe 写到任意目录（启动项持久化/钓鱼）](web-generic-file-upload-guns-sysfileinfo-filebucket-traversal-exe-write/) | verified | medium | 2026-11-08 |
| [ICPAS addmediadata.php / addmediadatapath.php：POST subpath/fullpath 控制上传目录，move_uploaded_file 任意路径写 PHP](web-generic-file-upload-icpas-addmediadata-fullpath-upload-arbitrary-write/) | verified | high | 2026-11-10 |
| [ICPAS busyscreenshotpush.php：jsondata 的 imagecontent base64 解码后 file_put_contents，callee 控目录、imagename 需 a_b_c.php](web-generic-file-upload-icpas-busyscreenshotpush-base64-file-write/) | verified | high | 2026-11-10 |
| [ICPAS php/addscenedata.php 未校验扩展名：upload 文件名拼入 ../images/scene/ 上传 PHP 直接执行](web-generic-file-upload-icpas-addscenedata-php-webshell/) | verified | medium | 2026-11-07 |
| [ICPAS php/uploadjson.php filename 未过滤：fopen(dirname(dirname(__FILE__))\lan\filename) 路径穿越任意写 webshell](web-generic-file-upload-icpas-uploadjson-path-traversal-arbitrary-write/) | verified | medium | 2026-11-07 |
| [IIS6 分号截断解析：test.asa;1.gif 以图片后缀上传后按 ASP 执行](web-generic-file-upload-iis6-semicolon-truncation-asp/) | verified | medium | 2026-11-10 |
| [IIS6 目录名以 .asp 结尾：123.asp/12.jpg 目录内任意文件按 ASP 解析](web-generic-file-upload-iis6-directory-asp-name-parsing/) | verified | medium | 2026-11-10 |
| [ImageIO.read 图片校验可被图片马绕过：保留原后缀上传 HTML 形成同源存储型 XSS](web-generic-file-upload-imageio-polyglot-arbitrary-extension/) | verified | high | 2026-11-05 |
| [inxedu 上传接口 gok4：允许列表来自请求参数 fileType 且只排除精确 jsp，上传 images.jspx 落 Web 目录](web-generic-file-upload-inxedu-gok4-client-filetype-jspx/) | verified | medium | 2026-11-12 |
| [iweboffice 自定义上传协议（DBSTEP）绕过 WAF：application/x-www-form-urlencoded 正文携带 JSP 与 base64 路径穿越](web-generic-file-upload-iweboffice-dbstep-custom-protocol-waf-bypass/) | verified | medium | 2026-11-10 |
| [jeeWMS CgformTemplateController 用 templateCode 控制解压目标目录导致 Zip Slip 写 JSPX](web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode/) | verified | high | 2026-11-05 |
| [jeeWMS CgUploadController 任意扩展名上传配合三种路径回显写 JSPX WebShell](web-generic-file-upload-jeewms-cgupload-extension-upload/) | verified | high | 2026-11-05 |
| [jeeWMS TokenController saveImage 的 fileAddr 路径穿越导致 PUT 任意文件写与 JSPX RCE](web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal/) | verified | high | 2026-11-05 |
| [JSP jsp:setProperty 属性引号逃逸：name 属性里的 \" 闭合 findAttribute 字符串并注入 Runtime.exec](web-generic-file-upload-jsp-setproperty-attribute-quote-escape/) | verified | medium | 2026-11-10 |
| [JSP jsp:useBean 标签注入：id 属性注入语句 + jsp:setProperty 闭合注释，纯标签反射链执行 Runtime.exec](web-generic-file-upload-jsp-usebean-tag-reflection-injection/) | verified | medium | 2026-11-10 |
| [JSP 上传接口的 uploadPath 由前端传参决定、后缀完全不校验，只做「时间戳+随机数」重命名：把 uploadPath 指到已知可写可访问目录即可落地脚本](web-generic-file-upload-jsp-uploadpath-param-any-extension-timestamp-rename/) | verified | medium | 2026-11-08 |
| [JSP 单/双/三编码绕过 WAF：BOM、XML encoding 与 pageEncoding 分层解码，WAF 看到乱码而容器解出可执行 JSP](web-generic-file-upload-jsp-multi-encoding-pageencoding-waf-bypass/) | verified | medium | 2026-11-10 |
| [JSP/Java Unicode 转义绕过 WAF：Runtime 与多重 u（\uuuu0074）在词法分析前还原关键字](web-generic-file-upload-jsp-java-unicode-escape-waf-bypass/) | verified | high | 2026-11-10 |
| [JSPX/XML 语法绕过 WAF：不存在的标签/PI、CDATA 与数字实体把 Runtime.exec 拆散](web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass/) | verified | medium | 2026-11-10 |
| [JuCheap APPController uploadAttachment 未授权 Base64 上传任意后缀：FileFormat 写 aspx 直接 getshell](web-generic-file-upload-jucheap-app-uploadattachment-base64-aspx/) | verified | high | 2026-11-07 |
| [JuCheap APPController VideoUpLoad 未授权上传：原始文件名后缀直存 UpLoad\EventVideo，仅限制 2MB](web-generic-file-upload-jucheap-app-videoupload-original-extension/) | verified | medium | 2026-11-07 |
| [JuCheap NewsManage/UploadNewsImg 经 IgnoreRightFilter 匿名上传：原始后缀直存 UpLoad\News 返回 aspx 地址](web-generic-file-upload-jucheap-newsmanage-uploadnewsimg-aspx/) | verified | high | 2026-11-07 |
| [Keras get_file PATH_MAX 符号链接链绕过 filter_safe_paths：恶意 tar 解压写到缓存目录之外（CVE-2025-12638）](web-generic-file-upload-keras-pathmax-symlink-chain-traversal/) | verified | high | 2026-11-06 |
| [Keras get_file tar 解压 filter_safe_paths 检查顺序缺陷：符号链接条目绕过过滤逃逸解压目录](web-generic-file-upload-keras-tar-filter-symlink-check-order-bypass/) | verified | high | 2026-11-06 |
| [Langflow /api/v2/files 文件名路径穿越导致任意文件写入与 RCE（CVE-2026-5027）](web-generic-file-upload-langflow-v2-filename-traversal-arbitrary-write/) | verified | high | 2026-11-05 |
| [Laravel 未鉴权图片上传接口扩展名零校验：原始后缀落盘 public 目录写入 PHP WebShell](web-generic-file-upload-laravel-unauth-uploadphoto-extension-webshell/) | verified | high | 2026-11-05 |
| [Likeshop ≤2.5.7.20210311 未授权上传：/api/file/formimage 免登录经 FileServer 存储引擎落地 PHP webshell（CVE-2024-0352）](web-generic-file-upload-likeshop-formimage-unauth-extensionless-php-webshell/) | verified | high | 2026-11-12 |
| [LyLme Spage MIME 信任上传 + 后台更新 copy/zipExtract：任意压缩包解压到站点根 getshell](web-generic-file-upload-lylme-update-zip-extract-rce/) | verified | high | 2026-11-11 |
| [LyLme Spage 后台更新 copy()+zipExtract 用 data:// 伪协议投递内存 ZIP：无需上传点解压到站点根 GetShell（CVE-2023-45952）](web-generic-file-upload-lylme-update-data-wrapper-zip-rce/) | verified | high | 2026-11-13 |
| [MAKU 低代码平台 /sys/file/upload 无后缀校验任意文件上传导致 HTML 存储型 XSS](web-generic-file-upload-maku-lowcode-no-extension-html-xss/) | verified | high | 2026-11-05 |
| [MCMS v5.4.1 后台 uploadTemplate 压缩包上传：添加图片魔数绕过 AOP 的 zip 内后缀检查 + 改写 jsp 文件头绕过 Controller 二次类型检查](web-generic-file-upload-mcms-uploadtemplate-zip-magic-header-jsp/) | verified | medium | 2026-11-09 |
| [MES 上传接口信任 uploadFileName：任意后缀 + 目录穿越写入 JSP（uploadImages/uploadFile）](web-generic-file-upload-mes-uploadfilename-arbitrary-jsp/) | verified | high | 2026-11-05 |
| [MetaCRM 前台 sendsms.jsp / mobileupload.jsp 上传 JSP WebShell（Upload 类 UUID+原始后缀）](web-generic-file-upload-crm-sendsms-mobileupload-jsp/) | verified | high | 2026-11-07 |
| [MetaCRM 后台 softlogo/upload.jsp 无后缀过滤上传 JSP WebShell（绕过全局黑名单）](web-generic-file-upload-crm-softlogo-jsp-no-filter/) | verified | high | 2026-11-07 |
| [Monitorr 1.7.6m CVE-2024-0713：/assets/php/upload.php 仅 getimagesize 校验，JPEG 尾附 PHP 以 .php 后缀上传 getshell](web-generic-file-upload-monitorr-cve-2024-0713-getimagesize-php-polyglot/) | verified | high | 2026-11-12 |
| [Monsta FTP 未授权 downloadFile 从攻击者 FTP 下载并写入任意 localPath 落地 webshell](web-generic-file-upload-monsta-ftp-unauth-download-write/) | verified | medium | 2026-11-05 |
| [move_uploaded_file 归一化尾部 /. 与 \\.，配合数组文件名绕过白名单](web-generic-file-upload-move-uploaded-file-trailing-dot/) | verified | high | 2026-11-05 |
| [multipart filename 与 filePath 参数文件名不一致：WAF 校验 filename=1.txt，后端按 ?filePath=1.jsp 落盘 JSP](web-generic-file-upload-filename-filepath-parameter-mismatch/) | verified | medium | 2026-11-10 |
| [multipart filename 路径穿越：PUT /file_upload 写任意路径并植入 SSH authorized_keys](web-generic-file-upload-multipart-filename-traversal-ssh-key/) | verified | high | 2026-11-05 |
| [Multipart 同一 part 重复 Content-Disposition/filename 绕过 WAF 后缀检测：WAF 取 .txt、后端落 .aspx](web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass/) | verified | medium | 2026-11-08 |
| [NewBeeMall /;/admin/upload/file 未校验后缀上传 JSP：分号绕过后台鉴权后任意文件落 Web 根](web-generic-file-upload-newbeemall-admin-upload-jsp/) | verified | medium | 2026-11-05 |
| [NginxWebUI addOver Zip Slip：hutool ZipUtil 不校验条目 ../ + hasDir 重名检查用 id/未用目录绕过](web-generic-file-upload-nginxwebui-addover-zipslip-hasdir-bypass/) | verified | high | 2026-11-10 |
| [NginxWebUI 后台任意文件上传 + addOver 任意解压目录：把 authorized_keys 解压进 ~/.ssh 获得 SSH 登录](web-generic-file-upload-nginxwebui-addover-arbitrary-unzip-ssh-key/) | verified | high | 2026-11-10 |
| [NocoDB 附件上传不限 MIME + 三个下载路由零守卫：任意类型文件公开可读与跨用户 IDOR](web-generic-file-upload-nocodb-attachment-unauth-download-idor/) | verified | high | 2026-11-05 |
| [node-tar hardlink linkpath 未做边界校验：解压目录内文件名绑定外部 inode 导致任意文件读写（CVE-2026-24842）](web-generic-file-upload-node-tar-hardlink-linkpath-traversal/) | verified | high | 2026-11-05 |
| [OA JSF 上传：getFieldName 拼入保存名 + 原始文件名后缀可控，路径穿越写 JSP](web-generic-file-upload-oa-jsf-transferdata-attachfile-getfieldname-traversal/) | verified | high | 2026-11-05 |
| [OA 三处上传：原始文件名/后缀可控 + skey 伪造写入 JSP（filecase/netdisk/notice）](web-generic-file-upload-oa-skey-filecase-netdisk-notice/) | verified | high | 2026-11-05 |
| [OTA 升级包脚本注入：上传篡改 check.sh/ota.sh 的更新包，发布即执行 RCE](web-generic-file-upload-ota-package-script-injection-rce/) | verified | high | 2026-11-07 |
| [PHP CGI/FastCGI pathinfo 解析：1.jpg/.php 让图片文件按 PHP 执行](web-generic-file-upload-php-cgi-pathinfo-jpg-php-parsing/) | verified | medium | 2026-11-10 |
| [PHP UploadFile 魔术方法 __set 只认 config 已有键：业务写 $upload->exts 被静默丢弃（正确键 allowExts），白名单为空导致任意文件上传](web-generic-file-upload-php-uploadfile-exts-allowexts-set-ignored/) | verified | high | 2026-11-11 |
| [PHP 上传接口 MD5 签名校验：硬编码 token 导致签名可伪造 + notify 回调外带上传路径](web-generic-file-upload-php-md5-sign-hardcoded-token-notify-path/) | verified | high | 2026-11-11 |
| [PHP 空字节截断上传保存路径：GET 解码 %00 或 POST 注入原始 NUL](web-generic-file-upload-null-byte-path-truncation/) | verified | medium | 2026-11-05 |
| [pluck CMS 4.7.16 后台主题 ZIP 上传执行 info.php 写 Webshell（CVE-2022-26965）](web-generic-file-upload-pluck-cve-2022-26965-theme-zip-info-php-rce/) | verified | high | 2026-11-05 |
| [PNG 头 + MPEG-TS 拼接 polyglot 伪装图片绕过上传校验并盗用 OSS 视频流量](web-generic-file-upload-png-ts-polyglot-oss-video-freeride/) | verified | medium | 2026-11-07 |
| [RootHub CommonController 上传：customPath 未校验导致任意目录写入且不限制文件后缀](web-generic-file-upload-roothub-custompath-traversal-no-extension/) | verified | medium | 2026-11-05 |
| [Spring MVC 上传接口 UUID 重命名但保留原始后缀：跳过扩展名校验的 JSP 任意文件上传](web-generic-file-upload-spring-uuid-preserve-original-extension/) | verified | medium | 2026-11-05 |
| [Spring 上传接口 tempPath + getOriginalFilename 直接拼接：../ 穿越写 JSP 到 Tomcat webapps getshell](web-generic-file-upload-spring-temppath-original-filename-traversal-jsp/) | verified | high | 2026-11-05 |
| [Spring 上传接口把 getOriginalFilename 拼到 catalina.home/webapps/ROOT：无后缀校验直接落 JSP webshell](web-generic-file-upload-catalina-webapps-root-original-filename-jsp/) | verified | high | 2026-11-07 |
| [ThinkPHP5 后台未授权 ZIP 上传 + Update/unzip 任意解压：压缩包内 public/shell.php 落 Web 根 RCE](web-generic-file-upload-thinkphp-admin-upload-unzip-webshell/) | verified | high | 2026-11-05 |
| [Tmall_demo 前台头像上传 UUID 重命名保留客户端后缀：JSP 哥斯拉马写入 Web 目录并解析](web-generic-file-upload-tmall-avatar-uuid-extension-jsp-getshell/) | verified | high | 2026-11-07 |
| [Traccar 5.9 后台路径穿越任意文件写：覆盖 templates/full/passwordReset.vm，触发密码重置渲染 Velocity 载荷 RCE](web-generic-file-upload-traccar-path-traversal-template-overwrite-rce/) | verified | high | 2026-11-13 |
| [UEditor .NET catchimage source[] 抓取远端文件落 upload 目录：source 后缀可控写入 aspx webshell](web-generic-file-upload-ueditor-net-catchimage-source-remote-write-aspx/) | verified | medium | 2026-11-08 |
| [UEditor .NET controller.ashx uploadfile 只校验 ContentType：改后缀上传 aspx webshell](web-generic-file-upload-ueditor-net-controller-contenttype-aspx/) | verified | medium | 2026-11-07 |
| [UEditor filePathFormat 模板目录穿越导致任意路径文件写](web-generic-file-upload-ueditor-filepathformat-traversal/) | verified | high | 2026-11-05 |
| [UEditor 默认 fileAllowFiles 白名单包含 .xml，上传脚本文件导致同源存储型 XSS](web-generic-file-upload-ueditor-default-whitelist-xml-xss/) | verified | medium | 2026-11-05 |
| [uploadbase64.php 的 data URI 上传：image/php 子类型被直接拼成 .php 后缀写入 Web 目录](web-generic-file-upload-base64-data-uri-subtype-php-webshell/) | verified | high | 2026-11-08 |
| [uploadPicture_qt.jsp 未授权上传：RandomFileRenamePolicy 保留原始后缀写入 Web 目录](web-generic-file-upload-uploadpictureqt-rename-policy-jsp/) | verified | medium | 2026-11-05 |
| [WebOffice OfficeServer.php 暴露在静态目录：FormData 控制 OPTION=LOADFILE/SAVEFILE 任意文件读 + 任意写 getshell](web-generic-file-upload-weboffice-officeserver-loadfile-savefile-arbitrary-read-write/) | verified | high | 2026-11-11 |
| [WeiPHP 5.0 前台 upload_root 未授权上传：只 ban php 后缀，phtml/末尾空格绕过直接 getshell](web-generic-file-upload-weiphp5-file-upload-root-noauth-extension-bypass/) | verified | high | 2026-11-12 |
| [Windows Defender 进程链查杀下 WebShell 命令无回显：Unable to fork 的排查与改用大马 Web 层执行](web-generic-file-upload-defender-process-chain-webshell-command-block/) | verified | high | 2026-11-11 |
| [Windows NTFS ::$data 后缀绕过文件上传黑名单：校验看到 php::$data，访问 shell.php 仍被解析](web-generic-file-upload-windows-ntfs-data-stream-extension-bypass/) | verified | high | 2026-11-11 |
| [WordPress WP-DownloadManager <=1.68.11 download-add.php 上传无后缀校验：管理员上传 PHP 直接执行（CVE-2025-10747）](web-generic-file-upload-wordpress-wp-downloadmanager-addfile-no-extension-check/) | verified | high | 2026-11-05 |
| [WordPress WPBookit <=1.0.4 未授权任意文件上传（CVE-2025-6058）：add_booking_type 的 cover_image_img 先 move 后校验](web-generic-file-upload-wordpress-wpbookit-cve-2025-6058/) | verified | high | 2026-11-07 |
| [WordPress WPCargo 插件未授权文件上传写 WebShell（CVE-2021-25003）](web-generic-file-upload-wordpress-wpcargo-cve-2021-25003/) | verified | high | 2026-11-05 |
| [WordPress 后台 Miscellaneous「Allow File Uploads」+ Allowed file extensions 加 php：管理员会话直接上传 PHP 到 wp-content 执行](web-generic-file-upload-wordpress-misc-allow-php-extension-upload/) | verified | high | 2026-11-08 |
| [XML 上传 XHTML 命名空间 <prefix:script> + javascript: 标签语法：绕过扩展限制的存储型 XSS](web-generic-file-upload-xml-xhtml-namespace-script-xss/) | verified | high | 2026-11-07 |
| [YiFangCMS ≤2.0.5 /api/file/webUploader 分片合并上传：uploadPath/md5value/name 可控写任意 PHP 文件 RCE（CVE-2025-9400）](web-generic-file-upload-yifangcms-webuploader-chunk-merge-rce/) | verified | high | 2026-11-05 |
| [Zip Slip 覆盖服务端模板泄露隐藏上下文变量：上传压缩包写 memo.html 后 {{flag}} 直接渲染](web-generic-file-upload-zipslip-template-overwrite-context-variable-leak/) | verified | high | 2026-11-06 |
| [ZIP 条目名 NUL 截断：白名单看到 .pdf，Windows 解压落盘为 evil.php](web-generic-file-upload-zip-entry-nul-windows-truncation/) | verified | high | 2026-11-05 |
| [Zip 解压目录穿越（Zip Slip）写入 Web 根目录实现 RCE](web-generic-file-upload-zip-slip-webshell-write/) | verified | high | 2026-11-05 |
| [万户OA FileUploadAction 任意文件上传：/defaultroot/upload/fileUpload 保留原始后缀写 Web 目录](web-generic-file-upload-whir-ezoffice-fileupload-action-extension/) | verified | high | 2026-11-07 |
| [三段式文件上传（fileId 关联）在文件名元数据处路径穿越，跨目录写系统根目录](web-generic-file-upload-multi-step-fileid-filename-traversal/) | verified | high | 2026-11-09 |
| [上传 .shtml 借 Apache 既有 SSI 配置执行命令：上传只挡 php 后缀时用 shtml 写 WebShell](web-generic-file-upload-shtml-apache-ssi-exec/) | verified | high | 2026-11-12 |
| [上传 JAR 利用 Servlet 3.0 META-INF/resources 直接访问：jar 内 JSP 作为静态资源被容器映射执行](web-generic-file-upload-jar-meta-inf-resources-jsp-carrier/) | verified | medium | 2026-11-10 |
| [上传 SVG 图片触发同源存储型 XSS：<svg><script>alert()</script></svg> 被当作图片放行](web-generic-file-upload-svg-inline-script-stored-xss/) | verified | high | 2026-11-08 |
| [上传 SVG 经服务端缩略图转换读取本地文件：ImageMagick text: 协议任意文件读取](web-generic-file-upload-svg-imagemagick-text-protocol-file-read/) | verified | high | 2026-11-06 |
| [上传仅按文件名后缀弱校验，改后缀即可落地任意类型文件](web-generic-file-upload-weak-suffix-bypass/) | verified | low | 2026-11-04 |
| [上传内容前后填充大量垃圾标记绕过 WAF 内容检测：300 段 <!*...*!> 包裹 ASPX webshell 落盘](web-generic-file-upload-waf-junk-padding-aspx-content-bypass/) | verified | medium | 2026-11-08 |
| [上传后缀黑名单只列脚本后缀、漏掉 html 家族：同源 uploads 目录落地存储型 XSS](web-generic-file-upload-upload-blacklist-miss-html-family-stored-xss/) | verified | high | 2026-11-08 |
| [上传扩展名零校验导致 webshell 落盘](web-generic-file-upload-extension-zero-check/) | draft | high | 2026-11-04 |
| [上传扩展名黑名单精确 equals 未 trim：filename 尾空格绕过并保留 .jsp 落地](web-generic-file-upload-extension-blacklist-trailing-space/) | verified | medium | 2026-11-07 |
| [上传接口不校验内容与类型且原始文件名含 ../：穿越写 JSP 到 Tomcat webapps](web-generic-file-upload-upload1-filename-traversal-jsp-webroot/) | verified | high | 2026-11-05 |
| [上传接口把 allow 参数当扩展名白名单：请求传 allow=php 直接上传 PHP WebShell](web-generic-file-upload-upload-allow-param-whitelist-bypass/) | verified | high | 2026-11-05 |
| [上传接口用 base64 name 字段决定落盘名、扩展名白名单只看上传文件名：cmd.php.jpg 落成 cmd.php](web-generic-file-upload-supercms-base64-name-rename-php/) | verified | low | 2026-11-12 |
| [上传文件名固定长度截断绕过后缀校验：.aspx 放进保留前缀、末尾补 .txt 落盘为 ASPX](web-generic-file-upload-filename-fixed-length-truncation-aspx/) | verified | high | 2026-11-08 |
| [上传文件名目录穿越：单次 replace("../","") 用 ..././ 还原绕过](web-generic-file-upload-single-replace-dotdot-bypass/) | verified | high | 2026-11-05 |
| [上传文件的签名访问接口 302 Location 泄露真实存储路径：以 ShowDoc visitFile 为例](web-generic-file-upload-signed-visit-302-path-disclosure/) | verified | high | 2026-11-08 |
| [上传文件缺 Content-Type 触发浏览器 MIME 嗅探：怪异文件名落地同源 HTML/JS 执行](web-generic-file-upload-mime-sniffing-no-content-type-xss/) | verified | low | 2026-11-07 |
| [上传校验用 end() 取扩展名、用 [count()-1] 拼文件名：PHP 数组插入顺序与数字键错位绕过白名单保存为 .php](web-generic-file-upload-php-array-end-count-order-bypass/) | verified | high | 2026-11-08 |
| [上传点信任 multipart filename：改后缀为 .jsp 落 Web 目录被 Tomcat 解析 getshell](web-generic-file-upload-multipart-filename-jsp-tomcat-webshell/) | verified | high | 2026-11-08 |
| [上传点接受 PHP 但明文 WebShell 被查杀，改用加密 WebShell 落地](web-generic-file-upload-encrypted-webshell-av-bypass/) | verified | medium | 2026-11-04 |
| [上传白名单放行 ipa：IPA 自解压把包内 JSP 释放到 Web 目录 getshell](web-generic-file-upload-ipa-autounzip-jsp-webshell/) | verified | high | 2026-11-05 |
| [上传目录参数路径穿越写入 /etc/cron.d：cron 自动加载实现 root RCE](web-generic-file-upload-crond-path-traversal-rce/) | verified | high | 2026-11-07 |
| [上传落地即删场景：分离密钥 XOR loader + 蚁剑自定义编码器落地 WebShell](web-generic-file-upload-xor-split-key-loader-antsword/) | verified | high | 2026-11-05 |
| [上传路径二次回显：数据 URI 上传成功后改 GET 请求同一资料接口，从 headpic 字段拿回随机落盘路径](web-generic-file-upload-get-endpoint-returns-upload-path/) | verified | high | 2026-11-12 |
| [上传重命名字段拼接系统 rename/ping 命令导致命令注入 RCE](upload-filename-param-rename-cmdi/) | draft | medium | 2026-11-08 |
| [东胜物流两处任意文件上传：FileInputHandler/Upload 与 MsWl_HaierMain/File 均不做扩展名白名单](web-generic-file-upload-dongsheng-logistics-extension-no-check/) | verified | medium | 2026-11-06 |
| [九垠赢系统 Common.ashx uploadtemppicture 未授权上传 ASPX 并执行](web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx/) | draft | high | 2026-11-05 |
| [云时空 ERP /servlet/fileupload/gpy 未授权任意文件上传：手写 multipart 不用扩展名白名单，JSP 落 uploads/pics 日期目录](web-generic-file-upload-yunshikong-erp-gpy-servlet-unauth-jsp/) | verified | medium | 2026-11-11 |
| [亿赛通 CDG hiddenWatermark uploadFile：鉴权排除 + 解压 Zip Slip 任意写 Web 目录 JSP](web-generic-file-upload-esafenet-hiddenwatermark-zipslip-webshell/) | verified | high | 2026-11-12 |
| [亿赛通 CDG uploadSoftWareFile 的 patch 参数未校验路径穿越写入 WebShell](web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell/) | verified | high | 2026-11-05 |
| [亿赛通 UploadFileFromClientServiceForClient：query 参数 a 经 CDGUtil.decode 还原 fileName，未过滤后缀与 ../ 直接写 JSP](web-generic-file-upload-esafenet-uploadfilefromclient-filename-traversal/) | verified | medium | 2026-11-13 |
| [仅前端 JavaScript 校验上传后缀，禁用脚本、改包或断点修改白名单均可绕过](web-generic-file-upload-clientside-js-whitelist-bypass/) | verified | high | 2026-11-05 |
| [任意后缀上传 HTML 到 Web 静态目录形成同源存储型 XSS](web-generic-file-upload-html-static-stored-xss/) | verified | high | 2026-11-05 |
| [保留图片后缀改 Content-Type 为 text/html 使上传文件被浏览器解析为 HTML](content-type-confusion-html-xss-upload/) | draft | high | 2026-11-08 |
| [信呼 OA 上传 + task.php?m=qcloudCos|runt&fileid 触发临时文件重命名为 .php：登录态两次请求即 getshell](web-generic-file-upload-xinhu-oa-qcloudcos-runt-fileid-upload-exec/) | verified | high | 2026-11-08 |
| [信呼OA v2.6.3 openkqj api headpic：base64 内容写入 UPDIR/face/kqj{snid}_u{uid}.jpg，sn/ccid 可控得到已知文件名任意文件写](web-generic-file-upload-xinhu-openkqj-headpic-controlled-filename-write/) | verified | high | 2026-11-08 |
| [先落盘后校验的删除竞态：上传并抢访问生成持久 WebShell](web-generic-file-upload-save-then-validate-race/) | verified | medium | 2026-11-05 |
| [免登录 /File/UploadFile 由 storagetype 头分发到 LocalStorage，路径由 basepath+vguid 拼接、扩展名黑名单漏掉 .ashx](web-generic-file-upload-noauth-storage-factory-header-dispatch-ashx-blacklist/) | verified | medium | 2026-11-08 |
| [凡诺CMS 2.1 upload_json.php 任意文件上传 + IIS `/.php` 路径解析 RCE](web-generic-file-upload-fannuo-cms-upload-json-iis-pathinfo-rce/) | verified | high | 2026-11-07 |
| [前端 RC4+MD5 上传签名伪造：从源码取密钥后上传 phtml webshell](web-generic-file-upload-frontend-rc4-md5-signature-forge/) | verified | medium | 2026-11-06 |
| [压缩包内软链接解压导致任意文件读取与写入](web-generic-file-upload-archive-symlink-extract-read-write/) | verified | high | 2026-11-05 |
| [后台「允许上传文件类型」配置追加 php：管理面自身成为白名单扩容入口](web-generic-file-upload-admin-upload-type-setting-append-php/) | verified | high | 2026-11-08 |
| [后端仅信任 multipart 的 Content-Type 判断类型，改包即可上传脚本](web-generic-file-upload-content-type-trust-bypass/) | verified | high | 2026-11-05 |
| [后缀用 ? 拆分为 a?s?p?x 绕过 WAF 关键字，服务端清理非法字符后还原 .aspx](web-generic-file-upload-question-mark-filename-sanitize-waf-aspx-bypass/) | verified | medium | 2026-11-08 |
| [图片二次渲染上传：把 PHP 载荷写进渲染后仍保留的像素/数据块](web-generic-file-upload-image-render-payload-survival/) | verified | medium | 2026-11-05 |
| [图片头 + ZIP 多语义上传：GIF89a 伪装压缩包，软链接解压读 /flag](web-generic-file-upload-image-zip-polyglot-symlink-read/) | verified | high | 2026-11-06 |
| [图片脏数据前后双向填充绕过主机杀软：只填一侧无效，前后都填后加密 ASP.NET 马落地执行](web-generic-file-upload-image-junk-padding-both-side-av-bypass/) | verified | medium | 2026-11-08 |
| [对象存储预签名 URL 覆盖 response-content-type 把上传文件当 HTML 渲染的存储型 XSS](web-generic-file-upload-presigned-url-response-content-type-xss/) | verified | medium | 2026-11-05 |
| [小智 ESP32 管理平台：/api/file/upload 仅取原始后缀且无类型校验，任意文件落 Web 可访问 uploads 目录](web-generic-file-upload-xiaozhi-upload-any-extension-webroot/) | verified | medium | 2026-11-05 |
| [帝国CMS 7.5 后台导入系统模型上传 .mod 执行 PHP 写 Webshell](web-generic-file-upload-empirecms-model-import-mod-php-rce/) | verified | high | 2026-11-05 |
| [恩特客户资源管理系统（ENTER CRM）文件上传三入口：fileupload.jsp 裸流写文件、MailAction saveAttaFile/AppUpload 与 ;.js 后缀黑名单鉴权绕过](web-generic-file-upload-enter-crm-fileupload-mailaction-semicolon-bypass/) | verified | high | 2026-11-13 |
| [文件头魔数只比对前 4 字节，GIF89a 前缀即可夹带 PHP 代码](web-generic-file-upload-magic-byte-gif-prefix-bypass/) | verified | high | 2026-11-05 |
| [新闻发布图片上传点不校验后缀直传 JSP，并用首页图片 src 拼接推出落地路径](web-generic-file-upload-news-publish-jsp-no-suffix-check-homedir-img-src-path/) | verified | medium | 2026-11-08 |
| [智慧云教育平台 /api/upload 拦截器白名单未授权上传：随机名仍保留原始 .jsp 后缀](web-generic-file-upload-wisdom-education-upload-whitelist-jsp/) | verified | medium | 2026-11-07 |
| [未授权文件上传接口导致对象存储同名对象覆盖](web-generic-file-upload-unauth-object-storage-overwrite/) | verified | high | 2026-11-05 |
| [未授权文件管理接口：上传/读取/删除三权裸奔](web-generic-file-upload-unauth-file-management-upload-read-delete/) | verified | high | 2026-11-05 |
| [未鉴权文件上传叠加 ThinkPHP 调试异常页变量泄露落盘路径 getshell](web-generic-file-upload-thinkphp-debug-error-path-leak/) | verified | high | 2026-11-05 |
| [来客（LKT）电商系统 uploadImg/upload：$_FILES['type'] 经 str_replace('image/','.') 拼成扩展名，后台与未授权 API 均可上传 PHP Getshell](web-generic-file-upload-lkt-uploadimg-type-strreplace-php-webshell/) | verified | high | 2026-11-11 |
| [某 Java HCM 未授权文件上传链：二维码 JSP 置 islogon 登录、uploadLogo.do 回显物理路径、filename 为空绕过全局上传校验任意后缀写文件](web-generic-file-upload-empty-filename-path-concat-bypass/) | verified | high | 2026-11-08 |
| [某协同办公系统上传接口：filename 必须含 @ 且按 @ 分隔为「上传目录+文件名」两段，filename=@1.jsp 直接落 cms/html 目录 getshell](web-generic-file-upload-filename-at-split-dir-filename-upload/) | verified | medium | 2026-11-08 |
| [某广播系统隐藏 jar 服务（独立端口 RESTEasy /api/saveFile）base64 任意文件上传：deviceCode 须有效可经 /api/list 获取、fileName 相对 E:\fileDir 穿越到 Tomcat webapps](web-generic-file-upload-faith-warning-server-savefile-base64-drive-traversal/) | verified | high | 2026-11-08 |
| [某应用云平台 Services/Convert/UploadFile.aspx 任意文件上传：原始文件名直接 SaveAs 到 ~/Upload/Video](web-generic-file-upload-dotnet-ava-convert-uploadfile-saveas/) | verified | medium | 2026-11-07 |
| [模板上传 relativePath 与原始文件名直拼路径：任意目录、任意后缀文件写入](web-generic-file-upload-template-relative-path-original-filename-arbitrary-write/) | verified | high | 2026-11-06 |
| [模板批量导入 batchImport Zip Slip：条目名 ../ 穿越写任意文件](web-generic-file-upload-template-batchimport-zipslip-arbitrary-write/) | verified | high | 2026-11-06 |
| [汇文图书馆系统未授权 /loan/PictureUpload：文件名由 name 参数拼接、后缀取 filename 首个点后内容，jsp 转 txt 可用 1.png.jspx 绕过并目录穿越落 web 根](web-generic-file-upload-libwan-pictureupload-name-concat-firstdot-jspx/) | verified | high | 2026-11-08 |
| [汉王e脸通任意文件上传：UUID + 原始后缀写入 ServletContext /resource，可落地 JSP](web-generic-file-upload-hanvon-eface-original-suffix-resource-jsp/) | verified | medium | 2026-11-07 |
| [泛微 e-office10 welink-move 上传 .phP 大小写绕过 + lang/desc-langs 路径穿越文件包含 RCE](web-generic-file-upload-weaver-eoffice10-welink-move-php-lang-include-rce/) | verified | high | 2026-11-13 |
| [泛微 E10 运维平台未授权上传 PS1 + ms_tools_mv_lib 移动 + updateMaster 触发 PowerShell RCE](web-generic-file-upload-weaver-e10-upload-move-updatemaster-powershell-rce/) | verified | high | 2026-11-07 |
| [泛微云桥 e-Bridge 任意文件上传：同名 multipart 字段覆盖 O'Reilly MultipartRequest files 哈希表绕过 isSafeFile](web-generic-file-upload-weaver-ebridge-multipart-name-overwrite-jsp/) | verified | medium | 2026-11-08 |
| [用户资料更新接口不校验上传类型，保留原名落盘 Web 目录写 WebShell](web-generic-file-upload-user-controlled-filename-webshell/) | verified | high | 2026-11-05 |
| [禅道 importMiniProgram 后台 zip 解压不校验文件名：并发绕过即时删除写入 PHP 并 RCE](web-generic-file-upload-zentao-importminiprogram-zip-extract-race/) | verified | high | 2026-11-05 |
| [融媒体系统 sobey-mchEditor 水印上传未鉴权 + 文件名穿越写 JSP 进 Web 根](web-generic-file-upload-sobey-mcheditor-watermark-filename-traversal-jsp/) | verified | high | 2026-11-07 |
| [通天星 CMSV6 /inspect_file/upload 未授权上传：folderName 拼进 realPath 可目录穿越且不校验后缀，JSP 落 Web 目录 getshell](web-generic-file-upload-cmsv6-inspect-file-upload-folder-traversal/) | verified | high | 2026-11-08 |
| [金和 OA C6 saveAsOtherFormatServlet 任意文件上传：fileName 参数同时决定路径与文件名，FileBlod 内容原样写入 Web 目录 getshell](web-generic-file-upload-jhsoft-saveasotherformatservlet-filename-webshell/) | verified | high | 2026-11-11 |
| [金和 OA C6 UploadFileEditorSave.aspx 的 filename 路径穿越 + 无类型校验：上传 ASP WebShell](web-generic-file-upload-jhsoft-uploadfileeditorsave-path-traversal-asp/) | verified | high | 2026-11-07 |
| [金盘图书馆 OPAC 两处上传保留原始后缀：/opac/shelf/upload 与 /opac/upload/upload 任意扩展名落盘](web-generic-file-upload-goldlib-opac-original-extension-upload/) | verified | high | 2026-11-07 |
| [金蝶云星空 ScpSupRegHandler 尾点空后缀绕过与 ../ 目录穿越任意文件上传](web-generic-file-upload-kingdee-scpsupreghandler-dot-traversal/) | verified | high | 2026-11-12 |
| [雷池 WAF 高防护文件上传绕过：Content-Disposition 畸形 filename、重复 file part 与空格语法造成解析差异](web-generic-file-upload-safeline-multipart-filename-parser-differential/) | verified | high | 2026-11-12 |
| [非标准上传格式：不写 multipart，自定义 filename: 1.jsp 头行 + 正文当文件，只解析标准 multipart 的 WAF 看不到文件](web-generic-file-upload-nonstandard-filename-header-line-parser/) | verified | medium | 2026-11-10 |
| [黑名单关键字被替换为空时，双写 php 使过滤后恢复可解析后缀](web-generic-file-upload-blacklist-double-write-bypass/) | verified | high | 2026-11-05 |
| [黑名单漏掉 Apache 默认 PHP 解析后缀，phtml/pht/php3 可直接执行](web-generic-file-upload-apache-alternate-php-extension/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
