---
title: 通用文件包含
weight: 1
---

# 通用文件包含

## 这层是什么

本地/远程包含、伪协议与日志包含。

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
| [.NET Handler getTxt 的 path 直拼 FileStream：读取 web.config 等任意站点文件](web-generic-file-inclusion-dotnet-handler-gettxt-path-read/) | verified | high | 2026-11-05 |
| [Apache HTTPD CVE-2021-41773/42013：%2e 编码绕过路径规范化，穿越读文件与 cgi-bin RCE](web-generic-file-inclusion-apache-cve-2021-41773-normalize-bypass/) | verified | high | 2026-11-07 |
| [Artery ERP FormStudioUpdater#getStudioFile 任意文件读取：fileStr 只替换斜杠未过滤 ..\ 穿越](web-generic-file-inclusion-artery-erp-formstudioupdater-getstudiofile/) | verified | medium | 2026-11-07 |
| [Artery ERP LoginServlet 用 errorpage 参数做内部转发：op=login 触发异常后读取 /WEB-INF/web.xml](web-generic-file-inclusion-artery-erp-loginservlet-errorpage-forward/) | verified | high | 2026-11-07 |
| [ASP.NET file_down.aspx 的 file 参数直拼 Server.MapPath("../upfile/affix/")：../ 回跳下载源码与任意站点内文件](web-generic-file-inclusion-dotnet-file-down-mappath-traversal/) | verified | high | 2026-11-08 |
| [ASP.NET FileDownload.aspx：README 泄露源码 → XFF 伪造 + Base64 路径穿越读取 web.config 凭据](web-generic-file-inclusion-aspnet-filedownload-xff-base64-traversal/) | verified | high | 2026-11-07 |
| [ASP.NET 报表参数路径遍历读取 web.config：泄露 MachineKey 与敏感配置](web-generic-file-inclusion-aspx-report-param-traversal-webconfig/) | verified | high | 2026-11-05 |
| [BossCMS ueditor action=delete 任意文件删除：path 仅校验 upload/ 前缀，../ 穿越后 dir::delete 直接 unlink](web-generic-file-inclusion-bosscms-ueditor-delete-path-traversal-unlink/) | verified | high | 2026-11-13 |
| [BossCMS ueditor listfile 目录遍历：folder 参数直拼 upload/ 后 opendir/readdir 列出任意目录](web-generic-file-inclusion-bosscms-ueditor-listfile-folder-traversal/) | verified | high | 2026-11-13 |
| [BossCMS 数据备份下载 id 直拼 SYSTEM_PATH/backup/sql/：../../ 穿越 readfile 下载 mysql.ini.php 泄露数据库凭据](web-generic-file-inclusion-bosscms-backup-download-id-traversal-readfile/) | verified | high | 2026-11-13 |
| [chfs（CuteHttpFileServer）/chfs/downloaddir 目录下载路径穿越：../ 逃逸共享根目录读取任意目录](web-generic-file-inclusion-chfs-downloaddir-directory-traversal/) | verified | low | 2026-11-11 |
| [CRM getFile 接口 fileName 与 folder/sCorpName 拼接导致路径穿越任意文件读取](web-generic-file-inclusion-crm-getfile-filename-folder-traversal/) | verified | medium | 2026-11-05 |
| [Django 拨号记录下载接口 szName 拼接路径穿越任意文件读取（16 位 token 门槛）](web-generic-file-inclusion-django-token-download-szname-traversal-read/) | verified | high | 2026-11-05 |
| [DocSys 预览/打开接口 readRealDocContentEx 与删除接口不校验 path：目录穿越任意文件读取与删除](web-generic-file-inclusion-docsys-preview-read-delete-path-traversal/) | verified | medium | 2026-11-08 |
| [FastAPI file_management 的 file 参数路径穿越：以 root 读取 /etc/shadow 与任意文件](web-generic-file-inclusion-fastapi-file-management-traversal/) | verified | high | 2026-11-05 |
| [FE 系统三处 Servlet 参数直入 File/FileInputStream：imagePath、base64 filename 与 pdf 前缀穿越读取](web-generic-file-inclusion-fe-system-servlet-param-arbitrary-read/) | draft | high | 2026-11-05 |
| [FileUploadServlet 的加密 path/filename 解密后直接拼进 File：后台任意文件下载与删除](web-generic-file-inclusion-fileuploadservlet-encrypted-path-download/) | verified | high | 2026-11-08 |
| [Flask send_file 下载接口路径拼接穿越：仅拦 flag/config 关键字时读源码与任意文件](web-generic-file-inclusion-flask-sendfile-download-traversal/) | verified | high | 2026-11-06 |
| [Flowise 未授权任意文件读取：get-upload-file/openai-assistants-file 的 chatId 路径拼接穿越读取 database.sqlite](web-generic-file-inclusion-flowise-get-upload-file-chatid-traversal/) | verified | high | 2026-11-07 |
| [GitLab Repository Commits API 未授权任意文件读取（CVE-2026-85706）：尾斜杠绕过 workhorse 路由并信任 file.path](web-generic-file-inclusion-gitlab-commits-api-file-path-unauth-read/) | verified | high | 2026-11-05 |
| [Go strings.NewReplacer 单次替换 ../ 为空：URL 路径用双写 ....// 还原出 ../ 穿越读取 users.json](web-generic-file-inclusion-go-newreplacer-dotdot-doublewrite-bypass/) | verified | high | 2026-11-08 |
| [Grafana 8.x CVE-2021-43798 插件目录穿越任意文件读取：取 secret_key 解密数据源口令并接管 PostgreSQL](web-generic-file-inclusion-grafana-cve-2021-43798-secretkey-datasource-postgres-rce/) | verified | high | 2026-11-09 |
| [Hoverfly /api/v2/simulation 的 bodyFile 只挡绝对路径：../ 相对路径穿越读任意文件（PUT 可重复读）](web-generic-file-inclusion-hoverfly-simulation-bodyfile-relative-traversal/) | verified | high | 2026-11-08 |
| [ICPAS php/exportrecord.php downname 任意文件下载：双重 URL 解码后直接 fopen/fread 流式输出](web-generic-file-inclusion-icpas-exportrecord-downname-file-download/) | verified | high | 2026-11-10 |
| [ICPAS php/getjson.php jsondata[filename] 路径穿越：读取 Web 目录任意文件](web-generic-file-inclusion-icpas-getjson-path-traversal-read/) | verified | low | 2026-11-07 |
| [Java new File(root, path) + FileUtils.readFileToString 路径穿越读取任意文件](web-generic-file-inclusion-java-new-file-root-path-traversal-read/) | verified | high | 2026-11-05 |
| [Java Path.resolve 绝对路径覆盖：%5c 反斜杠归一化为 / 后读取沙箱内任意文件](web-generic-file-inclusion-java-path-resolve-absolute-override/) | verified | high | 2026-11-06 |
| [JFinalCMS /ajax/html 的 html 参数目录穿越：render 模板路径拼接导致未授权任意文件读取](web-generic-file-inclusion-jfinalcms-ajax-html-render-traversal/) | verified | high | 2026-11-11 |
| [JFinalCMS 前台 /common/file/download 的 fileKey 直拼 Web 根路径：../../ 穿越读取任意文件](web-generic-file-inclusion-jfinalcms-common-download-filekey-traversal/) | verified | high | 2026-11-08 |
| [JFinalCMS 后台 /admin/database/delete 备份名直接拼路径：../../ 穿越删除 Web 根目录外任意文件](web-generic-file-inclusion-jfinalcms-database-delete-backup-name-traversal/) | verified | high | 2026-11-08 |
| [JFinalCMS 后台 TemplateController 路径穿越三连：edit/save/delete 拼接 directory/fileName，读/写/删任意文件](web-generic-file-inclusion-jfinalcms-template-controller-traversal-read-write-delete/) | verified | medium | 2026-11-11 |
| [JHSoft OA DownLoadBgImage.aspx 的 path 参数直入 Server.MapPath/File.OpenRead：任意文件读取](web-generic-file-inclusion-jhsoft-downloadbgimage-path-read/) | verified | medium | 2026-11-07 |
| [JHSoft OA UploadFileDownLoadnew.aspx 的 fcform 分支 FilePath 路径穿越：任意文件读取](web-generic-file-inclusion-jhsoft-uploadfiledownloadnew-fcform-traversal/) | verified | medium | 2026-11-07 |
| [JSP getuploadimage.jsp 的 00 截断任意文件读取：图片后缀校验与 JDK 1.7.0_40 前 NUL 路径截断（CVE-2023-47473）](web-generic-file-inclusion-jsp-null-byte-jdk7-getuploadimage/) | verified | high | 2026-11-12 |
| [LuckyFrameWeb /common/download 直接把 fileName 拼进下载路径：../ 路径穿越任意文件读取与删除](web-generic-file-inclusion-luckyframeweb-download-filename-traversal/) | verified | medium | 2026-11-05 |
| [Maccms 后台模板广告文件 m=template-adsinfo-file 参数路径穿越任意文件读取](web-generic-file-inclusion-maccms-backend-template-adsinfo-file-traversal-read/) | verified | high | 2026-11-06 |
| [MCMS 5.3.1 模板删除路径穿越：fileName=`/..` 绕过 `../`/`..\` 黑名单删除整个 template 目录](web-generic-file-inclusion-mcms-5-3-1-template-delete-slash-dotdot-bypass/) | verified | high | 2026-11-13 |
| [MCMS 模板删除接口 fileName 未过滤 ../：TemplateAction.delete 可路径穿越删除任意目录](web-generic-file-inclusion-mcms-template-delete-traversal/) | verified | medium | 2026-11-10 |
| [mee-admin CommonFileController 任意文件下载：/mee/common/file 的 filePath 直接拼接导致路径穿越](web-generic-file-inclusion-mee-admin-common-file-filepath-traversal/) | verified | medium | 2026-11-08 |
| [MES 下载接口 fileName 直接拼接路径导致任意文件读取（downloadImages/downloadLayout/imagesPreview.jsp）](web-generic-file-inclusion-mes-download-filename-path/) | verified | high | 2026-11-05 |
| [MetaCRM JSP include/forward 参数未过滤导致任意文件读取（限 Tomcat 目录）](web-generic-file-inclusion-crm-jsp-include-forward-param-read/) | verified | high | 2026-11-07 |
| [MetaCRM 后台 download.jsp AES 参数路径穿越任意文件读取（读 dbinfo.prop 取数据库口令）](web-generic-file-inclusion-crm-download-jsp-aes-path-traversal/) | verified | high | 2026-11-07 |
| [MetInfo 6.0.0 include/thumb.php dir 路径穿越读取 config_db.php 数据库凭据](web-generic-file-inclusion-metinfo-thumb-dir-config-read/) | verified | high | 2026-11-05 |
| [MikroTik Winbox CVE-2018-14847：用 ./../ 绕过 tokenize 路径检查实现未授权任意文件读](web-generic-file-inclusion-mikrotik-winbox-cve-2018-14847-traversal-read/) | verified | medium | 2026-11-07 |
| [MrDoc 文集 MD 导出图片路径穿越：/media/../ 与 <img src> 读取任意文件并打包下载](web-generic-file-inclusion-mrdoc-md-export-media-path-traversal/) | verified | high | 2026-11-10 |
| [Nexus Repository 3 未授权路径遍历任意文件读取（CVE-2024-4956）：多重 %2f 与 ../ 绕过 URI 归一化](web-generic-file-inclusion-nexus-repository-encoded-slash-traversal-cve-2024-4956/) | verified | high | 2026-11-08 |
| [nginx alias 缺少尾部斜杠导致 /images../ 路径穿越任意文件读取](web-generic-file-inclusion-nginx-alias-off-by-slash-traversal/) | verified | high | 2026-11-08 |
| [Node/archiver 打包下载 bookIds 路径穿越：/proc/self/cwd/database.js 读源码与数据库凭据](web-generic-file-inclusion-node-archiver-bookids-zip-traversal/) | verified | high | 2026-11-08 |
| [OA getfile.jsp 与 mappingAddress 接口参数直接进 FileInputStream 导致任意文件读取](web-generic-file-inclusion-oa-getfile-mappingaddress/) | verified | medium | 2026-11-05 |
| [OA 下载/转发 Servlet 直接 new File/FileInputStream，file 与 dir 参数任意文件读取](web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read/) | verified | high | 2026-11-05 |
| [Python os.path.join 绝对路径覆盖基目录导致目录穿越与任意文件读取](web-generic-file-inclusion-python-os-path-join-absolute-traversal/) | verified | high | 2026-11-05 |
| [SeaCMS 12.9 后台 admin_safe.php download 未校验 file：绝对路径任意文件下载/读取](web-generic-file-inclusion-seacms-admin-safe-arbitrary-file-download/) | verified | high | 2026-11-08 |
| [SolarWinds Serv-U CVE-2024-28995：InternalDir/InternalFile 混合分隔符绕过遍历检查，未授权任意文件读取](web-generic-file-inclusion-solarwinds-serv-u-cve-2024-28995-internaldir-traversal/) | verified | high | 2026-11-08 |
| [Windows 下载接口只替换正斜杠，反斜杠 ..\ 穿越读取任意文件](web-generic-file-inclusion-windows-backslash-download-traversal/) | verified | high | 2026-11-04 |
| [zipDownload 与 export 两个打包下载接口的 path 参数穿越：从单文件读取到整站源码与数据库备份打包](web-generic-file-inclusion-zipdownload-export-path-traversal/) | verified | medium | 2026-11-08 |
| [万户OA deleteFile.jsp 任意文件删除：delpath 被过滤但 delfile 未校验](web-generic-file-inclusion-whir-ezoffice-deletefile-traversal-delete/) | verified | high | 2026-11-07 |
| [万户OA 两处任意文件下载：down.jsp name 穿越与 download_ftp path/filename 拼接](web-generic-file-inclusion-whir-ezoffice-down-jsp-download-ftp/) | verified | high | 2026-11-07 |
| [下载接口 fileName 需 Base64 解码：编码目录穿越路径读取任意文件与 bash_history](web-generic-file-inclusion-base64-filename-traversal-download/) | verified | high | 2026-11-05 |
| [下载接口按 file 参数原样读取：泄露联调说明、内部路由索引与 admin.php 源码](web-generic-file-inclusion-download-param-source-disclosure/) | verified | high | 2026-11-06 |
| [下载接口路径穿越读取用户 ~/.aws/credentials：从任意文件读取升级为 AWS AK/SK 接管 S3](web-generic-file-inclusion-download-traversal-aws-credentials/) | verified | high | 2026-11-13 |
| [九垠赢系统 HttpCombiner css 参数任意文件读取并覆盖 StaticCss.css](web-generic-file-inclusion-jiuyin-httpcombiner-css-read-overwrite/) | verified | high | 2026-11-05 |
| [云网OA report/download.do 的 fileName 直接拼接根路径：相对路径穿越任意文件下载](web-generic-file-inclusion-cloudweb-report-download-filename-traversal/) | verified | medium | 2026-11-12 |
| [亿赛通 CDG DecryptApplication 任意文件读取：filePath 直入 new File/FileInputStream + getRequestURI 子串校验被 ;login/;SystemConfig 绕过](web-generic-file-inclusion-cdg-decryptapplication-filepath-read/) | verified | high | 2026-11-06 |
| [双重 URL 编码 + ./../ 交替：绕过连续目录穿越黑名单读取任意文件](web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal/) | verified | high | 2026-11-07 |
| [可写 extAttrs.fileName 目录穿越：下载接口按资源记录路径读取任意文件](web-generic-file-inclusion-extattrs-filename-traversal-download/) | verified | high | 2026-11-05 |
| [在线监控信息管理平台 downloadFile.action 的 filePath 直接拼接导致 ../ 路径遍历任意文件下载（实测读取 /etc/passwd）](web-generic-file-inclusion-monitoring-platform-downloadfile-filepath-traversal/) | verified | high | 2026-11-11 |
| [文件包含读取 Windows SAM 备份并破解 NTLM 哈希获取明文口令](web-generic-file-inclusion-windows-sam-ntlm-crack/) | verified | medium | 2026-11-04 |
| [文件查看接口对目录与不存在路径返回不同提示：把“是不是目录”变成枚举 oracle，扫出 .hidden 等隐藏目录再读文件](web-generic-file-inclusion-view-file-directory-oracle-hidden-dir-enum/) | verified | high | 2026-11-08 |
| [文件读取参数先黑名单后解码：%2e%2e%2f 绕过 .. 与 / 检查](web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass/) | verified | high | 2026-11-05 |
| [文档转换服务调用 mmark 时 {{filename}} 包含指令读取任意本地文件](web-generic-file-inclusion-mmark-include-directive-file-read/) | verified | high | 2026-11-05 |
| [未授权任意文件读取：admin/api.update/read 的 encode 参数按 GBK 字节逐位 base36 编码，逆向 encode 后读 config/database.php 与日志](web-generic-file-inclusion-admin-api-update-read-base36-encode-path/) | verified | high | 2026-11-12 |
| [某应用云平台 download.aspx 任意文件下载：file 参数直拼 Server.MapPath("~"+file) 读取站点内 web.config 等](web-generic-file-inclusion-dotnet-ava-download-aspx-server-mappath/) | verified | high | 2026-11-07 |
| [模板详情接口 relativePath 直拼 new File + readFileToString：任意文件读取与目录列举](web-generic-file-inclusion-template-detail-relative-path-read/) | verified | high | 2026-11-06 |
| [汉王e脸通 filePath 拼接任意文件读取：imgDownload 与 exportResourceByFilePath 直接回显](web-generic-file-inclusion-hanvon-eface-filepath-fileinputstream/) | verified | high | 2026-11-07 |
| [泛微 E10 downloadFile/downloadMonitorSelfFile 的 0981- 编码路径穿越：未授权任意文件读取](web-generic-file-inclusion-weaver-e10-0981-dash-path-traversal-read/) | verified | high | 2026-11-07 |
| [自实现 HTTP 服务把请求行路径直接 fopen 且不校验 ../：POST /../flag 读取根目录 flag](web-generic-file-inclusion-ctf-httpd-request-path-dotdot-flag-read/) | verified | medium | 2026-11-08 |
| [致远 OA A8 AIEdocCorrectController downloadErrorReport 后台任意文件读取](web-generic-file-inclusion-seeyon-aiedoc-correct-downloaderrorreport/) | draft | high | 2026-11-05 |
| [通天星 CMSV6 *_downLoad.action 的 path 相对路径穿越：CommonBaseAction#downLoad 的 tomcat/ 字符串检查被跨平台分隔符/规范化绕过，读 Tomcat 日志取管理员 session](web-generic-file-inclusion-cmsv6-standardlogin-download-path-traversal/) | verified | high | 2026-11-08 |
| [通天星 CMSV6 downloadLogger.action 的 fileName 直入文件读取：Windows 绝对路径任意文件下载（win.ini 验证）](web-generic-file-inclusion-cmsv6-downloadlogger-filename-read/) | verified | medium | 2026-11-08 |
| [通天星 CMSV6 StandardReportMediaAction_getImage 的 filePath/fileOffset/fileSize 直读文件：任意文件下载（win.ini 回显）](web-generic-file-inclusion-cmsv6-getimage-filepath-offset-read/) | verified | high | 2026-11-08 |
| [金盘 download.jsp items 参数路径穿越：ROOTPATH 拼接后直接 FileInputStream 任意文件读取](web-generic-file-inclusion-goldlib-download-items-traversal-read/) | verified | medium | 2026-11-07 |
| [金盘 FileController /admin/tools/file/delete：file 参数拼 ROOTPATH 后直接删除任意文件](web-generic-file-inclusion-goldlib-file-controller-delete-traversal/) | verified | medium | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
