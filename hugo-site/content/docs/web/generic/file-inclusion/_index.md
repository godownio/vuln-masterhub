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
| [ASP.NET 报表参数路径遍历读取 web.config：泄露 MachineKey 与敏感配置](web-generic-file-inclusion-aspx-report-param-traversal-webconfig/) | verified | high | 2026-11-05 |
| [CRM getFile 接口 fileName 与 folder/sCorpName 拼接导致路径穿越任意文件读取](web-generic-file-inclusion-crm-getfile-filename-folder-traversal/) | verified | medium | 2026-11-05 |
| [Django 拨号记录下载接口 szName 拼接路径穿越任意文件读取（16 位 token 门槛）](web-generic-file-inclusion-django-token-download-szname-traversal-read/) | verified | high | 2026-11-05 |
| [FastAPI file_management 的 file 参数路径穿越：以 root 读取 /etc/shadow 与任意文件](web-generic-file-inclusion-fastapi-file-management-traversal/) | verified | high | 2026-11-05 |
| [FE 系统三处 Servlet 参数直入 File/FileInputStream：imagePath、base64 filename 与 pdf 前缀穿越读取](web-generic-file-inclusion-fe-system-servlet-param-arbitrary-read/) | draft | high | 2026-11-05 |
| [Flask send_file 下载接口路径拼接穿越：仅拦 flag/config 关键字时读源码与任意文件](web-generic-file-inclusion-flask-sendfile-download-traversal/) | verified | high | 2026-11-06 |
| [GitLab Repository Commits API 未授权任意文件读取（CVE-2026-85706）：尾斜杠绕过 workhorse 路由并信任 file.path](web-generic-file-inclusion-gitlab-commits-api-file-path-unauth-read/) | verified | high | 2026-11-05 |
| [Java new File(root, path) + FileUtils.readFileToString 路径穿越读取任意文件](web-generic-file-inclusion-java-new-file-root-path-traversal-read/) | verified | high | 2026-11-05 |
| [Java Path.resolve 绝对路径覆盖：%5c 反斜杠归一化为 / 后读取沙箱内任意文件](web-generic-file-inclusion-java-path-resolve-absolute-override/) | verified | high | 2026-11-06 |
| [LuckyFrameWeb /common/download 直接把 fileName 拼进下载路径：../ 路径穿越任意文件读取与删除](web-generic-file-inclusion-luckyframeweb-download-filename-traversal/) | verified | medium | 2026-11-05 |
| [Maccms 后台模板广告文件 m=template-adsinfo-file 参数路径穿越任意文件读取](web-generic-file-inclusion-maccms-backend-template-adsinfo-file-traversal-read/) | verified | high | 2026-11-06 |
| [MES 下载接口 fileName 直接拼接路径导致任意文件读取（downloadImages/downloadLayout/imagesPreview.jsp）](web-generic-file-inclusion-mes-download-filename-path/) | verified | high | 2026-11-05 |
| [MetInfo 6.0.0 include/thumb.php dir 路径穿越读取 config_db.php 数据库凭据](web-generic-file-inclusion-metinfo-thumb-dir-config-read/) | verified | high | 2026-11-05 |
| [OA getfile.jsp 与 mappingAddress 接口参数直接进 FileInputStream 导致任意文件读取](web-generic-file-inclusion-oa-getfile-mappingaddress/) | verified | medium | 2026-11-05 |
| [OA 下载/转发 Servlet 直接 new File/FileInputStream，file 与 dir 参数任意文件读取](web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read/) | verified | high | 2026-11-05 |
| [Python os.path.join 绝对路径覆盖基目录导致目录穿越与任意文件读取](web-generic-file-inclusion-python-os-path-join-absolute-traversal/) | verified | high | 2026-11-05 |
| [Windows 下载接口只替换正斜杠，反斜杠 ..\ 穿越读取任意文件](web-generic-file-inclusion-windows-backslash-download-traversal/) | verified | high | 2026-11-04 |
| [下载接口 fileName 需 Base64 解码：编码目录穿越路径读取任意文件与 bash_history](web-generic-file-inclusion-base64-filename-traversal-download/) | verified | high | 2026-11-05 |
| [下载接口按 file 参数原样读取：泄露联调说明、内部路由索引与 admin.php 源码](web-generic-file-inclusion-download-param-source-disclosure/) | verified | high | 2026-11-06 |
| [九垠赢系统 HttpCombiner css 参数任意文件读取并覆盖 StaticCss.css](web-generic-file-inclusion-jiuyin-httpcombiner-css-read-overwrite/) | verified | high | 2026-11-05 |
| [亿赛通 CDG DecryptApplication 任意文件读取：filePath 直入 new File/FileInputStream + getRequestURI 子串校验被 ;login/;SystemConfig 绕过](web-generic-file-inclusion-cdg-decryptapplication-filepath-read/) | verified | high | 2026-11-06 |
| [可写 extAttrs.fileName 目录穿越：下载接口按资源记录路径读取任意文件](web-generic-file-inclusion-extattrs-filename-traversal-download/) | verified | high | 2026-11-05 |
| [文件包含读取 Windows SAM 备份并破解 NTLM 哈希获取明文口令](web-generic-file-inclusion-windows-sam-ntlm-crack/) | verified | medium | 2026-11-04 |
| [文件读取参数先黑名单后解码：%2e%2e%2f 绕过 .. 与 / 检查](web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass/) | verified | high | 2026-11-05 |
| [文档转换服务调用 mmark 时 {{filename}} 包含指令读取任意本地文件](web-generic-file-inclusion-mmark-include-directive-file-read/) | verified | high | 2026-11-05 |
| [模板详情接口 relativePath 直拼 new File + readFileToString：任意文件读取与目录列举](web-generic-file-inclusion-template-detail-relative-path-read/) | verified | high | 2026-11-06 |
| [致远 OA A8 AIEdocCorrectController downloadErrorReport 后台任意文件读取](web-generic-file-inclusion-seeyon-aiedoc-correct-downloaderrorreport/) | draft | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
