---
id: web-generic-file-inclusion-cmsv6-standardlogin-download-path-traversal
title: 通天星 CMSV6 *_downLoad.action 的 path 相对路径穿越：CommonBaseAction#downLoad 的 tomcat/ 字符串检查被跨平台分隔符/规范化绕过，读 Tomcat 日志取管理员 session
type: scenario
domain: web
path: web/generic/file-inclusion
technique: struts-base-action-download-path-traversal-log-session
aliases:
- 通天星 CMSV6 任意文件下载
- StandardLoginAction_downLoad
- StandardSchoolBusAction_downLoad
- CommonBaseAction downLoad
- CMSV6 日志 session 泄露
tags:
- cmsv6
- java
- struts2
- arbitrary-file-read
- path-traversal
- session-hijack
- log
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:07:06+08:00'
  notes: 已对照原文与全部18张图核对：CommonBaseAction#downLoad源码与PoC路径.././.././../tomcat/webapps/../logs/log_info.log&isTure=0、日志中p6spy update user_session+SESSION值（图17）均一致。已修正卡内对权限条件的错误解读并同步标题/变体：原文条件为真才下载，并非写反/包含tomcat就放行；按文章PoC，绕过点应为检查用正斜杠tomcat/与实际Windows反斜杠路径/规范化差异，卡内已改为该解释。未验证点：未实际请求；具体解析函数行为需目标版本确认。
---

## 一句话结论

`*_downLoad.action` 继承的 `com.gpsCommon.action.CommonBaseAction#downLoad` 把 `path` 直接交给文件下载逻辑；权限检查用正斜杠字面量 `contains("tomcat/")` 做黑名单，但实际解析后的 Windows 路径通常使用反斜杠（且相对路径可穿越），字符串匹配不到而放行。攻击者用 `.././../tomcat/webapps/../logs/log_info.log` 可下载 Tomcat 日志；日志里的 p6spy SQL 记录带 `user_session` 更新语句与 session 值，可直接提取管理员 JSESSIONID。

## 原理

- 文章先指出路由 `StandardSchoolBusAction_downLoad.action` 存在任意文件下载，跟进到继承的 `com.gpsCommon.action.CommonBaseAction#downLoad`；同一父类方法被 `StandardLoginAction` 等 Action 继承，所以 `StandardLoginAction_downLoad.action` 也能命中同一 sink。
- 关键代码与判断：

  ```java
  String filePath = this.getDownloadFileRealPath(this.getRequest());
  if ((!filePath.contains("tomcat/") || filePath.contains("tomcat/ttxapps"))
          && !filePath.contains(".xml")
          && !filePath.contains("WEB-INF")
          && !filePath.contains("classes")) {
      // 进入下载
  } else {
      // result = 24, "用户无权限下载Tomcat内的文件"
  }
  ```

  从注释意图看是想禁止下载 Tomcat 目录内的文件：条件为真才进入下载，路径字符串包含正斜杠 `tomcat/` 且不是 `tomcat/ttxapps` 时会被拒绝。文章 PoC 的相对路径最终落到 `tomcat/logs/log_info.log` 却下载成功，说明检查用的路径串与实际打开路径存在规范化/分隔符差异（Windows 下解析后的路径通常是反斜杠 `tomcat\`，`contains("tomcat/")` 匹配不到），且 `.xml`、`WEB-INF`、`classes` 之外的文件（如 `log_info.log`）不在拦截范围。
- `getDownloadFileRealPath(request)` 读取请求中的 `path` 参数；`isTure` 为 1 时直接用 `filePath`，否则用 `getDownloadFileRealPath(servletContext, filePath)` 把相对路径解析到应用目录。文章 PoC 用 `isTure=0` 与一串 `../`，最终解析到 `tomcat/logs/log_info.log`。
- `isDel=1` 时下载完还会 `file.delete()`，因此该接口同时是任意文件删除原语；`isStream=1` 控制是否省略 `Content-Disposition`，便于把响应当纯字节流处理。
- 日志由 p6spy（`com.p6spy.engine.spy.appender.Slf4JLogger`）输出，记录了 `update user_session set UpdateTime='...' where INSTR('<session值>', concat(',',SESSION,','))>0` 这类 SQL，其中 `SESSION` 列的取值就是在线会话标识——攻击者从中拿到管理员 session 后设置 `JSESSIONID` 即可接管后台。

## 触发条件

- 目标暴露任一继承 `CommonBaseAction` 的 `*_downLoad.action`，且该 Action 无需登录或可按文章方式前台访问（PoC 未带 Cookie）。
- 请求参数名为 `path`，并带 `isTure=0`（相对路径解析）或 `isTure=1`（直接使用原路径）。
- 路径中必须包含字符串 `tomcat/`，且不能包含 `.xml`、`WEB-INF`、`classes`；Tomcat 日志路径满足这些条件。
- 应用使用 p6spy 或类似 SQL 日志把 session 值写入日志；日志文件对运行账号可读。

## 利用步骤

1. 请求 `GET /808gps/StandardLoginAction_downLoad.action?path=.././.././../tomcat/webapps/../logs/log_info.log&isTure=0`，保存响应体；若 404/权限错误，换 `StandardSchoolBusAction_downLoad.action` 或其他继承同一父类的 Action，并调整 `../` 层数。
2. 在日志中搜索 `user_session`、`UpdateTime`、`SESSION`、`JSESSIONID` 等关键字，提取近期活跃的 session 值（文章截图中的日志行即为此类记录）。
3. 把提取到的 session 作为 `Cookie: JSESSIONID=<值>` 访问后台接口，验证是否已处于管理员会话；必要时结合 `downLoad` 继续读其他日志/配置。
4. 只读验证时可忽略 `isDel`；不要使用 `isDel=1`，它会删除服务器上的目标文件。

## PoC

```http
GET /808gps/StandardLoginAction_downLoad.action?path=.././.././../tomcat/webapps/../logs/log_info.log&isTure=0 HTTP/1.1
Host: 192.168.52.130
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```

日志中可看到类似记录（节选字段）：

```text
2024-07-27 00:42:15 [Thread-2] INFO SQL | ... | update user_session set UpdateTime='2024-07-27T00:42:15.177+0800' where INSTR('20f6d040b7904b4bad380...', concat(',',SESSION,','))>0
```

其中 `SESSION` 列对应的值即在线会话标识；把它填入 `JSESSIONID` 后访问 `/808gps/...` 后台页面验证权限。

## 变体与关联

- 同一产品的 `downloadLogger.action`（`fileName` 绝对路径）与 `StandardReportMediaAction_getImage.action`（`filePath` + `fileOffset/fileSize`）是另外两个文件读取 sink，参数与放行条件不同；本卡独有的是「tomcat/ 字符串检查被分隔符/规范化绕过 + 相对路径穿越 + 日志 session 提取」。
- 该原语是 CMSV6 组合 RCE 链的第一步：读日志拿管理员 session 后，才能访问后台上传/报表接口；后续 `.jasper` 反序列化见 `web/java/deserialization` 下 CMSV6 JasperReport 卡。
- `isDel=1` 的删除行为可单独作为破坏性原语，测试时避免使用；`isStream=1` 可用于绕过浏览器/代理对附件的处理。

## 检测与防御

- 修复：`path` 改为资源 ID 或白名单文件名；服务端 `getCanonicalPath()` 后按统一分隔符校验 `startsWith(允许目录)`；显式拒绝 `tomcat/`、`WEB-INF`、`classes`、`.xml`，并把 `tomcat/ttxapps` 例外改为独立的精确白名单；禁止 `isDel` 参数。
- 日志：不要把完整 session 值写入 SQL 日志；p6spy 生产环境关闭或脱敏；日志目录权限收紧，只允许运维账号读取。
- 检测：监控 `path` 含 `../`、`tomcat/`、`logs`、`log_info.log` 的请求；监控 `isDel=1` 的下载请求；对管理员 session 在异常 IP 上出现做告警。
- 排查：检查 `log_info.log` 的访问记录、下载响应大小与 `isDel` 调用；核对 `user_session` 表中异常活跃的 session 来源 IP。
