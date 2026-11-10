---
id: web-java-deserialization-cmsv6-standardline-report-jasper-jrloader
title: 通天星 CMSV6 StandardLineAction_report 的 name 控制 .jasper 路径：JRLoader.loadObject 反序列化 RCE（读日志取 session + 默认 FTP 上传组合链）
type: scenario
domain: web
path: web/java/deserialization
technique: jasperreport-jrloader-deserialization-report-name
tags:
- cmsv6
- java
- struts2
- jasperreports
- deserialization
- rce
- file-read
- session-hijack
- ftp
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:03:15+08:00'
  notes: 已对照原文与全部18张图核对：StandardLineAction#report取name→createReport(name)、getJasperReportFromFile拼jasperReportPath/<name>.jasper→JRLoader.loadObject→ContextClassLoaderObjectInputStream.readObject的调用栈与源码均一致；组合链第一步downLoad读日志拿session、第二步默认FTP上传.jasper、第三步触发报表与原文一致。原文未给恶意.jasper构造与执行回显，卡内已注明。未验证点：未实际构造/触发反序列化。
url: /docs/web/java/deserialization/web-java-deserialization-cmsv6-standardline-report-jasper-jrloader/
draft: false
kb_aliases:
- 通天星 CMSV6 组合拳 RCE
- StandardLineAction_report 反序列化
- JasperReport 反序列化
- JRLoader loadObject
- ContextClassLoaderObjectInputStream
- CMSV6 .jasper RCE
---

## 一句话结论

`/808gps/StandardLineAction_report.action` 的 `name` 参数被 `ReportCreater.createReport(name)` 拼成 `jasperReportPath/<name>.jasper` 后交给 `JRLoader.loadObject()`，而 `JRLoader` 用 `ContextClassLoaderObjectInputStream` 对 `.jasper` 内容做 Java 反序列化；攻击者只要能让一个恶意 `.jasper` 落到可读路径（组合链中通过默认 FTP 口令上传）并触发报表导出，就能用类路径上的反序列化 gadget 执行任意代码。

## 原理

- 入口 `com.gps808.operationManagement.action.StandardLineAction#report` 从请求取 `format`、`name`、`id`、`direct`、`disposition` 等参数，其中 `name` 原样传给 `this.getReportCreate().createReport(name)`。
- 调用栈（文章给出）：

  ```text
  com.framework.jasperReports.ReportCreater#_createReport
    -> com.framework.jasperReports.ReportCreater#getJasperReport
    -> com.framework.jasperReports.ReportCreater#getJasperReportFromFile
    -> net.sf.jasperreports.engine.util.JRLoader#loadObject
    -> net.sf.jasperreports.engine.util.ContextClassLoaderObjectInputStream#readObject
  ```

  `getJasperReportFromFile` 的关键代码：

  ```java
  String filePath = this.jasperReportPath + File.separator + reportKey + ".jasper";
  File reportFile = new File(filePath);
  if (reportFile.exists() && reportFile.isFile()) {
      jasperReport = (JasperReport) JRLoader.loadObject(reportFile);
  }
  ```

  `reportKey` 就是 `name`。`JRLoader.loadObject(File)` 内部用 `ContextClassLoaderObjectInputStream`（JasperReports 自定义的 `ObjectInputStream`）读取文件，`.jasper` 文件本质上是序列化后的 `JasperReport` 对象图，因此读取过程会执行其中自定义类的 `readObject`/`readResolve` 等方法。只要应用类路径上存在可用的反序列化 gadget 链，攻击者构造的 `.jasper` 就能在加载时触发任意代码执行。
- `name` 同时影响路径：`jasperReportPath + separator + name + ".jasper"`。若 `jasperReportPath` 可写或攻击者能把文件放到其上级目录，`name=../xxx` 一类的相对路径还可以把加载点指向别处（后缀固定为 `.jasper`，需要文件名以 `.jasper` 结尾或利用路径解析差异）。
- 组合链的三步：
  1. **拿管理员 session**：用 `StandardLoginAction_downLoad.action?path=.././.././../tomcat/webapps/../logs/log_info.log&isTure=0` 下载 Tomcat 日志；p6spy 的 SQL 日志里有 `update user_session ... where INSTR('<session值>', concat(',',SESSION,','))>0`，从中提取在线管理员的 `JSESSIONID`。
  2. **放置恶意 .jasper**：官方通告中的利用方式是登录默认口令未修改的 FTP 服务，把恶意 `.jasper` 上传到报表目录；文章也提到「后台任意文件上传漏洞」，但其后台 `WebuploaderAction_ajaxAttachFileUpload` 后缀限制很死，不能直接传 WebShell，所以默认 FTP 是更现实的投放路径。FTP 需要目标开启且仍是出厂口令。
  3. **触发反序列化**：带管理员 session 请求 `StandardLineAction_report.action`，`name` 指向刚上传的报表名，`id` 传一个存在的线路/公司 ID（`Integer.parseInt(lid)` 后才查库），`direct` 传 0/1，`format` 按导出类型传值；`createReport(name)` 加载 `.jasper` 即触发 `readObject`。

## 触发条件

- 目标为通天星 CMSV6，暴露 `StandardLineAction_report.action`；该动作通常要求登录会话，组合链用日志中提取的管理员 session 满足。
- `jasperReportPath` 下存在攻击者可写入的 `.jasper`（默认 FTP 口令未改、后台/其他上传可写该目录，或 `name` 相对路径能指向攻击者已控制的文件）。
- 应用类路径上存在可用的反序列化 gadget（如 CommonsCollections 等老依赖）；JasperReports 版本使用 `ContextClassLoaderObjectInputStream` 且未加白名单。
- 目标存在至少一条线路/公司记录，`id` 能被 `Integer.parseInt` 且查库成功；否则在加载报表前就可能异常返回。

## 利用步骤

1. 用 `downLoad` 原语读取 Tomcat 日志，搜索 `user_session` 与 `SESSION` 相关记录，提取管理员 `JSESSIONID`（详见 CMSV6 downLoad 卡）。
2. 确认 FTP 服务与默认口令：尝试用出厂 FTP 账号登录，进入报表目录（`jasperReportPath` 对应目录）；若不可用，改找其他能写 `.jasper` 的上传点。
3. 生成恶意 `.jasper`：以合法 `.jasper` 为模板，把其中的序列化字段替换为 gadget 链（例如 CommonsCollections 的 `Transformer` 链），保证文件仍能被 `JRLoader` 识别为 `JasperReport` 并走到 `readObject`；不同 JasperReports 版本的对象结构不同，需要按目标版本调整。
4. 上传后带管理员 session 请求：

   ```http
   GET /808gps/StandardLineAction_report.action?format=pdf&name=<报表名>&id=<线路ID>&direct=0&disposition=inline HTTP/1.1
   Host: target
   Cookie: JSESSIONID=<管理员session>
   ```

   `name` 不要带 `.jasper`（代码会自动追加），指向上传的文件名。
5. 观察响应/外带通道（DNS、HTTP、命令回显）确认代码执行；失败时检查 `name` 路径、`id` 是否有效、gadget 与目标依赖版本是否匹配。

## PoC

文章没有给出完整的恶意 `.jasper` 构造与执行回显，只给出触发代码与调用栈。最小触发请求形态：

```http
GET /808gps/StandardLineAction_report.action?format=pdf&name=demo&id=1&direct=0&disposition=inline HTTP/1.1
Host: 192.168.52.130
Cookie: JSESSIONID=<从日志提取的管理员session>
```

前置的日志读取请求：

```http
GET /808gps/StandardLoginAction_downLoad.action?path=.././.././../tomcat/webapps/../logs/log_info.log&isTure=0 HTTP/1.1
Host: 192.168.52.130
```

`.jasper` 投放依赖默认 FTP 口令或后台写文件能力；文章未展示该步的完整报文，实战需按目标 FTP/上传接口调整。恶意 `.jasper` 的构造属于 JasperReports 序列化对象改写，需匹配目标版本，文章未提供现成 payload。

## 变体与关联

- `ReportCreater` 的其他调用方若同样把请求参数作为 `reportKey`，也可触发同一 `JRLoader.loadObject` sink；`name` 的相对路径能力还可用于加载攻击者已写入其他目录的 `.jasper`。
- 前置原语：`web/generic/file-inclusion` 下 CMSV6 downLoad 卡（读日志拿 session）；WebShell 投放可参考 CMSV6 inspect_file upload 卡（若该上传点可写报表目录，可替代 FTP）。
- 通用手法：`web/java/deserialization` 下已有大量「文件/字节流交给 ObjectInputStream」的卡；本卡差异是 JasperReports 的 `.jasper` 格式与 `JRLoader` 入口，以及 CMSV6 的「日志 session + 默认 FTP + 报表加载」组合链。
- 该链的每一步都可独立利用：文件读取泄露日志/配置，默认 FTP 口令本身也是弱口令问题，报表反序列化是最终 RCE。

## 检测与防御

- 修复：不要把用户可控的 `name` 拼进报表路径；报表名走白名单/ID 映射；`JRLoader` 只加载应用内置、完整性校验过的 `.jasper`；升级 JasperReports 并避免在加载路径反序列化不可信文件。
- 文件系统：报表目录只允许应用账号写、禁止 FTP 写入；FTP 服务修改默认口令或关闭；Web 目录与报表目录分离。
- 会话与日志：不要把完整 session 写入 SQL 日志；管理员 session 绑定 IP/UA 并设置短超时；日志目录最小权限。
- 检测：监控 `StandardLineAction_report.action` 的 `name` 参数异常（路径分隔符、未知报表名）；监控报表目录新增/修改 `.jasper`；监控 FTP 默认账号登录与异常上传；对 `JRLoader`/`ObjectInputStream` 相关异常与反序列化 gadget 类加载做告警。
- 排查：核对报表目录文件哈希与来源、FTP 登录日志、`user_session` 异常会话，以及 `report` 请求前后的命令执行/外带迹象。
