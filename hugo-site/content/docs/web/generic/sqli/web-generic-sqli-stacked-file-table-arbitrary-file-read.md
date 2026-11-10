---
id: web-generic-sqli-stacked-file-table-arbitrary-file-read
title: 堆叠注入改 s_filedata 文件路径：借 FileGUID 下载接口任意文件读取（FileDir 长度溢出到 FilePath）
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-stacked-file-table-arbitrary-file-read
tags:
- sqli
- mysql
- stacked-query
- arbitrary-file-read
- file-download
- filedata
- tomcat
- web-xml
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T04:56:06+08:00'
  notes: 已对照原文与全部29图核对：IDs 堆叠注入（图05/07）、WAF Connection reset 与括号包 information_schema 绕过（图08/09）、update s_filedata FileDir/FilePath 读 C:/windows/win.ini（图11/12成功回显）、~/../webapps/ROOT/RUNNING.txt 与 Tomcat 404 7.0.100（图13-15）、web.xml 中 SecurityFilter/excludeUrls /admin/login.jsp（图16）、FileDir Data too long 报错（图17）及 FileDir/FilePath 拆分读 SecurityFilter.class（图18/19）、properties root+allowMultiQueries=true（图21）均一致。dedup 除自身外候选均 new；dup-scan 无涉及 pair。未验证点：未复跑请求；原文未标产品/组件版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-stacked-file-table-arbitrary-file-read/
draft: false
kb_aliases:
- s_filedata 任意文件读取
- FileGUID 任意文件读取
- 堆叠注入改 FileDir/FilePath
- 文件表路径改写
- 下载接口任意读
- FileDir 长度溢出到 FilePath
- 投票修改参与人注入
---

## 一句话结论

应用把上传文件的存储信息放在 `s_filedata` 表（`FileDir`、`FilePath`、`FileGUID`），下载接口按 `FileGUID` 查记录并读取 `FileDir + FilePath`；当投票“修改参与人”的 `IDs` 参数存在堆叠 SQL 注入时，可用 `UPDATE s_filedata SET FileDir='<目录>', FilePath='<文件>' WHERE FileGUID='<已知GUID>'` 把任意文件路径写进记录，再请求 `?FileGUID=<GUID>` 下载接口读取服务器任意文件。示例成功读取 `C:/windows/win.ini`、Tomcat 的 `WEB-INF/web.xml`、`SecurityFilter.class` 与数据库配置；`FileDir` 列有长度限制时，把超出部分拆到 `FilePath`（两者拼接）即可绕过。

## 原理

- **文件元数据与下载**：上传后接口返回 `FileDir`（如 `D:\...\UpLoad\`）、`FilePath`（如 `202408\c25ddf...jpg`）、`FileGUID`（GUID 去横线）与 `FileName`；文件列表接口会回显这些字段。下载/加载接口以 `FileGUID` 为键查询 `s_filedata`，读取 `FileDir + FilePath` 指向的文件并通过 `Content-Disposition: attachment` 返回。路径完全由数据库记录决定，不是由请求路径直接拼接。
- **堆叠注入改写记录**：投票“修改参与人”功能的 `IDs` 参数可执行多条语句（示例原始 SQL 含 `DELETE FROM mc_voteuser ...; INSERT INTO ...`），因此可追加 `update s_filedata ...`。MySQL 堆叠查询在同一连接内顺序执行，UPDATE 会真实修改记录。
- **任意文件读取成立的原因**：攻击者同时控制目录与文件名两部分，可写绝对路径（`C:/windows/` + `win.ini`）或相对路径（`~/../webapps/ROOT/` + `/WEB-INF/classes/...`）；下载逻辑没有把路径限制在上传目录内，也不校验文件类型，故读到的内容直接回传。示例用同一 FileGUID 改写后分别读出 win.ini、web.xml、class 文件与 properties。
- **FileDir 长度限制绕过**：`FileDir` 列长度有限（示例报 `Data too long for column 'FileDir' at row ...`），但应用拼接 `FileDir + FilePath`。把长路径拆成“较短且合法的 FileDir 前缀 + FilePath 剩余部分”（如 `FileDir='~/../webapps/ROOT/'`、`FilePath='/WEB-INF/classes/com/xxx/core/filter/SecurityFilter.class'`）即可绕过列长限制。
- **配套注入技巧**：该注入点支持报错注入（`extractvalue(1,concat(0x7e,(...)))`），也可在堆叠查询中直接返回数据；WAF 对 `information_schema` 等关键字有拦截，示例通过给 `information_schema.columns` 加括号（`from(information_schema.columns)where...`）绕过。Tomcat 7.0.100 可从 404 页 `Server`/错误页识别。
- **为什么危害高**：任意文件读取可直接拿到 `web.xml` 的过滤规则（示例发现 `/admin/login.jsp` 在 `excludeUrls` 中）、Spring SecurityFilter 类、数据库连接配置（含 root 口令）与源码，进而进入后台或继续 RCE；无需数据库 FILE 权限。

## 触发条件

- 存在支持堆叠语句的 SQL 注入（示例为 MySQL JDBC 且 `allowMultiQueries=true`），且注入账号对 `s_filedata` 有 UPDATE 权限。
- 应用使用“文件元数据表 + FileGUID 下载”机制，下载路径由数据库中的 `FileDir/FilePath` 拼接且未做目录白名单。
- 攻击者能获得至少一个有效 `FileGUID`（上传接口/文件列表接口返回）。
- 已知或可猜目标文件路径（Windows 盘符、Tomcat `webapps/ROOT`、Linux `~` 等）；`FileDir` 列长度限制可通过拆分绕过。
- 目标为 MySQL 时 `allowMultiQueries=true` 或驱动允许堆叠；其他数据库需对应堆叠语法。

## 利用步骤

1. 在投票“修改参与人”功能的 `IDs` 参数确认注入：原始 SQL 含 DELETE/INSERT，测试堆叠 `;select 1` 或 `;select user()`。
2. 用报错注入或堆叠查询枚举表/列：`t_userinfo`、`s_filedata`（示例列 `FileDir`、`FilePath`、`FileGUID`、`FileName`）。WAF 拦截关键字时，用括号包裹（如 `from(information_schema.columns)where...`）绕过。
3. 通过文件列表/上传接口获取一个 `FileGUID`（示例 `c25ddf570ca44b0787a50fa01ede793c`）。
4. 改写记录读取已知文件验证：`update s_filedata set FileDir='C:/windows/', FilePath='win.ini' where FileGUID='<GUID>'`，再 `GET ...?FileGUID=<GUID>`，应返回 win.ini 内容。
5. 读取 Tomcat 配置与源码：先 `FileDir='~/../webapps/ROOT/'`、`FilePath='/WEB-INF/web.xml'`，从 `SecurityFilter` 的 `excludeUrls` 找未鉴权路径（示例 `/admin/login.jsp`）；再读 `SecurityFilter.class`、数据库 properties、其他 class/jar 内配置。
6. 遇到 `FileDir` 超长：把路径拆分为 `FileDir='~/../webapps/ROOT/'` 与 `FilePath='/WEB-INF/classes/.../X.class'`，两步拼接后读取。
7. 用读到的配置/口令进入后台，或结合后台 SQL 功能继续（示例后台 SQL 以 `root@localhost` 执行，最终 general_log 写 WebShell）。

## PoC

确认堆叠并改写文件记录（示例，`+` 表示 URL 编码空格，GUID 与路径按目标替换）：

```http
POST /<投票修改参与人接口> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

IDs='HU002103');update+s_filedata+set+FileDir='C:/windows/',FilePath='win.ini'where+FileGUID='c25ddf570ca44b0787a50fa01ede793c';%23&ModifyState=2&TicketNo=MV000147
```

读取：

```http
GET /<文件下载接口>?FileGUID=c25ddf570ca44b0787a50fa01ede793c HTTP/1.1
```

读取 `web.xml`（拆路径绕过 FileDir 列长）：

```http
IDs='HU002103');update+s_filedata+set+FileDir='~/../webapps/ROOT/',FilePath='/WEB-INF/classes/com/xxx/core/filter/SecurityFilter.class'where+FileGUID='c25ddf570ca44b0787a50fa01ede793c';%23&ModifyState=2&TicketNo=MV000147
```

示例结果：win.ini 返回 `; for 16-bit app support ... [Mail] MAPI=1`；web.xml 返回 `<filter-name>SecurityFilter</filter-name>` 与 `excludeUrls` 中的 `/admin/login.jsp`；class 返回 `loginToken`、`filterSwitch`、`loginUrl`、`excludeUrls`、`AntPathMatcher` 等常量；properties 返回 `jdbc:mysql://127.0.0.1:3306/...` 与 `root` 配置。

## 变体与关联

- [[web-generic-file-inclusion-django-token-download-szname-traversal-read]]：同样借下载接口读文件，但那张卡是请求参数路径穿越；本卡是 SQL 注入改写数据库中的路径记录，文件路径从服务端记录读出。
- [[web-generic-sqli-mysql-outfile-general-log-webshell]]：另一条从 SQL 注入到文件/WebShell 的路径，依赖数据库 FILE/日志权限；本卡不需要 FILE 权限，读文件后用于信息收集与后续后台/RCE。
- [[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]]：JFinal 文件管理的 path/currentpath 穿越；本卡是文件元数据表被注入篡改，二者入口不同。
- [[web-generic-sqli-second-order-injection]]：注入原语相关但不同；本卡是堆叠 UPDATE 直接改业务表。
- 变体：若下载接口用 `FileGUID` 查不到记录则不返回，可先上传任意文件生成记录再改写；若 `FileDir` 不可写，可尝试 `FilePath` 拆更多；若数据库不支持堆叠，需寻找其他写文件/改记录原语。
- 边界：下载接口若对 `FileDir+FilePath` 做 realpath/白名单校验、文件存对象存储、注入账号无 UPDATE 权限或堆叠被禁用，本卡不成立。

## 检测与防御

- **检测**：SQL 日志/审计中出现 `update s_filedata`、`FileDir`、`FilePath`、`FileGUID` 等业务表字段的异常更新；`IDs`/`TicketNo` 参数出现堆叠语句、`extractvalue`、`updatexml`、括号包裹的 `information_schema`；下载接口请求后返回 `WEB-INF/`、`.class`、`win.ini`、`/etc/passwd`、`.properties` 等敏感文件；同一 FileGUID 的下载路径频繁变化。
- **防御**：SQL 全部参数化，禁用多语句（`allowMultiQueries=false`）；数据库账号最小权限，Web 账号不得 UPDATE 文件元数据表；文件路径不要由数据库任意值决定，下载时用 `realpath` 限制在允许的根目录并校验扩展名/内容；文件存储改用不可猜测的对象键并禁止跨目录；隐藏 SQL 报错；WAF 拦截堆叠/报错注入特征。
- **响应**：排查 `s_filedata` 是否有被篡改的记录与异常下载日志；重置数据库与后台口令；检查是否已读取 `web.xml`、配置、源码并进一步进入后台。
