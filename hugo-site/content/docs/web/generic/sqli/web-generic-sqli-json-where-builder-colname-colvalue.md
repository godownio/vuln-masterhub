---
id: web-generic-sqli-json-where-builder-colname-colvalue
title: JSON 条件构造器直接拼接 colName/colValue：ThemeUtil.whereSql 生成 MyBatis ${} 注入片段
type: scenario
domain: web
path: web/generic/sqli
technique: json-where-builder-sql-injection
tags:
- sqli
- java
- mybatis
- json
- where-builder
- identifier-injection
- authenticated
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:50:41+08:00'
  notes: 已对照原文核对：图8-14确认MsgDao.getXzry使用${whereSqlJson}/${treeWhereJson}，ThemeUtil.whereSql把colName/colValue/objlink直接拼接且colName不加引号，图12确认getXzry.action参数来源；图15-20确认getRs.action→PubDao.getProcessAmount的${tableName}/${condition}。未验证点：原文未给出注入请求/回显，利用需XGXT登录态；frontmatter无source_url；未本机复跑。
url: /docs/web/generic/sqli/web-generic-sqli-json-where-builder-colname-colvalue/
draft: false
kb_aliases:
- ThemeUtil.whereSql 注入
- whereSqlJson 注入
- treeWhereJson 注入
- colName colValue 拼接
- getXzry SQL 注入
- getRs tableName condition 注入
---

## 一句话结论

学生平台的 `getXzry.action` 从请求接收 `whereSqlJson`/`treeWhereJson`，`ThemeUtil.whereSql` 把 JSON 数组里的 `colName`、`colValue`、`objlink` 直接拼成 `and colName = colValue` 片段，再作为 MyBatis `${whereSqlJson}` 文本替换进 SQL；`colName` 不加引号进入语法层，攻击者可注入任意 WHERE 表达式。另一入口 `getRs.action` 的 `tableName`/`condition` 同样以 `${}` 拼接。

## 原理

- **数据流**：`@RequestMapping("getXzry.action")` → `this.getString("whereSqlJson")`/`getString("treeWhereJson")` 读取请求参数 → `ThemeUtil.whereSql(whereSqlJson)` / `ThemeUtil.getTreeWhere(treeWhereJson)` 生成 SQL 片段 → 放入 Map → `MsgDao.getXzry(Map)`。
- **构造器缺陷**：`whereSql` 把入参解析为 JSONArray，逐个取 `colName`、`colValue`、`objlink`：
  ```java
  if ("=".equals(objlink))  whereSql.append(" and " + colName + " = " + colValue);
  else if (">".equals(objlink)) whereSql.append(" and " + colName + " > " + colValue);
  // like/in/not in 等同理
  ```
  `colName` 完全不加引号，`colValue` 仅按运算符加引号/加 `%`，没有白名单、转义或参数绑定。
- **进入 SQL 的位置**：`MsgDao.xml` 的 `getXzry` 使用 `${whereSqlJson}` 与 `${treeWhereJson}`（文本替换，非 `#{}` 预编译），把构造器返回的片段原样插入 `where 1=1` 之后。
- **为什么成立**：SQL 的列名/运算符属于语法结构，JDBC 不能绑定；业务为了实现“动态条件”自行拼接字符串，攻击者可通过 `colName` 注入表达式、子查询或注释。`getRs.action` 的 `tableName`/`condition` 走 `PubDao.getProcessAmount` 的 `${tableName}`/`${condition}`，属同一类。
- **原文验证边界**：文章完整追踪了参数到 SQL 的代码路径，但未给出 sqlmap/手工注入的请求与数据库回显，且 XGXT 的 `SessionFilter` 要求登录态；confidence 记 medium。

## 触发条件

- 目标存在 `getXzry.action`/`getRs.action` 等入口，参数名与代码一致。
- 攻击者拥有 XGXT 会话（`SessionFilter` 要求登录；原文未发现绕过）。
- Mapper 中对应字段使用 `${}`，且 `ThemeUtil`/`getRs` 未做白名单校验。

## 利用步骤

1. 登录 XGXT 获取有效 `JSESSIONID`，确认 `getXzry.action` 可访问。
2. 构造 `whereSqlJson` 为 JSON 数组，元素包含 `colName`、`colValue`、`objlink`；在 `colName` 中放入 SQL 表达式/注释，观察排序、报错或布尔差异。
3. 或使用 `getRs.action` 的 `condition`/`tableName` 参数直接拼接 WHERE/表名。
4. 用布尔/时间/报错盲注提取数据；评估数据库权限与后续利用（文件读写、UDF 等取决于 DB）。
5. 注意 `treeWhereJson` 走另一构造器 `getTreeWhere`，注入形态可能不同，可分别测试。

## PoC

原文未给出实际注入请求/回显，仅给出代码路径。请求骨架：

```http
POST /xgxt/getXzry.action HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid>
Content-Type: application/x-www-form-urlencoded

whereSqlJson=[{"colName":"<SQL表达式>","colValue":"x","objlink":"="}]&treeWhereJson=&mtReceived=
```

```http
POST /xgxt/getRs.action HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid>
Content-Type: application/x-www-form-urlencoded

xn=&xybh=&xmlx=&xmbh=&ejxmlx=&ejxmbh=&tableName=<表名>&condition=<SQL片段>
```

`colName` 在 `whereSql.append(" and " + colName + " = ...")` 中未加引号，可直接承载表达式；具体闭合方式取决于前后 SQL 与注释符支持，原文未演示。

## 变体与关联

- 变体：`objlink` 选择 `in`/`not in` 时 `colValue` 进入括号列表；`colName` 注入子查询/`EXISTS`；`treeWhereJson` 的树形条件构造器可能有不同拼接点；`getRs` 的 `tableName` 可替换为子查询/其他表。
- 关联：`[[web-generic-sqli-mybatis-dollar-brace-injection]]`（MyBatis `${}` 五类拼接点总览）；`[[web-generic-sqli-java-identifier-table-order-by-injection]]`（标识符位置不可预编译）；`[[web-generic-sqli-second-order-injection]]`（条件片段持久化后的二次注入）。
- 与普通值注入的区别：注入点是 `colName`（标识符/表达式位置），不需要闭合引号；`colValue` 即使加了引号也仍可能通过特殊字符/宽字节等影响。

## 检测与防御

- 检测：请求参数 `whereSqlJson`/`treeWhereJson`/`condition`/`tableName` 中出现 SQL 关键字、括号、注释符、子查询；Mapper 的 `${}` 执行语句与正常业务 SQL 结构差异；数据库报错日志中的异常 WHERE。
- 修复：排序/列名/表名使用白名单枚举映射；条件值使用 `#{}` 参数绑定；不要让客户端提交完整 SQL 片段或 JSON 条件构造器。
- 缓解：WAF 对 JSON 条件字段中的 SQL 语法告警；数据库账户最小权限；关闭详细报错；限制该接口的登录要求与频率。
