---
id: web-generic-sqli-jfinalcms-admin-findpage-like-filter-concat
title: JFinalCMS 后台 Admin.findPage：name/username 拼接 LIKE filterSql 交给 paginate 的 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: jfinalcms-admin-findpage-filter-sql-concat
aliases:
- JFinalCMS 后台 SQL 注入
- Admin.findPage 注入
- filterSql 拼接
- JFinal paginate 注入
- name like 注入
tags:
- web
- java
- jfinalcms
- jrecms
- sqli
- like
- paginate
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:44:45+08:00'
  notes: 已对照原文 0x07 与图27-29 核对：Admin.findPage name/username 拼接 and name like '%..%' filterSql 后交给 paginate('select *','from cms_admin where 1=1 '+filterSql)，AdminController.index getPara 未过滤直传；图29 POST /admin/admin?name=%25'+and+sleep(1)+or+'%25 响应 3074ms 确认时间盲注，PoC 与原文一致。affected_versions 原文未声明。未在本机复跑。
---

## 一句话结论

JFinalCMS 后台 `AdminController.index` 把 `getPara("name")`、`getPara("username")` 原样传给 `Admin.findPage`，后者用字符串拼接出 `and name like '%<name>%'`、`and username like '%<username>%'` 组成的 `filterSql`，再与 `from cms_admin where 1=1` 一起交给 JFinal 的 `paginate` 执行；攻击者闭合 LIKE 引号即可注入任意 SQL（原文用 `%' and sleep(1) or '%` 做时间盲注）。

## 原理

- **污染路径**：`AdminController.index` 对 `name`/`username` 未做任何过滤，直接 `new Admin().dao().findPage(name, username, pageNumber, PAGE_SIZE)`。
- **拼接点**：`Admin.findPage` 中 `filterSql += " and name like '%" + name + "%'"`（username 同理），随后 `paginate(pageNumber, pageSize, "select *", "from cms_admin where 1=1 " + filterSql + orderBySql)`。
- **为什么可注入**：JFinal 的 `paginate` 把 `sqlExceptSelect` 当作原始 SQL 字符串执行，不做参数绑定；LIKE 值被单引号包裹，但未转义 `'`，攻击者用 `%'` 闭合后追加 `and sleep(1) or '%` 即可让 WHERE 恒真并执行延时函数。原文截图中 `POST /admin/admin?name=%25'+and+sleep(1)+or+'%25` 响应延迟明显。
- **与前台的差异**：该接口位于 `/admin/admin` 后台，需要管理员会话；常见利用路径是先通过弱口令、越权、CSRF 或其它漏洞取得后台权限，再进行注入。
- **验证要点**：对比正常 name 与带 `%' and sleep(1) or '%` 的响应时间/报错；也可用报错注入或 UNION 回显确认。

## 触发条件

- 目标为 JFinalCMS/JreCms，后台管理页 `/admin/admin` 可访问。
- 攻击者拥有管理员会话（或能通过其它手段进入后台）。
- `name`/`username` 参数可控且未做白名单/参数化。
- 数据库为 MySQL（原文 payload 使用 `sleep`），其它数据库需替换延时/报错语法。

## 利用步骤

1. 登录后台，访问用户管理列表 `/admin/admin`，抓取搜索请求。
2. 构造 `name=%25' and sleep(1) or '%25`（URL 编码后的 `%' and sleep(1) or '%`），发送并观察响应时间。
3. 若延时成立，改用报错注入（`extractvalue`/`updatexml`）或 UNION 读取 `cms_admin` 等表数据；也可用 `if(substr(...)...)` 做布尔盲注。
4. 根据回显/时间提取管理员账号密码哈希、其它业务数据。
5. 验证：延时/报错与输入条件一致；失败时检查参数是否被框架过滤、数据库类型、后台权限。

## PoC

```http
POST /admin/admin?name=%25%27%20and%20sleep(1)%20or%20%27%25 HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<admin session>
Content-Length: 0
```

原始参数值等价于：`%' and sleep(1) or '%`。

## 变体与关联

- [[web-generic-sqli-jfinalcms-baseform-orderby-extractvalue]]：同产品 `BaseForm.orderColumn` 的 order-by 报错注入；本卡是 `findPage` 的 LIKE/filterSql 拼接，参数与 sink 不同。
- [[web-generic-sqli-like-clause-append-search]]：LIKE 拼接注入的通用手法。
- 变体：`username` 参数同样可注入；`orderBySql` 由 `DbUtils.getOrderBySql` 生成，若其参数可控也可注入；数据库换成其它方言时替换延时函数。
- 边界：后台不可达、参数被参数化/白名单、数据库禁用延时函数时需换注入技术。

## 检测与防御

- 检测：`findPage`/`paginate` 中出现字符串拼接的 `like '%"+param+"%'`；请求参数含 `'`、`sleep`、`extractvalue` 等；后台出现异常长响应。
- 防御：使用参数化查询（`Db.paginate` 的占位参数或手动 `PreparedStatement`）；LIKE 值转义 `%`/`_`/`'`；对排序字段使用白名单；后台接口加 CSRF/权限与审计。
- 响应：排查后台注入日志，评估数据库数据是否泄露。
