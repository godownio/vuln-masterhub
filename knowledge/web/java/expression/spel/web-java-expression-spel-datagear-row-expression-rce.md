---
id: web-java-expression-spel-datagear-row-expression-rce
title: 'DataGear 数据行值 #{...} 被 SpEL 求值：SQL 插入触发命令执行与列长限制绕过'
type: scenario
domain: web
path: web/java/expression/spel
technique: datagear-row-spel-expression-injection
aliases:
- DataGear SpEL 注入
- ConversionSqlParamValueMapper 表达式注入
- evaluateVariableExpression
- 数据行
- DataGear 列长绕过
tags:
- java
- spring
- spel
- datagear
- expression-injection
- rce
- sql-param
- column-length-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:39:47+08:00'
  notes: 已对照原文与17张图核对；source/sink、#{...}解析、CREATE/ALTER拦截、ADDRESS varchar(200)与外部VARCHAR(1000)绕过、弹计算器均一致；原文仅出现环境版本5.1.0无受影响区间，未设版本；未复现
---

## 一句话结论

DataGear 的持久化层把数据库行里的字符串值交给 `SpelExpressionParser`，用默认的 `StandardEvaluationContext` 求值；只要向任意可写表插入形如 `#{T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('calc')}` 的值，再在页面查看该行，就会触发 SpEL 命令执行。

## 原理

- 入口是 DataGear 的数据查看/编辑接口（如 `/data/{schemaId}/{tableName}/view`），请求体 JSON 的列名/值被转成 `Row`，随后进入 `ConversionSqlParamValueMapper` 生成 SQL 参数。
- `resolveExpressionIf()` 对字符串值调用 `variableExpressionResolver.resolveNameExpressions()`；`resolveNextExpression()` 识别起始标识 `#{` 和结束标识 `}`，把中间内容作为 SpEL 表达式。
- `evaluateVariableExpression()` 执行：
  ```java
  spelExpression = this.spelExpressionParser.parseExpression(expression.getContent());
  expValue = spelExpression.getValue(expressionEvaluationContext.getVariableExpressionBean());
  ```
  上下文默认是 `StandardEvaluationContext`，支持 `T(Type)` 类型引用、构造函数与 bean 访问，因此可执行任意 Java 代码。
- `T(java.lang.String).forName('java.lang.Runtime')` 先拿到 `Runtime` 类，再 `.getRuntime().exec('calc')` 执行命令；`T()` 也可换成其他反射/命令链。
- 值在“查看/读取”行时求值，所以攻击者先把 payload 作为普通字符串存入某个列，再打开该行触发。DataGear 的 SQL 数据集编辑器会拦截 `CREATE`/`ALTER` 关键字（返回“SQL语句校验失败，不允许包含关键字”），因此不能直接改表结构扩大列宽。
- 列宽限制绕过：
  1. 找现有表中长度足够的文本列（原文 `ADDRESS varchar(200)`），payload 约 60 字符可直接放下；
  2. 在 DataGear 中新增一个攻击者可控的 MySQL 数据源，建表时使用 `VARCHAR(1000)` 或 `TEXT`，再通过 DataGear 插入/查看该行，绕过本地列宽限制。
- 根本问题是业务把“数据库里的用户数据”当成可执行表达式，而不是纯数据。

## 触发条件

- DataGear 版本存在该表达式求值行为（原文环境版本 5.1.0），且 `enableVariableExpression` 开启；
- 攻击者可登录并访问数据表的添加/编辑/查看功能，能控制某个字符串列的值；
- 目标列长度足够容纳 payload，或可接入攻击者自建数据库/使用 TEXT 列；
- SpEL 上下文为 `StandardEvaluationContext`（默认），不是受限的 `SimpleEvaluationContext`。

## 利用步骤

1. 登录 DataGear，选择可写的表；确认存在文本列及列宽。
2. 在添加/编辑数据时，把 payload 写入某个文本列（原文先试 `NAME`，因 VARCHAR(50) 报 `Data too long`）。
3. 若列太短，改选更长的列（如 `ADDRESS varchar(200)`），或在 DataGear 中新增外部 MySQL 数据源并建 `VARCHAR(1000)`/`TEXT` 表。
4. 保存后在列表点击“查看”，触发该行值的 SpEL 求值。
5. 观察命令执行效果（弹出计算器），或换成写文件/反弹 shell 的表达式。

## PoC

存入的值：

```text
#{T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('calc')}
```

对应的查看请求（列名按目标表调整）：

```http
POST /data/{schemaId}/{tableName}/view HTTP/1.1
Host: target
Content-Type: application/json
Cookie: JSESSIONID=...

{"NAME":"aaa","VALUE":"0.00"}
```

实际操作是先在添加/编辑接口把 payload 写入某一列，再对包含该行的记录执行 view；原文保存后点击“查看”，Windows 计算器弹出。

列宽不足时的报错：

```text
SQL出错: Data truncation: Data too long for column 'NAME' at row 1
```

改用 `ADDRESS varchar(200)` 或外部库 `VARCHAR(1000)` 后保存成功并触发。

## 变体与关联

- 变体：`T(java.lang.Runtime).getRuntime().exec(...)`、`new java.lang.ProcessBuilder(...)`、`T(java.lang.System).getenv()`、`T(java.lang.Runtime).getRuntime().exec(new String[]{...})`。
- 变体：无回显时用 DNS/HTTP 外带或写文件确认执行。
- 变体：payload 超长时用外部数据库 TEXT 列，或把命令拆成多段拼接。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 注入通用原理）；[[web-java-expression-spel-no-echo-exfil-streamutils]]（无回显利用）。
- 边界：若业务改用 `SimpleEvaluationContext`、关闭变量表达式、禁止用户创建数据源、或列值在入库前被转义/拒绝 `#{`，本链不成立。

## 检测与防御

- 检测：请求体/数据库行值中出现 `#{`、`T(`、`java.lang.Runtime`、`ProcessBuilder`；DataGear 日志中的 SpEL 求值异常。
- 检测：短时间内新增数据源、创建宽字符表、向文本列写入表达式样式内容。
- 防御：不要对数据库中读出的用户数据执行 SpEL；改用 `SimpleEvaluationContext` 并禁用类型/构造函数/bean 访问，或直接关闭变量表达式功能。
- 加固：限制数据源创建与 SQL 数据集编辑权限；对 `#{...}` 值做白名单/转义；升级到修复该行为的 DataGear 版本；最小权限运行。
