---
id: web-generic-sqli-taier-console-listnames-jobname
title: DTStack Taier ConsoleController.listNames 的 jobName 参数经 MyBatis ${} 拼接导致 SQL 注入（CVE-2024-41579）
type: scenario
domain: web
path: web/generic/sqli
technique: taier-listnames-jobname-mybatis-dollar-injection
tags:
- sqli
- mybatis
- java
- spring-boot
- dtsight
- taier
- dollar-brace
- code-audit
- cve-2024-41579
cve:
- CVE-2024-41579
affected_versions: Taier 1.4.0
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:32:16+08:00'
  notes: '已对照原文核对；本次核对未读取图片；listNames 接口与 jobName 参数、ConsoleController→ConsoleService→ScheduleJobCacheMapper 调用链与原文一致，卡片已按 MyBatis 真实语义纠正原文写反的 $ 与 # 说明。受影响版本取原文标题的 Taier 1.4.0。未验证点：原文未在正文给出具体 payload 字符串（仅截图），卡内 PoC 为按调用链推导、未经实测；listNames 使用 ${} 拼接这一点来自未读的 XML 截图，未逐字确认'
url: /docs/web/generic/sqli/web-generic-sqli-taier-console-listnames-jobname/
draft: false
kb_aliases:
- CVE-2024-41579
- Taier SQL 注入
- Taier listNames 注入
- ScheduleJobCacheMapper listNames
- ConsoleController jobName 注入
- DTStack Taier 1.4.0 SQLi
---

## 一句话结论

DTStack Taier 1.4.0 的 `ConsoleController.listNames` 把请求参数 `jobName` 原样透传到 `ConsoleService.listNames → ScheduleJobCacheMapper.listNames`，后者在 MyBatis XML 里用 `${}` 直接拼接 SQL，攻击者 POST 一个含引号/布尔表达式的 `jobName` 即可在调度元数据库上做注入（CVE-2024-41579）。

## 原理

- MyBatis 的 `#{}` 生成 `PreparedStatement` 占位符 `?`，值只能作为数据；`${}` 则在 SQL 文本层面做字符串替换，值会变成 SQL 语法的一部分。因此只要 Mapper XML 里出现 `${jobName}`，任何未过滤的入参都等价于把 SQL 片段交给数据库。
- Taier 的调用链是典型的 Spring MVC「Controller → Service → Mapper」三段式：`ConsoleController.listNames` 用 `@PostMapping` 直接绑定请求参数（`jobName` 来自请求体/表单，没有任何白名单或转义），`ConsoleService.listNames` 透传，最终 `ScheduleJobCacheMapper.listNames` 在 XML 里以 `${}` 拼接。
- 漏洞成立的关键不是「参数可控」本身，而是**可控参数跨过三层后仍保持字符串形态进入 SQL 文本**：中间没有任何 ORM 参数绑定、没有类型转换（不是按 ID 强转 long）、也没有业务校验，所以注入字符能完整到达数据库解析器。
- 该接口属于控制台内部 API（`/taier/api/console/**`），若部署时未加认证/网关限制，未授权即可访问，注入面直接暴露给攻击者。

## 触发条件

- 运行 DTStack Taier 1.4.0（或其他 `listNames` 仍使用 `${}` 的版本），数据库为 MySQL 等支持注释与函数的标准 SQL 后端。
- `/taier/api/console/listNames` 可从攻击者网络位置访问（未登录、或持有任意低权限账号）。
- 目标 Mapper XML 中 `jobName` 使用 `${}` 拼接；若已改为 `#{}`，该链不成立（同一产品的新版即属此类修复）。
- 具备回显、布尔差异或时间差异中的任意一种观测通道，用于确认注入生效。

## 利用步骤

1. 确认接口存在与参数名：向 `/taier/api/console/listNames` 发送 POST，携带 `jobName` 参数，观察返回是否为任务名列表。
2. 用单引号/括号做语法探测，对比 500 报错、返回条数变化与正常请求的差异，判断注入点是否落在 `WHERE`/`LIKE` 上下文，并据报错或差异闭合引号。
3. 建立布尔盲注基线（真/假两个 payload 的响应差异），或直接用时间盲注（`SLEEP`）绕过无回显。
4. 按数据库类型枚举当前库名、表名（Taier 元数据表如调度任务/数据源配置表），再取数据源连接串、账号口令等二次利用材料。
5. 若数据库账号具备 FILE 权限且 `secure_file_priv` 放开，可进一步考虑写文件；否则以数据窃取为终点。

## PoC

文中只把公开 payload 以截图形式给出，正文没有复述具体注入字符串，因此下面给出的是按上述调用链推导的最小验证请求，**未经实测**，需按目标实际 SQL 上下文调整闭合方式：

```http
POST /taier/api/console/listNames HTTP/1.1
Host: <taier-host>
Content-Type: application/x-www-form-urlencoded

jobName=1' AND SLEEP(5)-- -
```

判定：该请求相对 `jobName=1` 出现约 5 秒稳定延迟即认为注入成立；随后把 `SLEEP(5)` 换成布尔条件或子查询提取数据。

同一 Controller 下另有 `jobId` 走 `/taier/api/console/jobStick`，文中推测其 `getOne` 亦为注入点，但文中同时说明该处 XML 使用的是 `#{}` 占位符，按 MyBatis 语义不构成注入，且文中未给出任何验证结果，故本条不作为可复用场景收录。

## 变体与关联

- 变体：同类 `${}` 拼接在 Taier 其他列表/搜索接口（任务名、数据源名、模糊查询 `LIKE`）中常成对出现，可用同一套盲注手法横向排查。
- 变体：无回显且时间函数被 WAF 拦截时，可改用笛卡尔积放大（大表 join）产生的响应时间差，或 `CASE WHEN` 驱动的返回条数差异。
- 关联：[[web-generic-sqli-spring-rbac-mybatis-dollar-dictname-datascope]]（同为 Spring Boot + MyBatis `${}` 造成注入的代码审计范式，但产品与接口不同）。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（盲注阶段的函数/关键字过滤绕过）。
- 说明：`$` 与 `#` 的语义在文中写反了（文中称 `$` 为预编译、`#` 为直接拼接），实际相反；卡片按 MyBatis 真实语义描述，这直接影响「`getOne` 是否可注入」的判断。

## 检测与防御

- 修复：把 `ScheduleJobCacheMapper` 中所有 `${}` 改为 `#{}`；`LIKE` 场景用 `CONCAT('%', #{jobName}, '%')` 而非把 `%` 拼进 SQL 文本。
- 加固：对 `jobName` 做长度与字符白名单校验（仅允许字母数字、下划线、短横线），在 Controller 层就拒绝引号、括号、注释符。
- 加固：控制台 API（`/taier/api/console/**`）统一加认证与网络 ACL，避免未授权可达。
- 检测：应用日志或 WAF 中 `jobName` 出现 `'`、`)`、`--`、`/*`、`SLEEP(`、`BENCHMARK(`、`AND 1=1` 等特征；数据库侧慢查询日志出现由业务接口触发的异常 `SELECT ... SLEEP(...)`。
- 检测：同一来源对 `/taier/api/console/listNames` 高频 POST 且响应码在 200/500 间抖动，或响应体条数随 payload 系统性变化。
