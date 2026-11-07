---
id: web-generic-sqli-sobey-mcheditor-wxarticlelist-whitelist-bypass
title: sobey-mchEditor wxarticleList 未授权 SQL 注入：String.format 拼接叠加 getRequestURI 白名单路径穿越绕过
type: scenario
domain: web
path: web/generic/sqli
technique: sobey-mcheditor-wxarticlelist-sql-format-whitelist-bypass
aliases:
- /sobey-mchEditor/mch/statistics/wxarticleList
- wxarticleList SQL 注入
- 融媒体系统 SQL 注入
- getRequestURI 白名单 contains 绕过
- /mch/statistics/js/../wxarticleList
- createUserCode SQL 注入
tags:
- web
- sqli
- java
- spring-mvc
- string-format
- auth-bypass
- whitelist
- getrequesturi
- path-traversal
- sobey
- mcheditor
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:18+08:00'
  notes: 已对照原文与图10-13核对；String.format拼接createUserCode/username/title、getRequestURI().contains白名单与/ mch/statistics/js/../wxarticleList绕过一致；原文未给完整SQLi回显PoC，卡片confidence=medium并注明；未设置versions
---

## 一句话结论

`/sobey-mchEditor/mch/statistics/wxarticleList`（以及同一 controller 的 `wxarticleTotalList`、`queryMultiArgListCreateNname`、`countWxarticleByChannel`、`countArticleGroupByChannel`、`articleList`）把 `createUserCode`、`username`、`title` 等参数用 `String.format` 直接拼进 SQL，存在注入；接口本需鉴权，但鉴权拦截器用未规范化的 `request.getRequestURI()` 与白名单做 `contains` 匹配，请求 `/mch/statistics/js/../wxarticleList` 时原始 URI 命中白名单 `/mch/statistics` 或 `/js`，容器随后把 `js/..` 归一化并路由到真实受保护接口，从而未授权注入。

## 原理

- **SQL 拼接**：`wxarticleList` 接收大量可选参数（`channelId`、`id`、`pageSize`、`pageIndex`、`createStartTime`、`createEndTime`、`createUserCode`、`finalStartTime`、`finalEndTime`、`title`、`finalUserCode`、`username`、`orderCode`、`orderWay` 等），方法内用 `StringBuffer` 拼基础查询，再按条件追加：
  - `sqlBuffer.append(String.format(" and createUserCode = '%s' ", createUserCode))`
  - `sqlBuffer.append(String.format(" and zcnwxarticle.username = '%s' ", username))`
  - `sqlBuffer.append(String.format(" and zcnwxarticle.titleIn LIKE '%%%s%%' ", title))`
  参数被放进单引号内，攻击者输入 `'` 即可闭合字符串，后续 `AND`/`OR`/`UNION`/注释任意构造；`LIKE '%%%s%%'` 中的 `%` 只是 LIKE 通配符，同样不阻断注入。全程没有 `PreparedStatement` 占位符或参数绑定。
- **鉴权代码**：`preHandle` 取 `String uri = request.getRequestURI().replace(contextPath, "")`，遍历配置 `allowUrls`，对每个白名单值执行 `if (uri.contains(siteCode)) return true;`。`getRequestURI()` 返回 Tomcat 保存的原始请求目标，不做 `..` 归一化、不解码、不删除 `;` 路径参数。
- **绕过原理**：白名单里有 `/mch/statistics`、`/js`、`/css`、`/image`、`/images`、`/AIInt`、`/getList` 等片段。请求 `/sobey-mchEditor/mch/statistics/js/../wxarticleList` 的原始 URI 同时包含 `/mch/statistics` 与 `/js`，`contains` 判断直接放行；随后 Tomcat/Spring 在映射前按路径语义把 `js/..` 归一化为空，实际路由到 `/mch/statistics/wxarticleList`。鉴权看到的是“含白名单片段的原始串”，业务看到的是“归一化后的受保护接口”，两者不一致即形成绕过。
- **组合效果**：未登录用户先绕过鉴权，再把注入 payload 放进 `createUserCode`/`username`/`title` 等参数，得到未授权 SQL 注入；可按数据库类型选择布尔、时间、报错或 UNION 回显。

## 触发条件

- 目标为 sobey-mchEditor，`/mch/statistics/*` 接口可达；鉴权拦截器与白名单配置未修改。
- 白名单仍包含 `/mch/statistics`、`/js` 等可被路径片段命中的值，且使用 `getRequestURI()` + `contains` 判断。
- 容器/框架会对 `..` 做归一化后再路由（Tomcat + Spring MVC 默认如此）。
- 数据库账号有对应查询权限；若为盲注还需可观察的布尔差异/时间延迟/报错。

## 利用步骤

1. 先验证绕过：对比 `/sobey-mchEditor/mch/statistics/wxarticleList`（预期被拦截）与 `/sobey-mchEditor/mch/statistics/js/../wxarticleList`（预期进入业务逻辑），观察响应差异。
2. 在 `createUserCode` 等参数中放入单引号，确认 SQL 语法错误或页面差异；用 `AND '1'='1` / `AND '1'='2` 做布尔判断。
3. 按数据库类型构造 UNION、报错或时间盲注；`pageSize`/`pageIndex` 若参与拼接也可作为注入点。
4. 对同 controller 的其他接口（`wxarticleTotalList`、`queryMultiArgListCreateNname`、`countWxarticleByChannel`、`countArticleGroupByChannel`、`articleList`）重复验证，它们存在相同的 `String.format` 拼接模式。
5. 绕过路径可换成 `%2e%2e`、`;` 路径参数、双斜杠等变体，取决于容器解码与归一化顺序。

## PoC

原文未给出完整回显 PoC，以下按源码构造最小验证请求（需按实际参数名与数据库调整）：

```http
POST /sobey-mchEditor/mch/statistics/js/../wxarticleList?token=&siteCode=&createUserCode=1%27%20AND%20%271%27%3D%271 HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

参数也可放在 POST body 中。若 `AND '1'='1` 与 `AND '1'='2` 返回不同结果，说明注入成立；再按目标数据库替换为 UNION/时间盲注 payload。

## 变体与关联

- 变体：路径用 `/mch/statistics/../mch/statistics/wxarticleList`、`/mch/statistics/css/../wxarticleList`、`/js/../mch/statistics/wxarticleList`，或对 `..` 做 `%2e%2e`、`%252e%252e` 编码，只要原始 URI 含白名单片段且归一化后命中目标接口。
- 变体：`;` 路径参数（如 `/mch/statistics/;js/../wxarticleList`）利用不同容器对矩阵参数的解析差异。
- 关联：未授权 SQL 注入的通用模式 [[web-generic-sqli-artery-erp-workflow-sqlresult-unauth]]；`getRequestURI` 原始路径与 MVC 归一化路径差异 [[web-java-framework-spring-custom-auth-path-parsing-bypass]]；`contains` 白名单 + 路径穿越的具体案例 [[web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass]]；同系统的上传与 XXE [[web-generic-file-upload-sobey-mcheditor-watermark-filename-traversal-jsp]]、[[web-generic-xxe-sobey-mcheditor-aitaskback-documentbuilderfactory]]。
- 边界：改为预编译参数绑定、白名单用归一化后的精确路径匹配（`equals`/`startsWith` 且先 `normalize`）、或使用 `getServletPath()` 时，本链失效。

## 检测与防御

- 检测：请求路径中出现 `js/..`、`css/..`、`%2e%2e`、`;` 等异常片段且目标为受保护接口；SQL 参数中出现单引号、`AND`/`OR`/`UNION`/`SLEEP` 等特征；同一 IP 在短时间内对 `/mch/statistics/*` 做布尔差异探测。
- 修复：所有 SQL 使用 `PreparedStatement`/MyBatis `#{}` 参数绑定，禁止 `String.format` 拼接；`orderCode`/`orderWay` 等排序参数用白名单映射。
- 修复：鉴权白名单改用归一化后的路径做精确匹配，禁止 `contains` 子串判断；使用 `getServletPath()` 并先 `normalize()`，拒绝含 `..`、`;`、编码斜杠的路径。
- 加固：在网关层拒绝路径穿越片段；对 `/mch/statistics/*` 强制 token 校验并做统一权限拦截；开启 SQL 审计与异常查询告警。
