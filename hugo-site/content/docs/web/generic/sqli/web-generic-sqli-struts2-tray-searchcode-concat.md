---
id: web-generic-sqli-struts2-tray-searchcode-concat
title: Struts2 自研 Tray 封装 repHashMap 不过滤：searchCode 直接拼接 LIKE 造成 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: struts2-tray-searchcode-concat-sqli
tags:
- web
- java
- struts2
- sqli
- jdbc
- code-audit
- tray
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:18:17+08:00'
  notes: 已对照原文与 28 张图核对：TubisRequestTrayFactory.createTray 收集参数、Injection_pro.repHashMap 直接 return hmap、repInvalidChar 未被调用、ContractEdiPopupAct.searchcode 的 searchCode→LIKE 拼接、jdbc:mysql://10.10.19.218:13306/TSIS gw/gw 硬编码凭据均与图 24-28 一致。核实修正：卡内指向已 reject 草稿的 wiki 链接已改为既有同类卡 web-generic-file-inclusion-luckyframeweb-download-filename-traversal。未验证点：原文未展示注入回显/盲注结果，PoC 为按源码构造；需普通用户会话。
url: /docs/web/generic/sqli/web-generic-sqli-struts2-tray-searchcode-concat/
draft: false
kb_aliases:
- TubisRequestTrayFactory 注入
- Tray searchCode SQL 注入
- repHashMap 未过滤
- repInvalidChar 死代码
- ContractEdiPopupAct searchcode
---

## 一句话结论

老 Struts2 项目用自研 `TubisRequestTrayFactory` 把所有请求参数装进 `Tray`，其“过滤入口”`Injection_pro.repHashMap` 直接原样返回（真正实现过滤的 `repInvalidChar` 存在但从未被调用）；`ContractEdiPopupAct.searchcode` 从 `tray.getString("searchCode")` 取值后拼进 `PROJECT_NAME LIKE '%...%'` 并执行 JDBC 查询，普通登录用户即可注入，读取/篡改数据库数据。

## 原理

- **参数收集**：`TubisRequestTrayFactory.createTray` 遍历 `request.getParameterNames()` 与 `request.getParameterValues(name)`，把每个参数名和值加入 `Tray`；随后 `setReq` 的值经过 `Injection_pro.repHashMap`。
- **过滤是死代码**：`Injection_pro.repHashMap` 的实现只有 `return hmap;`；同一类里另有 `repInvalidChar`/`replChar` 会替换引号、分号、`--`、`#` 等字符，但调用链没有引用它，形成“看起来有过滤、实际没有”的假象。
- **拼接点**：`ContractEdiPopupAct.searchcode` 中 `String searchCode = tray.getString("searchCode");`，随后构造 `String query = "select PROJECT_SAP_CODE, PROJECT_NAME from VW_PROJECT_INFO where PROJECT_NAME like '%" + searchCode + "%'";`，用 `DriverManager.getConnection` 与 `stmt.executeQuery(query)` 执行。用户输入位于单引号字符串内，可直接闭合。
- **权限边界**：该 Action 继承 `CommonCountAct`，其 `init` 校验 session 中的 `ssCustId`，未登录会跳转登录页；因此注入需要普通用户会话，不是未授权漏洞。
- **代码中的硬编码凭据**：同一段代码写入 `jdbc:mysql://10.10.19.218:13306/TSIS`、账号 `gw`、密码 `gw`，源码泄露时可直接连库，也会扩大该注入的影响。

## 触发条件

- 目标为使用该 Tray 封装与 `ContractEdiPopupAct` 的 Struts2 应用，Action 路由可达。
- 攻击者拥有普通登录用户会话（session 中存在 `ssCustId`）。
- 数据库为 MySQL（原文硬编码 MySQL 连接），且当前数据库账号对 `VW_PROJECT_INFO` 及后续利用对象有权限。
- 未部署 SQL 注入 WAF 或 WAF 可被注释/编码绕过。

## 利用步骤

1. 登录普通账号，确认 `/ContractEdiPopupAct.do?method=searchcode` 可访问。
2. 在 `searchCode` 参数中闭合 `LIKE '%...%'` 的单引号，先用布尔/报错判断注入：
   `searchCode=' AND '1'='1` 与 `searchCode=' AND '1'='2` 返回差异。
3. 用 `UNION SELECT` 读取其他表（列数按原查询两列调整），或用时间盲注确认。
4. 读取管理员表/会话表，结合登录认证逻辑添加管理员或直接取数据。
5. 若源码泄露，使用硬编码数据库凭据直连数据库，绕过应用层限制。

## PoC

```http
GET /ContractEdiPopupAct.do?method=searchcode&searchCode='%20AND%20'1'='1 HTTP/1.1
Host: target:8080
Cookie: JSESSIONID=<普通用户会话>
```

布尔差异确认后，按两列构造 UNION：

```text
searchCode=' UNION SELECT USER(),DATABASE()-- -
```

原文只给出代码与路由构造，未展示实际注入回显截图，利用时需按目标数据库和查询列数调整。

## 变体与关联

- **同类参数**：其他 Action 中同样使用 `tray.getString(...)` 拼 SQL 的位置都可复用该入口；审计时全局搜索 `tray.getString(` 与 SQL 关键字。
- **同类框架**：`RequestTrayFactory.getTray → createTray` 的抽象封装可能被多个子类实现，过滤逻辑可能在某个子类中真正启用，需逐个子类确认。
- **权限前置**：普通用户会话可通过任意文件读取数据库配置后添加账号获得（同类下载接口参数直入文件路径见 [[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]）。
- **硬编码凭据**：源码中的 JDBC 地址/账号/密码属于独立风险，可作为源码泄露后的直连入口。

## 检测与防御

- 使用 `PreparedStatement` 参数化查询，禁止把 `searchCode` 等请求参数拼进 SQL 字符串。
- 修复 Tray 过滤：在 `repHashMap` 中实际调用 `repInvalidChar` 或统一在 DAO 层做参数化；删除死代码式“过滤器”以免误判。
- 移除源码中的硬编码数据库凭据，改用配置中心/密钥管理，并按最小权限授予数据库账号。
- 审计与监控：对 `LIKE '%...%'` 拼接、`tray.getString`、`stmt.executeQuery(query)` 组合做静态扫描；WAF 对 `'`、`UNION`、`--` 等做告警。
