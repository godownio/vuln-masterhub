---
id: web-java-component-finereport-getSessionID-auth-bypass
title: FineReport DecisionInterceptor 鉴权绕过：reportlets=/ 使模板鉴权返回 null，配合 op=getSessionID 未认证获取合法 sessionID
type: scenario
domain: web
path: web/java/component
technique: finereport-decision-interceptor-sessionid-bypass
aliases:
- 帆软 getSessionID 鉴权绕过
- FineReport DecisionInterceptor 绕过
- reportlets=/ 绕过
- ReportTemplateRequestChecker 绕过
- GroupReportletCreator getSessionID
- 帆软未授权 sessionID
tags:
- java
- finereport
- authentication-bypass
- sessionid
- interceptor
- reportlets
- session
cve: []
severity: high
confidence: high
status: verified
affected_versions: FineReport < 11.5.4.1（原文漏洞影响范围节标记；同节另列 FineBi/FineDataLink 区间）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:32:28+08:00'
  notes: 已对照原文及39张图核对：图01-11确认DecisionInterceptor/13个Checker/ReportTemplateRequestChecker.acceptRequest/reportlets参数/getTempAuthValidatorStatus返回[null]/checkRequest返回true；图12-20确认ReportDispatcher op=getSessionID、9个WebletCreator、GroupReportletCreator在op=getSessionID时返回非空Weblet、最终payload GET /webroot/decision/view/report?op=getSessionID&reportlets=[{'reportlet':'/'}] 返回36字节UUID(69f26a96-...)。卡片与原文一致。未验证点：sessionID有有效期，需重新获取；原文未展示后续接口的完整利用；未本机复跑。注意cards.json中该卡id写作全小写getsessionid，实际KB frontmatter id为getSessionID（大小写敏感），已按实际id核对。
---

## 一句话结论

FineReport 的 `DecisionInterceptor` 依据请求参数选择 `RequestChecker`，当 `reportlets=/`（或 `[{'reportlet':'/'}]`）时 `detectTemplateNeedAuthenticate()` 把模板名按 `/` 分割得到长度 0，`checkTemplateAuthority()` 返回 false，`getTempAuthValidatorStatus()` 返回只含 null 的列表，`checkRequest()` 因此返回 true 放行；随后用 `op=getSessionID` 让 `GroupReportletCreator` 生成合法 sessionID，攻击者无需登录即可拿到可用于后续导出接口的会话。

## 原理

- 请求先经过 `DecisionInterceptor.preHandle()`：`PreHandlerFactory.getRequestChecker()` 遍历 13 个 Checker，命中 `ReportTemplateRequestChecker.acceptRequest()` 即返回该 Checker。`acceptRequest()` 要求方法上有 `@TemplateAuth(product=FINE_REPORT)` 且 `TemplateParser.analyzeTemplateID()` 非空——后者依次读取 `viewlet`、`reportlet`、`formlet`、`reportlets` 参数，因此请求只需带其中一个参数。
- `ReportTemplateRequestChecker.checkRequest()` 在模板鉴权开启时调用 `getTempAuthValidatorStatus(request, templateId, authType)`。其内部对每个模板调用 `getTempAuthStatus()`：
  - `getTempAuthStatus()` 先执行 `detectTemplateNeedAuthenticate()`，若为 false 就返回 null；
  - 循环 `for (status : list)` 时，只有 `status != null && !status.isDirectAccessTemp()` 才把 `var9=true`；若列表元素全为 null，`var9` 保持 false，于是 `if (!var9) return true`，鉴权通过。
- 让 `detectTemplateNeedAuthenticate()` 返回 false 的关键：
  - 它先 `getNormalizeTemplatePath()`，再 `String[] parts = path.split("/")`，`int len = parts.length`；
  - 若传入 `/`，规范化后按 `/` 分割得到空数组，`len == 0`；
  - `checkTemplateAuthority("/", [], 0)` 查不到权限值（null），进入 else：`len > 1` 不成立、`len == 1` 不成立，最终 `return false`；
  - 因此 `getTempAuthStatus()` 返回 null，`getTempAuthValidatorStatus()` 返回 `[null]`。
- `getTemplateId` 还支持 JSON 数组形式：请求参数以 `[` 开头、`]` 结尾时，`getTemplateFromBookPath()` 用 JSON 解析出 `reportlet` 字段，因此 `reportlets=[{'reportlet':'/'}]` 同样得到模板名 `/`。
- 放行后进入 `ReportDispatcher.dealWithRequest()`：读取 `op` 与 `sessionID`；当 `op=getSessionID` 且无 sessionID 时调用 `SessionPoolManager.generateSessionIDWithCheckRegister()`，其中 `WebletFactory.createWebletByRequest()` 遍历 9 个 WebletCreator，按参数名与后缀/格式匹配。
- 前面的 payload 里 `reportlets=[{'reportlet':'/'}]` 命中 `GroupReportletCreator`（要求参数以 `[` 开头、`]` 结尾），其重写的 `createWebletByRequest()` 在 `op=getSessionID` 时返回 `GroupTemplateReportlet` 包装的非空 Weblet；其他 Creator 多数走父类反射实例化 `/` 失败返回 null，会导致 `generateSessionID()` 抛 `WebletException`。
- 最终请求：`GET /webroot/decision/view/report?op=getSessionID&reportlets=[{'reportlet':'/'}]` 返回 200 与一个 UUID 形式的 sessionID，全程不需要登录 Cookie。

## 触发条件

- FineReport 受影响版本（原文影响范围节列出 FineReport < 11.5.4.1；sessionID 绕过本身适用于该分析版本 11.5.4 的 `DecisionInterceptor`）。
- `/webroot/decision/view/report` 可达，且未在网关层拦截 `reportlets` 参数或 `[`/`]`/`/` 组合。
- 请求无需认证；原文请求不带 Cookie，Referer 为登录页。
- 需要按目标请求参数选择能通过的 Creator：`reportlets` 或 `viewlets` 传 `/` 或 `[{'reportlet':'/'}]`，并带 `op=getSessionID`。

## 利用步骤

1. 直接请求 `GET /webroot/decision/view/report?op=getSessionID&reportlets=[{'reportlet':'/'}]`。
2. 观察 `DecisionInterceptor` 未返回 401/403，响应体为 36 字节 UUID 字符串（原文为 `69f26a96-af08-40e9-9500-73dfdbd02843`）。
3. 将该值作为后续接口的 `sessionID` 头/参数使用（如 `/webroot/decision/nx/report/v9/largedataset/export/excel`），无需登录即可访问需要模板会话的业务。
4. sessionID 有过期时间，后续利用需重新获取。

## PoC

```http
GET /webroot/decision/view/report?op=getSessionID&reportlets=[{'reportlet':'/'}] HTTP/1.1
Host: 192.168.197.130:8075
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0
Accept: */*
Referer: http://192.168.197.130:8075/webroot/decision/login
```

```text
HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8
Content-Length: 36

69f26a96-af08-40e9-9500-73dfdbd02843
```

变体：`reportlets=/` 直接传单个 `/` 也能走 `getTempAuthStatus` 的非多模板分支；`viewlets` 与 `reportlets` 可互换。

## 变体与关联

- 变体：`reportlets=/`（不经 JSON 解析）与 `reportlets=[{"reportlet":"/"}]` 两种形态；参数名可换 `viewlets`。
- 关联：`[[web-java-component-finereport-export-excel-formula-sqli-vacuum-webshell]]`（本绕过获得的 sessionID 用于未认证调用导出接口并最终 RCE）；[[web-java-component-finereport-view-reportserver-template-sqli-webshell]]（同产品无需 sessionID 的另一条前台 SQLi 链）。
- 边界：sessionID 会过期；若部署层对 `reportlets` 参数值做严格白名单，或关闭模板鉴权分支（行为不同），绕过不成立；该缺陷本质是鉴权逻辑对“空模板路径列表”的默认放行，而非登录态伪造。

## 检测与防御

- 检测：`/webroot/decision/view/report` 请求同时出现 `op=getSessionID` 与 `reportlets`/`viewlets` 值为 `/`、`[{'reportlet':'/'}]`；未登录来源短时间内批量获取 sessionID；随后使用该 sessionID 调用导出/打印接口。
- 修复：升级到官方修复版本；在 `getTempAuthValidatorStatus`/`checkRequest` 中把 null 状态视为鉴权失败，拒绝空模板路径列表（长度为 0）的输入；对 `reportlets` 做格式与模板存在性校验。
- 加固：网关/WAF 拦截含 `reportlets=/`、`[{'reportlet':'/'}]` 的请求；对 sessionID 接口做频率限制与来源校验；导出/打印接口同时校验登录态，不只依赖模板 sessionID。
