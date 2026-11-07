---
id: web-generic-auth-idor-empty-wildcard-type-query-collapse
title: 越权探测中的查询条件失效：参数制空、通配符 %/* 与类型混淆导致全量返回
type: scenario
domain: web
path: web/generic/auth
technique: idor-empty-wildcard-type-query-collapse
tags:
- idor
- access-control
- auth
- parameter-tampering
- wildcard
- type-confusion
- data-exposure
- sqli
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/web/generic/auth/web-generic-auth-idor-empty-wildcard-type-query-collapse/
draft: false
kb_aliases:
- 参数制空越权
- 空值越权
- 通配符越权
- 通配符查询全量
- 类型混淆越权
- 查询条件失效
- 全表返回
---

## 一句话结论

当接口按 `id`/`resCode`/`studentid` 等条件查询单条或部分记录时，把参数置空（空串、`null`、`undefined`、删除参数）、传入 `%`/`*` 通配符，或把原本的字符串参数改成数字（1、2、3），可能让后端跳过该查询条件、把空值当“查询全部”、或发生类型转换，从而返回全表/全部公司数据，形成越权批量泄露。

## 原理

- **动态拼接条件的空值分支**：很多 PHP/Java/ORM 代码用 `if (param != null && param != "") { where += " AND id = ..." }` 组装查询。参数为空时条件被整体跳过，SQL 变成无 WHERE 的全表查询；如果开发人员把空值当作“默认查询全部”的兜底逻辑，也会主动返回所有记录。
- **通配符扩大匹配**：`LIKE '%...%'` 查询中传入 `%` 或 `*`，模式变成匹配任意字符串，返回所有行；`_` 可匹配单字符。若参数被 `${}`/字符串拼接进 `LIKE` 或 `ORDER BY`，还可能进一步演变为 LIKE 注入/ORDER BY 注入（原文指出 like、order by 常用 `${}` 而非 `#{}` 预编译）。
- **类型混淆**：接口原本按字符串（如 `studentid` 字符串）比较，传入数字 1、2、3 时，后端类型转换/ORM 绑定可能把条件变成恒真或直接忽略，返回全量记录；反之数字字段传字符串也可能触发异常兜底返回全部。
- **为什么构成越权**：授权依赖“查询条件只命中当前用户的对象”。条件一旦消失，SQL 返回所有用户/公司的记录，而序列化响应不会逐行做 owner 校验，于是低权限用户拿到全量数据。
- **边界**：并非所有接口都受影响；需要观察响应从单条变为列表/多条、记录数突增。部分框架/网关会校验空值或类型，需逐个参数试。

## 触发条件

- 目标存在按 id/编码/类型查询的详情、列表或统计接口，且响应包含记录数组或多条记录。
- 后端使用动态 SQL/ORM 条件拼接，未对空值、通配符、类型做严格校验；或空值被当作“默认全部”。
- 攻击者拥有低权限账号（或接口本身未授权），能在授权范围内发送变异参数。
- 响应能反映记录数量/内容差异（列表、总数、分页信息），便于判断是否全量返回。
- 若进一步测试 LIKE/ORDER BY 注入，需目标数据库支持相应语法且 WAF 不拦截。

## 利用步骤

1. 用自己账号请求目标接口，记录正常参数、响应结构、记录数与分页信息（如 `total`、`list` 长度）。
2. 依次尝试空值变体：`id=`、`id=null`、`id=undefined`、`id=0`、删除参数、JSON 中 `null`/`""`/`[]`；观察是否返回多条/全量。
3. 对编码/名称/类型字段尝试通配符：`%`、`*`、`_`、`%%`、`%25`（URL 编码）；若返回全量，记录参数与接口。
4. 尝试类型变异：原字符串参数改传数字 `1`、`2`、`3`、`true`、数组/对象；原数字参数改传字符串；观察类型转换是否让条件失效。
5. 检查响应总数与分页：若 `total` 等于全库数量或列表包含其他用户/公司的记录，确认越权数据暴露。
6. 若 `%` 返回全量且接口使用 LIKE/ORDER BY，尝试验证 SQL 注入：在通配符后追加 `'`、`AND SLEEP()`、`ORDER BY` 等；若确认注入，转入 SQL 注入利用（注意不要扩大破坏）。
7. 编写脚本批量对比不同变体的记录数，保存请求/响应证据；控制请求量，避免拖垮业务或触发风控。

## PoC

空值与通配符变体（按原文思路整理，接口路径以实际目标为准）：

```http
GET /api/agreement/list?resCode= HTTP/1.1
Host: target

GET /api/agreement/list?resCode=%25 HTTP/1.1
Host: target
```

原文示例中，`resCode` 制空后返回了全部公司的协议信息（响应分页显示 `total: 3415`、`page: 1`、`list` 为多家公司记录），说明查询条件被跳过或空值被当作全量。

类型混淆示例（原文 `/api/CommonSQL` 查询用户信息）：

```http
POST /api/CommonSQL HTTP/2
Host: target
Content-Type: application/json

{"key":["getUserInfo"],"postData":{"studentid":"6"}}
```

响应返回多条 `accountid`/`studentid`/`name`/`cellphone`/`idcard`/`email` 记录；原文进一步说明把 `studentid` 传为数字类型的 1、2、3 时返回所有数据，而字符串形式、空值和 `%`/`*` 未生效，属于类型混淆导致的查询条件失效。

LIKE/ORDER BY 注入升级思路：

```text
resCode=%' AND SLEEP(3)#
sort=id,(SELECT 1 FROM (SELECT SLEEP(3))x)
```

说明：原文只给出“`%` 返回全量时大概率存在 LIKE 注入”的判断，未给出完整注入 PoC；上述为按该思路构造的验证载荷，需在授权目标上先确认参数是否进入 LIKE/ORDER BY。

## 变体与关联

- **空值变体**：空串、`null`、`undefined`、`0`、`[]`、删除参数、JSON 类型错配；不同语言/框架对空值的处理不同，需逐个试。
- **通配符变体**：`%`、`*`、`_`、`%%`、URL 编码 `%25`；若参数进入 `LIKE`，还可能通过 `%'` 闭合进入 SQL 注入。
- **类型混淆变体**：字符串↔数字、单值↔数组、布尔值、对象；ORM 的隐式转换/绑定失败可能让条件消失。
- **分页/导出放大**：即使条件未完全失效，`pageSize=99999`、导出接口、`total` 统计接口也可能一次性返回全量；可与本卡组合。
- **关联**：[[web-generic-auth-idor-openid-leak-enumerable-query-chain]]（两段式标识泄露）、[[web-generic-auth-multi-session-matrix-leakscore]]（多会话矩阵验证）、[[pentest-recon-parameter-graph-attack-chain]]（参数关系推导越权链）、[[web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth]]（同类“参数进入拼接 SQL”的注入链）。

## 检测与防御

- **检测**：同一接口在参数为空/通配符/类型变化时返回记录数突增；响应出现 `total` 远大于正常值或列表跨用户/跨租户；短时间内对同一接口尝试多种空值/通配符/类型变体。
- **防御**：查询参数做严格类型与白名单校验；空值应返回空结果或参数错误，而不是全表；LIKE 查询对 `%`/`_` 转义并参数化，ORDER BY 使用列名白名单；所有列表/详情接口做对象级授权与租户隔离；限制单页最大条数与导出权限。
- **测试注意**：验证“全量返回”时只取少量样本确认，不要下载全库；避免使用 `SLEEP` 等影响业务的载荷，除非已获授权并控制时长。
