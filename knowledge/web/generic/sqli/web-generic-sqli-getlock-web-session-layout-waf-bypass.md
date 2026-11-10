---
id: web-generic-sqli-getlock-web-session-layout-waf-bypass
title: MySQL GET_LOCK 跨会话锁等待延时注入：按 Web 连接布局（短/长会话、连接池、多Web共用库）构造锁竞争并绕过 sleep/BENCHMARK 拦截
type: scenario
domain: web
path: web/generic/sqli
technique: getlock-cross-session-lock-wait-time-blind-sqli
aliases:
- GET_LOCK 延时注入
- 命名锁锁等待
- 跨会话锁竞争
- 连接池锁冲突
- 多Web共用数据库锁延时
- 时间盲注替代原语
- 雷池 WAF 绕过
tags:
- sqli
- blind
- time-based
- mysql
- get-lock
- release-lock
- connection-pool
- session
- waf-bypass
- lock-wait
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T22:00:52+08:00'
  notes: 已对照原文与 28 张图片逐张核对：GET_LOCK 会话级命名锁语义/返回值、RELEASE_LOCK、wait_timeout、两个必要条件（不同会话+持锁长时效应）、六类 Web 连接布局可行性矩阵、雷池 WAF 默认配置下 sleep/BENCHMARK 被拦而 GET_LOCK 未拦、长会话 MRCMS 获锁 + 短会话 sqli-labs ||GET_LOCK(1,5)||/if(1,GET_LOCK(1,5),1)|| 实测延时约 5.5s（img25/26）、数据库监听显示跨会话锁等待（img27）、WAF 后台未拦截 GET_LOCK（img28）均与 content.md 一致；为完整打通并实测的时间盲注链（条件延时 oracle 可逐字符提取数据并绕过 WAF），非 DoS/未打通/只有原语/理论链；路径合法，dedup 非同链、dup-scan 无 pair；未验证点：原文未演完整逐字符外带脚本（卡按标准 if 条件盲注做机械延伸），未在本机复跑注入，该批次卡按 KB 现状不含 sources/source_url 溯源字段。
---

## 一句话结论

MySQL 的 `GET_LOCK(name,timeout)` 是会话级命名锁：另一会话持有同名锁时，本会话的 `GET_LOCK` 会阻塞到超时，可当作 `SLEEP()` 的替代延时原语，且常不在 WAF 的延时函数黑名单里。但真实 Web 注入中攻击者无法凭空「另开一条连接持锁」，能否造成延时完全取决于目标应用的数据库连接布局——短会话与全局单长会话都不可行，连接池/用户级长连接/IP级连接/多Web共用库才可行；用 `||GET_LOCK(1,5)||` 或 `if(cond,GET_LOCK(1,5),1)` 把锁等待接成时间盲注 oracle，即可绕过只拦 `sleep`/`BENCHMARK` 的 WAF。

## 原理

- **函数语义**：`GET_LOCK(str lock_name, int timeout)` 基于字符串命名（≤64 字符、大小写敏感），返回 1 成功获取 / 0 超时（他会话持锁且未在 timeout 内释放）/ NULL 出错；`timeout=0` 立即返回，负数表示无限等待（MySQL 5.7.5+）。`RELEASE_LOCK(str)` 返回 1 成功释放 / 0 当前会话不持有 / NULL 锁不存在。不同锁名互不影响。
- **会话级作用域**：持锁会话内重复请求同名锁直接返回 1、不阻塞；只有**其他会话**请求同名锁才被阻塞到释放或超时。锁释放有三种途径：显式 `RELEASE_LOCK`、会话终止（连接关闭）隐式释放、受 `wait_timeout` 时效控制（`SHOW VARIABLES LIKE 'wait_timeout'`；`SET SESSION wait_timeout=600` 可调）；**不随事务结束自动释放**（区别于 InnoDB 行锁）。
- **为什么能延时**：把 `GET_LOCK` 拼进 WHERE 条件，若同名锁被别的会话持有，该查询会阻塞约 `timeout` 秒（实测返回 0、查询时间 5.025s / 5.51s），产生可观测的响应时间差；`if(cond, GET_LOCK(1,5), 1)` 把条件真假映射为「是否等待」，形成时间盲注 oracle。
- **两个必要条件**：① 不同会话（只有跨会话同名锁竞争才会等待）；② 持锁会话具备「长时效应」（锁不在等待发生前就被释放）。这两条解释了为何常见 Web 布局大多不可用。
- **按连接布局判断可行性**：
  - 短会话模式（每 HTTP 请求新建连接、用完即关，如 phpstudy 上的 sqli-labs）：条件①满足（并发产生不同连接）但条件②不满足——A 会话 `GET_LOCK` 后请求结束即 `Quit` 自动释放锁，B 还没来得及等待；大量并发发包也无效（数据库监听可见 Connect→Query→Quit 紧连，thread_id 各不同）。
  - 长会话模式（整个应用单条持久连接，示例为某老 CMS 3.1.2，thread_id 恒为 994）：所有用户操作在同一会话，条件①不满足，同会话重复 `GET_LOCK` 直接返回 1，不会等待；切换登录/凭证/IP 都仍是同一 thread_id。
  - 连接池模式（主流：Spring Boot/HikariCP、Django、Laravel 默认）：锁绑定物理连接、归还池时**不自动释放**；请求 A 借连接1 获锁不释放 → 归还 → 请求 B 借连接2 请求同名锁 → 跨会话冲突等待。大量请求必然借到两个不同物理连接，故可行。
  - 用户级长连接（每用户专属连接、会话期保持打开）：不同用户凭证请求同一锁即满足条件①+②，可行。
  - IP/客户端级连接（按客户端 IP 分配固定连接）：同 IP 组内共享连接、无冲突，需换不同 IP 组才有跨会话冲突。
  - 多Web共用数据库（站库分离/微服务）：共享同一连接池或各自独立连接池都等价于连接池模式（不同会话）；「无连接池 + 长会话 web + 短会话 web」组合尤其可用：先对长会话 web 注入获锁（锁随持久会话保持），再由短会话 web 注入请求同名锁造成等待。
- **为什么 WAF 放过**：WAF 规则常只把 `sleep`、`BENCHMARK` 等列入延时函数黑名单；`GET_LOCK` 虽能被语义引擎识别为 SQL 注入，但默认配置下不拦截（雷池 WAF 后台日志：`GET_LOCK` 与 `if(...,GET_LOCK...)` 均标「未拦截」，`sleep(5)`、`BENCHMARK(...,SHA1(...))` 标「已拦截」），于是成为绕过时间盲注检测的可行通道。

## 触发条件

- 存在可控 SQL 注入点（WHERE 可拼接闭合），且响应可计时。
- 目标为 MySQL（支持 `GET_LOCK`），数据库账号有执行权限（通常无需特殊权限）。
- 连接布局满足「跨会话 + 持锁长时效应」：连接池、用户级长连接、不同 IP 组、或多Web共用库且至少一个长会话应用；并存在「先获锁」与「后等待」两个注入入口（同一应用不同连接，或不同 web）。
- 持锁会话在等待期间不断开、不被 `wait_timeout` 回收；两次请求使用**同名且大小写一致**的锁。
- WAF 未把 `GET_LOCK` 等锁函数列入拦截规则。

## 利用步骤

1. **判布局**：用数据库监听/日志看 thread_id 是否复用、连接是否请求后即 `Quit`，对照上面的矩阵判断目标是否可行（短会话/单长会话直接放弃）。
2. **持锁**：在长会话或连接池应用的注入点执行 `... WHERE id=1 AND GET_LOCK('x',5)#`（或 `delete ... where id in(...)and GET_LOCK(1,5)#`），让该会话持有命名锁且返回后不释放（返回 1）。
3. **等待**：在另一会话（短会话 web 的另一请求、连接池的另一物理连接、另一用户/IP、另一 web）注入 `?id=1'|| GET_LOCK(1,5) ||'`；同名锁被持有，查询阻塞约 5 秒，页面响应时间出现 5 秒台阶。
4. **接成盲注 oracle**：`?id=1'|| if(ASCII(SUBSTR(database(),1,1))=N, GET_LOCK(1,5), 1) ||'`，按耗时逐字符/逐位提取数据；先测正常响应基线并设阈值，排除网络抖动。
5. **排错**：未延时时检查持锁会话是否提前释放（短会话）、两请求是否落同一会话（长会话）、锁名/大小写、`wait_timeout`、连接池是否只分配了同一物理连接。
6. **收尾**：用 `RELEASE_LOCK('x')` 或让持锁会话结束释放锁，避免长期占用影响目标。

## PoC

```sql
-- 1) 持锁（长会话/连接池应用的注入点，锁随会话保持）
SELECT * FROM t WHERE id=1 AND GET_LOCK('x',5)#
-- 2) 等待（另一会话的注入点，约 5s 延时）
?id=1'|| GET_LOCK(1,5) ||'
-- 3) 条件化时间盲注
?id=1'|| if(1,GET_LOCK(1,5),1) ||'
?id=1'|| if(ASCII(SUBSTR(database(),1,1))=115,GET_LOCK(1,5),1) ||'
```

（按文章 payload 最小化整理，未在本机复跑；`||` 为 MySQL 逻辑或，需闭合原查询引号，URL 中对引号/空格做编码。被拦的对照：`sleep(5)`、`BENCHMARK(99999999,SHA1(...))`。）

## 变体与关联

- 变体：锁名数字或字符串均可但大小写敏感；`timeout` 取 3~5 秒平衡可观测性与请求超时；MySQL 5.7.5+ 可用负 timeout 无限等待（慎用，易挂起连接）。
- 变体：连接布局不满足时，改用「多Web共用同一库」组合（长会话 web 获锁 + 短会话 web 等待），或对连接池应用大量并发请求迫使分配到不同物理连接。
- 变体：`GET_LOCK` 可与 `CASE WHEN`、`&&`/`||`、笛卡尔积、正则回溯等替代原语互换；若 WAF 也拦 `GET_LOCK`，可试 `IS_USED_LOCK`/`RELEASE_LOCK` 等锁函数或回到 `BENCHMARK` 变形。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（把 `GET_LOCK` 列为 IF/SLEEP 被过滤时的替代延时原语，但假设「另一连接已持锁」，未展开真实 Web 架构下如何满足该前提）、[[web-generic-sqli-cartesian-product-time-blind]]（笛卡尔积时间盲注）、[[web-generic-sqli-orderby-ordertype-hpp-parameter-pollution-blind]]（HPP 绕过 WAF 做时间盲注）。本卡补的是「跨会话锁竞争在目标连接布局下如何成立」与 WAF 实战。
- 局限：强依赖目标连接布局，短会话/单长会话应用完全不可行；持锁会话断开或 `wait_timeout` 到期会释放锁导致延时失效；高并发下锁被无关请求占用会造成误判。

## 检测与防御

- 根本修复：参数化查询消除注入入口；数据库账号最小权限。
- WAF：把 `GET_LOCK`、`RELEASE_LOCK`、`IS_USED_LOCK` 等锁函数纳入时间盲注检测/拦截，不要只黑名单 `sleep`/`benchmark`；对响应耗时呈固定阶梯（≈timeout）且伴随 `SUBSTR`/`ASCII`/`if` 的请求做频率限制。
- 数据库：设置 `max_execution_time`/语句超时、限制单用户并发连接与长时间锁持有；监控 `SHOW PROCESSLIST` 中大量 `GET_LOCK` 等待、同一锁名跨多会话、连接归还池后仍持有命名锁。
- 应用架构：连接池归还连接时显式释放用户级锁（`RELEASE_ALL_LOCKS()`），避免跨请求持有命名锁；适当缩短 `wait_timeout`。
