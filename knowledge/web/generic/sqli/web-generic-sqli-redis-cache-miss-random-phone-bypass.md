---
id: web-generic-sqli-redis-cache-miss-random-phone-bypass
title: Redis 结果缓存掩盖 SQL 注入：随机 PHPSESSID + 不存在手机号强制 cache miss，phone 拼接注入后结果再写入缓存
type: scenario
domain: web
path: web/generic/sqli
technique: redis-cache-miss-random-phone-sqli
aliases:
- Redis 缓存绕过注入
- cache miss SQL 注入
- 随机 PHPSESSID 绕计数
- 随机 phone 绕缓存
- listJson redis get
- phone 拼接注入
tags:
- php
- sqli
- redis
- cache
- cache-bypass
- phone-injection
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:36:06+08:00'
  notes: 已对照原文与图11-12：detail() 中 checkCode、phone=I(post.phone)、phoneKey=appeal_detail_.phone、sessionKey=appeal_.cookie(PHPSESSID)、redis get/incr、计数大于10 拒绝、where(phone=.phone)->order(...)->select()、json_encode 后 set(phoneKey,listJson,60*10) 与 expire 均与卡一致。修正：原文为无引号字符串拼接（phone= 后直接接变量），原 PoC 中 1380000<...> 后带不配对单引号会导致 SQL 语法错误，已改为 phone=1380000<随机数字> OR SLEEP(3)-- -，步骤3同步修改并注明无引号拼接。原文未提供实测注入请求/响应，属代码级审计结论；缓存绕过机制成立。dedup 候选（JPQL 拼接、ThinkPHP parseWhere 等）非同链，dup-scan 无涉及 pair。
---

## 一句话结论

前台接口先 `$listJson = $redis->get('appeal_detail_'.$phone)`，只有 `if (!$listJson)` 为真才执行 `UserAppealModel()->where('phone='.$phone)->select()`；攻击者使用不存在的随机手机号让 Redis 必然 miss（并配随机 PHPSESSID 绕过 `$redis->incr($sessionKey)` 的 10 次计数限制），即可让拼接的 phone 进入 SQL 造成注入，查询结果随后又被 `$redis->set($phoneKey,...)` 缓存 600 秒。

## 原理

- **cache-aside 结构**：接口把“按 phone 查询”的结果缓存在 Redis，key 为 `appeal_detail_<phone>`；命中时直接返回 JSON，完全不查库；未命中才走 `where('phone='.$phone)->select()`。
- **缓存键含用户输入**：phone 既拼进 Redis key 又拼进 SQL；只要 phone 在缓存里没有对应 key，SQL 必然执行。攻击者提交一个随机/不存在的手机号，缓存自然 miss，注入语句随之执行。
- **为什么要随机 PHPSESSID**：代码还有 `$sessionKey = 'appeal_'.cookie('PHPSESSID'); $count = $redis->incr($sessionKey); if ($count > 10) 拒绝`——计数按会话键累积；换一个随机 PHPSESSID 就得到一个全新的计数键（值为 1），绕过频率限制。
- **结果会污染缓存**：注入成功后 `$listJson = json_encode($list); $redis->set($phoneKey,$listJson,600)` 把结果写入缓存；这意味着同一 phone 的第二次请求可能直接命中缓存，调试时要用新的随机 phone。
- **为什么代码看起来“安全”**：`checkCode`（验证码）、`$phone` 非空、Redis 计数等检查都只校验“流程”，没有对 phone 做类型/白名单校验；注入点在 `where('phone='.$phone)` 的字符串拼接。
- **利用形态**：可做布尔/时间盲注、UNION、报错注入；若 select 结果被 JSON 返回，可直接读数据。

## 触发条件

- 目标为 PHP 应用，存在“先查 Redis 缓存、未命中再拼 SQL”的接口（如手机号查询申诉/订单/用户信息）。
- phone 参数未经参数化/类型校验直接拼接进 where。
- Redis 可达且缓存 key 由 phone 决定；接口对 phone 无严格格式校验。
- 有频率限制时可通过更换 PHPSESSID/Cookie 重置计数。

## 利用步骤

1. 审计/抓包找到接口（如 `?m=appeal&a=detail` 或 POST `phone=...`），确认 `$redis->get('prefix_'.$phone)` 与 `where('phone='.$phone)`。
2. 每次请求使用新的随机 PHPSESSID（避免 `incr` 计数）和一个不存在的随机手机号（避免缓存命中），如 `phone=1380000<随机数字>`。
3. 首次用正常随机号确认接口响应形态（空列表/JSON）；再用 `phone=<随机数字> OR SLEEP(3)-- -` 观察时间差，确认注入（`phone=` 后为无引号字符串拼接，payload 不要带前导引号）。
4. 进一步用布尔/UNION 提取数据；注意每次请求换随机前缀避免缓存与计数干扰。
5. 若结果被写入缓存，用新的随机号继续下一轮。

## PoC

```http
POST /index.php?m=appeal&a=detail HTTP/1.1
Host: target
Cookie: PHPSESSID=<每次随机>
Content-Type: application/x-www-form-urlencoded

phone=1380000<随机数字> OR SLEEP(3)-- -
```

```text
# 源码关键逻辑（示意）
$phoneKey = 'appeal_detail_' . $phone;
$sessionKey = 'appeal_' . cookie('PHPSESSID');
$listJson = $redis->get($phoneKey);
$count = $redis->incr($sessionKey);
if ($count > 10) { /* 拒绝 */ }
if (!$listJson) {
    $list = UserAppealModel()->where('phone=' . $phone)->order('update_time desc')->select();
    ...
    $redis->set($phoneKey, json_encode($list), 600);
}
```

## 变体与关联

- 变体：缓存 key 与 SQL 使用的参数不一致（如 key 用 md5(phone)、SQL 用原值）时，构造碰撞/前缀即可；也可利用缓存过期时间窗口。
- 变体：频率限制按 IP 而非会话时，需要代理池或低速率注入。
- 变体：若注入结果不可回显，可用时间盲注（SLEEP/BENCHMARK）或 DNS 外带。
- 关联：[[ctf-web-redis-getkey-name-injection-read-adjacent-secrets]]（Redis key 注入读相邻键，另一类缓存问题）、[[web-generic-sqli-mysql-outfile-general-log-webshell]]（注入写文件的后续利用）、[[web-generic-cache-poisoning]]（缓存层与业务层不一致的通用风险）。
- 边界：phone 做了严格数字校验/参数化查询时注入失败；Redis 不可用导致每次必查库时反而更容易触发；缓存命中时不会执行 SQL。

## 检测与防御

- 检测：同一接口大量不同 PHPSESSID/随机手机号的请求；phone 参数含引号、`SLEEP`、`UNION` 等特征；Redis 中出现异常 key（含注入 payload）；SQL 慢日志/审计日志中的拼接 phone。
- 防御：所有 SQL 使用参数化/ORM 绑定；phone 做严格格式（如 `^1\d{10}$`）校验；Redis key 使用规范化后的值并限制长度；频率限制按 IP+账号+设备等多维并做异常检测。
- 加固：缓存层与 SQL 层使用同一份“已校验”参数；对缓存 key 做白名单/哈希化，避免用户输入直接进入 key 空间。
