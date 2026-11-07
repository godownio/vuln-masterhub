---
id: web-generic-auth-sentinel-cookie-jsondecode-mysql-auth-bypass
title: Cartalyst Sentinel 原生 Cookie json_decode 类型失控叠加 MySQL 隐式转换绕过认证
type: scenario
domain: web
path: web/generic/auth/cookie
technique: cookie-json-decode-type-juggling-mysql-implicit-conversion
aliases:
- Sentinel Cookie 认证绕过
- cartalyst_sentinel=5
- json_decode Cookie 类型混淆
- MySQL 字符串整数隐式转换认证绕过
- Laravel Sentinel Native 弱类型绕过
tags:
- php
- cartalyst-sentinel
- laravel
- auth-bypass
- cookie
- json-decode
- type-juggling
- mysql
- implicit-conversion
cve: []
severity: high
confidence: high
affected_versions: < 2.0（Cartalyst Sentinel Native 版本；原文标注 v2.0+ 已修复）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:17:47+08:00'
  notes: 已对照原文与16张图核对：图01 简化认证代码；图02-06 未登录/正常登录/renewSession/persistences 表/第35条 code=5M6o0.../cartalyst_sentinel=5 成功输出 test@example.com；图07 CAST('5M6o0...' AS SIGNED)=5；图08 Sentinel check 非 false 判断；图09-10 cookie 取值后 json_decode；图11 默认 cookie 名 cartalyst_sentinel；图12 json_decode('1')=int(1) 而 '"1"' 为字符串；图13/15 漏洞版 findByPersistenceCode 与 where('code',$code)；图16 v2.0+ 返回类型约束。三环叠加链与原文一致；affected_versions 已存在（<2.0）且与原文 v2.0+ 修复一致。小偏差：卡内称首字符为数字概率约10%，按 Laravel Str::random 字母数字集约16%，不影响利用；PoC 未在本机复跑；原文无 CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

Cartalyst Sentinel（Native 版）从 Cookie 取值后直接 `json_decode`，纯数字 Cookie 会变成整数；该整数被 Illuminate 查询构造器拼成 `where code = 5`，MySQL 将 `code` 字符串隐式转数字，从而匹配任意以 `5` 开头的持久化 code，攻击者无需有效会话即可被识别为对应已登录用户。

## 原理

三个环节叠加成立：

1. **Cookie 解析类型失控**：`NativeCookie::getCookie()` 取 `$_COOKIE['cartalyst_sentinel']` 后调用 `json_decode($value)`。`json_decode('5')` 返回 `int(5)`，而 `json_decode('"5"')` 才返回字符串。攻击者完全控制返回值类型与数值。
2. **查询参数类型进入 SQL**：`IlluminatePersistenceRepository::check()` 将 Cookie 值作为 `$code` 交给 `findByPersistenceCode($code)`，最终执行 `newQuery()->where('code', $code)->first()`。查询构造器按 PHP 值类型绑定参数：字符串生成 `where code = '5'`（精确匹配），整数生成 `where code = 5`（数值比较）。
3. **MySQL 隐式类型转换**：字符串列与整数比较时，MySQL 把字符串按数字前缀转成数值，遇到非数字字符停止。`'5M6o0...'` 转为 `5`，`'1337d...'` 转为 `1337`，`'abc12...'` 转为 `0`。因此 `where code = 5` 会命中任意 `code` 以 `5` 开头的记录，而不是只命中 code 恰好为 `5` 的记录。

`findByPersistenceCode()` 命中记录后返回持久化对象，`findUserByPersistenceCode()` 再返回其 `user`。Sentinel `check()` 只判断返回值是否为 false，非 false 即视为已登录；原业务 `if ($user = Sentinel::check())` 同样只做真值判断，于是直接进入已登录分支并输出该用户邮箱。全程不需要知道 32 位随机 code，也不需要有效 PHPSESSID。

触发还依赖一个客观前提：`persistences` 表中存在 `code` 以所选整数开头的有效持久化记录。code 由 `str_random(32)` 生成，首字符为数字的概率约 10%，原文在 35 条有效会话中遇到 1 条以 `5` 开头的记录。

## 触发条件

- 目标使用 cartalyst/sentinel Native 版本且版本低于 2.0（2.0 起 `check()` 增加返回类型约束）。
- 应用使用 Sentinel 的持久化会话（persistences 表），且存在处于登录/记住状态的有效记录。
- `persistences.code` 为随机字符串且存在以数字开头的记录（概率性前提，可遍历 0-9 尝试）。
- 攻击者可设置 `cartalyst_sentinel` Cookie；Cookie 名可在 Sentinel 配置中改写，需按目标实际配置调整。

## 利用步骤

1. 确认目标使用 Sentinel Native Cookie 持久化认证，Cookie 名默认为 `cartalyst_sentinel`。
2. 先不带 Cookie 访问，确认返回未登录。
3. 发送 `cartalyst_sentinel=<数字>`（如 `5`），服务端 `json_decode` 得到整数，查询变为 `where code = 5`。
4. 若表中存在以该数字开头的持久化 code，查询命中，Sentinel 返回对应用户对象，业务判断为已登录。
5. 依次尝试 0-9，或结合业务侧可观察的会话/用户信息选择数字；成功后即冒用该持久化记录所属用户身份。

## PoC

```bash
# 正常未登录
curl http://target/

# 数字 Cookie 触发整数查询 where code=5，
# 命中 code 以 5 开头的持久化记录后即以该用户身份登录
curl --cookie 'cartalyst_sentinel=5' http://target/
```

```php
// 核心触发链（简化）
$code = json_decode($_COOKIE['cartalyst_sentinel']); // '5' -> int(5)
$persistence = Model::newQuery()->where('code', $code)->first(); // where code = 5
// MySQL: '5M6o0...' 隐式转 5，匹配成功
```

## 变体与关联

- 变体：任何对 Cookie/Header 值做 `json_decode` 后未强制转字符串、又直接进入数据库查询的解析器；数组/布尔/对象类型同样可能造成非预期绑定。
- 变体：其他字符串列与用户可控整数参数比较的场景（如 `token`、`username`、`id` 字段），均可利用数字前缀匹配绕过精确校验。
- 关联：PHP 弱比较（`==`）认证绕过、Cookie 身份伪造、会话固定。

## 检测与防御

- 检测：`cartalyst_sentinel` Cookie 为纯数字；同一账号出现不含完整 32 位 code 的会话访问；`persistences.code` 以数字开头且被短整数命中。
- 防御：升级 cartalyst/sentinel 至 2.0+，`check()`/`findByPersistenceCode()` 增加 `?string`/`?UserInterface` 类型约束。
- 防御：Cookie 取值后强制 `(string)` 并校验格式（定长字母数字），禁止 `json_decode` 结果直接进入查询；查询前显式转为字符串类型。
- 防御：数据库层避免字符串列与整数比较；业务鉴权使用严格类型判断（`instanceof` / `=== null`），不要只判断真值。
