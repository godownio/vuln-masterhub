---
id: web-generic-sqli-arjun-hidden-param-intruder-diff-time-blind
title: 隐藏参数发现到 SQL 注入：Arjun 扫出 PHP 端点 ?id + Burp Intruder 枚举报错差分 + if(sleep) 时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: arjun-hidden-param-intruder-diff-time-blind-sqli
aliases:
- Arjun 参数发现
- 隐藏参数 fuzz
- id 参数报错
- sleep 时间盲注
- sqlmap --dbs
- PHP 参数枚举
tags:
- sqli
- time-based-blind
- parameter-discovery
- arjun
- burp-intruder
- php
- sqlmap
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T08:23:12+08:00'
  notes: '已完整读 content.md 与全部16张图核对：Arjun仓库/安装--help(图02/03)、FOFA host与鹰图domain资产收集(图04/06)、默认建站页(图05)、about.php等PHP功能页(图07/08)、arjun -u输出Parameters found: id(图09)、about.php?id=2(图10)、Burp Intruder 1-1000结果id=15长度26313其余约9.7k(图12)、about.php?id=15报错页(图11)、sleep时间盲注URL(图13)、sqlmap --batch --random-agent --dbs(图14)、contact.php等其它功能点同样sleep注入(图15/16)，均与原文一致。卡内四闭合测试、--+注释、sqlmap与横向复用描述无虚构。单卡原子(Arjun隐藏参数发现→Intruder值枚举差分→if(sleep)时间盲注→sqlmap)，粒度合适。dedup最高分为卡自身exact自匹配；related候选search-union-time-blind-credential-dump为POST search参数+UNION/凭据dump的不同案例(dup-scan verdict=related)，非同链保留。无组件版本，未set-versions。未验证点：未复现目标站点测试。'
---

## 一句话结论

对只暴露少量功能页的 PHP 站点，先用 Arjun 从响应差异中扫出隐藏 GET 参数 `id`，再用 Burp Intruder 枚举 `id=1..1000`，按响应长度/报错页差分定位可注入点（如 `id=15`），最后用 `and if(15,sleep(5),3)--+` 确认时间盲注并用 `sqlmap --dbs` 拖库；同一站点的其他 PHP 功能页常复用同一套 `?id` 查询代码，可横向扩大危害。

## 原理

- **Arjun 的参数发现**：Arjun 是 HTTP 参数发现工具，向目标发送带候选参数名的请求，比较响应状态码、长度、正文相似度等特征，若某参数显著改变响应，就判定该参数被后端接受；`--passive` 模式不主动发请求，只从页面/响应中推断可能的参数名。
- **Burp Intruder 的值枚举差分**：Arjun 只给出参数名，值仍需枚举。把 `id` 设为 1–1000 批量请求，正常值与触发 SQL 错误/不同查询分支的值会在响应长度、状态码、报错页面上出现明显差异（原文 `id=15` 返回 26313 字节的报错页，其余多为约 9.7k 字节），HAE 等插件再把 SQL 关键字高亮，快速定位注入点。
- **SQL 注入成因**：后端把 `id` 直接拼接进 SQL 字符串，未使用预编译/参数化；错误页暴露了数据库报错，说明查询未做异常兜底。
- **时间盲注的判定**：`if(15,sleep(5),3)` 中 15 为真，条件成立时 `sleep(5)` 让响应延迟 5 秒；用 `'`、`"`、`)` 或无闭合四种形式分别测试，哪个能让页面稳定延迟 5 秒，就说明对应闭合方式正确。`--+` 中的 `+` 在 URL 解码后是空格，`-- ` 注释掉剩余 SQL（MySQL 的 `--` 后必须跟空格）。
- **为什么时间盲注可用**：即使页面不回显数据、错误被统一处理，响应时间仍是可观测侧信道；把 `if(15,...)` 换成 `if(substr(database(),1,1)='a',sleep(5),3)` 之类的条件，即可逐字符推断数据。
- **sqlmap 自动化**：确认注入后，sqlmap 用 `--batch --random-agent --dbs` 自动识别注入类型、随机 User-Agent 降低特征、列出数据库；后续可 `--dump` 取表。
- **横向复用**：同一套 CMS/建站程序的不同 PHP 功能页（about.php、contact.php 等）往往复制同一段查询代码，`?id` 参数同样可注入；在一个功能点打通后，应把所有解析 PHP 的功能页都按同一 payload 回归测试。

## 触发条件

- 目标为 PHP 站点，功能页通过 GET 参数（如 `?id=`）查询数据库；前端导航不暴露该参数或只暴露部分功能页。
- Arjun 的候选参数字典能覆盖目标参数名（`id`、`file`、`page` 等常见名），且目标对未知参数/缺失参数的响应有可区分差异。
- 后端未使用预编译，`id` 被直接拼接进 SQL；数据库支持 `sleep()`（MySQL）或对应延时函数。
- 页面会返回数据库错误（利于快速定位）或响应时间可稳定测量（时间盲注）；无 WAF 拦截 `if/sleep/--` 等关键字，或有绕过手段。
- 已获得授权（原文明确为授权测试）；未授权测试属违法行为。

## 利用步骤

1. **资产与功能页收集**：用 FOFA/鹰图等空间引擎按公司域名找边缘资产，筛出能解析 PHP 的功能页（about.php、contact.php 等）；默认页/无功能页的站点优先级低。
2. **Arjun 扫参数**：对目标页运行 `arjun -u "https://target/about.php"`，观察 `Parameters found: id`；需要低干扰时加 `--passive`。
3. **Burp Intruder 枚举值**：把 `id` 设为 payload 1–1000，记录状态码、响应长度、报错页；长度/状态异常的值（如 `id=15`）作为候选注入点。
4. **确认闭合与注入类型**：依次测试 `15' and if(15,sleep(5),3)--+`、`15" and if(15,sleep(5),3)--+`、`15) and if(15,sleep(5),3)--+`、`15 and if(15,sleep(5),3)--+`，用响应是否延迟 5 秒判断闭合方式。
5. **自动化利用**：`python sqlmap.py -u "https://target/about.php?id=15" --batch --random-agent --dbs` 列库；确认后 `--dump` 取表。
6. **横向扩展**：对其他 PHP 功能页逐个加 `?id=15 and if(15,sleep(5),3)--+` 测试；同一套查询代码通常同样存在注入，汇总后统一上报。

## PoC

```bash
# 1) 参数发现
arjun -u "https://target/about.php"
# 输出：Parameters found: id

# 被动模式（不发请求，从响应推断；原文说明）
arjun -u "https://target/about.php" --passive

# 2) 时间盲注闭合测试（Burp/HackBar 或直接 curl）
# ?id=15' and if(15,sleep(5),3)--+
# ?id=15" and if(15,sleep(5),3)--+
# ?id=15) and if(15,sleep(5),3)--+
# ?id=15  and if(15,sleep(5),3)--+

# 3) 逐字符提取（示例：判断 database() 首字符是否为 a）
# ?id=15 and if(substr(database(),1,1)='a',sleep(5),3)--+

# 4) sqlmap 列库
python sqlmap.py -u "https://target/about.php?id=15" --batch --random-agent --dbs
```

Burp Intruder 侧：Positions 只标记 `id` 的值，Payloads 设为 Numbers 1–1000，按 Length/Status 排序找异常响应。

## 变体与关联

- **变体**：参数发现工具可换 ParamSpider、x8、wfuzz，或直接从前端 JS/接口文档提取；POST/JSON 接口可用 Arjun 的 `-m POST`；`sleep` 被过滤时改用 `benchmark()`、大笛卡尔积、`LIKE` 盲注等。
- **关联卡片**：[[web-generic-sqli-cartesian-product-time-blind]]（`sleep`/空格/等号被过滤时的时间 oracle）；[[web-generic-sqli-error-based-extraction]]（有报错回显时更快的提取方式）；[[web-generic-sqli-search-union-time-blind-credential-dump]]（sqlmap UNION/时间盲注拖库的完整案例）；[[pentest-recon-error-driven-api-param-discovery]]（另一种基于后端错误反馈的参数发现思路）。

## 检测与防御

- **代码层**：所有数据库查询使用预编译/参数化（PDO prepared statement、MyBatis `#{}` 等）；对 `id` 等数值参数做类型与范围校验；统一异常处理，禁止把数据库错误回显到页面。
- **WAF/网关**：拦截 `if(`、`sleep(`、`benchmark(`、`--` 等注入特征，并对短时间大量参数枚举/值枚举做限速与告警。
- **检测特征**：同一路径短时间内出现大量不同 `id` 值；响应长度/状态码异常；请求携带 SQL 关键字或时间函数；Arjun 之类的参数扫描会在日志中留下大量未知参数请求，可作为扫描行为告警。
- **运营**：定期对全部 PHP 功能页做参数化审计与回归测试；限制数据库账号权限，降低注入成功后的数据暴露面。
