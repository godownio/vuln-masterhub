---
id: web-python-framework-pydash-set-jinja-loader-searchpath
title: pydash.set_ 可控路径篡改 Flask jinja_loader.searchpath 读取任意模板文件
type: scenario
domain: web
path: web/python/framework
technique: pydash-set-jinja-loader-path
tags:
- python
- flask
- pydash
- jinja2
- template-loader
- arbitrary-file-read
- ssti
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:38+08:00'
  notes: 已对照原文与图28-30核对：/operate?username=app&password=jinja_loader.searchpath[0]&confirm_password=/ 返回 oprate success，/impression?point=flag 回显 /flag 内容；源码中 username in globals()、old 过滤、point 长度≤5 与禁止 {}.%< >_ 均与卡片一致。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/python/framework/web-python-framework-pydash-set-jinja-loader-searchpath/
draft: false
kb_aliases:
- pydash set_ 利用
- Flask jinja_loader.searchpath
- render_template 任意文件读取
- 模板加载路径篡改
- app.jinja_loader
---

## 一句话结论

应用把用户可控的“全局变量名 + 属性路径 + 值”直接交给 `pydash.set_()` 时，可用 `username=app&password=jinja_loader.searchpath[0]&confirm_password=/` 把 Flask 的模板搜索路径改成根目录；随后 `render_template(point)` 渲染 `flag` 就会读取 `/flag` 并回显，若攻击者能在可控目录放置模板文件则可进一步 SSTI/RCE。

## 原理

- `pydash.set_(obj, path, value)` 支持点号与数组下标路径，例如 `set_(app, "jinja_loader.searchpath[0]", "/")` 等价于 `app.jinja_loader.searchpath[0] = "/"`。
- Flask 的 `app.jinja_loader` 通常是 `FileSystemLoader`，其 `searchpath` 是模板目录列表；`render_template("flag")` 会按该列表查找 `flag` 文件并作为 Jinja 模板渲染。
- 路由 `/operate` 先判断 `username in globals()`，再取 `globals()[username]` 作为操作对象。`app` 正是全局的 Flask 实例，因此成为可控对象。
- 过滤条件只有 `"old" not in password`，而攻击路径 `jinja_loader.searchpath[0]` 不含 `old`，可直接通过。
- 另一个路由 `/impression` 把用户参数 `point` 直接传给 `render_template(point)`，仅限制长度 ≤5 且禁止 `{ } . % < > _`；`flag` 完全合法。
- 两者组合：先改模板根目录为 `/`，再让 `render_template("flag")` 解析 `/flag`；文件内容被当模板执行并输出，读文件成功。

## 触发条件

- Python 应用安装 `pydash`，并使用 `pydash.set_()` 且对象/路径/值至少有一个来自用户输入；
- 可通过 `globals()[username]` 或类似方式选中 Flask `app` 等有敏感属性的全局对象；
- 存在把用户输入作为模板名传给 `render_template()` 的路由；
- 攻击者能访问这两个路由（不一定需要管理员权限，视路由鉴权而定）。

## 利用步骤

1. 注册并登录，抓包观察登录参数中的 `type`；尝试改为 `0` 进入管理界面或找到 `/operate`、`/impression` 路由。
2. 访问 `/operate`，令 `username=app`、`password=jinja_loader.searchpath[0]`、`confirm_password=/`，把模板搜索路径第一项改为根目录。
3. 访问 `/impression?point=flag`，让 Flask 以 `/flag` 为模板渲染并回显内容。
4. 若目标文件名未知，可先用其他路径/文件名枚举；若模板名长度限制 ≤5，优先用短文件名（如 `flag`）。
5. 若可上传文件到某个目录，可把该目录设为 searchpath，再渲染恶意模板实现 SSTI/RCE。

## PoC

```http
GET /operate?username=app&password=jinja_loader.searchpath[0]&confirm_password=/ HTTP/1.1
Host: target
```

响应：`oprate success`

```http
GET /impression?point=flag HTTP/1.1
Host: target
```

响应：`flag{...}`（`/flag` 文件内容）。

对应 Python 语义：

```python
import pydash
from flask import Flask
app = Flask(__name__)

pydash.set_(app, "jinja_loader.searchpath[0]", "/")
# app.jinja_loader.searchpath == ["/", ...]
app.jinja_env.get_template("flag")  # 读取 /flag 并渲染
```

## 变体与关联

- 变体：把 `app.config["SECRET_KEY"]`、`app.root_path`、`database` 字典等作为 `pydash.set_` 的目标，可改配置、会话密钥或业务数据。
- 变体：若 `render_template` 的名字限制更严，可改 searchpath 到包含同名短文件的目录，或利用模板名后缀。
- 变体：`pydash.set_` 也支持 `__class__` 等属性遍历时，可能进一步触达更多对象；取决于 pydash 版本与过滤。
- 关联：[[web-python-pydash-set-attribute-path-pollution]]（pydash.set_ 属性路径污染的通用手法；本卡是其 Jinja 模板加载路径的具体利用链）；[[web-python-framework-flask-werkzeug-debug-pin-forgery]]（同为 Flask 应用层配置/调试面滥用）。
- 边界：若 `/operate` 有严格鉴权、`username` 不在 globals 白名单、或 `render_template` 使用固定模板名，本链不可用。

## 检测与防御

- 检测：请求参数中出现 `jinja_loader`、`searchpath`、`__class__`、`config` 等属性路径；`/operate` 类接口接收点号/下标路径。
- 检测：`render_template` 的参数来自请求；模板根目录被运行时修改；渲染结果包含 `/flag` 等非模板文件内容。
- 防御：不要对用户输入使用通用属性设置函数（`pydash.set_`/`setattr`）；若必须使用，限制对象白名单与路径正则，禁止 `__`、`.`、`[` 等。
- 加固：`render_template` 只接受固定模板名或白名单；模板目录固定在应用目录；敏感文件（`/flag`、配置、密钥）不可被 Web 进程读取。
