---
id: web-python-merge-globals-file-source-echo-arbitrary-read
title: Python merge 污染模块全局 __file__：源码回显路由变任意文件读取
type: scenario
domain: web
path: web/python
technique: python-merge-globals-file-read
tags:
- python
- flask
- merge
- attribute-pollution
- class-pollution
- globals
- file
- arbitrary-file-read
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T08:57:49+08:00'
  notes: 已对照原文核对：EzFlask/GHCTF 两题源码的 merge(hasattr/getattr/setattr) 入口与 open(__file__).read() sink 一致；图15 显示 unicode 转义绕过黑名单后 /proc/1/environ 回显 FLAG=NSSCtf{...}，图03 显示读 /etc/passwd 成功，任意读取已打通。affected_versions 保持为空正确（python3.10、flask 路径仅为靶机环境）。未验证点：多 worker 场景需逐个进程污染，原文未涉及。
url: /docs/web/python/web-python-merge-globals-file-source-echo-arbitrary-read/
draft: false
kb_aliases:
- __file__ 污染
- __globals__ 改 __file__
- Flask 源码回显路由任意文件读取
- Python 属性污染读 /proc/1/environ
- merge 污染 __file__
---

## 一句话结论

当应用把用户 JSON 递归 merge 进对象（`hasattr`/`getattr`/`setattr` 写法）且不拦双下划线属性时，可沿 `__class__` → `__init__` → `__globals__` 进入模块全局字典，把 `__file__` 改成 `/proc/1/environ` 等任意路径；随后任何 `open(__file__).read()` 形式的“回显源码”路由都会直接返回该文件内容。

## 原理

- **`__file__` 是模块级全局变量，不是常量**：模块导入时解释器把自身文件路径写入模块 `__dict__["__file__"]`，函数体里的 `__file__` 是对该字典项的按名查找（LOAD_GLOBAL），不是编译期常量。因此运行期改字典值，下一次调用即读到新值。
- **`__globals__` 拿到同一份字典**：函数对象的 `__globals__` 就是其定义模块的 `__dict__`（与 `globals()` 是同一对象）。类方法 `user.check` 的 `__globals__` 与模块级 `__file__` 共享同一份命名空间，改 `f.__globals__["__file__"]` 等价于改模块全局。
- **merge 为什么能走这么深**：脆弱 merge 对每个 key 先判 `hasattr(dst, k)`，为真且 value 是 dict 就 `getattr(dst, k)` 递归。Python 实例天然有 `__class__`，类有 `__init__`，函数有 `__globals__`，`hasattr` 对它们全返回 True，递归便从“用户数据”无缝穿到“解释器内部对象”。最后一个非 dict 值落到 `setattr`/`dst[k] = v`，即完成写入。
- **为什么这是任意文件读取而非仅读源码**：sink 侧 `return open(__file__, "r").read()` 只信任全局变量，没有路径白名单或 `realpath` 校验；把值换成 `/proc/1/environ`、`/flag`、`/app/app.py` 后即读出对应文件。CTF 中 flag 常以环境变量注入，`/proc/1/environ` 因此比 `/flag` 更常命中。
- **`__class__` 与 `__init__` 两条入口等价**：`{"__class__":{"check":{"__globals__":{...}}}}` 与 `{"__init__":{"__globals__":{...}}}` 都能到达模块命名空间，后者依赖目标对象的 `__init__` 定义在同一模块，前者依赖类上有可访问的方法（如 `check`），实战按目标结构调整。
- **过滤器只匹配字面量时可绕过**：若黑名单按原文匹配 `__class__`、`__init__`、`__globals__` 等字符串，用 JSON 的 `\u005f` 转义表示下划线，`json.loads` 解码后键名完全一致，原文却不含被禁子串。

## 触发条件

- 存在把用户可控嵌套 JSON 递归合并进对象的入口，merge 用 `hasattr`/`getattr`/`setattr`（或 `dst.__dict__` 递归），且未拒绝 `__` 开头的键。
- 同一模块中存在以 `__file__`（或其它模块级变量）作为文件路径的 sink，典型是“回显当前源码”的调试路由。
- 目标文件对 Web 进程可读；`/proc/1/environ` 需要进程能看到 PID 1 的环境（容器内通常可以）。
- 修改是进程级、跨请求生效；多 worker 部署时需命中被污染的 worker 或对所有 worker 各发一次。

## 利用步骤

1. 读源码确认 merge 语义与 sink：是否有 `open(__file__)`、`open(module.__file__)`、`send_file(__file__)` 一类按全局变量取路径的读取点。
2. 用正常字段注册/提交一次，确认 merge 会写入目标对象且不报错。
3. 发送污染包，把 `__globals__["__file__"]` 指向 `/proc/1/environ`（或先指 `/etc/passwd` 验证读权限）。
4. 访问源码回显路由，读取返回值；若返回环境变量或 `root:x:0:0`，说明 sink 生效。
5. 若被关键字过滤，改用 `\u005f` 等 Unicode 转义重发；若 `__class__` 分支不可用，换 `__init__`、或类上其它方法名。
6. 读 `/proc/self/environ`、`/proc/1/cmdline`、应用配置、数据库凭据，继续横向。

## PoC

最小 payload（污染全局 `__file__`）：

```http
POST /register HTTP/1.1
Host: target
Content-Type: application/json

{"username":"aaa","password":"bbb","__class__":{"check":{"__globals__":{"__file__":"/proc/1/environ"}}}}
```

等价写法：

```json
{"username":"aaa","password":"bbb","__init__":{"__globals__":{"__file__":"/proc/1/environ"}}}
```

随后：

```http
GET / HTTP/1.1
Host: target
```

路由 `return open(__file__, "r").read()` 返回 `/proc/1/environ` 内容。

过 WAF 的转义写法（下划线转 `\u005f`）：

```json
{"username":"abc","password":"123","\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f":{"\u0063\u0068\u0065\u0063\u006b":{"\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f":{"\u005f\u005f\u0066\u0069\u006c\u0065\u005f\u005f":"\u002f\u0070\u0072\u006f\u0063\u002f\u0031\u002f\u0065\u006e\u0076\u0069\u0072\u006f\u006e"}}}}
```

## 变体与关联

- **变量变体**：`__file__`、`__name__`、模块级 `CONFIG_PATH`、`TEMPLATE_DIR`、`LOG_FILE`；凡是路由按全局名取路径的都可替换。
- **入口变体**：`__class__.<method>.__globals__`、`__init__.__globals__`、`__class__.__mro__[1].__init__.__globals__`；也可直接污染 `app.static_folder="/"` 走 `/static/` 读文件（见关联卡）。
- **过滤绕过变体**：JSON `\uXXXX` 转义、大小写、拼接键名（若 merge 支持）。
- **关联**：[[web-python-recursive-merge-class-pollution-globals-rce]]（同一 merge 入口的类属性提权、`secret_key` 覆盖、白名单 RCE，sink 不同）；[[web-python-framework-flask-static-folder-arbitrary-file-read]]（改 `static_folder` 经 `/static/` 读文件）；[[web-python-recursive-merge-config-filename-arbitrary-read]]（改业务属性 `config.filename` 读文件）；[[web-python-waf-json-unicode-escape-bypass]]（同类解析前后表示不一致绕过）。
- **边界**：merge 拒绝 dunder 键、sink 使用固定路径常量而非全局变量、进程无读权限、或 `__file__` 被框架在使用前重新赋值时，该链失效。

## 检测与防御

- **检测**：请求 JSON 出现 `__class__`、`__init__`、`__globals__`、`__file__` 或 `\u005f` 转义键；合并入口收到含双下划线的字段名；源码回显路由返回内容不是 Python 源码（出现 `PATH=`、`root:x:`、`BEGIN` 等特征）。
- **防御**：不用通用递归 merge 处理用户输入，改显式字段白名单或 Pydantic 模型；必须递归时拒绝所有 `__` 开头/结尾的键并限制值类型。
- **加固**：生产环境不注册“回显源码”路由；文件读取使用固定目录 + `realpath`/`commonpath` 校验；Web 进程低权限运行，flag/密钥不放在其可读路径；发现被污染后重启进程并轮换泄露凭据。
