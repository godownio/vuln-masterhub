---
id: web-python-codetype-function-code-hijack
title: Python 运行时函数劫持：用 types.CodeType 替换 __code__
type: scenario
domain: web
path: web/python
technique: python-codetype-function-hijack
tags:
- python
- codetype
- function-hijack
- bytecode
- variable-overwrite
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:55:56+08:00'
  notes: 已对照原文与9张图片核对：types.CodeType接管__code__的通用原语与最小PoC（改co_consts读取/flag）与原文一致；Python3.8参数顺序及3.11+字段变化已注明；原文payload的ctypes CodeType笔误未带入本卡；PoC未本机执行；frontmatter无sources/source_url。
url: /docs/web/python/web-python-codetype-function-code-hijack/
draft: false
kb_aliases:
- CodeType 函数劫持
- __code__ 替换
- Python 动态修改函数
- 函数字节码替换
- types.CodeType 构造代码对象
---

## 一句话结论

只要能对任意已有函数对象执行 `setattr(f, '__code__', new_code)`，就能用 `types.CodeType` 构造的代码对象把该函数改写成任意逻辑；函数名、模块、路由注册和其他调用方接口都保持不变，可把只读接口变成任意文件读取或命令执行。

## 原理

- Python 函数对象持有 `__code__` 属性（code object），调用函数时解释器执行其中的字节码。`__code__` 可写，给它赋新 code object 不会重建函数对象，也不会影响装饰器、Flask 路由表等外部引用。
- `types.CodeType` 允许直接构造 code object。Python 3.8 的参数顺序为：`co_argcount`、`co_posonlyargcount`、`co_kwonlyargcount`、`co_nlocals`、`co_stacksize`、`co_flags`、`co_code`、`co_consts`、`co_names`、`co_varnames`、`co_filename`、`co_name`、`co_firstlineno`、`co_lnotab`、`co_freevars`、`co_cellvars`；Python 3.11+ 以 `co_linetable`/`co_exceptiontable` 取代 `co_lnotab`，需按目标版本取字段。
- 最省事的改写方式不是重写字节码，而是复用模板函数的 `co_code`/`co_names`，只替换 `co_consts` 中 `LOAD_CONST` 引用的字符串。例如模板函数 `open("app.py").read()` 的字节码不变，把常量 `'app.py'` 换成 `'/flag'`，函数行为就从读源码变成读 flag。
- `co_code` 是 `bytes`。用 `_codecs.encode(s, 'latin-1')`（或 `base64` 解码）可把字符串按 1:1 映射为原始字节；用 utf-8 会改写 `\x80` 以上的字节，导致 `SystemError: unknown opcode`。
- 控制点不限于 pickle：变量覆盖、对象属性注入、Python 原型链/属性污染、SSTI 中可赋值表达式等，只要能拿到函数对象并执行一次属性赋值，就能复用该原语。

## 触发条件

- 目标为 Python 3（参数列表随版本变化），攻击者能导入 `types`/`builtins`（默认可导入）。
- 攻击者能对目标函数对象执行属性赋值（`setattr`、对象注入、变量覆盖、污染等）。
- 目标函数可被访问触发（如已注册的 Web 路由），且其签名与模板函数兼容（参数个数、局部变量数、栈大小等需匹配）。
- 能获得或推断目标函数 `__code__` 的字段值；同签名模板函数可直接提供。

## 利用步骤

1. 选定要劫持的函数 `target`（例如负责返回页面的路由函数）与一个同签名模板函数 `src`。
2. 枚举 `src.__code__` 的字段，确认 `co_argcount`、`co_stacksize`、`co_flags`、`co_names`、`co_varnames` 等值。
3. 按目标版本构造新的 code object：复用模板字段，修改 `co_consts`（把文件名/命令替换为目标值）；如重写 `co_code`，用 latin-1 或 base64 还原成 bytes。
4. 执行 `target.__code__ = new_code`（或在 pickle/变量覆盖中调用 `setattr`）。
5. 通过正常业务入口访问 `target`，其返回值/副作用即变为攻击者逻辑。

## PoC

```python
import types

def src():
    return open("app.py", "r", encoding="utf-8").read()

def secret():
    return

o = src.__code__
secret.__code__ = types.CodeType(
    o.co_argcount,
    o.co_posonlyargcount,
    o.co_kwonlyargcount,
    o.co_nlocals,
    o.co_stacksize,
    o.co_flags,
    o.co_code,
    tuple(c if c != "app.py" else "/flag" for c in o.co_consts),
    o.co_names,
    o.co_varnames,
    o.co_filename,
    o.co_name,
    o.co_firstlineno,
    o.co_lnotab,
    o.co_freevars,
    o.co_cellvars,
)
print(secret())   # 读取 /flag
```

改写 `co_code` 时生成 bytes 的等价写法：

```python
import _codecs
co_code = _codecs.encode(raw_bytecode_as_latin1_str, "latin-1")
```

## 变体与关联

- 只改 `co_consts` 是最小改动；改 `co_code` 可执行全新逻辑（命令执行、内存马、任意函数调用）。
- 在 pickle 场景中可用 `builtins.getattr`/`builtins.setattr`/`types.CodeType`/`_codecs.encode` 完成同样操作并绕过关键字黑名单，见 pickle 链卡片。
- 其他控制点：变量覆盖（如题目中的 `Student.__init__` 属性覆盖）、对象注入、`pydash.set_` 属性污染、SSTI 中可赋值表达式。
- `co_filename`、`co_name`、`co_lnotab` 对执行结果影响很小，通常直接复制模板值即可。
- 关联：[[web-python-deserialization-pickle-codetype-function-hijack]]、[[web-python-pydash-set-attribute-path-pollution]]。

## 检测与防御

- 禁止不可信输入触发对函数对象的属性赋值；对 `setattr` 的目标做白名单，尤其禁止 `__code__`、`__globals__`、`__dict__` 等敏感属性。
- 对代码执行上下文做最小权限：限制文件读、命令执行与网络访问，降低函数劫持后的危害。
- 用 `sys.addaudithook` 监控 `code.__new__`、`function.__new__` 等审计事件，检测异常的 code object 构造与 `__code__` 赋值。
- 不要依赖“函数未重新定义”来假设行为不变；运行时可校验关键函数的 `__code__` 指纹。
- 由于该原语常由其他漏洞（变量覆盖、属性污染、反序列化）触发，根本措施是修复上游注入点。
