---
id: binary-pwn-sandbox-escape-python-audit-hook-print-poisoning
title: Python 审计钩子绕过：污染 builtins.print 并篡改 audit 局部 os._exit
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-audit-hook-print-poisoning
aliases:
- addaudithook 绕过
- 审计钩子 os._exit 覆盖
- builtins.print 污染
- audit hook exit bypass
- PEP 578 逃逸
tags:
- python
- pyjail
- sandbox-escape
- audit-hook
- pep578
- builtins
- frame
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:46:06+08:00'
  notes: 已对照原文核对：audit 钩子先 print 后 os._exit、通过生成器帧回溯拿 audit 局部 os、setattr 替换 _exit、最终 eval/getattr/__import__ 执行命令的 exp 与卡片一致；未验证点：原文最终 exp 未附 flag 回显截图，本线程未实际执行
---

## 一句话结论

当 `sys.addaudithook` 的钩子在命中黑名单时先调用 `print` 再调用 `os._exit(1)`，攻击者可先拿到真实 builtins，把 `builtins.print` 替换成恶意函数；钩子调用 `print` 时，恶意函数沿栈帧找到 audit 函数的局部变量 `os`，把 `os._exit` 替换成无害函数，使钩子无法退出进程，随后继续执行命令。

## 原理

- 审计钩子 `audit(event, args)` 是一个普通 Python 函数。它里面 `print(i)` 的 `print` 不是局部变量，按 LEGB 规则会从 `builtins` 查找；因此修改 `builtins.print` 会直接影响钩子的行为。
- 钩子的典型写法是：
  ```python
  for i in blacklist:
      if i in (event + str(args)).lower():
          print(i)
          os._exit(1)
  ```
  `os` 是在 `audit` 内部 `import os` 得到的局部变量，指向进程全局的 `os` 模块对象。`os._exit` 是模块属性，替换 `locals['os']._exit` 会修改同一个模块对象，因此钩子接下来的 `os._exit(1)` 调用的是被替换后的函数。
- 恶意 print 需要拿到 audit 函数的局部变量。用生成器帧回溯：`(q.gi_frame.f_back.f_back.f_locals for _ in [1])`，用 `[*q]` 驱动生成器，运行时其 `f_back` 链指向 audit 帧，`f_locals` 中就有 `os`。也可以在恶意函数内部直接沿 `f_back` 找调用者帧。
- 把 `os._exit` 替换成 `print` 后，钩子调用 `os._exit(1)` 只会打印 `1` 并返回，进程继续执行；此后所有审计事件都不再导致退出。
- 源码过滤 `__`/`getattr`/`exit` 时，用字符串拼接构造 `'_ex' + 'it'`、`'_' + '_import_' + '_'`，用 `eval('bti.get' + 'attr', ...)` 取 `getattr`，避开关键字匹配。

## 触发条件

- 目标使用 `sys.addaudithook` 作为主要隔离层，且钩子内部通过 builtins 调用 `print`、通过模块属性调用 `os._exit`。
- 用户代码能拿到真实 builtins（例如通过栈帧恢复），并能执行 `setattr`/属性赋值。
- 钩子与用户代码在同一进程；钩子没有把 `print`/`os._exit` 固定在闭包或默认参数里。
- 源码黑名单只过滤 `__`、`getattr`、`exit` 等字面量，未禁止 `setattr`、`builtins`、帧属性。

## 利用步骤

1. 先通过生成器帧回溯拿到外层帧的 `__builtins__`（见关联卡）。
2. 定义恶意替换函数 `Acc_print(a)`：在内部用生成器帧回溯到 audit 帧的 `f_locals`，若其中存在 `os`，执行 `setattr(locals['os'], '_ex' + 'it', print)`。
3. 执行 `bti.print = Acc_print`，污染 builtins.print。
4. 触发一个会被钩子拦截的审计事件（例如 `os.system`、`open`），钩子调用 `print(i)` 时进入恶意函数，替换 `os._exit`；钩子随后调用 `os._exit(1)` 变成普通打印，进程不退出。
5. 用 `bti.eval` + `getattr` 取 `__import__`，执行 `os.system('cat /flag')`。
6. 若钩子把 `_exit` 用 `from os import _exit` 绑定为局部函数，替换模块属性无效；需要换其他依赖名或直接阻止钩子代码执行。

## PoC

核心片段（沿用生成器帧回溯拿 builtins）：

```python
bti = frame.f_globals['_' + '_' + 'builtins' + '_' + '_']

def Acc_print(a):
    q = (q.gi_frame.f_back.f_back.f_locals for _ in [1])
    loc = [*q][0]
    if 'os' in loc:
        bti.setattr(loc['os'], '_ex' + 'it', print)
    print('intercepted')

bti.print = Acc_print

ev = bti.eval
gta = ev('bti.get' + 'attr', {'bti': bti})
ipt = gta(bti, '_' + '_import_' + '_')
ipt('os').system('cat /flag')
```

说明：`Acc_print` 被钩子调用时，`q` 生成器的 `f_back` 链指向 audit 帧；`loc['os']` 就是 audit 内 `import os` 得到的模块对象。替换后，钩子的 `os._exit(1)` 变成 `print(1)`，不再终止进程。

## 变体与关联

- 变体：污染 `builtins.print` 以外的钩子依赖（如 `str`、`len`、事件判断函数），让黑名单判断失效。
- 变体：把 `os._exit` 替换为 `lambda *a: None` 或 `sys.exit` 的替代；也可替换 `sys.exit`、`os.kill` 等退出路径。
- 变体：钩子若使用 `from os import _exit`，可尝试替换 `builtins.__import__`，让钩子重新导入时拿到被污染的 os；或在钩子执行前覆盖其依赖。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（先拿 builtins 的前置链）。
- 关联：[[binary-pwn-sandbox-escape-python-audit-hook-bypass]]（另一类审计钩子绕过：覆盖钩子依赖的全局名/恢复被污染的 os）。
- 注意：该手法依赖钩子的具体实现（先 print 后 os._exit、os 为 audit 局部变量）；不同实现的钩子需要重新寻找可污染的依赖点。

## 检测与防御

- 检测：用户代码中出现对 `builtins.print`/`builtins.str`/`builtins.len` 的赋值，或对 `os._exit`、`sys.exit` 的赋值；出现 `gi_frame`/`f_back`/`f_locals` 帧回溯；出现 `'_ex' + 'it'` 等拼接。
- 防御：钩子内用闭包/默认参数固定关键函数：`def audit(event, args, _print=print, _exit=os._exit): ...`；不要通过 builtins 或可被替换的模块属性调用退出函数。
- 防御：把钩子定义在用户代码不可达的独立模块；不要与用户代码共享命名空间；对 `builtins` 和 `os` 模块属性的修改做监控。
- 防御：审计钩子只能作为纵深防御，最终隔离应使用独立进程/容器、低权限用户、seccomp/AppArmor 和只读文件系统。
