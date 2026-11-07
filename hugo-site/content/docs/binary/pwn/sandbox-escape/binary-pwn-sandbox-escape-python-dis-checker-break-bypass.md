---
id: binary-pwn-sandbox-escape-python-dis-checker-break-bypass
title: Python dis 字节码检查器的 break 逻辑绕过：前置白名单指令跳过后续检查
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-dis-checker-break-bypass
tags:
- python
- pyjail
- sandbox-escape
- bytecode
- dis
- blacklist-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:46:08+08:00'
  notes: 已对照原文与图 10-18 核对：source_opcode_checker 的 break 逻辑、[].print() 前置触发、3.11 LOAD_ATTR/CALL 变化与题目环境差异描述一致；本卡仅绕过字节码检查层，完整链由同文另外两张卡衔接；未实际执行
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-dis-checker-break-bypass/
draft: false
kb_aliases:
- dis 反汇编检查绕过
- LOAD_METHOD print 绕过
- opcode 黑名单 break 绕过
- 字节码检查器逻辑漏洞
- source_opcode_checker 绕过
---

## 一句话结论

当沙箱用 `dis` 反汇编用户代码并逐行检查，命中 `LOAD_GLOBAL`/`IMPORT_NAME`/`LOAD_METHOD` 后若该行还含 `print`/`seed`/`randint`/`randrange` 就 `break`，这个 `break` 会直接结束整个 `for` 循环，使后续所有恶意指令不再被检查；攻击者只需在源码开头放一条同时满足两个条件的指令。

## 原理

- 典型的检查器：
  ```python
  for line in dis(code):
      if any(x in line for x in ["LOAD_GLOBAL", "IMPORT_NAME", "LOAD_METHOD"]):
          if any(x in line for x in ["randint", "randrange", "print", "seed"]):
              break
          exit()
  ```
  这里的 `break` 作用于外层 `for line in opcode`，而不是“跳过当前行继续检查下一行”。一旦某行同时命中危险 opcode 和白名单词，循环整体终止，后面的 `LOAD_GLOBAL __import__`、`IMPORT_NAME os`、`LOAD_METHOD system` 等都不会被看到。
- 在 Python 3.10 及以前，`[].print()` 这类方法调用会编译出 `LOAD_METHOD ... (print)`，一行同时包含 `LOAD_METHOD` 和 `print`，正好触发 `break`。因此 payload 开头放：
  ```python
  try:
      [].print()
  except:
      pass
  ```
  就能让检查器在第一行退出检查。
- Python 3.11+ 方法调用改为 `LOAD_ATTR` + `CALL`，`[].print()` 不再产生 `LOAD_METHOD`；可改用能产生 `LOAD_GLOBAL ... (print)` 的写法，例如在函数体内调用 `print(...)`（模块级 `exec` 中是 `LOAD_NAME print`，函数内才是 `LOAD_GLOBAL print`），或用 `seed`/`randint` 等其他白名单词构造同样的“危险 opcode + 白名单词”同一行。
- 检查器通过 `str(line)` 做子串匹配，因此 `LOAD_METHOD` 与 `print` 只要出现在同一行文本即可，不要求它们属于同一条真实指令；这进一步扩大了可构造面。
- 根本问题：用“逐行字符串包含”做字节码安全边界，且控制流写错；正确的做法应是 `continue` 跳过白名单行，或对整份反汇编做结构化白名单，而不是命中即终止。

## 触发条件

- 目标使用 `dis.dis(code, file=...)` 把用户代码反汇编后逐行做字符串黑名单。
- 检查器在命中白名单后使用 `break`（而非 `continue`），且没有在循环外再做一次完整检查。
- 攻击者能让第一条被检查的指令同时包含危险 opcode 与白名单词；版本/语法需匹配。
- 后续代码仍能执行（检查器只是检查，不修改字节码）。

## 利用步骤

1. 先提交一条会触发检查器的 `import os`，观察是否被拦截，确认检查器存在。
2. 在 payload 开头放 `try: [].print() except: pass`（Python <=3.10）或函数内 `print(...)`（3.11+ 产生 `LOAD_GLOBAL print`）。
3. 在其后写真正的逃逸链（生成器帧回溯、恢复 builtins、命令执行）。
4. 若检查器版本/行为不同，用 `dis` 在本地确认第一行是否同时含危险 opcode 与白名单词，再调整。
5. 注意 `break` 只会跳过检查，不会阻止执行；后续代码照常运行。

## PoC

最小触发结构：

```python
try:
    [].print()
except:
    pass

# 后续任意危险代码不再被检查
import os
os.system('id')
```

对应的 `dis` 关键行（Python <=3.10，示意）：

```text
LOAD_METHOD             3 (print)
```

Python 3.11+ 可用函数内 `print` 产生 `LOAD_GLOBAL`：

```python
def trigger():
    print('x')   # 函数内 print 是 LOAD_GLOBAL

trigger()

import os
os.system('id')
```

## 变体与关联

- 变体：用 `seed`、`randint`、`randrange` 等白名单词替代 `print`，构造同一行的危险 opcode + 白名单词。
- 变体：若检查器只匹配 `str(line)`，可用长变量名/注释让白名单词与危险 opcode 落在同一行文本。
- 变体：检查器若改为 `continue`，则只能尝试其它绕过（如运行期构造字符串、反射、栈帧）而不是依赖 `break`。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（本卡负责过字节码检查，后续用栈帧拿 builtins）。
- 关联：[[binary-pwn-sandbox-escape-python-audit-hook-print-poisoning]]（过掉字节码检查后绕过审计钩子）。
- 注意：Python 3.11+ 的 opcode 变化会影响 `[].print()` 是否触发；不要把该 payload 当成跨版本通用。

## 检测与防御

- 修复：把 `break` 改为 `continue`，确保每一行都被检查；或在循环结束后再用独立的完整检查器复核。
- 修复：不要用 `dis` 文本的逐行子串匹配做安全边界；使用 AST 白名单（只允许算术、受限调用）或真正的进程隔离。
- 加固：对白名单词也要求它属于特定的安全调用（如只允许 `print` 作为独立语句），而不是任意行包含即可。
- 检测：用户代码开头出现 `[].print()`、`try/except` 包裹的无意义方法调用、函数内 `print` 后紧跟 `import`/`os` 等组合；反汇编第一行同时含危险 opcode 与白名单词。
