---
id: web-python-deserialization-pickle-parser-differential-checks
title: Python pickle/_pickle/pickletools 解析差异：4 字节 payload 分别控制 5 类校验通过/失败
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-parser-differential-checks
aliases:
- pickle 与 _pickle 差异
- pickletools 解析差异
- pickle 解析器差异
- APPENDS 零元素
- BUILD 空 state 真值差异
- INT 空字节截断
- pickle 校验绕过
tags:
- python
- pickle
- pickletools
- deserialization
- parser-differential
- validation-bypass
- cpython
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:10+08:00'
  notes: 已对照原文核对；五组payload(NN./N(e./]]b./(./I\0\n.)在三解析器上的成败矩阵与原文一致；原文未标注CPython版本区间，未设置versions；PoC未在本机复跑
---

## 一句话结论

Python 纯实现 `pickle`、C 加速 `_pickle` 与静态反汇编器 `pickletools` 对同一段字节的校验语义并不一致：栈残留检查、`APPENDS` 零元素、`BUILD` 空 `state` 的真值判断、`MARK`/`STOP` 栈下溢、`INT` 参数中的空字节截断各有不同；攻击者可用 4 字节以内的 opcode 组合精确控制三个解析器“谁成功、谁报错”，从而绕过只依赖其中一个解析器做校验或检测的逻辑。

## 原理

- 三个解析器的职责不同：`pickle._Unpickler` 是纯 Python 虚拟机，`_pickle.Unpickler` 是 C 实现，`pickletools.dis/genops` 只做静态模拟与反汇编，不执行 `GLOBAL`/`REDUCE`。实现差异会导致同一字节流在“是否报错、栈如何变化、参数如何解析”上不一致。
- 差异一：`pickletools` 在 `STOP` 后检查模拟栈必须为空，否则抛 `ValueError("stack not empty after STOP")`；`pickle`/`_pickle` 只弹出栈顶作为结果。payload `NN.`（NONE NONE STOP）会让两个反序列化器成功返回 `None`，而 `pickletools` 报栈残留。
- 差异二：`APPENDS` 弹出 `MARK` 之后若元素数为 0，C 实现有 `if (len == mark) return 0;` 提前返回，纯 Python 的 `load_appends` 没有零元素检查，直接对栈顶对象取 `extend`/`append`。payload `N(e.`（NONE MARK APPENDS STOP）在纯 Python 中报 `'NoneType' object has no attribute 'append'`，C 实现与 `pickletools` 均成功。
- 差异三：`BUILD` 的 `state` 判断不同：C 实现是 `if (state != Py_None)` 后要求 `state` 必须是 dict，纯 Python 是 `if state:`，空 dict/空 tuple 会被当作假值跳过。payload `]]b.`（EMPTY_LIST EMPTY_LIST BUILD STOP）在纯 Python 中成功，C 实现报 `state is not a dictionary`，`pickletools` 静态模拟成功。
- 差异四：`MARK` 在纯 Python 中把当前栈压入 `metastack` 并新建空栈，随后 `STOP` 对空栈 `pop()` 触发 `IndexError`；C 实现用 `mark_set` 标志位在栈下溢时报 `unexpected MARK found`；`pickletools` 只把 `markobject` 当作普通栈元素，`STOP` 照常弹出。payload `(.` 于是只有 `pickletools` 成功。
- 差异五：`INT` 操作码读取到换行为止的整行；C 实现把整行交给 `strtol`，遇到空字节即停止并返回 `0`，纯 Python 的 `int(b'\x00\n')` 和 `pickletools` 的 `int(b'\x00')` 都会抛 `invalid literal`。payload `I\x00\n.` 于是只有 `_pickle` 成功。
- 安全意义：当校验器、扫描器、WAF 或“安全检查”使用 `pickletools` 之类的静态解析，而真正加载数据的是 `pickle`/`_pickle` 时，两者对同一字节流的理解可以不同。攻击者可以让检测侧看到无害/报错的解析结果，而运行时侧继续执行；反之也可让检测侧误判。原文在 CTF 校验关卡中完整验证了这五类差异，但未进一步构造隐藏 `GLOBAL` 的 RCE payload。
- 这些差异属于 CPython 实现细节（部分已有 issue 记录：APPENDS/ADDITEMS 零元素检查、BUILD 空 state 真值、INT/LONG 空字节截断），不能假设不同版本/实现之间行为一致。

## 触发条件

- 目标对同一段不可信 pickle 数据使用两个不同解析器：例如先用 `pickletools.genops/dis` 做静态检查，再用 `pickle.loads`/`_pickle.loads` 实际加载；或同时用纯 Python 与 C 实现做双重校验。
- 校验逻辑依赖“解析成功/失败”本身作为安全判断（成功即放行、报错即拒绝），或依赖解析出的 opcode 序列而非运行时真实行为。
- 输入长度受限或校验只看前若干字节时，差异更容易被利用。
- 若目标是 CTF 式多关卡校验，需要分别构造满足“某实现成功、某实现失败”的字节序列；真实应用中还需结合具体校验代码确认差异方向。

## 利用步骤

1. 确认解析器组合：代码中同时出现 `pickle`、`_pickle`、`pickletools`、`picklescan` 等；记录每个解析器用于“校验”还是“加载”。
2. 用最小 harness 复现三者的行为差异：对候选 payload 分别运行纯 Python `pickle._Unpickler`、C `_pickle.Unpickler` 与 `pickletools.dis`，记录成功/失败与异常类型。
3. 按需要的“成功/失败矩阵”选择 payload：
   - 两个反序列化器成功、`pickletools` 失败：`NN.`
   - 纯 Python 失败、C 与 `pickletools` 成功：`N(e.`
   - C 失败、纯 Python 与 `pickletools` 成功：`]]b.`
   - 仅 `pickletools` 成功：`(.`
   - 仅 C 成功：`I\x00\n.`
4. 把 payload 送入目标的校验/加载流程，观察是否出现“校验器拒绝但加载器接受”或相反的路径；若校验器在异常时 fail-open，优先寻找“校验器报错、加载器成功”的方向。
5. 若目标是静态扫描器，尝试把危险 opcode 放在解析器差异位置（如空字节后、`STOP` 后、`MARK` 边界），验证扫描器与加载器看到的 opcode 序列是否不同；本文未给出完整 RCE payload，需按实际扫描器实现自行构造并在授权环境验证。
6. 记录每个 payload 的十六进制、三者输出与目标响应，作为差异证据。

## PoC

最小复现 harness（本地 Python 环境）：

```python
import io
import pickle
import _pickle
import pickletools

payloads = {
    "stack_leftover": bytes.fromhex("4e4e2e"),          # NN.   -> C/py OK, pickletools rejects
    "appends_zero":   bytes.fromhex("4e28652e"),        # N(e.  -> py fails, C/pickletools OK
    "build_empty":    bytes.fromhex("5d5d622e"),        # ]]b.  -> C fails, py/pickletools OK
    "mark_stop":      bytes.fromhex("282e"),            # (.    -> only pickletools OK
    "int_nul":        bytes.fromhex("49000a2e"),        # I\0\n. -> only C OK
}

for name, data in payloads.items():
    results = {}
    for label, unpickler in (
        ("py", pickle._Unpickler),
        ("c", _pickle.Unpickler),
    ):
        try:
            unpickler(io.BytesIO(data)).load()
            results[label] = "OK"
        except Exception as e:
            results[label] = f"ERR:{type(e).__name__}:{e}"
    try:
        pickletools.dis(data)
        results["pickletools"] = "OK"
    except Exception as e:
        results["pickletools"] = f"ERR:{type(e).__name__}:{e}"
    print(name, results)
```

预期结果（CPython 3.x，具体异常文本随版本略有差异）：

```text
stack_leftover {'py': 'OK', 'c': 'OK', 'pickletools': 'ERR:ValueError:stack not empty after STOP'}
appends_zero   {'py': "ERR:AttributeError:'NoneType' object has no attribute 'append'", 'c': 'OK', 'pickletools': 'OK'}
build_empty    {'py': 'OK', 'c': 'ERR:UnpicklingError:state is not a dictionary', 'pickletools': 'OK'}
mark_stop      {'py': 'ERR:IndexError:pop from empty list', 'c': 'ERR:UnpicklingError:unexpected MARK found', 'pickletools': 'OK'}
int_nul        {'py': "ERR:ValueError:invalid literal for int() with base 0: b'\\x00\\n'", 'c': 'OK', 'pickletools': 'OK'}
```

说明：payload 均为十六进制字符串；`I\x00\n.` 需以原始字节发送，不能经文本编码转换。不同 CPython 版本/实现可能已修复部分差异，使用前先跑 harness 确认。

## 变体与关联

- 变体：`ADDITEMS` 与 `APPENDS` 类似，C 实现对零元素提前返回，纯 Python 无检查；可把栈顶换成无 `add` 方法的对象触发差异。
- 变体：`BUILD` 的 `state` 用空 list/tuple/空 dict 等假值；C 实现会在某些分支报 “state is not a dictionary”，纯 Python 直接跳过。
- 变体：`INT`/`LONG` 参数中的空字节、前导空白、正负号、进制前缀都是解析差异候选；C 的 `strtol`/`PyLong_FromString` 与 Python `int()` 的停止位置不同。
- 变体：`STOP` 后的尾随数据、`MARK` 未闭合、栈残留等“格式不严格”的流，在静态模拟器与真实虚拟机之间常有不同处理。
- 关联：[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（pickle 黑名单绕过）、[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（`find_class` 白名单绕过）、[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle + CodeType 绕过）；这些卡解决“加载后能执行什么”，本卡解决“校验器与加载器看到的是不是同一份数据”。
- 边界：服务端只用一个解析器且校验逻辑不依赖解析成功/失败、或在加载前做了规范化重序列化、或使用白名单 `find_class` 并对 opcode 做严格校验时，本差异不能直接形成绕过；原文只演示 CTF 校验关卡，未给出真实扫描器隐藏 `GLOBAL` 的完整链。

## 检测与防御

- 防御：不要用 `pickletools` 的静态解析结果替代真实加载器的安全判断；校验与加载必须使用同一个解析器、同一份规范化后的字节，且对解析后对象做类型/白名单校验。
- 防御：对 pickle 数据做严格格式校验：只接受预期协议版本、拒绝 `STOP` 后尾随数据、拒绝栈残留、拒绝未闭合 `MARK`、拒绝参数中的空字节/控制字符/多余空白。
- 防御：根本方案是不对不可信数据使用 pickle；改用 JSON/MessagePack 等数据格式，或使用 `RestrictedUnpickler` + `find_class` 白名单 + HMAC 签名。
- 加固：统一 CPython 版本与实现（纯 Python/C 加速行为可能随版本变化），在 CI 中对校验器与加载器做差分测试；对 `pickle`/`_pickle`/`pickletools` 混用的代码路径做重点审计。
- 检测：请求中出现短小但包含 `MARK`/`APPENDS`/`BUILD`/`INT` 等 opcode 的异常 pickle；同一数据在校验器与加载器中的结果不一致；静态扫描器报错但业务仍继续处理的 fail-open 逻辑。
