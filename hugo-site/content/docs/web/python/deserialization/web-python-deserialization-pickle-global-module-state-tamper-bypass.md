---
id: web-python-deserialization-pickle-global-module-state-tamper-bypass
title: Pickle GLOBAL 引用模块对象并 BUILD 篡改全局变量通过对象比较校验
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-global-module-state-tamper-bypass
tags:
- python
- pickle
- deserialization
- opcode
- global
- build
- validation-bypass
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V602
  verified_at: '2026-11-12T18:14:42+08:00'
  notes: 已对照原文与全部42张截图核对：图16 dis（GLOBAL __main__.A -> EMPTY_DICT -> SETITEMS -> BUILD -> POP -> 正常B对象）与图17 Success（A.num==6/A.passwd==123456）与卡片PoC逐字节一致；本地复现主PoC及cA\nnum\n变体均通过，c__main__\nA\nnum字面量经测试非法已修正为cA\nnum\n，另修正Python版本描述（原文为Py3.9实测而非Py2风格）与FRAME长度须修正的表述（原文未修正仍成功，已实测）。无组件版本信息故不设affected_versions；dedup top候选（BUILD __setstate__ RCE、sys.modules self-rebind、pker原语、R过滤绕过）均非同一条链。
url: /docs/web/python/deserialization/web-python-deserialization-pickle-global-module-state-tamper-bypass/
draft: false
kb_aliases:
- pickle 改变量绕过
- GLOBAL 引用修改全局变量
- BUILD 篡改模块属性
- pickle 对象比较绕过
- 无 R 指令 pickle 绕过
---

## 一句话结论

pickle 的 `GLOBAL`（`c`）取到的是 `find_class` 返回的**原对象引用**而不是副本；当目标是一个 `__dict__` 可写的模块（或实例）时，攻击者可在反序列化开头用 `GLOBAL 模块名 + EMPTY_DICT + SETITEMS + BUILD` 把该模块的全局变量改写为任意值，再正常构造待校验对象，业务代码随后用这些被篡改的变量做比较（如 `B(A.num, A.passwd)` 登录校验）时就会通过——全程不使用 `R`/`os.system` 等危险调用，即使 `find_class` 只允许 `__main__` 也能用。

## 原理

- `GLOBAL`（`c<module>\n<name>\n`）调用 `find_class` 并按名字取对象，返回的是**引用**：对模块而言就是 `sys.modules` 里那个模块对象的属性读取结果；对实例而言是同一对象。
- `BUILD`（`b`）的语义是：弹出 `state`（dict），取 `inst = stack[-1]`；若 `inst` 有 `__setstate__` 就调用它，否则把 `state` 的键值逐个合并进 `inst.__dict__`。
- 模块对象的 `__dict__` 是普通可写 dict，因此 `BUILD` 可以成功写入 `module.__dict__[k] = v`，等于在运行时修改了模块全局变量；业务校验函数若在反序列化**之后**读取这些变量（`A.num`、`A.passwd`）作为基准值，读到的就是攻击者设定的值。
- 若直接 `GLOBAL` 一个**类**再 BUILD，则会因 `Class.__dict__` 是只读 `mappingproxy` 而报 `TypeError`；必须引用模块或实例（实例的 `__dict__` 可写）。这也是该手法容易踩空的地方：原文的 `__main__.A` 是 `import A` 后绑定在 `__main__` 命名空间里的**模块对象**，不是类。
- 同理，`SETITEM`（`s`/`u`）也可以向模块 `__dict__` 或字典对象写键；`SETATTR`（`b` 的另一路径/`pker` 的赋值语法）写法等价。
- 另一条更短的路径：把正常序列化串中承载字段值的 `K`（BININT1）/`V`（UNICODE）指令替换成 `c` 引用模块属性（原文为 `cA\nnum\n`、`cA\npasswd\n`，即 `GLOBAL(模块A, 属性num/passwd)`），使反序列化出的对象字段值直接取自模块变量——用于"字段必须等于某全局值"的校验。
- 该手法不改变 `find_class` 白名单能取到什么，只滥用"取引用 + 可写 dict 合并"的语义，因此与 R 指令过滤、危险函数黑名单都不冲突；危害取决于业务把什么判断建立在可变全局状态之上（常见于 CTF 登录校验、配置比对、白名单检查）。

## 触发条件

- 存在用户可控的 `pickle.loads`/`Unpickler.load` 入口，且 `find_class` 至少允许引用目标模块（只允许 `__main__` 也够）。
- 目标代码在反序列化之后、做比较判断之前，从模块/全局读取基准值（口令、flag、配置项）。
- 反序列化结果会与这些全局值做 `==`/成员判断，或字段值被用于后续鉴权。
- 服务端未对反序列化对象类型做白名单校验，也未在加载后重新校验来源。

## 利用步骤

1. 正常序列化一个合法对象（如 `pickle.dumps(B(A.num, A.passwd))`），用 `pickletools.dis` 记录字节布局作为基线。
2. 在字节流开头（PROTO/FRAME 之后、对象构造之前）插入篡改前缀：`c<module>\n<name>\n`（GLOBAL 取目标模块）→ `}`（EMPTY_DICT）→ `(`（MARK）→ 交替压键/值 → `u`（SETITEMS）→ `b`（BUILD 合并进模块 `__dict__`）。
3. 用 `0`（POP）或直接把栈上残留弹掉，保持栈干净。
4. 拼接正常对象构造串，字段值填成篡改后的值（或改用 `c` 引用模块变量），以 `0`/`.` 结束。原文载荷保留了原串的 FRAME 长度字段（43，未随内容同步修正）仍解析成功——CPython 的 Unpickler 不强制帧边界；稳妥起见也可改用 protocol 0 省略帧、手工拼字节。
5. `pickletools.dis` 核对 opcode 顺序与 BUILD 的目标对象；在隔离环境用同构模块验证 `A.num/A.passwd` 确实被改写。
6. 提交 payload；若校验通过即返回成功/flag。无回显场景可结合布尔差异判断。

## PoC

原文场景（Python 3 实测，PyCharm 3.9 解释器；载荷为协议 4 帧头 + 手工文本式 opcode。模块 `A` 中预置 `num/passwd`，类 `B.__eq__` 按 `B(A.num, A.passwd)` 比较）：

```text
# 篡改前缀：GLOBAL __main__.A -> EMPTY_DICT -> MARK -> {num:6, passwd:'123456'} -> SETITEMS -> BUILD
c__main__\nA\n}(Vnum\nK\x06Vpasswd\nV123456\nub
# 清栈 + 正常构造 B(num=6, passwd='123456')
0c__main__\nB\n)\x81}(\x8c\x03numK\x06\x8c\x06passwd\x8c\x06123456ub.
```

要点说明：

- `c__main__\nA\n` 必须指向**模块对象**（`import A` 后的 `__main__.A`）；若 A 是类，BUILD 会因 mappingproxy 报错。
- `u`（SETITEMS）在 MARK 之后两两成对填 dict；`b`（BUILD）把 dict 合并进模块 `__dict__`，`A.num/A.passwd` 随即被改写。
- 更短变体：基线串中 `K\x01`（字段 num 的值）替换为 `cA\nnum\n`（模块 `A` 直接 import 后按属性名取值），`\x8c\x05aiwin`（字段 passwd 的值）替换为 `cA\npasswd\n`，让字段值直接引用模块 `A` 的全局变量，无需先篡改（原文截图实测 Success）。注意 `c__main__\nA\nnum` 不是合法 GLOBAL（name 只会读到 `A`，剩余字节 `num` 会成为未知 opcode），若走 `__main__` 应使用点号形式 `c__main__\nA.num\n`。
- 该 PoC 依赖类名/模块名与原文一致；复用时按目标环境替换 `__main__`/模块名/类名，并用同版本 Python 验证。

## 变体与关联

- 变体：目标不是模块而是实例对象时，对其 `__dict__` BUILD 同样可写；对类对象则失败（mappingproxy）。
- 变体：用 `SETITEM` 改字典/`sys.modules`，或用 `SETATTR` 改函数对象，属同一"写状态"原语族。
- 关联：[[web-python-deserialization-pker-opcode-primitives]]（GLOBAL/SETITEM/SETATTR 原语与可写不可读约束）；[[web-python-deserialization-pickle-build-setstate-newobj-instance-rce]]（同样用 BUILD，但目标是注入 `__setstate__=os.system` 求 RCE；本卡不调用危险函数，仅篡改状态）；[[web-python-deserialization-pickle-sys-modules-self-rebind]]（SETITEM 重绑 `sys.modules` 的白名单绕过）；[[web-python-deserialization-pickle-inst-obj-reduce-filter-bypass]]（R 被过滤时的调用路径）。
- 边界：`find_class` 完全禁用业务模块引用、BUILD 被整体拦截、校验在反序列化前完成或使用不可变值做常量内联时失效。

## 检测与防御

- 检测：pickle 载荷中出现 `GLOBAL` 后紧跟 `EMPTY_DICT`/`SETITEMS`/`BUILD` 的组合（正常业务序列化极少对模块对象 BUILD）；`GLOBAL` 引用的目标是模块或配置对象而非待恢复的 DTO。
- 检测：反序列化前后对比关键全局变量的哈希/值，发现运行时被改写；对 `pickle.loads` 输入做 opcode 级审计。
- 防御：不与不可信 pickle 交互；必须使用时用严格 `find_class` 白名单（只允许具体业务类），并在加载后对对象类型和字段做白名单校验。
- 防御：不要把安全判断（口令、flag、权限）建立在模块全局变量或可变配置上；校验基准使用常量或从可信存储重新读取；反序列化完成后在独立进程/容器中处理业务逻辑。
