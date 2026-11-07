---
id: code-analysis-reverse-obfuscation-python-ast-identifier-attribute-rename
title: Python AST 混淆：变量/属性名重写与 getattr/__dict__/gc.get_referents 别名
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: python-ast-identifier-attribute-rename
aliases:
- Python AST 混淆
- 变量名混淆
- 属性名混淆
- ast.NodeTransformer
- gc.get_referents
- __builtins__.__dict__
- Python 代码混淆
tags:
- python
- ast
- obfuscation
- identifier-renaming
- attribute
- gc
- code-protection
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:06+08:00'
  notes: 已对照原文核对：Name/Attribute/Import/ImportFrom重写、getattr/__builtins__.__dict__/gc.get_referents别名、str2hash自定义Base64字母表均一致；原文代码未运行（依赖astor且部分片段不完整），卡内confidence=medium。
---

## 一句话结论

用 `ast.NodeTransformer` 遍历 Python AST，在 `Name`/`Attribute`/`Import`/`ImportFrom` 节点上把变量名、模块名和属性名替换成随机标识符，并通过 `getattr`、`__import__`、`__dict__`、`gc.get_referents` 在运行时建立新旧名字的别名，可在保持程序语义不变的前提下抹掉源码中的标识符特征，提高静态分析与人工阅读成本。

## 原理

- Python 的变量绑定在 AST 中表现为 `Name(id=..., ctx=Load/Store)`：赋值目标、函数参数、`for`/推导式目标是 `Store`，读取是 `Load`。只要在 `Store` 处生成随机名并记录映射，在所有 `Load` 处替换成同名，语义就保持不变。
- 内置变量不能直接改名：可以通过 `obfname = xx`、`obfname = getattr(__builtins__, 'xx')` 或 `__builtins__.__dict__[obfname] = __builtins__.__dict__['xx']` 建立别名；后两种把原名字保留为字符串，便于继续做字符串混淆。
- 导入语句需要改写：`import xx` 变成 `xx = __import__('xx', globals(), locals(), [], 0)`；`from xx import yy` 变成先 `__import__` 模块，再 `yy = getattr(xx, 'yy')`；`from xx import *` 需要记录模块的 `__all__`/公开属性，在后续出现未知变量时按需 `getattr` 导入。
- 属性名混淆取决于属性所属对象：
  - 模块属性：`xx.__dict__[obfname] = xx.__dict__['yy']`，之后把 `xx.yy` 替换成 `xx.obfname`。
  - 类属性：`xx.__dict__` 是 mappingproxy，不能直接写；用 `gc.get_referents(xx.__dict__)[0][obfname] = gc.get_referents(xx.__dict__)[0]['yy']` 拿到底层 dict 再复制。
  - 常量/列表/字典节点的属性类型可静态确定，直接按对应类（`str`/`list`/`dict` 等）处理；`Call` 返回值类型未知时无法确定所属类，通常保持原样。
- 作用域处理：进入 `FunctionDef` 后区分局部变量与全局变量；`ListComp`/`DictComp`/`SetComp`/`For` 会创建临时变量（如 `i`、`k`、`v`），需要按局部作用域单独记录和替换。
- 新增的别名赋值节点要收集到列表中，并在 `visit_Module` 时按“内置属性 → 导入 → 模块属性 → 类属性”的顺序插到模块体前面，保证使用前已经建立别名。

## 触发条件

- 目标是 Python 源码（非已编译字节码），可被 `ast.parse` 正常解析。
- 混淆器需要在目标 Python 版本上运行；文章使用 `astor` 做反解析，Python 3.9+ 也可用 `ast.unparse`。
- 代码中的变量/属性访问能被 AST 静态定位；动态 `getattr`/`globals()`/`eval` 等会限制混淆覆盖面。
- 混淆后的代码仍需要可执行，且外部依赖（模块、类、属性）存在。

## 利用步骤

1. 用 `ast.parse` 读取源码，创建 `ast.NodeTransformer` 子类。
2. 维护 `import_var`、`builtin_var`、`local_var`、`global_var`、`attribute_var`、`temp_var` 等映射，以及待插入的别名节点列表。
3. 在 `visit_FunctionDef` 中标记进入函数、处理参数和局部变量；在 `visit_Name` 中按 `Load/Store` 分别查表替换，未登记的 `Store` 生成随机名。
4. 在 `visit_Import`/`visit_ImportFrom` 中把导入改写成 `__import__`/`getattr` 形式，并记录模块属性。
5. 在 `visit_Attribute` 中按模块/类/常量类型生成 `__dict__` 或 `gc.get_referents` 别名，并替换 `attr` 名。
6. 在 `visit_ListComp`/`visit_DictComp`/`visit_SetComp`/`visit_For` 中单独处理临时变量。
7. 在 `visit_Module` 中把别名节点按依赖顺序插到模块体前，再用 `astor.to_source`/`ast.unparse` 输出；运行测试用例确认语义不变。

## PoC

最小变量重命名示意（仅演示 `Name` 节点替换，完整实现需处理作用域、导入和属性）：

```python
import ast

class Renamer(ast.NodeTransformer):
    def __init__(self):
        self.mapping = {}

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.mapping.setdefault(node.id, f"v_{len(self.mapping)}")
        if node.id in self.mapping:
            node.id = self.mapping[node.id]
        return node

src = "x = 1\nprint(x)\n"
tree = ast.parse(src)
tree = Renamer().visit(tree)
ast.fix_missing_locations(tree)
print(ast.unparse(tree))  # v_0 = 1; print(v_0)
```

文章中的属性别名形态：

```python
# 模块属性
xx.__dict__[obfname] = xx.__dict__['yy']

# 类属性
gc.get_referents(xx.__dict__)[0][obfname] = gc.get_referents(xx.__dict__)[0]['yy']

# 内置变量
obfname = getattr(__builtins__, 'xx')
```

说明：文章还实现了 `str2hash`（自定义 Base64 字母表）用于把字符串常量转成混淆字符串，可与标识符混淆叠加。

## 变体与关联

- 变体：用自定义 Base64 字母表/`getattr` 字符串化进一步隐藏属性名和内置名。
- 变体：只做局部变量重命名（轻量，不需要运行时别名）；或只做属性名混淆（需要 `__dict__`/`gc.get_referents` 前置）。
- 变体：与 AST 控制流平坦化叠加，先平坦化再重命名，进一步降低可读性；见 [[code-analysis-reverse-obfuscation-python-ast-control-flow-flattening]]。
- 关联：[[code-analysis-reverse-obfuscation-go-ast-cross-file-obfuscation]]（Go AST 跨文件标识符混淆，思路相同但语言/实现不同）。
- 关联：[[code-analysis-reverse-unpacking-python-nested-marshal-consts-chain]]、[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（Python 打包/字节码层面的混淆与还原）。
- 边界：代码使用 `eval`/`exec`/`globals()`/动态 `getattr` 时，静态 AST 改写无法覆盖所有名字；属性来自 `Call` 返回值且类型未知时无法确定所属类。

## 检测与防御

- 检测：源码中出现大量随机短标识符、`getattr(__builtins__, ...)`、`__builtins__.__dict__[...]`、`module.__dict__[name]`、`gc.get_referents(...)[0][...]` 等运行时别名模式；`.py` 文件与 AST 反编译结果不一致。
- 防御：对混淆代码做 AST 规范化/别名追踪还原，结合动态执行/`sys.settrace` 观察真实调用；对 `gc.get_referents`、`__dict__` 动态赋值等异常模式告警。
- 加固：混淆只能提高分析成本，不能替代权限隔离/行为监控；对敏感 Python 代码使用签名/完整性校验，防止被篡改后重新分发。
