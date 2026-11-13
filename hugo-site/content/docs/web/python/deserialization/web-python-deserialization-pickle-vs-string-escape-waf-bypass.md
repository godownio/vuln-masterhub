---
id: web-python-deserialization-pickle-vs-string-escape-waf-bypass
title: Pickle 字符串 opcode 转义绕过关键字检测：V 的 \u 与 S 的 \x 让明文关键字不出现在载荷里
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-vs-string-opcode-escape-keyword-bypass
tags:
- python
- pickle
- deserialization
- bypass
- encoding
- waf
- opcode
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:32:26+08:00'
  notes: 已对照原文核对：V 操作符 e 与 S 操作符 \x73 转义让明文关键字不出现在载荷中，与原文『绕过显式字符串检测』一节一致；两条 PoC 已在 Python 3.12 本地复跑（均解析为 secret）。未在目标环境复跑。
url: /docs/web/python/deserialization/web-python-deserialization-pickle-vs-string-escape-waf-bypass/
draft: false
kb_aliases:
- V 操作符 unicode 转义
- S 操作符十六进制转义
- pickle 关键字绕过
- pickle WAF 字符串检测
- \u0065 绕过
---

## 一句话结论

当 WAF/黑名单对 pickle 原始字节做明文关键字匹配时，可用 protocol 0 的 `V`（UNICODE）或 `S`（STRING）操作符写字符串：`V` 会把 `\u0065` 等 Unicode 转义解码，`S` 会按 Python 字符串字面量解析 `\x73` 等十六进制转义；解析后得到 `secret`/`eval` 等关键字，但原始载荷里不出现明文，从而绕过只扫字节流的检测。

## 原理

- pickle 的字符串操作符不只有 BINUNICODE（`X`，直接存 UTF-8 原始字节）。protocol 0 的 `V` 读取整行后做 Unicode 转义解码：`Vsecr\u0065t\n` 解析为 `secret`；`S` 读取带引号的 Python 字符串字面量并按 Python 规则解码转义：`S'\x73ecret'\n` 解析为 `secret`。
- 因此同一个逻辑字符串有多种字节表示：明文、`\u` 转义、`\x` 转义、引号风格（单/双/三引号）等。只对原始请求体做 `contains('secret')` 的 WAF 会被绕过，因为字节流里只有 `\u0073`/`\x73`。
- 该技巧适用于 protocol 0/1 的文本式 pickle；`X`/`\x8c` 等二进制协议操作符存的是解码后的原始 UTF-8，不能用这种转义隐藏关键字。
- 与评论/注释无关：pickle 没有注释语法，`V`/`S` 的转义是解析器真实支持的字符串语法，不是“把关键字藏进不参与解析的字节”。
- 限制：如果 WAF 先 base64 解码、再用 `pickletools.dis` 或实际 `pickle.loads` 还原字符串后检测，转义会被还原，绕过失效；如果 WAF 对 `\u`/`\x` 序列本身做归一化，也会失效。

## 触发条件

- 存在可控 pickle 反序列化入口，且 WAF/黑名单对原始字节做明文关键字匹配（如 `os`、`system`、`eval`、`subprocess`、`__import__`）。
- 载荷使用 protocol 0/1 的 `V`/`S` 字符串操作符（或可混用）。
- 目标 Python 版本支持 `V`/`S` 的转义解析（Python 2/3 均支持）。
- 转义后的字符串最终会被 `find_class`、函数名或参数使用。

## 利用步骤

1. 确认 WAF 检测层：提交一个含明文 `os`/`system` 的 pickle，观察是否被拦；再把同一字符串改成 `\x6f\x73`/`\u006f\u0073` 形式，观察是否放行。
2. 选择操作符：Unicode 字符串用 `V`（`\u` 转义）；普通字符串用 `S`（`\x` 转义、引号风格）。注意 `V` 只解码 `\u`/`\U`/`\N` 等 Unicode 转义，`\x` 需用 `S`。
3. 把危险模块名/函数名/命令参数替换成转义形式，保持 pickle 解析后的语义不变。
4. 用 `pickletools.dis` 确认反汇编显示的是解码后的字符串（这正说明解析器会还原），再在本地 `pickle.loads` 验证。
5. 发送并在目标上验证命令执行/回显；必要时把转义与 `INST`/`OBJ`、`STACK_GLOBAL` 等组合，进一步规避字节级规则。

## PoC

```python
# V：Unicode 转义
payload_v = b"Vsecr\\u0065t\n."      # 解析为 'secret'
# S：十六进制转义（Python 字符串字面量）
payload_s = b"S'\\x73ecret'\n."      # 解析为 'secret'
```

```python
# 组合示意：把 GLOBAL 的模块名/属性名写成转义形式
# 注意：GLOBAL 是两行文本，模块名/属性名本身不做转义解码；
# 需要把危险字符串作为 V/S 压栈后配合 STACK_GLOBAL/INST 使用。
payload = b"Vos\nVsystem\n\x93..."   # STACK_GLOBAL 需要 protocol 4 的 \x93，V/S 需与协议匹配
```

说明：`V`/`S` 适用于 protocol 0/1 的字符串；`STACK_GLOBAL` 需要 protocol 4，混用时需确认协议版本与解析器行为。以上为结构示意，未在目标环境复跑。

## 变体与关联

- 变体：`S` 支持单引号、双引号、三引号等写法，可用于规避对引号/转义的简单规则；`V` 支持 `\u`、`\U`、`\N{...}` 等 Unicode 转义。
- 变体：把关键字拆成多个字符串再拼接（`SETITEM`/`dict.get`），或使用 `_codecs.encode` 等运行时变换，适用于 WAF 对转义也做检测的场景。
- 关联：[[web-python-deserialization-pickle-inst-obj-reduce-filter-bypass]]（opcode 级调用绕过）；[[web-python-deserialization-pickle-parser-differential-checks]]（pickle 解析差异）；[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（短 payload 与黑名单漏项）。
- 边界：WAF 先解码/反序列化再检测、协议为 2+ 的二进制字符串、目标解析器不支持 `V`/`S` 转义时失效。

## 检测与防御

- 检测：不要只对原始字节做关键字匹配；先 base64 解码，再用受限的 `pickletools` 解析/反汇编，检查 `GLOBAL`/`INST` 的模块与属性名、`STACK_GLOBAL` 的栈上字符串，以及 `V`/`S` 解码后的值。
- 修复：禁止反序列化不可信 pickle；使用严格 `find_class` 类白名单；对 pickle 输入做协议/opcode 白名单。
- 加固：在低权限进程/容器中反序列化；监控异常模块导入、子进程与文件访问；对 `\u`/`\x` 转义密集的载荷提高告警等级。
