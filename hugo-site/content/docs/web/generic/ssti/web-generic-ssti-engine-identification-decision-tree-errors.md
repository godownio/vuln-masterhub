---
id: web-generic-ssti-engine-identification-decision-tree-errors
title: SSTI 模板引擎识别：决策树探测与报错特征对照
type: scenario
domain: web
path: web/generic/ssti
technique: ssti-engine-identification
tags:
- ssti
- recon
- fingerprint
- jinja2
- twig
- smarty
- mako
- thymeleaf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:27+08:00'
  notes: 已对照原文决策树与报错对照图核对；未逐引擎实测
url: /docs/web/generic/ssti/web-generic-ssti-engine-identification-decision-tree-errors/
draft: false
kb_aliases:
- SSTI 引擎识别
- 模板引擎判断
- SSTI 决策树
- SSTI 报错探测
- Jinja2 Twig Smarty Mako 判断
- 模板引擎指纹
---

## 一句话结论

SSTI 利用前先用两组探针分流：`${7*7}` 命中时用 Smarty 注释语法与 Mako 的 Python 表达式区分，`{{7*7}}` 命中时用 Jinja2/Twig 的字符串乘法差异区分；若决策树被 WAF 阻断，则按触发字符与报错类名（MakoException、Twig Error、ParseErrorException 等）反推引擎。

## 原理

不同模板引擎的定界符、表达式语义和异常类型不同：

- 定界符：`${}`（Mako/JSP EL/FreeMarker）、`{{ }}`（Jinja2/Twig/Django）、单 `{}`（Smarty）、`%`/`<% %>`（Mako/Tornado/ERB）、`#`（Velocity）、`@`（Razor）。
- 表达式语义：Jinja2 中 `7*'7'` 是字符串重复得到 `7777777`，Twig 中按数值乘法得到 `49`；Mako 支持 Python 的 `.join()`；Smarty 支持 `{*comment*}` 注释。
- 报错：Mako 抛 `MakoException`/`SyntaxException`，Twig 抛 `Twig Error`，Velocity 抛 `ParseErrorException`，Jinja2/Django 抛 `TemplateSyntaxError`，Razor 抛 `TemplateParsingException`，ERB 抛 `SyntaxError`/`ActionView::Template::Error`。

这些差异可组合成低成本探测，不需要先拿到命令执行。

## 触发条件

- 目标存在 SSTI 注入点，输入会进入模板解析；
- 响应会回显表达式结果或错误信息；
- 若 WAF 拦截，需要能观察拦截/报错差异。

## 利用步骤

1. 发送 `${7*7}`：
   - 返回 `49` → 进入 `${}` 分支；
   - 再发 `a{*comment*}b`：原样输出 `ab`（注释生效）→ Smarty；
   - 再发 `${"z".join("ab")}`：返回 `azb` → Mako；否则标记 Unknown。
2. 发送 `{{7*7}}`：
   - 返回 `49` → 进入 `{{}}` 分支；
   - 再发 `{{7*'7'}}`：返回 `7777777` → Jinja2；返回 `49` → Twig；都不对 → Unknown/Not vulnerable。
3. 若决策树被 WAF 阻断，改用报错探测：发送裸 `%`/`<%`、`@`、`#`、`{`/`{{`、`$`/`${`、`<`/`<%`，观察错误类名与关键字。
4. 结合语言环境（Python/PHP/Java/C#/Ruby）缩小范围，再进入对应引擎的利用卡。

## PoC

```text
# ${} 分支
${7*7}
a{*comment*}b          # Smarty: 输出 ab
${"z".join("ab")}      # Mako: 输出 azb

# {{}} 分支
{{7*7}}
{{7*'7'}}              # Jinja2: 7777777；Twig: 49
```

```text
# 报错探测
%        -> Mako/Tornado: MakoException, SyntaxException
<%       -> Mako/Tornado/ERB
@        -> Razor: TemplateParsingException, CSXXXX
#        -> Velocity: ParseErrorException, Lexical error
{ 或 {{  -> Jinja2/Twig/Django: TemplateSyntaxError, Twig Error
$ 或 ${  -> FreeMarker/JSP EL: ParseException, ELException
< 或 <%  -> ERB: SyntaxError, ActionView::Template::Error
```

## 变体与关联

- Jinja2 vs Twig 的其他差异：Jinja2 支持 `{{ ''.__class__ }}` 等 Python 属性链；Twig 使用 `.` 访问数组/对象，过滤器语法不同。
- Smarty 识别：单大括号、`{* *}` 注释、`{if}`/`{foreach}`。
- Mako 识别：`${}`、`<% %>`、`%` 控制行；报错含 `MakoException`。
- Thymeleaf 识别：HTML 属性 `th:text`、`${}`/`*{}`/`__${}__`、Spring 环境。
- 关联：[[web-python-ssti-bottle-unicode-octal-walrus-bypass]]、[[web-python-ssti-mako-context-write-getattr-bypass]]、[[web-generic-ssti-twig-filter-map-reduce-callback-rce]]、[[web-generic-ssti-smarty-direct-rce-v4-v5-bypass]]、[[web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti]]。

## 检测与防御

- 检测：请求中出现 `7*7`、`a{*comment*}b`、`7*'7'`、`${`、`{{`、`<%` 等探测串；同一来源短时间内切换多种模板语法。
- 防御：统一错误页，避免泄露模板引擎/异常类名；对模板输入做白名单；不允许用户控制模板源码；WAF 对模板定界符与表达式做检测。
- 注意：决策树会被 WAF、编码、上下文（属性/文本/JS）影响，应结合报错与语言环境交叉判断。
