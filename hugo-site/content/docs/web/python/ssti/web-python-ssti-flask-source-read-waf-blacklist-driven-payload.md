---
id: web-python-ssti-flask-source-read-waf-blacklist-driven-payload
title: 先读源码再打 SSTI：用 file 参数读 app.py 与 waf.py，针对黑名单逐条构造 Jinja 注入
type: scenario
domain: web
path: web/python/ssti
technique: flask-ssti-source-read-blacklist-driven-bypass
tags:
- python
- flask
- ssti
- jinja2
- waf-bypass
- file-read
- source-disclosure
- blacklist
cve: []
severity: high
confidence: low
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:48:00+08:00'
  notes: 已对照原文核对；本次核对未读取图片；主要问题：PoC 第二段与文中抄录的黑名单自相矛盾——黑名单同时禁用 'set'、'__'、'{{'、'.'，而示例用 {% set %}（含 set）、['__class__']（含 __）、{{ lipsum... }}（含 {{），照抄必然被 waf_check 拦；只能保留「先读 app.py/waf.py 再逐条等价改写」的方法论，具体 payload 需作者按黑名单重写（如 \\x5f 转义避开 __、用 {% print %} 替代 set/{{ }}、纯下标访问替代点号）后重新验证；另外原文最终生效的表达式只在截图中，本次未读图，无法确认。
url: /docs/web/python/ssti/web-python-ssti-flask-source-read-waf-blacklist-driven-payload/
draft: false
kb_aliases:
- Flask SSTI 先读源码
- 读 waf 源码构造 payload
- render_template_string 黑名单绕过
- 文件读取 + SSTI 组合
- 关键字黑名单逐条规避
---

## 一句话结论

当同一个 Flask 应用既有一个「参数直接拼进文件路径」的读取接口、又有 `render_template_string` 的模板注入点时，正确顺序不是盲猜 payload 而是：先用文件读取接口读回 `app.py` 与 `waf.py`（黑名单实现），把被过滤的字符串一条条列出来，再针对每一条选出等价写法（换行内点号访问、下划线拼接、块语法替代输出语法），这样一次就能构造出通过过滤的链。

## 原理

- **源码比字典更有价值**：黑名单类 WAF 的强度完全取决于过滤表本身；读到 `dangerous_patterns` 列表后，被禁的子串（如 `os`、`set`、`__builtins__`、`=`、`.`、`{{`、`}}`、`popen`、`+`、`__`）就是构造约束，剩余工作是「用不被禁的语法表达同一语义」。
- **为什么不建议先盲打**：Jinja2 的可用语法空间很大（点号/中括号/`|attr`、字面量拼接、块语法、过滤器、`{% set %}`），盲打会大量触发限流（原文应用对注入路由做了每分钟 10 次的限制），且关键字命中与否无法归因。
- **文件读取接口的价值边界**：它只要求「路径可控」，`open(path).read()` 即可读任意可读文件；本例唯一限制是路径里含 `proc` 会被拦（防止读 `/proc/self/environ` 等），但读应用自身源码完全不受影响。
- **语义等价改写思路**：①`.` 被禁 → 用 `[ ]` 下标或 `|attr(...)`；②`__` 被禁 → 用 `\x5f\x5f` 或字符串拼接构造属性名；③`{{ }}` 被禁 → 用 `{% ... %}` 块语法（`{% set %}`/`{% print %}`）或语句式输出；④`+` 被禁 → 用 `~`（Jinja 的字符串连接符）或相邻字面量；⑤关键字（`os`、`popen`、`system`）被禁 → 用 `chr`/字符串拼接/`request.args` 二次传入拆分。
- **为什么这类组合链危险等级高**：文件读取本身只是信息泄露，但它把「黑盒 WAF」变成「白盒约束」，直接决定了 SSTI 能否一次打通；两个点常出现在同一应用（调试接口 + 模板渲染）里，属于典型的 1+1>2。
- **本卡证据边界**：原文对凭据/最终 payload 的截图未纳入本卡，具体通过过滤的表达式只在图片中，故 confidence 为 low，payload 一节给的是「按黑名单推导」的通用写法。

## 触发条件

- 目标为 Flask（`render_template_string` 直接把用户输入当模板源码渲染），且存在一个参数拼进 `open()` 的文件读取接口。
- 文件读取接口能读到应用源码与 WAF 实现文件（同目录或可通过相对路径到达）。
- 模板渲染接口有频率限制/关键字过滤，但未禁用危险语法本身（只是字符串黑名单）。
- 目标进程上下文里存在可用的链（`__globals__`/`__subclasses__` 可达 `os`/`subprocess`）。

## 利用步骤

1. 找到文件读取接口（参数常见为 `file`/`path`/`filename`），先读入口文件（如 `app.py`）确认路由、参数名与渲染方式。
2. 读 WAF 实现文件，把过滤表原样抄下来（列表元素即「禁用子串」），标注每个子串会影响 payload 的哪一部分。
3. 对每条禁用子串选替代语法：点号→下标/`attr`；双下划线→十六进制转义或字符串拼接；`{{ }}`→`{% %}` 块语法；`+`→`~`；敏感函数名→`chr` 拼接或从请求参数二次传入。
4. 用最小无害表达式验证模板执行（如算术表达式），确认渲染点确实求值。
5. 逐步扩展：先取到 `__class__.__mro__`（或 `__class__.__base__.__subclasses__()`）验证链可达，再定位 `os`/`subprocess.Popen`，最后执行命令。
6. 若渲染接口有速率限制，注意请求预算：每次只验证一个假设，避免把限流打满。
7. 复核：把最终 payload 与黑名单逐条比对（含大小写、编码后形式），确认没有触发任何禁用子串。

## PoC

```text
# 1) 读源码（参数名以实际路由为准）
GET /?file=app.py HTTP/1.1
GET /?file=waf.py HTTP/1.1

# 2) 从 waf.py 抄出黑名单（示例形态）
#    dangerous_patterns = ['os','set','__builtins__','=','.','{{','}}','popen','+','__']
```

```jinja
{# 3) 按黑名单推导的等价写法（示意，需按实际黑名单调整） #}
{% set c = ''['__class__'] %}                  {# 点号被禁 → 下标访问 #}
{% set b = c['__base__'] %}                    {# 双下划线被禁 → 十六进制/拼接构造 #}
{% set o = b['__subclasses__']() %}
{% print o %}                                  {# {{ }} 被禁 → print 块语法输出 #}
```

```jinja
{# 关键字（os/popen）被禁时的构造思路：拼接而非字面量 #}
{% set m = 'o' ~ 's' %}                        {# + 被禁 → ~ 连接 #}
{{ lipsum['__glo' ~ 'bals__'][m]['pop' ~ 'en']('id')['read']() }}
```

## 变体与关联

- **变体一**：`file` 参数只允许读固定目录时，先读 `.git/config`、`requirements.txt`、模板目录里的备份文件，从部署信息推断 WAF 与依赖版本。
- **变体二**：黑名单按子串匹配时，可用 Jinja 的相邻字面量拆分（`'__glo''bals__'`）或 `\x5f` 转义绕过，不需要拼接运算。
- **变体三**：限流存在时改用「一次请求内多步」的复合表达式，减少请求数。
- **关联**：[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（`\x5f` + `|attr` + `request.args` 拆分）、[[web-python-ssti-length-gated-waf-filler-blacklist-split]]（长度门控型 WAF 的对抗）、[[web-python-ssti-jinja2-subclasses-index-rce]]（黑名单通过后的标准取链）、[[web-python-ssti-jinja2-print-tag-adjacent-literal-json-cmd]]（块语法与相邻字面量拆分）。

## 检测与防御

- **代码层**：绝不把用户输入拼进 `render_template_string`；需要动态渲染时用 `render_template` + 固定模板 + 变量传参。文件读取接口改为「ID → 服务端映射路径」，禁止用户控制路径。
- **WAF 层**：字符串黑名单是最弱的一层，应改为「模板沙箱（SandboxedEnvironment）+ 禁用 `attr`/`getattr` 等危险过滤器」；对模板表达式做 AST 级校验而不是子串匹配。
- **监控**：同一会话内「先请求文件读取接口拿非静态资源，紧接着请求渲染接口送含 Jinja 语法字符的参数」是强特征；对 `{{`/`{%`/`__class__`/`__globals__` 等关键字在参数中的出现做告警（即使已被绕过）。
- **加固**：调试/源码读取类接口不得与业务渲染接口同域暴露；生产环境关闭 `debug`、限制可读文件白名单。
